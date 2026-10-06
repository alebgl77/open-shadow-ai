"""Offline normalized-metadata matching quality, never capture or model-use quality."""

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from shadai.engine.catalog_loader import build_catalog_index
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead, CatalogYAMLEntry
from shadai.models.event import CanonicalEvent
from shadai.qualification.schemas import QualificationError, bounded_read, bounded_text, strict_object

MAX_CORPUS_BYTES = 64 * 1024 * 1024
MAX_CASE_BYTES = 65536
MAX_CASES = 100000
SIGNALS = (
    "domain",
    "sni",
    "url_host",
    "url_path",
    "user_agent",
    "process_name",
    "extension_id",
    "oauth_app_id",
    "local_port",
    "container_image",
)


def metrics(counts):
    tp, fp, fn, tn = (counts.get(key, 0) for key in ("tp", "fp", "fn", "tn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    values = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1}
    values["undefined"] = {name: "zero_denominator" for name in ("precision", "recall", "f1") if values[name] is None}
    return values


def frozen_matcher(directory):
    root = Path(directory).resolve()
    files = sorted(root.glob("*.yaml"))
    if not files or len(files) > 10000:
        raise QualificationError("A bounded, nonempty frozen catalog is required")
    hashes, items, seen = {}, [], set()
    total = 0
    for path in files:
        if path.is_symlink():
            raise QualificationError("Catalog links are not accepted")
        data = bounded_read(path, 1048576)
        total += len(data)
        if len(data) > 1048576 or total > 16 * 1048576:
            raise QualificationError("Catalog exceeds byte budget")
        entry = CatalogYAMLEntry.model_validate(yaml.safe_load(data))
        if entry.id in seen:
            raise QualificationError("Frozen catalog contains duplicate item identifiers")
        seen.add(entry.id)
        items.append(
            CatalogItemRead(
                catalog_item_id=entry.id,
                **entry.model_dump(exclude={"id", "signatures"}),
                **entry.signatures.model_dump(),
                source_of_truth="builtin",
            )
        )
        hashes[path.name] = hashlib.sha256(data).hexdigest()
    return CatalogMatcher(build_catalog_index(items)), hashes


def read_corpus(path):
    data = bounded_read(path, MAX_CORPUS_BYTES)
    lines = data.splitlines()
    if not lines or len(lines) - 1 > MAX_CASES or any(len(line) > MAX_CASE_BYTES for line in lines):
        raise QualificationError("Corpus exceeds case budget")

    def decode(line):
        # Reuse the duplicate/nonfinite JSON checks without temporary files.
        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise QualificationError("Duplicate JSON field")
                result[key] = value
            return result

        return json.loads(
            line,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(QualificationError("Nonfinite JSON")),
        )

    manifest = strict_object(
        decode(lines[0]), {"schema", "type", "synthetic", "sampling_frame", "period", "labelling_method", "provenance"}
    )
    if (
        type(manifest["schema"]) is not int
        or manifest["schema"] != 1
        or manifest["type"] != "manifest"
        or type(manifest["synthetic"]) is not bool
    ):
        raise QualificationError("Unknown corpus manifest")
    for field in ("sampling_frame", "period", "labelling_method", "provenance"):
        bounded_text(manifest[field], 2048)
    cases, seen = [], set()
    for line in lines[1:]:
        case = strict_object(
            decode(line), {"schema", "case_id", "family", "source", "protocol", "event", "truth", "labelling_method"}
        )
        if type(case["schema"]) is not int or case["schema"] != 1:
            raise QualificationError("Unknown case schema")
        for field in ("case_id", "family", "source", "protocol", "labelling_method"):
            bounded_text(case[field])
        if case["case_id"] in seen:
            raise QualificationError("Duplicate case identifier")
        seen.add(case["case_id"])
        truth = strict_object(case["truth"], {"ai_service", "expected_attribution"})
        if truth["ai_service"] is not None and type(truth["ai_service"]) is not bool:
            raise QualificationError("Truth must be true, false or unknown")
        if truth["expected_attribution"] is not None:
            bounded_text(truth["expected_attribution"], 100)
        event = CanonicalEvent.model_validate(case["event"])
        if event.source_type != case["source"] or (event.protocol or "none") != case["protocol"]:
            raise QualificationError("Case source/protocol differs from canonical event")
        # Boundary-produced attribution is not an observed input for this evaluator.
        if event.catalog_match_id or event.match_field or event.match_confidence:
            raise QualificationError("Corpus must contain observed metadata, not precomputed attribution")
        cases.append((case, event))
    if not cases:
        raise QualificationError("Corpus contains no cases")
    return manifest, cases, hashlib.sha256(data).hexdigest()


def evaluate_quality(corpus, catalog):
    from shadai.qualification.provenance import source_stamp

    manifest, cases, corpus_hash = read_corpus(corpus)
    matcher, hashes = frozen_matcher(catalog)
    counts, families, coverage = Counter(), defaultdict(Counter), Counter()
    outputs = []
    for case, event in cases:
        families[case["family"]]  # Keep unknown-only families with undefined supervised metrics.
        resolution = matcher.resolve_event(event)
        attribution = resolution.match.catalog_item_id if resolution.match else None
        if attribution:
            status = "matched"
        elif resolution.ambiguous:
            status = "ambiguous"
        elif not any(getattr(event, field) for field in SIGNALS):
            status = "no_observable_signal"
        else:
            status = "no_match"
        coverage[status] += 1
        truth = case["truth"]["ai_service"]
        if truth is None:
            coverage["unknown_truth"] += 1
        else:
            coverage["labelled"] += 1
            classification = ("tp" if attribution else "fn") if truth else ("fp" if attribution else "tn")
            counts[classification] += 1
            families[case["family"]][classification] += 1
        expected = case["truth"]["expected_attribution"]
        if attribution and expected is not None and attribution != expected:
            coverage["attribution_errors"] += 1
        outputs.append({"case_id": case["case_id"], "status": status, "attribution": attribution})
    coverage["total"] = len(cases)
    return {
        "schema": 1,
        "source": source_stamp(),
        "measurement": "normalized_metadata_matching",
        "synthetic": manifest["synthetic"],
        "corpus_sha256": corpus_hash,
        "catalog_sha256": hashes,
        "global": metrics(counts),
        "families": {name: metrics(value) for name, value in sorted(families.items())},
        "coverage": dict(coverage),
        "labelling_coverage": coverage["labelled"] / len(cases),
        "cases": outputs,
        "limitations": [
            "not_capture_completeness",
            "not_actual_model_use",
            "not_probability_calibration",
            "synthetic_reference_not_representative" if manifest["synthetic"] else "operator_sampling_frame",
        ],
    }
