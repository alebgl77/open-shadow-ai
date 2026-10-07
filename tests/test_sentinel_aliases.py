"""Known-vulnerable controls preserve producer IDs while validating NVD aliases."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sentinel_components", ROOT / "scripts/component_scanner.py")
COMPONENTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPONENTS)
QUERY = "cpe:2.3:a:redislabs:redis:5.0.0:*:*:*:*:*:*:*"
CVE = "CVE-2021-32675"
PRIMARY = "BIT-redis-2021-32675"


def related(identifier=CVE, **changes):
    value = {"id": identifier, "namespace": "nvd:cpe",
             "dataSource": "https://nvd.nist.gov/vuln/detail/" + identifier, "urls": [], "cvss": []}
    value.update(changes)
    return value


def report(*, primary=PRIMARY):
    # Public identity excerpt from both original Grype 0.120.1 native reports.
    return {"descriptor": {"name": "grype", "version": "0.120.1", "configuration": {},
                           "db": {"status": {}, "providers": {"bitnami": {}, "nvd": {}}}},
            "source": {"type": "cpe", "target": QUERY}, "ignoredMatches": [],
            "matches": [{"artifact": {"id": "redis-query", "name": "redis", "version": "5.0.0", "cpes": [QUERY]},
                         "vulnerability": {"id": primary, "namespace": "bitnami", "severity": "High",
                                           "fix": {"versions": ["5.0.14", "6.0.16", "6.2.6"]}},
                         "relatedVulnerabilities": [related()]}]}


def validate(value, *, query=QUERY, required=None):
    return COMPONENTS.validate_sentinel_report(value, query=query, configuration={}, database_status={},
                                               required_advisories=required or {CVE})


def test_native_bitnami_alias_satisfies_control_without_rewriting_ids_or_findings():
    value = report()
    before = copy.deepcopy(value)
    raw = json.dumps(value, sort_keys=True).encode()
    assert not {CVE}.intersection({match["vulnerability"]["id"] for match in value["matches"]})
    original_findings = COMPONENTS.validate_report(value, query=QUERY, configuration={}, database_status={})
    assert validate(value) == original_findings == [QUERY + ": " + PRIMARY]
    assert value == before and value["matches"][0]["vulnerability"]["id"] == PRIMARY
    assert hashlib.sha256(json.dumps(value, sort_keys=True).encode()).digest() == hashlib.sha256(raw).digest()


@pytest.mark.parametrize("representation", ["absent", "null", "empty"])
@pytest.mark.parametrize("primary", [CVE, PRIMARY])
def test_primary_legacy_related_representations_preserve_coverage_requirements(representation, primary):
    value = report(primary=primary)
    match = value["matches"][0]
    if representation == "absent":
        del match["relatedVulnerabilities"]
    else:
        match["relatedVulnerabilities"] = None if representation == "null" else []
    if primary == CVE:
        assert validate(value) == [QUERY + ": " + CVE]
    else:
        with pytest.raises(ValueError, match="known-vulnerable sentinel"):
            validate(value)


@pytest.mark.parametrize("primary", ["CVE-2023-48795", "GHSA-45x7-px36-x8w8", "GO-2023-2402"])
def test_original_go_control_primary_identifiers_still_satisfy_it(primary):
    value = report(primary=primary)
    query = "pkg:golang/golang.org/x/crypto@0.1.0"
    value["source"] = {"type": "purl", "target": query}
    value["matches"][0]["artifact"] = {"id": "go-query", "name": "golang.org/x/crypto",
                                       "version": "0.1.0", "purl": query}
    value["matches"][0]["relatedVulnerabilities"] = [related("CVE-2023-48795"),
        related("GHSA-45x7-px36-x8w8", namespace="github:language:go", dataSource="")]
    assert validate(value, query=query, required={"CVE-2023-48795", "GHSA-45x7-px36-x8w8", "GO-2023-2402"})


class PoisonDict(dict):
    def get(self, *args):
        raise AssertionError("untrusted dictionary method called")


class ListSubclass(list):
    pass


class StringSubclass(str):
    pass


@pytest.mark.parametrize("mutation", ["list_dict", "list_string", "list_subclass", "entry_null", "entry_string",
    "entry_subclass", "missing_id", "empty_id", "id_int", "id_bool", "id_subclass", "key_int", "key_subclass",
    "missing_source", "source_null", "source_subclass", "missing_urls", "urls_null", "urls_subclass",
    "url_int", "url_subclass", "missing_cvss", "cvss_null", "cvss_subclass", "score_int", "score_subclass",
    "namespace_int", "namespace_subclass", "severity_bool", "description_list", "known_exploited_dict",
    "epss_subclass", "cwe_int", "duplicate", "mixed", "wrong_namespace", "wrong_url", "wrong_url_suffix",
    "missing_namespace"])
@pytest.mark.parametrize("primary", [PRIMARY, CVE])
def test_malformed_present_related_cannot_be_rescued_by_primary_or_other_valid_alias(mutation, primary):
    value = report(primary=primary)
    aliases = value["matches"][0]["relatedVulnerabilities"]
    item = aliases[0]
    if mutation.startswith("list_"):
        value["matches"][0]["relatedVulnerabilities"] = {
            "list_dict": {}, "list_string": "alias", "list_subclass": ListSubclass(aliases)}[mutation]
    elif mutation.startswith("entry_"):
        aliases.append({"entry_null": None, "entry_string": "alias", "entry_subclass": PoisonDict(item)}[mutation])
    elif mutation.startswith("missing_"):
        del item[{"missing_id": "id", "missing_source": "dataSource", "missing_urls": "urls",
                  "missing_cvss": "cvss", "missing_namespace": "namespace"}[mutation]]
    elif mutation.startswith("id_") or mutation == "empty_id":
        item["id"] = {"id_int": 1, "id_bool": True, "id_subclass": StringSubclass(CVE), "empty_id": ""}[mutation]
    elif mutation.startswith("key_"):
        item[1 if mutation == "key_int" else StringSubclass("extra")] = "extra"
    elif mutation.startswith("source_"):
        item["dataSource"] = None if mutation == "source_null" else StringSubclass(item["dataSource"])
    elif mutation.startswith("urls_"):
        item["urls"] = None if mutation == "urls_null" else ListSubclass()
    elif mutation.startswith("url_"):
        item["urls"] = [1 if mutation == "url_int" else StringSubclass("https://example.test")]
    elif mutation.startswith("cvss_"):
        item["cvss"] = None if mutation == "cvss_null" else ListSubclass()
    elif mutation.startswith("score_"):
        item["cvss"] = [1 if mutation == "score_int" else PoisonDict()]
    elif mutation.startswith("namespace_"):
        item["namespace"] = 1 if mutation == "namespace_int" else StringSubclass("nvd:cpe")
    elif mutation == "severity_bool":
        item["severity"] = True
    elif mutation == "description_list":
        item["description"] = []
    elif mutation == "known_exploited_dict":
        item["knownExploited"] = {}
    elif mutation == "epss_subclass":
        item["epss"] = ListSubclass()
    elif mutation == "cwe_int":
        item["cwes"] = [1]
    elif mutation in {"duplicate", "mixed"}:
        aliases.append(copy.deepcopy(item) if mutation == "duplicate" else None)
    elif mutation == "wrong_namespace":
        item["namespace"] = "bitnami"
    else:
        item["dataSource"] = "https://example.test/" + CVE if mutation == "wrong_url" else item["dataSource"] + "?extra"
    with pytest.raises(ValueError):
        validate(value)


def test_duplicate_alias_identity_refuses_even_if_optional_metadata_differs():
    value = report()
    value["matches"][0]["relatedVulnerabilities"].append(related(description="different text"))
    with pytest.raises(ValueError, match="Duplicate sentinel"):
        validate(value)


def test_same_alias_on_independent_provider_matches_is_preserved():
    value = report()
    second = copy.deepcopy(value["matches"][0])
    second["vulnerability"]["namespace"] = "independent-provider"
    value["matches"].append(second)
    before = copy.deepcopy(value)
    assert validate(value) == [QUERY + ": " + PRIMARY] * 2
    assert value == before


def test_unrelated_optional_metadata_may_be_empty_and_extra_producer_fields_are_preserved():
    value = report()
    value["matches"][0]["relatedVulnerabilities"].append(related("CVE-unrelated", namespace="", dataSource="",
        severity="", description="", knownExploited=[], epss=[], cwes=[], futureMetadata={"observed": True}))
    before = copy.deepcopy(value)
    assert validate(value) and value == before


@pytest.mark.parametrize("mutation", ["source_query", "artifact_query", "other_match", "ignored", "database",
                                     "configuration", "tool", "fix"])
def test_alias_never_bypasses_existing_report_binding_and_policy_validation(mutation):
    value = report()
    if mutation == "source_query":
        value["source"]["target"] = QUERY.replace("5.0.0", "5.0.14")
    elif mutation == "artifact_query":
        value["matches"][0]["artifact"]["version"] = "5.0.14"
    elif mutation == "other_match":
        other = copy.deepcopy(value["matches"][0])
        other["artifact"]["cpes"] = [QUERY.replace("5.0.0", "5.0.14")]
        value["matches"].append(other)
    elif mutation == "ignored":
        value["ignoredMatches"] = [{"reason": "hidden"}]
    elif mutation in {"database", "configuration", "tool"}:
        descriptor = value["descriptor"]
        if mutation == "database":
            descriptor["db"]["status"] = {"foreign": True}
        else:
            descriptor["configuration" if mutation == "configuration" else "version"] = "foreign"
    else:
        value["matches"][0]["vulnerability"]["fix"]["versions"] = [True]
    with pytest.raises(ValueError):
        validate(value)


def test_valid_related_for_another_advisory_cannot_satisfy_this_control():
    value = report()
    value["matches"][0]["relatedVulnerabilities"] = [related("CVE-2021-99999")]
    with pytest.raises(ValueError, match="known-vulnerable sentinel"):
        validate(value)


def test_later_malformed_match_is_checked_after_an_earlier_valid_primary():
    value = report(primary=CVE)
    other = copy.deepcopy(value["matches"][0])
    other["vulnerability"]["id"] = "BIT-another"
    other["relatedVulnerabilities"] = [related(namespace="foreign")]
    value["matches"].append(other)
    with pytest.raises(ValueError, match="source differs"):
        validate(value)


def nested_advisory():
    return related(cvss=[{"version": "", "vector": "", "metrics": {"baseScore": 0,
        "exploitabilityScore": 0.0, "impactScore": 0}, "vendorMetadata": None, "source": "", "type": ""}],
        knownExploited=[{"cve": "", "knownRansomwareCampaignUse": "", "vendorProject": "", "product": "",
            "dateAdded": "", "requiredAction": "", "dueDate": "", "notes": "", "urls": [], "cwes": []}],
        epss=[{"cve": "", "date": "", "epss": 0, "percentile": 0.0}],
        cwes=[{"cve": "", "cwe": "", "source": "", "type": ""}])


def nested_report(primary):
    value = report(primary=primary)
    value["matches"][0]["relatedVulnerabilities"] = [nested_advisory()]
    return value


def locate(item, path):
    for key in path[:-1]:
        item = item[key]
    return item, path[-1]


@pytest.mark.parametrize("primary", [PRIMARY, CVE])
@pytest.mark.parametrize("mutation", ["empty", "version", "vector", "metrics", "base_bool", "missing_base"])
def test_oracle_twelve_nested_cvss_counterexamples_refuse_before_primary_success(primary, mutation):
    value = nested_report(primary)
    score = value["matches"][0]["relatedVulnerabilities"][0]["cvss"][0]
    if mutation == "empty":
        score.clear()
    elif mutation == "version":
        score["version"] = 1
    elif mutation == "vector":
        score["vector"] = []
    elif mutation == "metrics":
        score["metrics"] = True
    elif mutation == "base_bool":
        score["metrics"]["baseScore"] = True
    else:
        del score["metrics"]["baseScore"]
    with pytest.raises(ValueError):
        validate(value)


REQUIRED_NESTED = [
    ("cvss", 0, "version"), ("cvss", 0, "vector"), ("cvss", 0, "metrics"),
    ("cvss", 0, "vendorMetadata"), ("cvss", 0, "metrics", "baseScore"),
    ("knownExploited", 0, "cve"), ("knownExploited", 0, "knownRansomwareCampaignUse"),
    ("epss", 0, "cve"), ("epss", 0, "date"), ("epss", 0, "epss"), ("epss", 0, "percentile"),
    ("cwes", 0, "cve"),
]
OPTIONAL_NESTED = [
    ("cvss", 0, "source"), ("cvss", 0, "type"), ("cvss", 0, "metrics", "exploitabilityScore"),
    ("cvss", 0, "metrics", "impactScore"), ("knownExploited", 0, "vendorProject"),
    ("knownExploited", 0, "product"), ("knownExploited", 0, "dateAdded"), ("knownExploited", 0, "requiredAction"),
    ("knownExploited", 0, "dueDate"), ("knownExploited", 0, "notes"), ("knownExploited", 0, "urls"),
    ("knownExploited", 0, "cwes"), ("cwes", 0, "cwe"), ("cwes", 0, "source"), ("cwes", 0, "type"),
]


@pytest.mark.parametrize("primary", [PRIMARY, CVE])
@pytest.mark.parametrize("path", REQUIRED_NESTED)
def test_each_nested_required_field_missing_refuses(primary, path):
    value = nested_report(primary)
    parent, key = locate(value["matches"][0]["relatedVulnerabilities"][0], path)
    del parent[key]
    with pytest.raises(ValueError):
        validate(value)


@pytest.mark.parametrize("primary", [PRIMARY, CVE])
@pytest.mark.parametrize("path", [p for p in REQUIRED_NESTED + OPTIONAL_NESTED if p[-1] != "vendorMetadata"])
def test_known_present_nested_fields_reject_null(primary, path):
    value = nested_report(primary)
    parent, key = locate(value["matches"][0]["relatedVulnerabilities"][0], path)
    parent[key] = None
    with pytest.raises(ValueError):
        validate(value)


@pytest.mark.parametrize("primary", [PRIMARY, CVE])
def test_empty_strings_zero_scores_optional_absence_and_extra_fields_preserve_original(primary):
    value = nested_report(primary)
    item = value["matches"][0]["relatedVulnerabilities"][0]
    for path in OPTIONAL_NESTED:
        parent, key = locate(item, path)
        del parent[key]
    for name in ("cvss", "knownExploited", "epss", "cwes"):
        item[name][0]["futureField"] = {"preserved": [None, False]}
    before = copy.deepcopy(value)
    assert validate(value) and value == before


@pytest.mark.parametrize("primary", [PRIMARY, CVE])
@pytest.mark.parametrize("metadata", [None, False, 0, "", [], {"unknown": [1, "text", None]}])
def test_vendor_metadata_required_key_accepts_arbitrary_value_without_projection(primary, metadata):
    value = nested_report(primary)
    value["matches"][0]["relatedVulnerabilities"][0]["cvss"][0]["vendorMetadata"] = metadata
    before = copy.deepcopy(value)
    assert validate(value) and value == before


NUMBER_PATHS = [("cvss", 0, "metrics", field) for field in ("baseScore", "exploitabilityScore", "impactScore")] + [
    ("epss", 0, "epss"), ("epss", 0, "percentile")]


class IntSubclass(int):
    pass


class FloatSubclass(float):
    pass


@pytest.mark.parametrize("primary", [PRIMARY, CVE])
@pytest.mark.parametrize("path", NUMBER_PATHS)
@pytest.mark.parametrize("number", [True, False, float("nan"), float("inf"), float("-inf"),
                                    IntSubclass(0), FloatSubclass(0.0), "0"])
def test_nested_scores_refuse_bool_nonfinite_subclass_and_nonnumeric(primary, path, number):
    value = nested_report(primary)
    parent, key = locate(value["matches"][0]["relatedVulnerabilities"][0], path)
    parent[key] = number
    with pytest.raises(ValueError):
        validate(value)


@pytest.mark.parametrize("primary", [PRIMARY, CVE])
@pytest.mark.parametrize("mutation", ["version", "vector", "source", "type", "metrics", "metric_key",
    "known_record", "known_cve", "known_ransomware", "known_optional", "known_urls", "known_url",
    "known_cwes", "known_cwe", "epss_record", "epss_cve", "epss_date", "cwe_record", "cwe_cve", "cwe_optional"])
def test_nested_structs_strings_and_lists_require_exact_builtin_types(primary, mutation):
    value = nested_report(primary)
    item = value["matches"][0]["relatedVulnerabilities"][0]
    if mutation in {"version", "vector", "source", "type"}:
        item["cvss"][0][mutation] = StringSubclass("")
    elif mutation == "metrics":
        item["cvss"][0]["metrics"] = PoisonDict(item["cvss"][0]["metrics"])
    elif mutation == "metric_key":
        item["cvss"][0]["metrics"][StringSubclass("unknown")] = 0
    elif mutation.endswith("record"):
        name = {"known_record": "knownExploited", "epss_record": "epss", "cwe_record": "cwes"}[mutation]
        item[name][0] = PoisonDict(item[name][0])
    elif mutation.startswith("known_"):
        key = {"known_cve": "cve", "known_ransomware": "knownRansomwareCampaignUse", "known_optional": "notes",
               "known_urls": "urls", "known_url": "urls", "known_cwes": "cwes", "known_cwe": "cwes"}[mutation]
        item["knownExploited"][0][key] = (ListSubclass() if mutation in {"known_urls", "known_cwes"} else
                                         [StringSubclass("")] if mutation in {"known_url", "known_cwe"} else
                                         StringSubclass(""))
    elif mutation.startswith("epss_"):
        item["epss"][0]["cve" if mutation == "epss_cve" else "date"] = StringSubclass("")
    else:
        item["cwes"][0]["cve" if mutation == "cwe_cve" else "type"] = StringSubclass("")
    with pytest.raises(ValueError):
        validate(value)
