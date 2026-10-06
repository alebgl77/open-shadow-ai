"""Bounded load with UUID5 identities and identical retained retry bytes."""

import concurrent.futures
import hashlib
import json
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from shadai.qualification.http_transport import HttpTransport
from shadai.qualification.http_worker import NoRedirect as NoRedirect
from shadai.qualification.schemas import QualificationError, canonical_bytes


def batched_fixtures(run_id, case, profile, collector, timestamp):
    namespace = UUID(run_id)
    events = []
    for index in range(profile["load"]["total_events"]):
        events.append(
            {
                "event_id": str(uuid5(namespace, f"{case}:{profile['load']['seed']}:{index}")),
                "timestamp": (
                    datetime.fromisoformat(timestamp)
                    + timedelta(
                        seconds=(index // profile["load"]["batch_size"])
                        * profile["load"]["batch_size"]
                        / profile["load"]["events_per_second"]
                    )
                ).isoformat(),
                "source_type": "dns",
                "collector_id": collector,
                "domain": "api.openai.com",
            }
        )
        if len(events) == profile["load"]["batch_size"]:
            yield canonical_bytes({"events": events})
            events = []
    if events:
        yield canonical_bytes({"events": events})


def fixtures(run_id, case, profile, collector, timestamp):
    return list(batched_fixtures(run_id, case, profile, collector, timestamp))


def endpoint(url, *, lab=False):
    parsed = urlsplit(url)
    if parsed.scheme != "https" and not (lab and parsed.scheme == "http" and parsed.hostname == "127.0.0.1"):
        raise QualificationError("Target load requires exact HTTPS; lab requires loopback HTTP")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise QualificationError("Load URL must be an exact origin")
    return url.rstrip("/") + "/api/v1/ingest/events"


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math_ceil(len(ordered) * fraction) - 1))]


def math_ceil(value):
    import math

    return math.ceil(value)


class LoadSender:
    def __init__(self, profile, run_id, case, run_dir, collector, *, clock=time.monotonic):
        self.profile, self.run_id, self.case = profile, run_id, case
        self.directory, self.collector, self.clock = Path(run_dir), collector, clock
        self.cancelled = threading.Event()
        self.transport = HttpTransport(self.cancelled, clock=clock)

    def stop(self):
        self.cancelled.set()

    def run(self, url, key, *, deadline=None):
        start = self.clock()
        profile = self.profile
        deadline = min(deadline or float("inf"), start + profile["limits"]["max_wall_seconds"])

        def preparation_budget():
            if self.clock() >= deadline:
                raise QualificationError("Load wall budget exhausted during preparation")

        preparation_budget()
        previous = self.directory / (self.case + "-load.json")
        prior_requests = json.loads(previous.read_text()).get("requests", 0) if previous.exists() else 0
        target = endpoint(url, lab=profile["scope"] == "disposable_lab")
        manifest_path = self.directory / (self.case + "-load-manifest.json")
        if self.cancelled.is_set():
            manifest = {"batches": []}
        elif manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            if manifest["run_id"] != self.run_id or manifest["collector"] != self.collector:
                raise QualificationError("Retained load belongs to another run or collector")
            if len(manifest["batches"]) != len(manifest["sha256"]):
                raise QualificationError("Retained request manifest differs")
            for name, expected_hash in zip(manifest["batches"], manifest["sha256"], strict=True):
                preparation_budget()
                if not re.fullmatch(re.escape(self.case) + r"-batch-[0-9]{6,8}\.json", name):
                    raise QualificationError("Retained request path is outside the fixed case")
                path = self.directory / name
                if path.is_symlink() or path.stat().st_size > profile["limits"]["max_request_bytes"]:
                    raise QualificationError("Retained request file exceeds its boundary")
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                    raise QualificationError("Retained request bytes changed")
                preparation_budget()
        else:
            timestamp = datetime.now(UTC).isoformat()
            batches = batched_fixtures(self.run_id, self.case, profile, self.collector, timestamp)
            names, hashes = [], []
            retained_bytes = 0
            for path in self.directory.rglob("*"):
                preparation_budget()
                if path.is_file():
                    retained_bytes += path.stat().st_size
            for index, payload in enumerate(batches):
                preparation_budget()
                retained_bytes += len(payload)
                if (
                    len(payload) > profile["limits"]["max_request_bytes"]
                    or retained_bytes > profile["limits"]["max_disk_bytes"]
                ):
                    raise QualificationError("Retained load exceeds explicit request/disk budgets")
                name = f"{self.case}-batch-{index:06d}.json"
                path = self.directory / name
                with path.open("xb") as file:
                    file.write(payload)
                path.chmod(0o600)
                names.append(name)
                hashes.append(hashlib.sha256(payload).hexdigest())
            manifest = {
                "schema": 1,
                "run_id": self.run_id,
                "collector": self.collector,
                "batches": names,
                "sha256": hashes,
            }
            manifest_path.write_bytes(canonical_bytes(manifest))
            manifest_path.chmod(0o600)
            preparation_budget()
        attempted, accepted, status_counts, durations, submitted = set(), set(), {}, [], []
        lock = threading.Lock()
        requests = 0

        def send(payload):
            nonlocal requests
            ids = {event["event_id"] for event in json.loads(payload)["events"]}
            for _ in range(3):
                with lock:
                    if (
                        self.cancelled.is_set()
                        or requests >= profile["limits"]["max_requests"]
                        or self.clock() >= deadline
                    ):
                        return
                    requests += 1
                    attempted.update(ids)
                before = self.clock()
                status, body, _ = self.transport.request(
                    target,
                    method="POST",
                    body=payload,
                    credential=key,
                    deadline=deadline,
                    timeout=profile["load"]["request_timeout_seconds"],
                )
                if status == 202:
                    try:
                        received = json.loads(body).get("received")
                    except (ValueError, AttributeError):
                        raise QualificationError("Ingestion acknowledgement is malformed") from None
                    if type(received) is not int or received != len(ids):
                        raise QualificationError("Ingestion acknowledgement differs from submitted logical events")
                with lock:
                    durations.append(self.clock() - before)
                    status_counts[str(status)] = status_counts.get(str(status), 0) + 1
                    if status == 202:
                        accepted.update(ids)
                if status == 202 or status not in {0, 429, 503}:
                    return
                if self.cancelled.wait(min(0.2, max(0, deadline - self.clock()))):
                    return

        with concurrent.futures.ThreadPoolExecutor(max_workers=profile["load"]["concurrency"]) as pool:
            try:
                for index, name in enumerate(manifest["batches"]):
                    if self.cancelled.is_set() or self.clock() >= deadline:
                        break
                    due = start + index * profile["load"]["batch_size"] / profile["load"]["events_per_second"]
                    if self.cancelled.wait(min(max(0, due - self.clock()), max(0, deadline - self.clock()))):
                        break
                    if self.clock() >= deadline:
                        break
                    submitted.append(pool.submit(send, (self.directory / name).read_bytes()))
                for future in submitted:
                    future.result()
            except BaseException:
                self.stop()
                for future in submitted:
                    future.cancel()
                raise
        # These are client UUIDs; persistence verification applies the enrolled
        # collector namespace independently, rather than counting physical rows.
        expected = [
            str(
                uuid5(
                    NAMESPACE_URL,
                    json.dumps([profile["installation"], self.collector, event_id], separators=(",", ":")),
                )
            )
            for event_id in sorted(accepted)
        ]
        result = {
            "schema": 1,
            "case": self.case,
            "attempted": len(attempted),
            "accepted": len(accepted),
            "persisted": None,
            "accepted_scoped_ids": expected,
            "http_status_counts": status_counts,
            "requests": requests + prior_requests,
            "http_latency_p50_seconds": percentile(durations, 0.5),
            "http_latency_p95_seconds": percentile(durations, 0.95),
            "end_to_end_latency_p95_seconds": None,
            "elapsed_seconds": self.clock() - start,
            "cancelled": self.cancelled.is_set(),
        }
        output = self.directory / (self.case + "-load.json")
        output.write_bytes(canonical_bytes(result))
        output.chmod(0o600)
        return result
