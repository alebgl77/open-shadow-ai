"""Live Compose acceptance: HTTP -> Redis -> workers -> ClickHouse and PostgreSQL."""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

api = "http://127.0.0.1:8443"
key = Path("secrets/agent_api_key.txt").read_text().strip()
event_id = str(uuid.uuid4())
directory_id = str(uuid.uuid4())
timestamp = datetime.now(UTC).isoformat()
events = [
    {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_type": "dns",
        "collector_id": "ci-dns",
        "domain": "chatgpt.com",
        "src_ip": "192.0.2.10",
    },
    {
        "event_id": directory_id,
        "timestamp": timestamp,
        "source_type": "directory",
        "evidence_type": "inventory",
        "collector_id": "ci-ad",
        "identity_provider": "active_directory",
        "identity_object_id": str(uuid.uuid4()),
        "device_id": "ci-managed-device",
        "hostname": "ci-device.example.test",
    },
]


def query(service: str, command: list[str]) -> str:
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", service, *command], capture_output=True, text=True, check=True, timeout=20
    )
    return result.stdout.strip()


with urlopen(api + "/ready", timeout=10) as response:
    assert response.status == 200
with urlopen("http://127.0.0.1:3000/health", timeout=10) as response:
    assert response.status == 200
payload = json.dumps({"events": events}).encode()
try:
    urlopen(
        Request(api + "/api/v1/ingest/events", data=payload, headers={"Content-Type": "application/json"}), timeout=10
    )
except HTTPError as error:
    assert error.code in {401, 403}
else:
    raise AssertionError("Unauthenticated ingestion was accepted")
request = Request(
    api + "/api/v1/ingest/events", data=payload, headers={"Content-Type": "application/json", "X-API-Key": key}
)
with urlopen(request, timeout=10) as response:
    assert response.status in {200, 201, 202}

deadline = time.monotonic() + 100
while time.monotonic() < deadline:
    # UUIDs are generated locally; SQL contains no user-controlled strings.
    sql = f"SELECT count() FROM shadai.events WHERE event_id IN ('{event_id}','{directory_id}')"
    count = query(
        "clickhouse",
        [
            "sh",
            "-c",
            'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --query "$1"',
            "sh",
            sql,
        ],
    )
    if int(count) >= 2:
        break
    time.sleep(2)
else:
    raise AssertionError("Events did not reach ClickHouse")
# PostgreSQL schema must exist and workers should persist a catalog detection.
while time.monotonic() < deadline:
    count = query("postgres", ["psql", "-U", "shadai", "-d", "shadai", "-Atc", "SELECT count(*) FROM detections"])
    if int(count) > 0:
        break
    time.sleep(2)
else:
    raise AssertionError("Matched event did not become a PostgreSQL detection")
print("PASS: protected ingestion, readiness, frontend, queue pipeline, event storage, detection persistence")
