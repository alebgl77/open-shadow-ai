"""Bounded private monitoring acceptance against the disposable Compose CI project.

Run after provisioning both UID-owned token copies and starting the monitoring
overlay. No credential, authorization header or response body reaches output.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.monitoring.yml"]

API_PROOF = r"""
import json
import os
import stat
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

assert os.getuid() == os.getgid() == 10001, "API must run as UID/GID 10001"
path = Path('/run/secrets/metrics_api_key')
metadata = path.stat()
assert metadata.st_uid == metadata.st_gid == 10001
assert stat.S_IMODE(metadata.st_mode) == 0o600, "API token copy must be private"
key = path.read_text().strip()
agent = Path('/run/secrets/agent_api_key').read_text().strip()
assert len(key) >= 32 and key != agent

def metrics(headers, expected, path='/metrics'):
    request = Request('http://127.0.0.1:8443' + path, headers=headers)
    try:
        response = urlopen(request, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        assert response.status == expected, 'Unexpected metrics authorization result'
        body = response.read(1_048_577)
        assert len(body) <= 1_048_576
        assert key.encode() not in body and agent.encode() not in body
        if expected == 200:
            assert b'# HELP shadai_' in body, 'Operational metrics were not returned'

metrics({'Authorization': 'Bearer ' + key}, 200)
metrics({}, 401)
metrics({'Authorization': 'Bearer ' + 'wrong-monitoring-key-' + '0' * 32}, 401)
metrics({'Authorization': 'Bearer ' + agent}, 401)
metrics({'X-API-Key': agent}, 401)
metrics({'Authorization': 'Bearer ' + key}, 401, path='/api/v1/collectors')

deadline = time.monotonic() + 45
while time.monotonic() < deadline:
    try:
        with urlopen('http://prometheus:9090/api/v1/targets?state=active', timeout=3) as response:
            raw = response.read(262_145)
            assert len(raw) <= 262_144
        result = json.loads(raw)
        targets = [target for target in result['data']['activeTargets']
                   if target['labels'].get('job') == 'open-shadow-ai']
        if (len(targets) == 1 and targets[0]['health'] == 'up'
                and targets[0]['lastError'] == ''
                and targets[0]['scrapeUrl'] == 'http://api:8443/metrics'):
            break
    except (OSError, ValueError, KeyError):
        pass
    time.sleep(1)
else:
    raise AssertionError('Private Prometheus target did not become up within 45 seconds')
print('PASS: API UID/private token, authenticated metrics, wrong/absent/agent refusal, Prometheus target up')
"""

PROMETHEUS_PROOF = """
set -eu
test "$(id -u)" = 65534
test "$(id -g)" = 65534
test "$(stat -c '%u:%g %a' /run/secrets/shadai_metrics_token)" = '65534:65534 600'
test -r /run/secrets/shadai_metrics_token
test "$(stat -c '%u:%g' /prometheus)" = '65534:65534'
test -w /prometheus
echo 'PASS: Prometheus UID/private token and persistent data volume ownership'
"""

INITIAL_VOLUME_PROOF = """
test ! -e /prometheus/.shadai-monitoring-ci
umask 077
printf '%s\\n' 'disposable-private-monitoring-volume-proof' > /prometheus/.shadai-monitoring-ci
"""

RECREATED_VOLUME_PROOF = """
test "$(stat -c '%u:%g %a' /prometheus/.shadai-monitoring-ci)" = '65534:65534 600'
test "$(cat /prometheus/.shadai-monitoring-ci)" = 'disposable-private-monitoring-volume-proof'
echo 'PASS: exact private volume marker recovered after Prometheus container replacement'
"""

API_OTHER_UID_PROOF = """
from pathlib import Path
try:
    Path('/run/secrets/metrics_api_key').read_bytes()
except PermissionError:
    pass
else:
    raise AssertionError('Other UID could read private API token copy')
"""


def execute(service, command, *, code=None, user=None, timeout=20):
    arguments = [*COMPOSE, "exec", "-T"]
    if user:
        arguments.extend(["--user", user])
    result = subprocess.run(
        [*arguments, service, *command], input=code, text=True, capture_output=True, timeout=timeout
    )
    if result.returncode:
        # Suppress container stderr/response details, including third-party logs.
        raise RuntimeError(f"Private monitoring acceptance failed in {service}")
    if result.stdout:
        print(result.stdout.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--after-recreate", action="store_true", help="Require the first run's disposable volume marker"
    )
    args = parser.parse_args()
    volume_proof = RECREATED_VOLUME_PROOF if args.after_recreate else INITIAL_VOLUME_PROOF
    execute("prometheus", ["sh", "-c", PROMETHEUS_PROOF + volume_proof])
    execute("api", ["python", "-"], code=API_OTHER_UID_PROOF, user="65534:65534")
    execute("prometheus", ["sh", "-c", "test ! -r /run/secrets/shadai_metrics_token"], user="10001:10001")
    execute("api", ["python", "-"], code=API_PROOF, timeout=65)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {type(error).__name__}: private monitoring acceptance incomplete", file=sys.stderr)
        raise SystemExit(1) from None
