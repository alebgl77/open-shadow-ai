"""ShadAI Agent entry point."""

from __future__ import annotations

import json
import logging
import signal
import time
from datetime import UTC, datetime

import requests

from shadai_agent.collectors.browser_ext import collect_extensions
from shadai_agent.collectors.container import collect_containers
from shadai_agent.collectors.local_ai import detect_local_ai, detect_model_files
from shadai_agent.collectors.process import collect_processes
from shadai_agent.config import load_agent_config

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("shadai-agent")

_running = True

# Mirrors the API's TelemetryBatch bound per list and stays under its 2 MiB request limit.
MAX_RECORDS_PER_LIST = 500
MAX_BODY_BYTES = 1_500_000
SECTIONS = ("processes", "containers", "local_ai_hits", "extensions", "model_files")
# The server builds process events from these fields only; identical keys are identical events.
PROCESS_KEY = ("name", "parent", "username", "listening_port")
# The API rejects a whole batch for one text field that is not a string of at most 2048
# characters, or one port outside 0-65535. Records are brought within that contract first.
TEXT_FIELDS = ("name", "path", "parent", "username", "image", "process_name", "tool_name", "id", "browser")
PORT_FIELDS = ("port", "listening_port")
MAX_TEXT_LENGTH = 2048


def _handle_signal(signum, frame):
    global _running
    logger.info(f"Received signal {signum}, shutting down...")
    _running = False


def unique_processes(processes: list[dict]) -> list[dict]:
    """Collapse process instances the server would record as the same observation."""
    seen, result = set(), []
    for process in processes:
        key = tuple(process.get(field) for field in PROCESS_KEY)
        if key not in seen:
            seen.add(key)
            result.append(process)
    return result


def conform(record: dict) -> dict:
    """Coerce a collected record to the API's field contract without dropping the observation."""
    record = dict(record)
    for field in TEXT_FIELDS:
        if field in record:
            value = record[field]
            record[field] = ("" if value is None else str(value))[:MAX_TEXT_LENGTH]
    for field in PORT_FIELDS:
        value = record.get(field)
        if field in record and (isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535):
            del record[field]
    return record


def split_batches(header: dict, sections: dict[str, list[dict]]) -> list[dict]:
    """Split one snapshot into API-sized batches that share its hostname and timestamp."""

    def empty():
        return {**header, **{section: [] for section in SECTIONS}}

    base_size = len(json.dumps(empty()))
    batches, current, size = [], None, 0
    for section in SECTIONS:
        for record in map(conform, sections.get(section, [])):
            record_size = len(json.dumps(record, default=str)) + 2
            if base_size + record_size > MAX_BODY_BYTES:
                logger.warning(f"Skipping one oversized {section} record")
                continue
            if current is None or len(current[section]) >= MAX_RECORDS_PER_LIST or size + record_size > MAX_BODY_BYTES:
                current = empty()
                batches.append(current)
                size = base_size
            current[section].append(record)
            size += record_size
    return batches or [empty()]


def send_batch(url: str, batch: dict, headers: dict, verify) -> int | None:
    """Return the accepted event count, or None once retries are exhausted or pointless."""
    attempts = 3
    for attempt in range(attempts):
        try:
            resp = requests.post(url, json=batch, headers=headers, timeout=30, verify=verify)
        except requests.RequestException as e:
            logger.warning(f"Send attempt {attempt + 1} failed: {type(e).__name__}")
        else:
            if resp.status_code == 200:
                try:
                    return int(resp.json().get("received", 0))
                except (ValueError, AttributeError, TypeError):
                    return 0
            logger.warning(f"Server returned HTTP {resp.status_code}")
            if 400 <= resp.status_code < 500 and resp.status_code not in (408, 429):
                return None
        if attempt + 1 < attempts:
            time.sleep(2**attempt)
    return None


def main():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    config = load_agent_config()
    logger.info(f"ShadAI Agent starting on {config.hostname} (poll every {config.poll_interval_seconds}s)")

    while _running:
        try:
            header = {"hostname": config.hostname, "agent_version": "0.1.0", "timestamp": datetime.now(UTC).isoformat()}
            sections: dict[str, list[dict]] = {}

            # Collect processes
            processes = collect_processes() if config.collect_processes else []
            sections["processes"] = unique_processes(processes)
            if config.collect_processes:
                logger.info(f"Collected {len(processes)} processes ({len(sections['processes'])} distinct)")

            # Collect containers
            if config.collect_containers:
                sections["containers"] = collect_containers()
                logger.info(f"Collected {len(sections['containers'])} containers")

            # Detect local AI
            if config.collect_local_ai:
                sections["local_ai_hits"] = detect_local_ai(processes)
                sections["model_files"] = detect_model_files()
                if sections["local_ai_hits"]:
                    logger.info(f"Detected {len(sections['local_ai_hits'])} local AI processes")

            # Collect browser extensions
            if config.collect_extensions:
                sections["extensions"] = collect_extensions()
                logger.info(f"Collected {len(sections['extensions'])} browser extensions")

            # Send telemetry
            url = f"{config.server_url.rstrip('/')}/api/v1/agent/telemetry"
            headers = {"X-API-Key": config.api_key, "Content-Type": "application/json"}
            batches = split_batches(header, sections)
            accepted, failed = 0, 0
            for batch in batches:
                received = send_batch(url, batch, headers, config.ca_bundle or True)
                if received is None:
                    failed += 1
                else:
                    accepted += received
            if failed:
                logger.warning(f"Telemetry partially sent: {failed} of {len(batches)} batches failed")
            logger.info(f"Telemetry sent: {accepted} events accepted in {len(batches) - failed} batches")

        except Exception as e:
            logger.error(f"Collection error: {type(e).__name__}")

        # Sleep with interruptibility
        for _ in range(config.poll_interval_seconds):
            if not _running:
                break
            time.sleep(1)

    logger.info("ShadAI Agent stopped")


if __name__ == "__main__":
    main()
