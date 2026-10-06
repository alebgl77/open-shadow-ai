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
from shadai_agent.collectors.local_ai import detect_local_ai
from shadai_agent.collectors.process import collect_processes
from shadai_agent.config import load_agent_config
from shadai_agent.delivery_spool import DurableSpool, SpoolError, default_spool_dir

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
SECTIONS = ("processes", "containers", "local_ai_hits", "extensions")
WIRE_FIELDS = {
    "processes": ("name", "parent", "username", "listening_port"),
    "containers": ("name", "image", "port"),
    "local_ai_hits": ("process_name", "tool_name", "port"),
    "extensions": ("id", "name", "browser"),
}
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
        for collected in sections.get(section, []):
            record = conform({field: collected[field] for field in WIRE_FIELDS[section] if field in collected})
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


class AgentDeliveryError(RuntimeError):
    def __init__(self, reason: str, *, retryable: bool = True):
        super().__init__(reason)
        self.retryable = retryable


def send_once(url: str, payload: bytes, headers: dict, verify) -> int:
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=30, verify=verify, allow_redirects=False)
    except requests.RequestException:
        raise AgentDeliveryError("delivery_transport_error") from None
    if response.status_code != 200:
        status = response.status_code
        raise AgentDeliveryError("delivery_http_" + str(status),
                                 retryable=status in {401, 408, 429} or 500 <= status <= 599)
    try:
        received = response.json()["received"]
        original = json.loads(payload)
        expected = sum(len(original.get(section, [])) for section in SECTIONS)
        if type(received) is not int or received != expected:
            raise ValueError()
        return received
    except (ValueError, AttributeError, TypeError, KeyError):
        raise AgentDeliveryError("delivery_invalid_response") from None


def send_batch(url: str, batch: dict, headers: dict, verify) -> int | None:
    """Return the accepted event count, or None once retries are exhausted or pointless."""
    attempts = 3
    payload = json.dumps(batch, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    for attempt in range(attempts):
        try:
            return send_once(url, payload, headers, verify)
        except AgentDeliveryError as exc:
            logger.warning("Telemetry delivery failed: %s", str(exc))
            if not exc.retryable or str(exc) == "delivery_http_401":
                return None
        if attempt + 1 < attempts:
            time.sleep(2**attempt)
    return None


def drain_spool(spool: DurableSpool, config, *, limit: int = 50) -> int:
    url = f"{config.server_url.rstrip('/')}/api/v1/agent/telemetry"
    headers = {"X-API-Key": config.api_key, "Content-Type": "application/json"}
    accepted = 0
    for _ in range(limit):
        batches = spool.claim(limit=1)
        if not batches:
            break
        [batch] = batches
        try:
            received = send_once(url, batch.payload, headers, config.ca_bundle or True)
        except AgentDeliveryError as exc:
            if exc.retryable:
                spool.retry(batch)
            else:
                spool.quarantine(batch, str(exc))
            logger.warning("Durable telemetry delivery failed: %s", str(exc))
        else:
            spool.ack(batch)
            accepted += received
    return accepted


def discover_binding(config, spool: DurableSpool) -> bool | None:
    """Bind retained snapshots to the authenticated collector; unavailable discovery keeps them."""
    spool.bind("target", config.server_url.rstrip("/"))
    try:
        response = requests.get(f"{config.server_url.rstrip('/')}/api/v1/agent/config",
                                headers={"X-API-Key": config.api_key}, timeout=5,
                                verify=config.ca_bundle or True, allow_redirects=False)
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        binding = response.json()
        age_days = binding.get("ingestion_max_age_days")
        if age_days is not None and spool.ttl_seconds > int(age_days) * 86400:
            raise AgentDeliveryError("spool_ttl_exceeds_server_age")
        if binding.get("legacy", True):
            if spool.has_binding("collector"):
                raise AgentDeliveryError("collector_binding_mismatch")
            return False
        collector_id = binding["collector_id"]
        if not isinstance(collector_id, str) or not collector_id or len(collector_id) > 255:
            raise ValueError()
        if config.collector_id and config.collector_id != collector_id:
            raise AgentDeliveryError("collector_binding_mismatch")
        spool.bind("collector", collector_id)
        config.collector_id = collector_id
        sources = binding.get("allowed_source_types", ["endpoint", "browser"])
        if not isinstance(sources, list) or any(not isinstance(source, str) for source in sources):
            raise ValueError()
        config._allowed_source_types = set(sources)
        for feature in ("collect_processes", "collect_containers", "collect_local_ai"):
            if hasattr(config, feature) and "endpoint" not in sources:
                setattr(config, feature, False)
        if hasattr(config, "collect_extensions") and "browser" not in sources:
            config.collect_extensions = False
        return True
    except (ValueError, TypeError, KeyError):
        raise AgentDeliveryError("invalid_collector_binding") from None


def send_heartbeat(config, stats: dict) -> None:
    body = {"collector_id": config.collector_id, "client_version": "0.2.0",
            "queue_events": stats["queued_events"], "queued_bytes": stats["queued_bytes"],
            "dropped_events": stats.get("overflow_events", 0) + stats.get("storage_failed_events", 0),
            "expired_events": stats.get("expired_events", 0),
            "rejected_events": stats.get("quarantined_events", 0)}
    try:
        response = requests.post(f"{config.server_url.rstrip('/')}/api/v1/agent/heartbeat", json=body,
                                 headers={"X-API-Key": config.api_key}, timeout=5,
                                 verify=config.ca_bundle or True, allow_redirects=False)
        if response.status_code != 200:
            logger.warning("Collector heartbeat unavailable: HTTP %s", response.status_code)
    except requests.RequestException:
        logger.warning("Collector heartbeat unavailable: transport failure")


def main():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    config = load_agent_config()
    spool = DurableSpool(config.spool_dir or default_spool_dir("agent"), max_bytes=config.spool_max_bytes,
                         max_batches=config.spool_max_batches, ttl_seconds=config.spool_ttl_seconds)
    logger.info(f"ShadAI Agent starting on {config.hostname} (poll every {config.poll_interval_seconds}s)")

    while _running:
        try:
            # Configuration/key-file rotations take effect without rebuilding queued snapshots.
            config = load_agent_config()
            scoped = discover_binding(config, spool)
            if scoped is not None:
                drain_spool(spool, config)
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
                if sections["local_ai_hits"]:
                    logger.info(f"Detected {len(sections['local_ai_hits'])} local AI processes")

            # Collect browser extensions
            if config.collect_extensions:
                sections["extensions"] = collect_extensions()
                logger.info(f"Collected {len(sections['extensions'])} browser extensions")

            # Send telemetry
            batches = split_batches(header, sections)
            if (scoped and "endpoint" not in config._allowed_source_types
                    and all(not records for records in sections.values())):
                batches = []
            for batch in batches:
                spool.enqueue(json.dumps(batch, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                              event_count=sum(len(batch[section]) for section in SECTIONS))
            accepted = drain_spool(spool, config) if scoped is not None else 0
            logger.info("Telemetry accepted: %s; spool counters: %s", accepted, spool.stats())
            if scoped:
                send_heartbeat(config, spool.stats())

        except SpoolError as exc:
            logger.error("Telemetry retention failure: %s", str(exc))
        except AgentDeliveryError as exc:
            logger.error("Collector configuration rejected: %s; spool: %s", str(exc), spool.stats())
        except Exception as e:
            logger.error(f"Collection error: {type(e).__name__}")

        # Sleep with interruptibility
        for _ in range(config.poll_interval_seconds):
            if not _running:
                break
            time.sleep(1)

    logger.info("ShadAI Agent stopped")
    spool.close()


if __name__ == "__main__":
    main()
