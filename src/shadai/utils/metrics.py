"""Prometheus metrics definitions for ShadAI."""

from prometheus_client import Counter, Gauge, Histogram

# ── Ingestion metrics ────────────────────────────────────────────
EVENTS_INGESTED = Counter(
    "shadai_events_ingested_total",
    "Total events ingested",
    ["source_type"],
)

EVENTS_PARSED = Counter(
    "shadai_events_parsed_total",
    "Total events parsed successfully",
    ["parser"],
)

PARSE_ERRORS = Counter(
    "shadai_events_parse_errors_total",
    "Total parse errors",
    ["parser"],
)

EVENTS_REJECTED = Counter(
    "shadai_events_rejected_total",
    "Parsed events refused at the ingestion boundary (timestamp window, organization, hostname)",
    ["source_type"],
)

# ── Matching metrics ─────────────────────────────────────────────
EVENTS_MATCHED = Counter(
    "shadai_events_matched_total",
    "Total events matched to catalog",
    ["source_type"],
)

# ── Detection metrics ────────────────────────────────────────────
DETECTIONS_TOTAL = Gauge(
    "shadai_detections_total",
    "Total active detections",
    ["risk_level"],
)

DETECTIONS_UNREVIEWED = Gauge(
    "shadai_detections_unreviewed",
    "Detections not yet reviewed",
)

# ── Queue metrics ────────────────────────────────────────────────
QUEUE_DEPTH = Gauge(
    "shadai_queue_depth",
    "Redis stream depth",
    ["stream"],
)

# ── Source health metrics ────────────────────────────────────────
SOURCE_LAST_EVENT = Gauge(
    "shadai_source_last_event_seconds",
    "Seconds since last event from source",
    ["source_type"],
)

# ── API metrics ──────────────────────────────────────────────────
API_REQUEST_DURATION = Histogram(
    "shadai_api_request_duration_seconds",
    "API request latency",
    ["method", "endpoint"],
)
