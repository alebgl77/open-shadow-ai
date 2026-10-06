"""Prometheus metrics definitions for ShadAI."""

from prometheus_client import Counter, Gauge, Histogram


def operational_metrics(snapshot):
    """Fresh Redis deployment snapshot; local API/worker counters are excluded.

    Unknown quantities are omitted with explicit knowledge/freshness gauges.
    Counter epochs are exposed because expired operational hashes may reset.
    """
    from datetime import datetime

    from prometheus_client import CollectorRegistry, generate_latest
    from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

    families = []

    def gauge(name, help_text, labels=()):
        family = GaugeMetricFamily('shadai_' + name, help_text, labels=list(labels))
        families.append(family)
        return family

    availability = gauge('operations_redis_available', 'Fresh operational Redis snapshot available')
    availability.add_metric([], int(snapshot['backend_available']))
    scope = gauge('operations_deployment_scope', 'Metrics have installation-wide scope, not a tenant backlog')
    scope.add_metric([], 1)
    labels = ('stage', 'stream')
    retained = gauge('stream_retained_entries', 'Retained stream entries; not ready backlog', labels)
    pending = gauge('group_pending_messages', 'Delivered messages still pending acknowledgement', labels)
    lag = gauge('group_undelivered_messages', 'Consumer-group undelivered messages, only when known', labels)
    known = gauge('group_undelivered_known', 'Consumer-group lag is known', labels)
    group = gauge('group_present', 'Expected consumer group exists', labels)
    fresh = gauge('worker_state_fresh', 'Worker publication is at most 90 seconds old', labels)
    oldest = gauge('group_oldest_pending_age_seconds', 'Oldest pending queue-ID age, not event observation age', labels)
    dlq = gauge('deadletter_retained_entries', 'Retained dead-letter pointers, including replayed pointers', ('stage',))
    timestamps = {field: gauge('worker_' + field + '_seconds', 'Worker Redis server timestamp for ' + field, labels)
                  for field in ('last_worker_seen_at', 'last_poll_at', 'last_progress_at', 'last_failure_at',
                                'counters_since')}
    counters = {}
    for field in ('acknowledged', 'retryable_failures', 'rejected_attempts', 'deadlettered', 'replayed'):
        family = CounterMetricFamily('shadai_queue_' + field, 'Actual Redis queue ' + field +
                                     '; physical operations in the published epoch', labels=list(labels))
        families.append(family)
        counters[field] = family
    for stage in snapshot['stages']:
        dlq.add_metric([stage['stage']], stage['deadletter_retained'])
        for row in stage['streams']:
            values = [stage['stage'], row['stream']]
            for family, field in ((retained, 'retained_entries'), (pending, 'pending'), (lag, 'undelivered'),
                                  (oldest, 'oldest_pending_age_seconds')):
                if row[field] is not None:
                    family.add_metric(values, row[field])
            known.add_metric(values, int(row['undelivered'] is not None))
            group.add_metric(values, int(row['group_present']))
            fresh.add_metric(values, int(row['worker_state_fresh']))
            for field, family in timestamps.items():
                if row[field] is not None:
                    family.add_metric(values, datetime.fromisoformat(row[field]).timestamp())
            for field, value in row['counters'].items():
                if value is not None:
                    counters[field].add_metric(values, value)

    class SnapshotCollector:
        def collect(self):
            return iter(families)

    registry = CollectorRegistry()
    registry.register(SnapshotCollector())
    return generate_latest(registry)

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
