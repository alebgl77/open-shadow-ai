# Production monitoring

The optional [monitoring overlay](../docker-compose.monitoring.yml) loads
[alert rules](../deploy/monitoring/alerts.yaml) for the authenticated
`open-shadow-ai` target. Follow [private token provisioning](collector-operations.md#authenticate-monitoring)
first. Prometheus remains on the private backend network with no published port;
API and Prometheus retain separate private token copies and their existing UIDs.
The overlay adds no notification service or receiver. A firing rule alone does
not notify anybody, and these pilot defaults do not certify an SLO or capacity.

## Observable inventory

All application queue measurements cover the deployment, not a tenant or an
individual collector. Trusted labels are `stage` and `stream`; Prometheus adds
`job` and `instance`. Ingest has nine streams (`events:dns`, `events:proxy`,
`events:endpoint`, `events:browser`, `events:oauth`, `events:directory`,
`events:instrumented`, `events:casb`, `events:network`); correlation has `matches`.
The publication completeness rule expects these ten pairs. Update its count and
fixtures together if the application inventory changes.

| Measurement | Actual exported metric | Interpretation |
|---|---|---|
| Snapshot access | `shadai_operations_redis_available` | 1 means the current Redis snapshot was read; 0 means unavailable |
| Publication/contact | `shadai_worker_state_fresh`, `shadai_worker_last_worker_seen_at_seconds` | Heartbeat freshness is at most 90 seconds; it does not prove progress |
| Polling | `shadai_worker_last_poll_at_seconds` | A recent poll plus known zero pending/lag supports idle health |
| Progress/epoch | `shadai_worker_last_progress_at_seconds`, `shadai_worker_counters_since_seconds` | Progress records ACK, dead-letter or replay transitions; epoch start is the fallback before first progress |
| Queue backlog | `shadai_group_pending_messages`, `shadai_group_undelivered_messages`, `shadai_group_undelivered_known`, `shadai_group_present` | Pending ACKs and undelivered lag are distinct; unsupported/missing lag remains unknown |
| Pending age | `shadai_group_oldest_pending_age_seconds` | Age of the oldest pending queue ID, not the original event observation |
| Retained inventory | `shadai_stream_retained_entries`, `shadai_deadletter_retained_entries` | Retained records/pointers, including replay sources; not ready backlog or unique lost events |
| Physical operations | `shadai_queue_acknowledged_total`, `shadai_queue_retryable_failures_total`, `shadai_queue_rejected_attempts_total`, `shadai_queue_deadlettered_total`, `shadai_queue_replayed_total` | Actual queue transitions in the published epoch, not unique events, detections or capture loss |
| Store memory | Not exposed by this endpoint | Requires a private Redis/store or managed-service exporter and container/host measurements |
| Disk/volume capacity | Not exposed by this endpoint | Requires an infrastructure exporter for the filesystems backing Redis AOF, PostgreSQL, ClickHouse and Prometheus volumes |

Missing quantities are omitted. An unavailable snapshot suppresses queue rules
and raises its own alert. A missing heartbeat publication or incomplete inventory
is separate from a fresh heartbeat without a usable group, known lag, epoch or
recent poll. An idle queue does not need recent ACKs or new events to be healthy.
Counter `increase` handles numeric resets; observed epoch changes suppress retry
and dead-letter alerts while that change remains in the five-minute window.
Prometheus extrapolates increases, so the retry threshold is an estimated window
increase, not an exact count of five distinct events.

For resource coverage, the platform owner should inventory each actual store,
container and backing filesystem, choose exporters compatible with that target,
and protect scrape credentials/routes. Measure Redis used memory versus its
configured limit, rejected writes, AOF persistence health, container memory/CPU,
and volume free bytes/inodes and growth. Set headroom and time-to-exhaustion
thresholds from measured retention/load and test them on an isolated target.
These are follow-up requirements; this overlay supplies no resource exporter,
resource alert or saturation/restore evidence. Prometheus failure itself also
needs an independent external watchdog because its own rules cannot run then.

## Alerts, owners and pilot defaults

Assign the `platform` and `pipeline` owner labels to named on-call people before
relying on these rules. Evaluation runs every 30 seconds; scrape runs every five
seconds. The `for` duration requires the condition to remain true continuously.

| Alert | Condition and duration | Owner / initial remediation |
|---|---|---|
| `ShadaiMetricsTargetDown` | Authenticated scrape fails or the expected job is absent for 2 minutes | Platform: check target error, API readiness, private route and token copy ownership/rotation; verify absent/wrong/agent credentials still fail |
| `ShadaiOperationalSnapshotUnavailable` | Scrape succeeds but the current Redis availability flag is absent or not 1 for 2 minutes | Platform: inspect Redis connectivity, authentication, resource pressure and API snapshot timeout; do not interpret absent queue data as zero |
| `ShadaiWorkerPublicationMissing` | Heartbeat stale/missing, freshness metric missing for a row, or publication count differs from ten for 2 minutes | Pipeline: inspect worker state publication, Redis access and the exact missing stage/stream; an instance-only alert means incomplete inventory |
| `ShadaiQueueEvidenceMissing` | Fresh heartbeat without an expected group, known pending/lag, epoch or poll within 90 seconds for 2 minutes | Pipeline: inspect worker polling, group creation and Redis lag support; confirm evidence before declaring idle health |
| `ShadaiBacklogBlocked` | Known pending + undelivered work is positive and progress (or initial epoch start) is older than 300 seconds, sustained for another 5 minutes | Pipeline: check downstream store errors, retries and reclaim activity; verify ACK/dead-letter/replay transitions resume; a dead-letter transition counts as progress, so also inspect its alert |
| `ShadaiOldPendingWork` | A pending ACK has queue-ID age greater than 900 seconds for 5 minutes | Pipeline: inspect the pending record, reclaim/retry state and downstream failures; continued progress elsewhere does not clear old work |
| `ShadaiQueueRetriesIncreasing` | Estimated retryable-failure increase at least 5 over 5 minutes, sustained for 2 minutes in a stable observed epoch | Pipeline: inspect retry reasons and store health; compare progress and backlog before restarting or replaying |
| `ShadaiDeadLettersIncreasing` | Positive physical dead-letter increase over 5 minutes, sustained for 1 minute in a stable observed epoch | Pipeline: inspect poison/rejection reasons and original retained sources; use the existing dry-run replay procedure after correcting the cause |

The 90-second freshness budget comes from the application contract. Other
durations/counts are conservative starting settings for a bounded pilot. Review
them with an event profile, normal idle periods, queue recovery and notification
latency; edit the rule file and matching tests together. Preserve separate
absence/evidence alerts when tuning. Do not purge pending work or replay blindly
to silence an alert. See [dead-letter inspection/replay](collector-operations.md#inspect-and-replay-server-dead-letters).

## Deterministic validation

Use `promtool` from the same image selected by `docker-compose.monitoring.yml`.
These [rule fixtures](../deploy/monitoring/tests/alerts.test.yaml) run on synthetic
time series; they need no secrets, network, stores or production services.
They cover firing/nonfiring and duration boundaries, target recovery, missing
series, idle versus missing evidence, old pending work, resets and epoch changes.
On a Linux CI host with the selected image already available:

```bash
MONITORING_IMAGE=$(python -c 'import yaml; print(yaml.safe_load(open("docker-compose.monitoring.yml"))["services"]["prometheus"]["image"])')
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /bin/promtool -v "$PWD/deploy/monitoring:/workspace:ro" "$MONITORING_IMAGE" \
  check config --syntax-only /workspace/prometheus.yaml
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /bin/promtool -v "$PWD/deploy/monitoring:/workspace:ro" "$MONITORING_IMAGE" \
  check rules --lint-fatal /workspace/alerts.yaml
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /bin/promtool -v "$PWD/deploy/monitoring:/workspace:ro" "$MONITORING_IMAGE" \
  test rules /workspace/tests/alerts.test.yaml
python -m pytest -q tests/test_monitoring_alerts.py
```

Syntax-only config validation intentionally does not inspect referenced mounted
files. In the already provisioned disposable CI monitoring project, also run
`docker compose -f docker-compose.yml -f docker-compose.monitoring.yml exec -T prometheus promtool check config --lint-fatal /etc/prometheus/prometheus.yml`
and the existing `python scripts/monitoring-smoke.py` to verify the actual rule
mount, private credentials and scrape. Do not start production services to run
fixture tests. With a trusted local `promtool` installed, set `PROMTOOL` to its
path and `SHADAI_REQUIRE_PROMTOOL=1` to require its pytest scenarios; otherwise
that one test explicitly skips and the image commands remain the required gate.
The [official promtool commands](https://prometheus.io/docs/prometheus/latest/command-line/promtool/)
and [fixture format](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)
describe the two validation modes.

## Receiver setup and notification exercise

1. The operator selects a private Alertmanager target, receiver type/address,
   owning team, change window and test recipient. Keep secrets in private files;
   do not reuse the scrape token or publish Prometheus/Alertmanager ports.
2. Configure that independently managed Alertmanager's receiver, route by
   `owner`/`severity`, grouping by `alertname`/`job`/`instance`, repeat interval,
   and resolved notifications. Validate with `amtool check-config alertmanager.yml`.
   Review rendered routing against the chosen test labels before enabling sends.
   Use the [official Alertmanager configuration](https://prometheus.io/docs/alerting/latest/configuration/).
3. In an operator-managed Prometheus configuration, add `alerting.alertmanagers`
   with the selected private target and appropriate HTTPS CA verification and
   file-based credentials. Mount its private files using the target platform's
   supported ownership mechanism, then validate the effective config and reload
   in the approved window. The supplied overlay has no `alerting` destination.
4. First run the offline fixture commands above and inspect pending/firing
   rules through the existing private administration path. For a route dry run,
   inspect Alertmanager's route tree with the test labels and confirm the intended
   receiver, grouping, silences and inhibition; no message should be sent yet.
5. Only after the operator has supplied and approved the target/test recipient,
   submit a synthetic `ShadaiNotificationTest` to that Alertmanager's `/api/v2/alerts`
   endpoint with `owner=platform`, `severity=critical`, and a bounded expiry.
   Use a clear test annotation with no event payload or credential. Confirm one
   firing message reaches that recipient and a resolved message follows expiry;
   repeat for `owner=pipeline`, `severity=warning`. Verify routing does not page
   an unintended team. This repository has not sent either message.
6. Record commit/image, config revision, test labels, receiver, operator,
   timestamps, receipt/resolution and failures in the operational evidence log.
   A configuration check, a unit test and a successful scrape do not demonstrate
   actual message delivery. Exercise the route again after receiver, token or
   deployment changes; keep the independent Prometheus watchdog separate.
