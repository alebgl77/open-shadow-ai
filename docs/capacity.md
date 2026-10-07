# Capacity planning and staged validation

There is no measured production throughput or enterprise sizing claim for this project. Python matching speed alone would not measure queueing, persistence, concurrent correlation, disk pressure or UI latency.

## Establish a baseline

Record the exact commit, image digests, CPU/RAM/disk, database versions, retention, collector count and event mix. Use synthetic events with stable UUIDs and realistic diversity. Include DNS negatives, shared domains, endpoint inventory, AD objects, duplicated deliveries and large valid batches. Never copy production personal data into a load fixture.

## Increase load in bounded stages

1. Confirm one source end to end and record a quiet baseline.
2. Send a fixed small batch through the authenticated API. Verify accepted/stored/detected counts and that inventory is not labeled model usage.
3. Increase the offered rate gradually while measuring API latency/errors, Redis stream depth/pending age, worker CPU/memory, ClickHouse disk/insert latency, PostgreSQL locks and query latency.
4. Hold each stage long enough for backlog to stabilize. Stop increasing when latency, errors or backlog exceed your predefined service objectives.
5. Stop the producer and measure drain time. Restart one worker during a bounded stage and verify retry/receipt behavior and dead-letter visibility.
6. Run the same procedure after changing concurrency, retention or storage. Do not infer horizontal scalability from a replica count alone.

Define maximum batch/rate and total event budget before testing. Keep the pilot isolated from production. Retain counts and measurements in a private test report, not screenshots of real employee activity.

## Retention and restoration

Project storage from observed daily event volume and measured bytes/event, accounting for indexes, replication and backup copies. Treat the estimate as a budget with headroom. The initial ClickHouse table has a 90-day TTL. The purge worker applies the configured event TTL and runs immediately, then every 24 hours; it does not interpret a cron schedule. Keep receipt_days at least ingestion_max_age_days + events_days + 1 so accepted retries remain covered. Test backup and recovery at the intended data size.

Local endpoint/network/syslog spool defaults are 64 MiB of retained payloads, 2,048 batches and seven days, with configurable maxima of 16 GiB, 100,000 batches and 365 days. TTL must also be below the server ingestion-age ceiling. Reserve SQLite/journal/filesystem overhead beyond the payload budget. Claims are bounded to 64 batches/16 MiB, so a large disk allowance is not one in-memory send. Quarantine consumes capacity. Measure overflow, expiry and storage failures during outages; these queues do not measure or eliminate packet loss before retention. An already-old observation may fall outside server acceptance before its spool TTL expires.

Redis `redis_data` persists AOF in Compose and `noeviction` makes memory exhaustion visible. Verify deployed `appendonly`, `appendfsync` and `maxmemory-policy` before assigning a recovery objective. Queue admission defaults to exact caps of 100,000 retained entries per source/matches stream and 10,000 pointers per group DLQ, with batches of at most 500 records/2 MiB field bytes. No source TTL or MAXLEN trims work. Mandatory explicit retention reconciliation initializes ten fixed reference hashes before readiness; until then ACKs conservatively retain sources. Normal single-group, unreferenced ACKs can delete their source; other originals and DLQ pointers require the explicit guarded archive/discard maintenance after the default seven-day Redis-ID creation cutoff. Full destinations return retryable refusal rather than trimming. These entry limits and noeviction do not bound total RAM or make Lua rollback on a later OOM. Watch stream memory separately from outstanding group pending/lag, and do not discard pending records to recover memory. See [queue retention](queue-retention.md) for bootstrap, archive privacy, group guards, structural index checks and the isolated pressure/AOF qualification boundary. Power-loss durability, backups and external Redis failover require measured deployment proof.

Identity membership has its own positive retention window, at most event retention (default `min(30, events_days)`). Expiry changes current distinct observed-ID counts without making every materialized risk score current. Inspect `risk_score_stale` and `risk_calculated_at`, and test retention/maintenance with independently aged observations. See [collector operations](collector-operations.md) for pseudonymization, historical scrub and advisory client versus server counters.

Before a production claim, validate source freshness, memory-pressure behavior, bounded retries, restart recovery, administrative queries, retention enforcement, restore time and full downstream persistence. See the [deployment guide](deployment.md).
