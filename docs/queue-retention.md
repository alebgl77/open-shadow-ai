# Redis queue admission and explicit retention

The nine `events:<source>` streams belong to `ingest_group`; `matches` belongs to `correlate_group`. Capacity is shared across producers of a stream, including retained replay originals. Pending work and retained entries are different measurements.

| Configuration | Default | Supported bounds |
|---|---|---|
| `redis_queue.stream_max_entries` / `REDIS_STREAM_MAX_ENTRIES` | 100,000 per source or matches stream | 1–10,000,000 |
| `redis_queue.dlq_max_entries` / `REDIS_DLQ_MAX_ENTRIES` | 10,000 per group DLQ | 1–20,000 |
| `redis_queue.retained_days` / `REDIS_RETAINED_DAYS` | 7 days | 1–365 |
| `redis_queue.admission_max_batch_bytes` / `REDIS_ADMISSION_MAX_BATCH_BYTES` | 2 MiB | 1 byte–16 MiB |

Environment overrides must be supplied to every relevant API, worker and collector process. Entries have at most 32 field pairs; each admission has at most 500 records. The byte budget counts the UTF-8 stream names, field names and field values, including repeated destinations. It does not count total Redis allocator, group, AOF or replication overhead.

All six runtime producers use capacity admission: canonical HTTP ingestion, endpoint telemetry HTTP, the base/syslog collector, Entra inventory, the ingest worker's matches output, and operator replay. Admission validates every destination/type/field and accumulates each destination's required slots before its first write. A full or wrong-type second destination refuses the entire batch. Accepted batches return one positive Redis ID per record. There is no producer `MAXLEN`, source TTL, automatic trim or counter allocation before the first `XADD`.

Both HTTP endpoints return generic `503` with `Retry-After: 5` for an unconfirmed enqueue; a refusal never records a validated collector contact. Quiet endpoint snapshots with no observations still report contact. A lost response can follow a successful write: stable event IDs and downstream receipts/correlation suppress completed retries. Base collector spools retain the exact original prepared bytes until every chunk has positive IDs; a lost reply retains the whole uncertain chunk. Entra retries its rejected prepared chunks before fetching another inventory, and reports complete collection only after all chunks confirm. Its buffer is in process memory and does not survive a crash. An oversized record stays blocked rather than producing a false success. A full matches stream prevents PostgreSQL receipt commit and leaves the source message retryable; ClickHouse may already contain a raw duplicate, covered by its existing event-ID analytics deduplication.

New endpoint-agent snapshots split at 500 total observations and the existing 1,500,000-byte request bound. Previously retained larger parents are split at send time into deterministic children; their snapshot headers, item fields and stored parent bytes stay unchanged. The API derives event UUIDs from the snapshot and collector namespace rather than child position, so retries preserve identity. A parent is ACKed only after every child confirms its exact observation count; a partial or lost reply retains the original parent and retries identical child bytes. A valid parent already within both bounds is sent byte for byte. Invalid or individually oversized retained records remain quarantined in the spool with a generic error until an explicit operator decision. Legacy `model_files` fields remain preserved, with the API's existing behavior of producing no observation from that section.

Entry quotas and Redis `noeviction` do not guarantee that RAM can always hold an admitted batch. Lua has no rollback after a later error/OOM. A first-allocation refusal leaves all destinations untouched; a later allocation failure can leave partial additions, an uncertain reply or a transient memory overshoot. Retain unconfirmed work, provision headroom, monitor actual memory, and rehearse recovery. Do not change a shared production Redis memory limit to run the pressure tests.

## Mandatory bootstrap and upgrade

A new or legacy Redis without a valid retention schema deliberately retains ACKed sources. It can reach its entry caps until the migration below completes. No application process silently initializes an ambiguous existing queue graph.

1. Stop all legacy queue writers, consumers and replay clients; verify none can resume during reconciliation. This is mandatory for mixed-version upgrades. Back up the stores and matching archive key through your existing recovery process.
2. Deploy the indexed writer/consumer version. Initialize the fixed source groups through the new workers. New indexed scripts can coexist with reconciliation; legacy scripts cannot.
3. In the configured API/worker environment, run:

```bash
python -m shadai.workers.redis_lifecycle reconcile --execute --legacy-writers-stopped
python -m shadai.workers.redis_lifecycle inventory --group ingest_group
python -m shadai.workers.redis_lifecycle inventory --group correlate_group
```

Reconciliation bounds both DLQs to the configured cap, never more than 20,000 each, and validates all pointers, stream allowlists and key types before writing. Invalid legacy pointers or over-cap graphs fail without silent trimming. Resolve them under an explicit reviewed archive/discard procedure before retrying. The first mutation sets `retention:schema=building`; it rebuilds the ten fixed `retention:refs:v1:<stream>` hashes, with `__schema=1` sentinels and counts of active pointers by source ID. The last mutation sets `retention:schema=1`. An interrupted rebuild stays unavailable for deletion and must be retried after its cause is resolved.

Readiness must require `retention_ready(redis)`: it reads only the fixed schema and ten hash sentinels. Missing/wrong-type/building state makes processing unready while process liveness stays healthy. This is a structural check, not proof against arbitrary logical corruption. Missing sentinels, invalid numeric counts and wrong key types prevent source deletion. A malicious or external `HDEL`/plausible count edit with an intact sentinel cannot always be detected without a graph reconciliation. Restrict Redis writers, use `noeviction`, preserve the whole graph in backup/restore, and verify graph consistency in recovery rehearsals.

## ACK, dead letters and replay

Normal success ACKs the owner PEL entry. Source deletion additionally requires exactly one current group, schema 1, a valid reference hash sentinel and zero active DLQ references. Other topologies keep the source for maintenance. A duplicate/lost ACK response does not inflate the operation counter. Previously ACKed records retained before migration need explicit maintenance; a duplicate ACK does not delete them.

Poison handling prevalidates the source PEL entry, DLQ/retry/reference/schema/counter types and the exact DLQ cap. Its first write appends a pointer containing only stream/ID/error class/attempt count. It increments the source reference, records the operation, then ACKs and clears retry state. A full DLQ leaves the source pending and preserves all existing pointers. No approximate trimming is permitted.

Replay preserves the original source fields and acceptance timestamp. It rereads the exact pointer inside Lua and compares the inspected stream/ID/ordered fields before copying; concurrent purge or replacement refuses replay. An existing `replayed:<group>:<pointer-ID>` marker returns the same prior ID for one year. Source capacity and byte limits apply to a new replay. The old source and pointer remain until explicit maintenance.

## Inspect, archive, and purge

This maintenance is separate from the PostgreSQL/ClickHouse purge worker and never imports an archive. `shadai queue-maintenance ...` and `python -m shadai.workers.redis_lifecycle ...` expose the same commands. `--group` is allowlisted; an optional `--stream` selects source orphan candidates instead of DLQ pointers. `--after` is exclusive, `--end` inclusive, and `--limit` is 1–500 (default 100). Inventory and purge without `--execute` only read operational data. Candidate status is not a deletion guarantee: execution reruns every guard atomically.

```bash
python -m shadai.workers.redis_lifecycle inventory --group ingest_group --limit 100
python -m shadai.workers.redis_lifecycle purge --group ingest_group --limit 100
# Supply a new private archive path for each execution page.
python -m shadai.workers.redis_lifecycle purge --group ingest_group --execute --archive /var/lib/shadai/archives/page-001.fernet
python -m shadai.workers.redis_lifecycle verify-archive /var/lib/shadai/archives/page-001.fernet
# Explicit discard requires the operator's retention decision.
python -m shadai.workers.redis_lifecycle purge --group ingest_group --stream events:dns --execute --discard --limit 100
```

Execution requires exactly one of `--archive PATH` or `--discard`. Archives use the configured Fernet encryption key, a versioned authenticated document, exact ordered binary Redis field arrays (including duplicate names) and exact pointers. Files are capped at 16 MiB; collection is paged and bounds raw field bytes to 8 MiB so encoded/encrypted overhead also fits. Request a smaller page if it exceeds the budget. Paths reuse the private spool ancestor/reparse/owner/permission/hardlink guards. The archive is exclusively created, privately checked, flushed and fsynced, then reread/authenticated before any Redis deletion. On POSIX the parent directory is fsynced too. A write/privacy/fsync/key/verification failure leaves Redis unchanged. A failed attempt may leave a private incomplete archive; review it and choose a fresh path, since overwrite is refused. Windows durability is the portable file-flush boundary, not a measured power-loss RPO. Keep the matching key with backups. Local verification does not connect to Redis and prints only count/hash/status.

Each purge freezes its cutoff from Redis `TIME`. Age uses Redis source/pointer creation IDs, never event timestamps or `accepted_at`. Decimal ID comparisons use length and lexical order, preserving values above 2^53. Inside Lua, deletion requires schema/sentinels/types/counts, exact archived source/pointer arrays, and the expected source owner. Every current source group (maximum 16) must have delivered at least that ID and have no PEL entry for it. A new/unread/pending group created after archiving is still caught. Zero source groups or a missing expected owner blocks deletion. Additional group names are permitted only when all these current guards pass. A normal DLQ has zero groups; any additional DLQ groups must also have delivered/ACKed the pointer, with the same 16-group bound.

Pointer purge removes only an old eligible pointer, its replay marker, and one active reference. It deletes the original source only if the remaining count becomes zero, the source is old, and all source guards pass. Young or multiply referenced sources remain. Source orphan purge likewise requires zero refs, age, exact fields and all group guards. No allocating metric update occurs after deletion. A single page can report a mix of purged and blocked IDs; inspect statuses and resume with the last inspected ID. No source/pointer expiry runs automatically after seven days.

## Qualification boundary

Normal opt-in `SHADAI_INTEGRATION=1` tests require explicit `SHADAI_REDIS_QUEUE_TEST_URL` selecting an initially empty disposable DB 14. They use only the fixed allowlisted graph and clean only owned keys; no `FLUSHDB` or production memory changes. They cover concurrent admission, HTTP refusals/contact, multi-destination rollback on preflight refusal, DLQ pressure, bad indexes/types/counters, group races, exact archives, large IDs and replay/purge races.

The separate `redis_pressure` marker requires `SHADAI_REQUIRE_REDIS_PRESSURE=1`, `SHADAI_REDIS_PRESSURE_HOST=labredis-pressure`, port `6379`, the private password file and a private shared `SHADAI_REDIS_PRESSURE_MANIFEST`. It verifies actual 32 MiB/noeviction/AOF settings. `python tests/redis_pressure_fixture.py` exits 2 for missing or mismatched prerequisites. Required tests fail rather than silently skip. `SHADAI_REDIS_PRESSURE_MODE=seed` runs OOM/refusal/recovery and writes an IDs/hashes-only manifest after `WAITAOF`; `assert` requires a different Redis process after the host stops/copies/restores the labeled lab volume, checks source/pointer/reference/marker/PEL consistency, replays idempotently, and performs guarded GC. No Docker control or socket is present in the test container. The qualification host owns the isolated restore orchestration and private mount ownership.

These are disposable laboratory checks, not a production RPO/RTO or crash-loss guarantee. Local unit tests run on the Windows host; daemon-backed Redis/OOM/AOF checks require the mandatory CI lab. No local Docker execution is claimed.
