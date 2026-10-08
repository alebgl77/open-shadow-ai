# Collector operations and recovery

This guide covers scoped collector credentials, local delivery queues, pipeline recovery and identity retention. It describes one organization per installation. Complete the [deployment](deployment.md) and [source coverage](collectors.md) checks before enrolling a pilot; installation does not configure a mirror, directory, GPO or fleet manager.

## Enroll a collector

Sign in as an administrator and open **Sources & coverage → Enrolled collectors → Enroll collector**. Choose an immutable ID, a display name and the smallest source scope needed. Save the one-time key directly to a private file through your approved secret-management channel. Analysts can read operational collector status; enrollment, rotation, revocation and the credential registry require an administrator. Viewer accounts cannot access these operations.

The console API uses an administrator session or JWT. Cookie-authenticated writes also require `X-CSRF-Token`. Collector keys cannot administer the registry.

| Operation | Request and result |
|---|---|
| Enroll | `POST /api/v1/collectors` with `collector_id`, `display_name`, `allowed_source_types` and optional `expires_in_days` (1–365, default 365); returns `collector`, `credential_id`, `api_key`, `expires_at` after commit |
| Inventory | `GET /api/v1/collectors?offset=0&limit=100`; offset 0–1,000,000, limit 1–500; returns `items`, `total`, `offset`, `limit`, with no keys or digests |
| Rotate | `POST /api/v1/collectors/{collector_id}/rotate` with optional `overlap_seconds` (0–86,400, default 3,600) and `expires_in_days`; returns a new one-time key, credential ID, expiry and `previous_valid_until` |
| Revoke | `POST /api/v1/collectors/{collector_id}/revoke`, with no body; permanently disables the collector and all its credentials; repeated revocation is safe |

For example, enrollment of a network sensor uses this JSON body:

```json
{
  "collector_id": "office-mirror",
  "display_name": "Paris mirror pilot",
  "allowed_source_types": ["network"],
  "expires_in_days": 90
}
```

IDs contain 1–255 characters and match `^[A-Za-z0-9][A-Za-z0-9_.:-]*$`; the `legacy:` prefix is reserved. Scopes are distinct canonical values from `dns`, `proxy`, `endpoint`, `browser`, `oauth`, `directory`, `instrumented`, `casb`, `network`. Display-name changes do not redefine identity. The server stores only a SHA256 secret digest; the token has the form `sc_<credential UUID without hyphens>.<opaque secret>` and is supplied as `X-API-Key`.

Keys appear once after the transaction commits. The UI keeps the returned key only in the current component state and clears it when the dialog/session closes or navigation/role changes. If the response is lost, refresh the registry before retrying: creation or rotation may have committed, and the secret cannot be retrieved. Do not place keys in command arguments, YAML committed to Git, browser storage, logs, SYSVOL or broadly readable management scripts.

Malformed IDs/scopes/expiry/overlap fail request validation (422). An existing enrollment ID or rotation of a revoked collector returns 409; an unknown collector returns 404. Invalid, expired or revoked ingestion keys return 401; a mismatched collector or disallowed source returns 403. Treat these as configuration/authorization problems rather than retrying indefinitely, and retain the original queue while recovering the correct credential.

## Bind and rotate clients

Endpoint and network clients discover `GET /api/v1/agent/config` automatically. The response supplies the scoped collector ID and ingestion age ceiling; the server applies its configured tenant, which discovery does not return. Use the enrolled network ID as `--sensor-id`; a scoped endpoint client uses its discovered collector binding. The server validates tenant and the entire batch's source scopes atomically, and checks credential revocation on every request. A scoped key cannot select another collector or tenant. Revoked/expired credentials fail authentication; a disallowed source or identity fails validation rather than partially accepting a batch.

For external scoped events, the stored event UUID is UUID5 over the canonical JSON tuple `[tenant, immutable collector_id, source_event_id]` in `NAMESPACE_URL`. Keep original source UUIDs for retries and exports. Rotation within the same collector preserves stored identity; two collectors using the same source UUID remain separate. Legacy event UUIDs remain unchanged. This attribution identifies the collector, not a verified employee.

During rotation, provision the new key to the same private key file, restart/reload the client as appropriate and verify a new server contact and successful delivery. Existing credential deadlines can only shorten; rotation never revives an expired/revoked key. Use zero overlap for immediate invalidation only when clients are ready. Revocation disables the whole collector permanently; resuming after revocation requires a new enrollment and a separately reviewed queue transition.

The shared `AGENT_API_KEY` remains enabled by default for compatibility (`security.allow_legacy_agent_key: true`, `ALLOW_LEGACY_AGENT_KEY=true`). Its provenance is `legacy:unattributed`; it cannot claim an enrolled identity or send attributed heartbeats. Enroll and verify all HTTP producers before setting `security.allow_legacy_agent_key: false` or `ALLOW_LEGACY_AGENT_KEY=false` on the API. Base Compose reads the mounted YAML; environment overrides require an explicit API/worker environment entry in your private override and are not inferred from `.env`. Never supply an empty `IDENTITY_RETENTION_DAYS`. This setting does not authenticate syslog senders. The base bootstrap still creates six secrets; a disabled legacy key need not be distributed to clients.

HTTP ingestion and endpoint telemetry use shared exact Redis entry admission. A full or wrong-type destination returns generic `503` with `Retry-After: 5`, without validated collector contact or partial admission of that request. Clients must retain uncertain bytes, including a lost reply after a successful write. Collector spools acknowledge only after all Redis chunks return positive IDs; Entra reports full collection only after every chunk confirms. Stable source/snapshot identity is required for retries. Redis queue bootstrap, reference indexes, replay and explicit encrypted archive/discard retention are separate from local spool TTL and database purging; follow [queue retention](queue-retention.md) before advertising the deployment ready.

## Configure private persistent queues

Endpoint, network and syslog collectors retain prepared batches in a standard-library SQLite spool before delivery. Entra retains rejected prepared chunks in process memory and retries them before collecting a new inventory; it has no crash-durable spool. These SQLite spool guarantees do not apply to it or to the AD exporter's retained JSON files.

| Setting | Default | Maximum |
|---|---|---|
| `spool_max_bytes` | 67,108,864 bytes (64 MiB) of retained payloads | 17,179,869,184 bytes (16 GiB) |
| `spool_max_batches` | 2,048 | 100,000 |
| `spool_ttl_seconds` | 604,800 (7 days) | 31,536,000 (365 days), also bounded by the discovered server ingestion age |
| Individual spool payload | Client-dependent batching | 2 MiB; endpoint/network limits are tighter |
| One claim page | 50 batches | 64 batches and 16 MiB |

All configured budgets must be positive. Byte limits count retained payload bytes, not SQLite overhead or total filesystem size. Quarantined batches consume the same capacity. Leave disk headroom for the database, journals and other services. Quota overflow, expiry and storage failures are observable; a full or unwritable disk cannot retain data indefinitely.

Endpoint YAML accepts `spool_dir`, `spool_max_bytes`, `spool_max_batches`, `spool_ttl_seconds`; `SHADAI_AGENT_SPOOL_DIR` overrides its directory. Keep `AGENT_API_KEY_FILE` separate from the spool. Example settings:

```yaml
server_url: https://ai-inventory.example.test
spool_dir: /var/lib/shadai/endpoint
spool_max_bytes: 67108864
spool_max_batches: 2048
spool_ttl_seconds: 604800
```

For a network sensor, explicitly provision a private directory owned by the service account and retain the same directory across restarts:

```bash
python -m shadai.collectors.network --sensor-id office-mirror --format zeek-tls --input ssl.jsonl --api-url https://ai-inventory.example.test --api-key-file /etc/shadai/network-agent.key --spool-dir /var/lib/shadai/network/office-mirror --spool-max-bytes 67108864 --spool-max-batches 2048 --spool-ttl-seconds 604800
```

Syslog uses the same four keys inside each source's `config` in `config/sources.yaml`; it has no separate spool CLI flags. The supplied example uses `/var/lib/shadai/syslog/dns-pilot`. Compose mounts the named `syslog_spool` volume at `/var/lib/shadai`, and the collector image creates that parent owned by UID/GID 10001 with mode `0700`. The root filesystem remains read-only. Container replacement preserves this named volume; `docker compose down --volumes` deletes it and is appropriate only for disposable test projects.

On Unix, spool directories/files are private (`0700`/`0600`) and owned by the running account, with trusted ancestors. Windows leaf files/directories allow only the current user, SYSTEM and Administrators; ancestor owners must also be trusted (the exact TrustedInstaller system SID is allowed on ancestors). Ancestor checks include permissions that allow replacement. Unsafe owners, symlinks, reparse points and hardlinks are rejected. An ACL failure is a refusal to use that path. Provision a trusted private path; do not weaken the guard, grant broad rights or reuse another principal's queue. For the SYSTEM Windows installer, use a protected path inside the approved installation tree and validate it under the actual task identity.

Windows ACL checks invoke the fixed system PowerShell executable with one child-only `PSMODULEPATH` pointing to its system modules. All inherited casing variants are removed from that child environment; the parent environment stays unchanged. This prevents inherited module-path collisions from breaking native ACL checks. A missing system ACL module or an unsafe existing parent still causes refusal and requires resolving that deployment prerequisite.

Spool metadata is plaintext on the client disk. Protect backups and host access, and apply local retention separately from server pseudonymization. Changing server privacy settings does not scrub queued client bytes.

## Recover an interrupted delivery

A first startup without server discovery can capture and retain locally, but sends no HTTP batch until verified target and collector identity bindings are persisted and the freshly discovered server age ceiling is checked. The ceiling itself is not persisted. A mismatched principal or a scoped-to-legacy switch stops new capture/transmission and preserves the existing backlog. Restore the correct server/key for that collector; do not point its queue at another tenant or enrollment to force delivery. A same-collector key rotation is compatible with recovery.

Claims have leases and owner tokens. A process crash leaves retained bytes and IDs available after the lease expires; stale owners cannot acknowledge a later claim. Lost acknowledgements can cause redelivery, so transport is at least once and downstream receipts deduplicate stable IDs. Retryable infrastructure failures retain work. Terminal invalid payloads are separated from retries; review rejection/quarantine counters rather than continuously replaying poison data.

The TTL is an outage-buffer bound, not a universal acceptance guarantee. An observation already near the ingestion age limit can become too old while queued, even when spool TTL is below the server limit. Source timestamps are never rewritten to make old data recent. Capture downtime, packet drops before retention, UDP delivery and TCP disconnects can lose observations. Client storage/overflow counters do not measure those unknown losses.

## Inspect and replay server dead letters

Use an authorized worker environment with the same private configuration and stores. Inspect bounded dead-letter pointers first; dry run is the default:

```bash
python -m shadai.workers.replay --group ingest_group --start 0-0 --end + --limit 100 --dry-run
python -m shadai.workers.replay --group ingest_group --start 0-0 --end + --limit 100 --execute
```

`correlate_group` is also supported. The limit is 1–500 and stream IDs must be valid bounded numeric IDs. JSON output identifies `ready`, `missing_source`, `invalid_pointer`, `replayed` or `already_replayed`; it omits event payloads and secrets. Only known streams/groups and a matching source pointer are replayed. Investigate and fix a poison schema/data problem before execution; retryable store outages belong to pending-work recovery.

Execution atomically copies the original server stream fields, including original JSON, source ID and trusted `accepted_at` when present. It marks each pointer idempotently for one year. It does not fabricate a missing source record or a new observation timestamp. `accepted_at` is a new internal queue field: pre-upgrade backlog without it remains subject to original ingestion-age validation. Idempotence is bounded by retained markers/receipts; replay is not an unlimited exactly-once guarantee.

Compose Redis uses `appendonly yes`, persistent `redis_data` and `noeviction`; its `appendfsync` policy is not explicitly configured. Verify deployed settings and backup durability rather than promising accepted data survives every power loss. This read-only check uses the mounted secret without printing it:

```bash
docker compose exec -T redis sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli CONFIG GET appendonly appendfsync maxmemory maxmemory-policy'
```

Source streams have exact retained-entry admission caps, default 100,000 per source/matches stream; dead-letter pointer streams have an exact cap, default 10,000 per group. No producer `MAXLEN`, source TTL or automatic trim removes pending work or active pointers. A full DLQ leaves the source pending and preserves existing pointers. Normal single-group, unreferenced ACKs can delete their source after retention reconciliation; other originals and pointers require explicit guarded archive/discard maintenance. Stream depth is not outstanding work. The dead-letter metric counts currently retained pointers, not all historical rejections. The replay CLI's start/end selectors address retained DLQ pointer IDs; it has no direct source-message selector. Inspect and archive pointer/source references under the [queue retention contract](queue-retention.md); do not fabricate replacement pointers or timestamps. Capacity, retention and recovery objectives need explicit monitoring; never trim pending source records to make a backlog graph smaller. With `noeviction`, memory exhaustion rejects writes visibly rather than silently evicting queues or receipts. External Redis deployments must preserve that policy and validate their AOF/volume/replication behavior.

## Read operational status

In **Sources & coverage**, analysts and administrators can inspect enrolled collector status. Administrators can also open **Deployment pipeline**. The read APIs are:

| API | Authorization and interpretation |
|---|---|
| `GET /api/v1/operations/collectors?offset=0&limit=100` | Analyst/admin, configured-tenant SQL scope, no credential metadata |
| `GET /api/v1/operations/pipeline` | Admin only; explicitly `scope: deployment`, covering the deployment's fixed streams/groups |

Collector `last_server_contact_at`, heartbeat receipt time and original `last_observed_at` are separate. Status is `unknown` without contact, `stale` after an hour without contact, `quiet` for a recent contact but no observation in the last hour, `active` with recent contact/observation, or `revoked`. Silence can be legitimate; none proves complete capture or AI activity.

`client_reported` counters carry provenance, `as_of` and freshness: `queue_events`, `queued_bytes`, `dropped_events`, `expired_events`, `rejected_events`, `last_success_at`. They count events or bytes, not packets, and remain advisory. `capture_loss` is null because total capture loss is unknown.

Pipeline status distinguishes group pending acknowledgements, undelivered lag (nullable), retained source entries, oldest pending age and retained dead letters. Worker poll/progress/failure times and `counters_since` qualify physical ACK/retry/rejection/dead-letter/replay operation counts; they are not lifetime unique-event totals. Worker state is fresh for 90 seconds, can show blocked backlog after five minutes without ACK/dead-letter progress, and expires after a day. Missing groups/lag/stale state remain unknown. A Redis outage returns 503 rather than zero backlog. API `/ready` and process liveness do not prove worker progress or capture completeness.

## Authenticate monitoring

`GET /metrics` requires an admin console identity or a separate read-only metrics bearer token. Agent keys are not accepted. Configure optional `security.metrics_api_key` (omit or use null when disabled), `METRICS_API_KEY` or preferably `METRICS_API_KEY_FILE`; the file takes priority. The secret must contain at least 32 non-whitespace characters. Generate it through your secret manager, independently of collector/JWT/SCIM keys. The six base bootstrap secrets remain required; monitoring is a separate optional seventh secret.

The optional [monitoring overlay](../docker-compose.monitoring.yml) is for Linux with rootful Docker. It runs the API as UID/GID 10001 and Prometheus as UID/GID 65534. The [pinned Prometheus image](https://github.com/prometheus/prometheus/blob/v3.15.0/Dockerfile) uses `nobody` and initializes `/prometheus` for that user. Keep Prometheus's data ownership at 65534; changing it to the API user can make an existing data volume unwritable. Review actual UID mapping and secret permissions separately for rootless Docker, Docker Desktop or another secret manager.

Local [Compose file secrets](https://docs.docker.com/reference/compose-file/services/#secrets) preserve the host file's ownership and permissions; setting `uid`/`gid` in the service secret declaration does not remap a bind-mounted file. Use two separate `0600` copies of the **same independently generated metrics token**, each owned by its reader. A single `0600` file owned by UID 10001 cannot serve both users. The protected host `secrets` directory remains `0700`, and each container receives only its own read-only token mount.

| Host file | Owner and mode | Container mount |
|---|---|---|
| `secrets/metrics_api_key.api.txt` | `10001:10001`, `0600` | API: `/run/secrets/metrics_api_key` |
| `secrets/metrics_api_key.prometheus.txt` | `65534:65534`, `0600` | Prometheus: `/run/secrets/shadai_metrics_token` |

Provision through your secret manager. On the documented Linux host, these commands copy a private source file whose path is supplied in `SHADAI_METRICS_SOURCE_FILE`; the token never appears in arguments or output. Numeric host ownership requires administrative file-provisioning rights. Verify the existing secret directory is trusted before copying; do not broaden its permissions.

```bash
test "$(stat -c '%a' secrets)" = 700
test -n "$SHADAI_METRICS_SOURCE_FILE"
sudo install -o 10001 -g 10001 -m 0600 -- "$SHADAI_METRICS_SOURCE_FILE" secrets/metrics_api_key.api.txt
sudo install -o 65534 -g 65534 -m 0600 -- "$SHADAI_METRICS_SOURCE_FILE" secrets/metrics_api_key.prometheus.txt
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d --wait --wait-timeout 180 api prometheus
```

The overlay mounts [Prometheus configuration](../deploy/monitoring/prometheus.yaml), using its supported [Bearer `authorization.credentials_file`](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#http_config) to scrape `api:8443/metrics` every five seconds over the private backend network. It publishes no Prometheus port and retains data in `prometheus_data`. Before reusing an existing volume, verify its owner and writability under UID 65534; stop and follow your approved storage migration if ownership differs. Do not change the process UID or make token files broadly readable to bypass a failure. If the frontend is already running, reload its upstream after API recreation with `docker compose exec -T frontend nginx -s reload`.

The existing Compose CI job provisions disposable copies, verifies actual UID/mode/readability and refusal under the other UID, checks authenticated `GET /metrics` plus missing/wrong/agent-key 401 responses, and proves the metrics token cannot administer `GET /api/v1/collectors` (401). It waits for the real Prometheus target to report `up`, recreates Prometheus against the same named volume, recovers a private synthetic volume marker and repeats the scrape proof. `scripts/monitoring-smoke.py` has bounded waits and omits credentials and response bodies from output; it writes its marker only in the disposable CI volume. These container checks remain pending until CI runs; local YAML parsing does not prove Docker ownership behavior. Base startup still requires only its original six secrets.

This HTTP target is internal only. A remote scraper needs an explicitly configured private HTTPS proxy route and trusted certificate; the bundled frontend forwards `/api/` and does not automatically expose `/metrics`. Restrict network access and scrub Authorization headers from logs. Rotate the independent token by updating both private copies, then force-recreate the API and Prometheus with both Compose files so replaced host files are remounted. Confirm authenticated scrape success plus unauthenticated refusal. Do not restore public scraping as a workaround.

## Retain and pseudonymize identities

`retention.identity_days` / `IDENTITY_RETENTION_DAYS` must be positive and at most `events_days`; the default is `min(30, events_days)`. Detection user/device membership ages each observed identifier independently using the observation timestamp. Activity by B does not refresh A. Counts are exact distinct observed identifiers in that window, not staff headcount; retained evidence samples are capped at ten. Migration `005` clears unaged historical identity arrays/counts rather than inventing freshness.

List/detail/export projections and user/device sorting use the same current cutoff before pagination. Risk filtering/sorting retains the materialized `risk_score`/level. A changed current membership projection can mark `risk_score_stale`; `risk_calculated_at` is nullable and records only an actual calculation. Notes and general update times do not prove risk was recalculated. The CSV appends that UTC timestamp, or an empty value when unknown. Maintenance/rescoring materializes a new score; avoid interpreting stale scores as current headcount-based risk.

`security.pseudonymize_identities: true` / `PSEUDONYMIZE_IDENTITIES=true` enables field-separated HMAC pseudonyms derived from the existing encryption key. Personal user/device/name/object-ID/SID fields are aliased, personal source IP and free-form identity-provider text are cleared. AI hosts, destination IP, site, tenant and collector operational metadata remain. Paths, query strings, application payloads and user agents remain outside retained evidence. Pseudonyms are still linkable organizational data and do not establish human identity.

Activation affects new server processing only; historical event/detection evidence and local spools are not automatically scrubbed. For historical maintenance, quiesce collectors, drain local spools and processing queues, then stop writers/replay before enabling the mode or changing the master key. Keep that state for the entire scrub and its completion verification. Run the explicit bounded command in the configured worker environment:

```bash
python -m shadai.workers.purge --scrub-personal-history --batch-size 500 --max-batches 100
```

Batch size is 1–500 and maximum batches 1–1,000. JSON reports `complete`, `clickhouse_complete`, `sql_complete`, `event_batches`, `detections_scrubbed`, `next_detection_id`. If bounded SQL work remains, resume with `--after-detection-id <returned UUID>` and the same limits; do not invent a cursor. ClickHouse mutations are synchronous and verified, and SQL pages clear personal evidence/members and recalculate risk under locks. Exit zero means all completion checks passed; incomplete capped work and errors exit nonzero. Retries are idempotent. Console accounts, manual notes and audit actors are excluded; review those separately under your retention policy.

No live historical scrub has been validated by this change. Rehearse on an isolated restored copy first. Changing the master encryption key changes the pseudonym basis and affects encrypted material; preserve matching backup keys and plan identity reconstruction. Privacy activation alone does not clean backups. See [validation boundaries](validation.md) and [backup/recovery](deployment.md#backup-and-restore).
