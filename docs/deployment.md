# Deployment and operations

This package targets a controlled pilot. Docker and Kubernetes execution has not been verified on the authoring workstation. CI defines an actual Linux service smoke test; its results must be checked for the commit you deploy. No live AD or Entra tenant was used for validation.

## Profiles by organization

| Environment | Starting profile | Before broader rollout |
|---|---|---|
| Startup | One Compose host, one log source, local UI | HTTPS, backups and access review |
| SME | Compose, AD/Entra plus selected Windows pilot endpoints | Source ownership, directory scope, protected agent-key provisioning |
| Mid-sized / ETI | External stores and staged collector rollout | Restore drill, retention capacity, monitoring and failure tests |
| Large enterprise | Kubernetes baseline, external managed stores, segmented pilot | SSO strategy, isolation, HA, capacity, security review and change control |

These are adoption patterns, not certified sizing tiers. Event rate, retention and query shape determine sizing. Begin with at least 4 vCPU / 8 GiB RAM as a pilot budget and measure; this is a starting assumption, not a benchmark.

## Docker Compose

Run the README bootstrap and startup commands. The bootstrap copies configuration templates and creates six secrets. It never overwrites files. Unix secrets are read-only under a private `0700` directory, allowing nonroot containers to read Compose bind-mounted secret files. On Windows, both the Python entry point and PowerShell wrapper validate ownership, the complete secrets ACL and reparse points **before** generating any secret. New directories have a protected ACL granting only the current user and SYSTEM; administrator elevation is not required. Existing secrets are preserved only when their tree is private and owned by the current user or a trusted system principal. Unsafe explicit grants, foreign owners, junctions and replaceable ancestors cause an actionable refusal. Review the named path and provision a private destination before retrying; do not automatically reset an untrusted tree. Protect the host account and Docker daemon.

State is kept in named PostgreSQL, ClickHouse and Redis volumes, plus `syslog_spool` for the optional syslog collector. Stores expose no host port. API/UI bind to `127.0.0.1` by default. Redis uses authenticated access, AOF persistence and `noeviction` so memory pressure causes a visible failure instead of silently evicting queued events. Its fsync policy is not explicitly set; verify the running policy before assigning a power-loss recovery objective.

The syslog image creates `/var/lib/shadai` as private `0700` storage owned by UID/GID 10001, mounted from `syslog_spool` while the rest of the filesystem stays read-only. Configure per-source paths below that parent in `config/sources.yaml`. A new container reuses the named volume; deleting volumes discards backlog. Existing volumes must already satisfy owner/mode/ancestor checks. Endpoint and network services need their own persistent private client paths. See [collector operations](collector-operations.md) for queue limits, first-start offline binding, rotation, expiry and plaintext metadata protection.

```bash
docker compose ps --all
curl --fail http://127.0.0.1:8443/health
curl --fail http://127.0.0.1:8443/ready
docker compose logs --tail 100 api ingest-worker correlation-worker
```

`/health` tests the API process; `/ready` checks its store dependencies. Worker process liveness is not proof of forward progress. Monitor stream backlog, pending work, dead-letter streams and the last event per collector. Do not treat a healthy UI as proof that every collector reports.

**Sources & coverage** separates collector contact/heartbeat/original observation timestamps from client-reported queue counters. Admin-only **Deployment pipeline** distinguishes pending acknowledgements, nullable undelivered lag and retained entries/replay sources. Unknown capture loss remains unknown. `/metrics` now requires an administrator or an independent read-only bearer credential; the [monitoring procedure](collector-operations.md#authenticate-monitoring) supplies a private optional Compose override and Prometheus `authorization.credentials_file`. Base bootstrap remains six secrets; monitoring adds a separately provisioned token and explicit private route.

Use `docker compose run --rm api python -m shadai.cli create-admin` for administration: the image entrypoint resolves mounted database secrets before invoking the CLI. The catalog is synchronized on API startup; `sync-catalog` is also available through the CLI.

## Remote access and TLS

The API listens on HTTP internally despite port 8443. Place a reverse proxy with a trusted TLS certificate in front of the frontend, which forwards `/api/` to the API. Keep raw API ports private. For a proxy on another host, explicitly select a private bind address and firewall allowlist; do not expose the databases.

The bundled nginx replaces `X-Forwarded-For` with its TCP peer address. Uvicorn trusts that header only from the frontend's fixed address on the dedicated Compose `edge` network; direct API/collector requests keep their TCP peer identity and cannot select a login-rate bucket with a forged header. Only the API and frontend join `edge`. The defaults are subnet `172.30.0.0/24`, frontend `172.30.0.2`, API `172.30.0.3`. If this subnet overlaps another network, set **all three** `SHADAI_EDGE_SUBNET`, `SHADAI_EDGE_FRONTEND_IP` and `SHADAI_EDGE_API_IP` in `.env` to unused, distinct addresses in the chosen subnet, then recreate the deployment network during a maintenance window. The same frontend variable configures Uvicorn's trust; never replace it with `*` or a broad network range. Protect access to the Docker daemon and do not attach other workloads to this network.

If another TLS proxy is placed ahead of nginx, its TCP address is the default client identity. To preserve distinct clients, explicitly configure nginx's `set_real_ip_from` for only that upstream proxy's exact private address, plus `real_ip_header X-Forwarded-For`; require the upstream to overwrite incoming client-address headers and restrict frontend ingress to that proxy. Review this host-specific configuration before publication. Without it, clients behind the upstream share one login limit. Docker/host NAT that already hides source addresses has the same limitation; proxy headers from arbitrary clients are never a safe substitute.

Use an exact `CORS_ORIGINS` JSON array only when clients need cross-origin access. The bundled frontend uses same-origin requests and keeps the console session in an HttpOnly, SameSite=Strict cookie, so a reload no longer signs users out. The cookie is Secure and `__Host-` prefixed on every host except `localhost`; serve remote access over HTTPS, or set `SESSION_COOKIE_SECURE` (`true`, `false` or `auto`) when the reverse proxy changes the host name. Endpoint agents and the AD uploader require HTTPS and validate certificates. Supply `SHADAI_CA_BUNDLE` for a private CA; never disable validation.

Compose keeps its stores on the private project network. When the API and workers reach an external ClickHouse, enable native TLS with `CLICKHOUSE_SECURE=true` (port 9440 unless `CLICKHOUSE_PORT` is set). Certificate and hostname verification are always on; `CLICKHOUSE_CA_CERTS`, `CLICKHOUSE_CERTFILE`/`CLICKHOUSE_KEYFILE` and `CLICKHOUSE_SERVER_HOSTNAME` cover a private CA, mutual TLS and a certificate name that differs from the host. The same keys exist under `database:` in `shadai.yaml`. PostgreSQL and Redis take TLS through `DATABASE_URL` and a `rediss://` `REDIS_URL`.

## Optional console SSO and provisioning

The base Compose file keeps OIDC/SCIM disabled and requires only the six bootstrap secrets. The optional [identity guide](sso-scim.md) describes `docker-compose.sso.yml`, two operator-provisioned secret files and Entra/generic OIDC setup. SCIM controls console accounts, separately from collected directory inventory. Keep a tested local administrator for recovery.

The public origin must serve both the frontend and `/api/` over HTTPS. The existing frontend proxy carries SCIM; no extra port is needed. Configure every upstream proxy and tracing system to omit OAuth callback query strings and sensitive headers. The bundled proxy logs method/path/status without query strings or referrers; callback error logging and raw Uvicorn access logs are disabled because they can contain authorization codes. Diagnose failures using sanitized application events and provisioning status.

## Updates

Back up data, configuration and encryption keys first. Validate the new commit against a restored copy before production. Review migration SQL and deployment changes.

The 0.2.0 identity migration (`003`) must complete before the new API/workers start. It takes an exclusive lock on the users table and checks stripped, case-folded usernames before schema changes. Empty names or case-insensitive collisions block the migration; resolve them by explicitly renaming the affected local accounts, then rerun it. Accounts are never silently merged. Schedule the migration with application writes stopped and test it against a restored backup first.

Collector hardening adds PostgreSQL migrations `004` (scoped registry/credentials) and `005` (timestamped identity membership). `init-db` applies the chain before API/worker startup. Migration `005` clears unaged historical identity arrays and counts because their observation age cannot be proven. Review that visible count change on a restored copy. Existing shared-key clients remain compatible until you enroll scoped replacements and disable legacy access. Configure positive identity retention at most event retention, and plan explicit history/local-spool handling before enabling pseudonymization or changing the encryption key.

```bash
set -e
docker compose build
# Stop writers; start only stores, without waiting for the new ClickHouse schema probe.
docker compose stop api frontend ingest-worker correlation-worker purge-worker
docker compose up -d postgres clickhouse redis
docker compose exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --multiquery' < migrations/clickhouse/002_event_metadata.sql
# --no-deps avoids starting an API dependency graph before the migrations have completed.
docker compose run --rm --no-deps api python -m shadai.cli init-db
docker compose up -d
```

Stop optional collectors and quiesce remote producers as well. Wait for the stores to accept connections; if a store is still starting, retry its migration command before continuing. The ClickHouse `002` migration must run **before** any API command that starts dependencies or waits on ClickHouse health: the new probe selects `identity_sid`, which is absent on legacy volumes. An unhealthy ClickHouse status during this step is expected until the SQL completes. `exec` does not depend on that health status. Verify `docker compose ps` shows healthy stores before starting applications. Init scripts run only during first database initialization. Fresh installs mount both `docker/clickhouse-init/001_create_database.sql` and `migrations/clickhouse/002_event_metadata.sql`. There is no automatic schema rollback.

Migration `003` refuses a downgrade once external identities, SCIM groups, service audit entries or session revocations exist. Do not delete those records to bypass the guard. Recover a pre-migration backup into an isolated deployment with its matching code/configuration if rollback is required. For SSO-enabled deployments use both Compose files in the commands above, as described in the [identity guide](sso-scim.md#docker-compose).

## Backup and restore

The following Bash procedure is for a small pilot. Production should use tested database-native backups with defined RPO/RTO. Schedule a maintenance window, stop producers/collectors and workers, and avoid writes during the snapshot. If enabled, stop the `syslog` and `entra` profiles too. Quiesce remote agents upstream.

```bash
umask 077
mkdir -p backups
docker compose stop api frontend ingest-worker correlation-worker purge-worker
docker compose exec -T postgres pg_dump -U shadai -d shadai -Fc > backups/postgres.dump
docker compose exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --query "SELECT * FROM shadai.events FORMAT Native"' > backups/events.native
docker compose exec -T redis sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli SAVE'
```

Preserve the three store volumes and optional `syslog_spool` through the platform's volume backup mechanism, plus private endpoint/network spool snapshots, restricted copies of `config/`, `secrets/` and the deployment commit. Stop each client before snapshotting SQLite. Retain matching encryption keys for encrypted credentials and the pseudonym basis; local spool snapshots still contain plaintext metadata. Encrypt backups, restrict access and test recovery. A Redis volume snapshot preserves queue/pending state subject to actual AOF/flush settings; PostgreSQL and event exports alone do not. Backups are not automatically scrubbed by privacy activation or historical cleanup.

For a restore drill, create an isolated project with empty stores and the same application version; do not restore over a live installation. Start only its stores, then import the exports (fresh schema initialization has already created ClickHouse tables):

```bash
docker compose -p osa-restore-drill up -d postgres clickhouse redis
docker compose -p osa-restore-drill exec -T postgres pg_restore -U shadai -d shadai --no-owner < backups/postgres.dump
docker compose -p osa-restore-drill exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --query "INSERT INTO shadai.events FORMAT Native"' < backups/events.native
```

Run the drill from a separate checkout with restored private configuration/secrets and an unused `SHADAI_EDGE_SUBNET` plus matching frontend/API addresses; also choose unused host API/UI ports before starting its applications. Keep `-p osa-restore-drill` on **every** restore/start/cleanup command. Confirm that project's stores are empty before importing; project naming does not make repeated imports safe. Restore Redis from its stopped volume backup using your volume platform, or deliberately start a new queue and document the discarded in-flight interval. Do not blindly replay old events into a populated store. Restore keys/config, start the application, check readiness, log in, compare event/detection counts and verify a synthetic event end to end. Logical exports are not a guarantee of exactly-once recovery.

Restore local spools only to their original verified target/collector binding with private owners and permissions. A changed URL, tenant or collector must not reinterpret retained bytes. Reconcile observation ages, quota/expiry counters, receipts and dead-letter pointer capacity before replay. The [replay CLI](collector-operations.md#inspect-and-replay-server-dead-letters) preserves original queue fields and is dry-run by default; old backlog without trusted `accepted_at` does not gain an ingestion-age bypass.

## Kubernetes

See [deploy/kubernetes/README.md](../deploy/kubernetes/README.md). The manifests use external PostgreSQL, Redis and ClickHouse (native TLS on port 9440 by default) and provide no operator, database HA or public credentials. Resources are deliberately constrained and need load testing. TLS ingress and a NetworkPolicy-enforcing CNI are prerequisites for network publication.

## Readiness gates

Local accounts, optional OIDC/SCIM console access and administrator-run scoped collector enrollment, rotation and revocation are implemented. Automatic secret distribution and fleet rollout remain operator work. Verify private key/spool provisioning, correct collector scope, offline restart, same-collector rotation, permanent revocation, quota/expiry visibility and authenticated monitoring in your pilot. One install is one organization. Do not infer tenant isolation from an event's `tenant_id`. Validate identity-provider interoperability, backup/restore, ingress authentication, least privilege, encrypted private connectivity to stores, privacy maintenance, failure recovery and measured capacity before production. Current hardening native/real-store CI evidence must be checked for the exact deployed commit; earlier release runs do not validate these changes.
