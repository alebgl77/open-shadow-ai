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

Run the README bootstrap and startup commands. The bootstrap copies configuration templates and creates six secrets. It never overwrites files. Unix secrets are read-only under a private `0700` directory, allowing nonroot containers to read Compose bind-mounted secret files. The PowerShell wrapper applies a restrictive Windows ACL. Protect the host account and Docker daemon.

State is kept in named PostgreSQL, ClickHouse and Redis volumes. None exposes a host port. API/UI bind to `127.0.0.1` by default. Redis uses authenticated access, persistence and `noeviction` so memory pressure causes a visible failure instead of silently evicting queued events.

```bash
docker compose ps --all
curl --fail http://127.0.0.1:8443/health
curl --fail http://127.0.0.1:8443/ready
docker compose logs --tail 100 api ingest-worker correlation-worker
```

`/health` tests the API process; `/ready` checks its store dependencies. Worker process liveness is not proof of forward progress. Monitor stream backlog, pending work, dead-letter streams and the last event per collector. Do not treat a healthy UI as proof that every collector reports.

Use `docker compose run --rm api python -m shadai.cli create-admin` for administration: the image entrypoint resolves mounted database secrets before invoking the CLI. The catalog is synchronized on API startup; `sync-catalog` is also available through the CLI.

## Remote access and TLS

The API listens on HTTP internally despite port 8443. Place a reverse proxy with a trusted TLS certificate in front of the frontend, which forwards `/api/` to the API. Keep raw API ports private. For a proxy on another host, explicitly select a private bind address and firewall allowlist; do not expose the databases.

Use an exact `CORS_ORIGINS` JSON array only when clients need cross-origin access. The bundled frontend uses same-origin requests. Endpoint agents and the AD uploader require HTTPS and validate certificates. Supply `SHADAI_CA_BUNDLE` for a private CA; never disable validation.

Compose keeps its stores on the private project network. When the API and workers reach an external ClickHouse, enable native TLS with `CLICKHOUSE_SECURE=true` (port 9440 unless `CLICKHOUSE_PORT` is set). Certificate and hostname verification are always on; `CLICKHOUSE_CA_CERTS`, `CLICKHOUSE_CERTFILE`/`CLICKHOUSE_KEYFILE` and `CLICKHOUSE_SERVER_HOSTNAME` cover a private CA, mutual TLS and a certificate name that differs from the host. The same keys exist under `database:` in `shadai.yaml`. PostgreSQL and Redis take TLS through `DATABASE_URL` and a `rediss://` `REDIS_URL`.

## Optional console SSO and provisioning

The base Compose file keeps OIDC/SCIM disabled and requires only the six bootstrap secrets. The optional [identity guide](sso-scim.md) describes `docker-compose.sso.yml`, two operator-provisioned secret files and Entra/generic OIDC setup. SCIM controls console accounts, separately from collected directory inventory. Keep a tested local administrator for recovery.

The public origin must serve both the frontend and `/api/` over HTTPS. The existing frontend proxy carries SCIM; no extra port is needed. Configure every upstream proxy and tracing system to omit OAuth callback query strings and sensitive headers. The bundled proxy logs method/path/status without query strings or referrers; callback error logging and raw Uvicorn access logs are disabled because they can contain authorization codes. Diagnose failures using sanitized application events and provisioning status.

## Updates

Back up data, configuration and encryption keys first. Validate the new commit against a restored copy before production. Review migration SQL and deployment changes.

The 0.2.0 identity migration (`003`) must complete before the new API/workers start. It takes an exclusive lock on the users table and checks stripped, case-folded usernames before schema changes. Empty names or case-insensitive collisions block the migration; resolve them by explicitly renaming the affected local accounts, then rerun it. Accounts are never silently merged. Schedule the migration with application writes stopped and test it against a restored backup first.

```bash
docker compose build
docker compose run --rm api python -m shadai.cli init-db
docker compose exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --multiquery' < migrations/clickhouse/002_event_metadata.sql
docker compose up -d
```

The above ClickHouse migration is needed on existing volumes; init scripts run only during first database initialization. Fresh installs mount both `docker/clickhouse-init/001_create_database.sql` and `migrations/clickhouse/002_event_metadata.sql`. There is no automatic schema rollback.

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

Preserve all three named volumes through the platform's volume backup mechanism, plus restricted copies of `config/`, `secrets/` and the deployment commit. In particular, retain the encryption key to recover encrypted credentials. Encrypt backups, restrict access and test recovery. A Redis volume snapshot preserves queue/pending state; PostgreSQL and event exports alone do not.

For a restore drill, create an isolated project with empty stores and the same application version; do not restore over a live installation. Start only its stores, then import the exports (fresh schema initialization has already created ClickHouse tables):

```bash
docker compose up -d postgres clickhouse redis
docker compose exec -T postgres pg_restore -U shadai -d shadai --no-owner < backups/postgres.dump
docker compose exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --query "INSERT INTO shadai.events FORMAT Native"' < backups/events.native
```

Restore Redis from its stopped volume backup using your volume platform, or deliberately start a new queue and document the discarded in-flight interval. Do not blindly replay old events into a populated store. Restore keys/config, start the application, check readiness, log in, compare event/detection counts and verify a synthetic event end to end. Logical exports are not a guarantee of exactly-once recovery.

## Kubernetes

See [deploy/kubernetes/README.md](../deploy/kubernetes/README.md). The manifests use external PostgreSQL, Redis and ClickHouse (native TLS on port 9440 by default) and provide no operator, database HA or public credentials. Resources are deliberately constrained and need load testing. TLS ingress and a NetworkPolicy-enforcing CNI are prerequisites for network publication.

## Readiness gates

Local accounts, optional OIDC/SCIM console access and a shared collector key are implemented. Validate identity-provider interoperability and deactivation with a pilot account; per-device enrollment keys and automatic key rotation remain future work. One install is one organization. Do not infer tenant isolation from an event's `tenant_id`. Validate backup/restore, ingress authentication, least privilege, encrypted private connectivity to stores, retention, failure recovery and measured capacity before production.
