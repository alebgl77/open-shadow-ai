# Expert implementation handbook

[English](README.md) | [Français](../fr/README.md) | [简体中文](../zh-CN/README.md)

This handbook takes an infrastructure or identity specialist from a bounded evaluation to an operationally reviewed pilot. It covers backend development preview **0.3.0** and standalone agent **0.1.0**, aligned on **2026-10-08** with source commit `49a58d778d3014879e30a3ac5334df45cd426dbf`. Work from the repository root for every command unless a procedure says otherwise. Command examples preserve the detailed procedures' syntax; documentation-only hosts, IDs, paths and interfaces must be replaced with reviewed values before execution.

One installation serves **one organization**. A `tenant_id` is a scope guard, not an isolation boundary. No production certification, SLA, measured enterprise throughput, automatic fleet deployment or universal AI detection is claimed. The complete English, French and Simplified Chinese handbooks cover equivalent procedures; detailed linked documents are explicitly labeled English references. Historical audits and changelogs retain their own language and validation scope. Existing motion diagrams use French labels and synthetic data. The [English roadmap (English reference)](../roadmap.md) describes future stages and their delivery gates.

The console language selector works before and after sign-in for English, French and Simplified Chinese. Its validated browser-local preference is separate from authentication; absent or blocked storage defaults to English. Raw source values and machine/API identifiers stay literal. See [Documentation and language coverage](../README.md).

## 1. Define scope and evidence

Record the deployment owner, data owner, source owners, pilot machines/OUs/segments, approved collection fields, retention, access roles and stop criteria. Begin with one source and a known synthetic positive plus non-AI negatives. Keep the exact source commit, image digests, configuration revision and CI results with the pilot evidence. A service-health screenshot alone establishes neither complete capture nor correct attribution.

The API authenticates ingestion and console access. Redis carries nine source streams into ingestion workers and a `matches` stream into correlation workers. ClickHouse retains event metadata; PostgreSQL holds catalog, detections, identities, receipts and access state. Purge and explicit queue maintenance have different responsibilities. The frontend presents their evidence; it does not scan the fleet. See [Architecture (English reference)](../architecture.md) and [Source coverage (English reference)](../collectors.md).

| Signal | What it supports | What remains unproven |
|---|---|---|
| DNS, SNI, HTTP Host, proxy metadata | A name or connection observation at a documented vantage point | Completed AI request, content, employee, model, tokens or invoice |
| Endpoint process/container/runtime/extension | Presence or observed running asset | Actual model use or every user's browser profile |
| AD object, Entra application/grant | Directory presence or permission | Activity, hybrid identity equivalence or application usage |
| Instrumented event | Explicitly supplied model/token/cost metadata | Provider's internal routing; calculated cost remains an estimate until billing reconciliation |

TLS hides content. DoH hides queried names from the passive DNS adapter; a resolver's SNI cannot recover them. ECH protects the inner name: an offer may be GREASE, acceptance remains unknown, and missing SNI alone does not diagnose ECH. Supported metadata suppresses outer SNI for an identified ECH offer, but versions can leave offers undetected. QUIC requires source/dissector identification; UDP/443 alone proves neither QUIC nor AI. NAT, VPNs, remote users, shared CDNs, unmirrored traffic, local models and embedded SaaS AI leave gaps. IPs and fingerprints are not catalog identities; no automatic AD/DHCP/IP-to-employee join is performed. Multiple observations cannot be summed into AI request counts.

## 2. Prepare the host and install Compose

Require Git, Python 3.12+ and a working Docker Engine with Compose v2; Docker is not bundled. The interface demo additionally requires Node.js 22.22.2+ on the 22.x line. A starting pilot budget is 4 vCPU/8 GiB RAM, an assumption to measure rather than a sizing guarantee. Validate CPU, disk, clocks and network access before connecting sources. The package defines real Linux CI service checks; authoring-host static checks do not replace them.

On Linux/macOS, bootstrap from a trusted checkout:

```bash
git clone https://github.com/alebgl77/open-shadow-ai.git
cd open-shadow-ai
bash scripts/bootstrap.sh
docker compose config --quiet
docker compose up -d --build
docker compose exec -T api python /app/entrypoint.py python -m shadai.workers.redis_lifecycle reconcile --execute --legacy-writers-stopped
docker compose up -d --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
docker compose run --rm api python -m shadai.cli create-admin
```

On Windows, replace only the bootstrap command with:

```powershell
./scripts/bootstrap.ps1
```

The two bootstraps preserve existing configuration and six base secrets; use `--dry-run` or `-DryRun` to preview. Unix secret storage uses a private `0700` parent. Windows validates ownership, complete ACLs and reparse/ancestor safety before generating bytes; new directories permit the current user and SYSTEM without administrator elevation. A refused existing tree needs a trusted private destination, not automatic permission repair.

Start the new workers without global readiness first: they create the actual Redis groups. If reconciliation reports that initialization is incomplete, wait and retry it. Reconciled schema/hash sentinels are mandatory before readiness and collector activation. For upgrades, stop all legacy writers, workers and replay clients first. The `--legacy-writers-stopped` assertion requires that operational fact; it is not a command that stops them. PostgreSQL migrations run before API startup. Fresh ClickHouse volumes receive both schema files. Existing volumes require the separate migration in section 9.

Open `http://localhost:3000`, create a local recovery administrator and verify the pipeline:

```bash
docker compose ps --all
curl --fail http://127.0.0.1:8443/health
curl --fail http://127.0.0.1:8443/ready
docker compose logs --tail 100 api ingest-worker correlation-worker
```

Stores have no host ports; API/UI bind to localhost. `/health` proves API process health, `/ready` its dependencies. Worker readiness additionally requires local progress and retention state; an idle or blocked pipeline must be assessed separately. See [Deployment (English reference)](../deployment.md).

## 3. Establish secrets, TLS and organization boundaries

Set `SHADAI_TENANT_ID` consistently and dedicate external store credentials to this installation. Base bootstrap secrets do not provision a usable Microsoft credential, OIDC client secret, SCIM token or metrics token. Distribute each credential through the approved secret-management channel and private files; never put values in Git, `.env`, command arguments, browser storage, logs or SYSVOL. Protect the host account and Docker daemon.

Port 8443 serves internal HTTP. Publish one trusted HTTPS origin through a reverse proxy in front of the frontend, which forwards `/api/`; keep raw API/store ports private. Agents and AD upload require HTTPS, validate certificates and reject redirects. Set `SHADAI_CA_BUNDLE` or the collector's CA-file option for a private CA. Configure the final endpoint directly and keep verification enabled.

Compose's dedicated `edge` network defaults to `172.30.0.0/24`, frontend `172.30.0.2`, API `172.30.0.3`. For overlap, change **all three** `SHADAI_EDGE_SUBNET`, `SHADAI_EDGE_FRONTEND_IP`, `SHADAI_EDGE_API_IP` coherently and recreate the network in a maintenance window. Uvicorn trusts only that frontend address, whose nginx overwrites incoming client-address headers. An additional upstream proxy requires exact-address real-IP trust and restricted ingress; otherwise its clients share one login quota. Never broaden `TRUSTED_PROXY_IPS` or trust `*` to pass a test.

Use exact `CORS_ORIGINS` only if cross-origin access is needed. Console cookies are HttpOnly, SameSite=Strict, and Secure/`__Host-` outside localhost; check `SESSION_COOKIE_SECURE` against the actual public origin. Cookie-authenticated writes require `X-CSRF-Token`. PostgreSQL TLS belongs in `DATABASE_URL`, Redis TLS in `rediss://` `REDIS_URL`. External ClickHouse uses native TLS with `CLICKHOUSE_SECURE=true` and normally port 9440; private CA, client certificates and hostname settings are documented in [TLS configuration (English reference)](../deployment.md#remote-access-and-tls).

## 4. Prepare Kubernetes with external stores

The baseline requires external PostgreSQL/Redis/ClickHouse, a NetworkPolicy-enforcing CNI, private encrypted store connectivity, an ingress controller and an existing trusted TLS certificate. It supplies no database operator, store HA or certificate issuance. Build API/worker/frontend images in the approved registry and replace all runtime and migration images with immutable verified digests in a private overlay.

Provision the namespace and `open-shadow-ai-runtime` Secret using the existing secret manager. Required keys are `DATABASE_URL`, `REDIS_URL`, `CLICKHOUSE_HOST`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `JWT_SECRET`, `ENCRYPTION_KEY` and `AGENT_API_KEY`. Set organization configuration, actual database CIDRs/ports, DNS selectors and ingress selectors. TEST-NET ranges intentionally provide no production route. Apply both ClickHouse schema files in order using the store administration process, then complete PostgreSQL migration before applications:

```bash
kubectl apply -f deploy/kubernetes/base/namespace.yaml
# Provision the runtime Secret using your existing secret manager.
kubectl apply -f deploy/kubernetes/migrate.yaml
kubectl -n open-shadow-ai wait --for=condition=complete job/open-shadow-ai-migrate --timeout=180s
kubectl apply -k deploy/kubernetes/base
```

These commands assume the referenced configuration has been prepared with real images/routes. Render and server-validate before publication:

```bash
kubectl kustomize deploy/kubernetes/base > rendered.yaml
kubectl apply --dry-run=server -k deploy/kubernetes/base
kubectl -n open-shadow-ai get pods
kubectl -n open-shadow-ai rollout status deployment/api
```

Reconcile Redis in a new configured maintenance pod after the new workers initialize groups; the PostgreSQL Job does not migrate Redis. Preserve external Redis's `noeviction`, full reference graph and measured persistence behavior. Base workers have one replica; additional replicas require load, reclaim and concurrent-correlation proof. Validate pod scheduling, ingress/TLS, NetworkPolicy, probes, disruptions, stores and restore on the actual cluster. A manifest or server dry-run does not prove HA. See [Kubernetes procedures (English reference)](../../deploy/kubernetes/README.md).

## 5. Integrate AD and Entra inventory

Use RSAT ActiveDirectory on a management host with read access to explicit pilot OUs. Domain-root queries are rejected; Domain Administrator is unnecessary for the exporter. Preview then export:

```powershell
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export' -WhatIf
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export'
```

Each run creates private API-compatible batches of at most 500 with observation times/GUIDs/SIDs and selected names; no directory mutation, passwords, broad attribute dump or group memberships. For upload, enroll `ad-pilot` with `directory`, provision its private key and explicitly set the collector:

```powershell
$env:AGENT_API_KEY_FILE = 'C:/Protected/OpenShadowAI/collector-key.txt'
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export' -Upload -ApiUrl 'https://ai-inventory.example.com' -TenantId 'default' -CollectorId 'ad-pilot'
```

Failed uploads retain original JSON/IDs; a fresh export is a new observation. Protect exports and their retention. AD GUID/SID, Entra object IDs and agent IDs are distinct; mapping must be independently validated.

Create a dedicated Entra **inventory** application, separately provision `secrets/entra_client_secret.txt`, and set `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_POLL_INTERVAL_SECONDS` (minimum 60). `Application.Read.All` application permission with admin consent covers service-principal inventory. Grants are disabled by `ENTRA_COLLECT_GRANTS=false`; enabling them requires reviewed broader `Directory.Read.All` consent.

```bash
docker compose --profile entra up -d --build entra-collector
docker compose logs --tail 100 entra-collector
```

The shipped catalog has no built-in OAuth application-ID mappings. Review verified Graph **appId** values, not service-principal object IDs or display names; adapt the unloaded example in `catalog/local/entra-app.yaml.example`, preserve existing signatures when reusing an ID, and synchronize the catalog. Inventory/grants remain presence/permission evidence. Validate tenant permissions, throttling and observations live. See [Microsoft procedures (English reference)](../microsoft.md).

## 6. Roll out OIDC, SCIM and MFA deliberately

OIDC/SCIM are optional, disabled by default and manage **console access**, separately from inventory. Keep a tested local recovery administrator. Login requires an active pre-provisioned SCIM user: verified issuer plus stable `externalId`; no first-login creation, email linking or conversion of local users. Generic OIDC needs discovery, confidential authorization-code flow, PKCE S256 and RS256; use stable client-specific `sub`. Entra uses a dedicated single-tenant sign-in app, exact tenant issuer, `OIDC_IDENTITY_CLAIM=oid` and the same user objectId in SCIM `externalId`.

Register the HTTPS callback `/api/v1/auth/sso/callback`, not frontend `/auth/callback`. The latter completes a one-use cookie exchange at `POST /api/v1/auth/sso/session`, requiring exact `Origin` and `X-SSO-CSRF: 1`. Configure Conditional Access/MFA at the IdP: the application does not independently enforce an MFA claim. Sign-in requests `openid profile`, no inventory Graph permissions.

Provision private `secrets/oidc_client_secret.txt` and an independent `secrets/scim_bearer_token.txt` generated from at least 32 random bytes. Configure exact issuer/client/public origin and an explicit `SCIM_GROUP_ROLE_MAP`; immutable group external IDs grant `viewer`, `analyst`, `admin`, highest role wins, empty map yields viewer. Every API replica must use the same policy. Configure the SCIM enterprise application's tenant URL `/api/v1/scim/v2`, Test Connection and explicit mappings: objectId→externalId, UPN→userName, enabled→active, group objectId→externalId, memberships→members. Start with assigned pilot users/groups and provision on demand.

```bash
docker compose -f docker-compose.yml -f docker-compose.sso.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d --build
docker compose exec -T frontend nginx -s reload
```

Use both Compose files for all subsequent operations; reload nginx after API recreation. Kubernetes adds a separately provisioned `open-shadow-ai-identity` Secret, API-only settings and reviewed HTTPS IdP egress. Standard NetworkPolicy does not authorize hostnames.

Test provisioned/unprovisioned login, matching identifiers, consent denial, expiry/replay, exact cookie/CSRF behavior, mapped groups and active-session deactivation. Disable/delete/role reduction revokes affected sessions **on receipt**; directory synchronization delay is outside the application. Reactivation does not revive old tokens. Profile/unmapped-group changes do not end sessions; roles resolve on requests. Console logout is not global IdP logout. Rotate credentials in coordination with the provisioner and restart API; overlapping SCIM-token rotation is not delivered. SCIM is a bounded subset without Bulk, nested groups, complete filters, SAML or multiple IdPs. See [Identity rollout and acceptance (English reference)](../sso-scim.md) and [SSO admission (English reference)](../sso-admission.md).

## 7. Enroll collectors and establish coverage

An administrator uses **Sources & coverage → Enrolled collectors → Enroll collector** to assign immutable ID and least source scope. Save the one-time returned key privately; lost responses may have committed, so inspect the registry before retrying. Rotation defaults to 3,600-second overlap (0–86,400) and 365-day expiry (1–365); revoked collectors remain permanently disabled. Collector keys cannot administer registry or metrics. Disable `ALLOW_LEGACY_AGENT_KEY` only after every producer has scoped credentials and verified delivery; legacy traffic is unattributed. Supply environment overrides explicitly to relevant services, not merely `.env`.

For Windows endpoints, build the platform-specific offline wheelhouse and approve its hashes. The SYSTEM installer requires a new protected installation tree, trusted administrative Python/wheelhouse owners and safe ancestors; a per-user Python is unsuitable. Preview on one device, verify task/HTTPS inventory then stage through existing GPO/Intune/Configuration Manager processes. Server installation does not deploy agents or edit GPOs. SYSTEM may miss user browser profiles; extension collection needs `browser` scope. Upgrade/uninstall/signing remain fleet acceptance tasks.

For syslog, choose the exact BIND/Windows DNS/Squid/PAN-OS/FortiGate parser, correct source IANA timezone and clock. Default TCP/1514 is localhost; remote forwarding needs private binding, firewall restrictions and a trusted TLS relay where required. Syslog sender authentication is separate from the HTTP legacy-key setting. Enable after source review:

```bash
docker compose --profile syslog up -d
```

For network metadata, provision SPAN/TAP/mirror coverage deliberately, use stable sensor/site IDs and prefer persisted Zeek JSONL or Suricata EVE logs. Inspect before authenticated delivery:

```bash
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format zeek-tls --input ssl.jsonl --dry-run --csv-output network-observations.csv
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format zeek-tls --input ssl.jsonl --api-url https://shadai.example.test --api-key-file /etc/shadai/network-agent.key --ca-file /etc/shadai/organization-ca.pem --spool-dir /var/lib/shadai/network/office-mirror
```

Zeek TSV is not JSONL input; TShark PCAP/live extraction is optional and local, never a PCAP upload. Imports support IPv4/IPv6 and DNS/TLS/QUIC/HTTP. Live interfaces require capture permissions and explicit selection; installing the server starts none. Generic events use authenticated 1–500-event batches, timezone-bearing timestamps, stable UUIDs and reject unknown fields. Timestamps over five minutes ahead or outside `ingestion_max_age_days` are refused. Preserve timestamps on retries. See [Collector operations (English reference)](../collector-operations.md), [Coverage (English reference)](../collectors.md) and [Network procedures (English reference)](../network-analysis.md).

## 8. Operate queues, monitoring and capacity

Endpoint/network/syslog SQLite spools retain prepared plaintext metadata across restarts: default 64 MiB payloads, 2,048 batches, seven days; maxima 16 GiB, 100,000 batches, 365 days, TTL capped by server acceptance age. Budget SQLite/journal/filesystem overhead separately; quarantine consumes capacity. Private paths require real service ownership and trusted ancestors (`0700`/`0600` on Unix; restricted Windows ACLs); do not weaken guards. Entra retries in-memory chunks without crash durability; AD retains export JSON instead.

Offline first-start retention sends nothing until target/collector discovery verifies binding. Restore the correct principal after mismatch; another tenant/enrollment cannot inherit retained bytes. Same-collector rotation is compatible. Leases permit restart recovery; at-least-once delivery uses stable IDs/receipts, not unlimited exactly-once guarantees. Capture downtime, UDP loss, pre-enqueue drops, expiry and full disk remain possible. `capture_loss` is unknown.

Redis defaults to 100,000 retained entries per source/matches stream, 10,000 pointers per DLQ, 500 records/2 MiB field bytes per admission, seven-day explicit-maintenance cutoff. New guarded scripts preflight destinations; later Lua allocation/OOM can still leave partial or uncertain writes. Retain unconfirmed bytes, preserve `noeviction` and measure memory/headroom. No automatic TTL/MAXLEN deletes pending sources or active pointers. Pending acknowledgements, nullable undelivered lag and retained replay sources are separate. Use dry-run replay after resolving poison data:

```bash
python -m shadai.workers.replay --group ingest_group --start 0-0 --end + --limit 100 --dry-run
python -m shadai.workers.replay --group ingest_group --start 0-0 --end + --limit 100 --execute
```

Replay preserves original fields and trusted `accepted_at`; old backlog without it remains age-validated. Inspect explicit archive/discard maintenance before executing it; never trim pending work to silence an alert. Verify actual AOF/fsync policy before assigning RPO:

```bash
docker compose exec -T redis sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli CONFIG GET appendonly appendfsync maxmemory maxmemory-policy'
```

`/metrics` needs admin identity or a separate read-only token of at least 32 non-whitespace characters. The optional Linux/rootful overlay uses two private copies of the same token for API UID10001 and Prometheus UID65534; bind-mounted file secrets do not remap ownership. Keep scrape routes private and reverify authentication after rotation. Application metrics cover queues, not physical memory/disk. Measure Redis AOF/memory, container CPU/RAM, store disks/inodes and growth with target infrastructure monitoring. Alert rules require owners and an independently configured receiver; firing alone sends no notification. Prometheus itself needs an external watchdog.

Measure baseline, bounded staged rate, API/error latency, pending age, locks, inserts, query latency and drain/reclaim time. Stop at predefined thresholds. Projection uses measured bytes/event plus indexes/replication/backups. Event TTL and daily purge are distinct from identity/queue retention; keep `receipt_days >= ingestion_max_age_days + events_days + 1`. Define RPO/RTO and rehearse at intended data size. See [Queue retention (English reference)](../queue-retention.md), [Monitoring (English reference)](../production-monitoring.md) and [Capacity (English reference)](../capacity.md).

## 9. Back up, migrate and rehearse rollback

Before updates, back up stores, config, deployment commit, matching encryption keys and private collector spools/exports. Quiesce remote producers and optional collectors, then stop application writers. Stop SQLite clients before snapshots. Encrypt and restrict backups: server pseudonymization does not clean backups or local plaintext spools. PostgreSQL/ClickHouse logical exports alone omit Redis pending/reference state; preserve store volumes and actual AOF/flush boundaries.

The small-pilot logical procedure is:

```bash
umask 077
mkdir -p backups
docker compose stop api frontend ingest-worker correlation-worker purge-worker
docker compose exec -T postgres pg_dump -U shadai -d shadai -Fc > backups/postgres.dump
docker compose exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --query "SELECT * FROM shadai.events FORMAT Native"' > backups/events.native
docker compose exec -T redis sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli SAVE'
```

Production recovery objectives require tested database-native backups. Restore into a separate checkout/project with empty stores, matching version/keys, unused ports and edge subnet. Keep that project name on every command; repeated imports are unsafe. Restore stopped Redis volumes through the storage platform or explicitly document a discarded in-flight interval. Compare events/detections, verify readiness/login and a new synthetic event end to end. Restore local spools only to their original verified binding.

Migration `003` locks local users and rejects empty/case-folded duplicate names; rename explicitly, never merge accounts silently. Migration `004` adds scoped credentials. **Migration `005` resets unaged historical identity arrays/counts, clears `primary_evidence`, removes retained `sample_values`, `sample_observations` and `network_observations` excerpts, and marks risk stale.** Detection records remain. Their historical identity evidence age cannot be proven; the migration does not assign fresh dates. Review that irreversible evidence/count change on a restored copy. ClickHouse `002_event_metadata.sql` must precede dependency-starting API commands because the new health probe selects `identity_sid` absent on old volumes:

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
docker compose exec -T api python /app/entrypoint.py python -m shadai.workers.redis_lifecycle reconcile --execute --legacy-writers-stopped
docker compose up -d --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
```

Wait/retry store connectivity before continuing; temporary unhealthy ClickHouse is expected until SQL succeeds. Stop every optional/remote legacy writer too. With SSO, use both Compose files. There is no automatic schema rollback. `003` rejects downgrade after external identities/groups/audit/revocations exist; do not delete records to bypass it. Restore a pre-migration backup in isolation with matching code/configuration. See [Updates and recovery (English reference)](../deployment.md#updates).

## 10. Maintain privacy and access

Paths, queries and user agents are not retained. In-memory matching is product-host scoped; `privacy.match_transient_signals: false` disables it. Shared equal-confidence signatures remain ambiguous; discarded paths cannot be reconstructed after catalog changes. Review custom signatures and source negatives before attribution.

Identity membership ages each observation independently; default `min(30, events_days)`, positive and no longer than events. Counts are distinct observed identifiers, not staff headcount. Inspect nullable `risk_calculated_at` and `risk_score_stale`; general update time does not prove recalculation. `PSEUDONYMIZE_IDENTITIES` aliases personal fields using field-separated HMAC from the encryption key and clears personal source IP/free-form IdP text. Pseudonyms remain linkable organizational data. It affects new processing, not historical events, backups or spools.

For a reviewed historical scrub, rehearse on restored data, quiesce collectors, drain queues/spools, stop writers/replay and keep that state throughout verification:

```bash
python -m shadai.workers.purge --scrub-personal-history --batch-size 500 --max-batches 100
```

Inspect `complete`, `clickhouse_complete`, `sql_complete` and the returned cursor; resume bounded SQL only with the returned `--after-detection-id`. Zero exit requires complete synchronous/verified work; capped incomplete work is nonzero. Accounts, notes and audit actors are excluded. Changing the encryption key changes the pseudonym basis and encrypted material; retain matching backups and plan reconstruction. See [Privacy maintenance (English reference)](../collector-operations.md#retain-and-pseudonymize-identities).

## 11. Review security and delivery evidence

Check exact-commit mandatory Linux/Python, frontend, Windows native, real-store/Compose, offline agent, native amd64/arm64 image and qualification gates. Hash-pinned locks/base inputs and BuildKit SBOM/provenance bind inputs and artifacts; they do not promise identical binaries across machines. Image scans must cover their subject/inventory and retain all severities/unfixed findings. Scanner errors, incomplete coverage and fixable high/critical or unknown-severity findings fail according to the documented gate.

The gosu and node_exporter main-module SBOM observations retain **`UNKNOWN`**; reviewed source-projected query versions are not invented binary versions. ClickHouse's absent principal SBOM entry is preserved and receives a separate declared query/CLI observation. **GO-2026-5932 remains visible where reported**; maintained recipes do not claim removal from every layer. The earlier zero named-package npm audit does not inventory embedded affected `braces` in Vite/Rollup. Literal-path watcher restrictions mitigate the identified build-tool route, not every parser/plugin risk.

Trusted internal `main` pushes may produce verified GitHub/Sigstore attestations for exact OCI archives/evidence after all required gates. The signature scope is the exact OCI archives and separate evidence manifests, not a GitHub source ZIP. PR artifacts are unsigned; local predicates, tags and tests are not signatures or a signed release. Verify repository, workflow, source ref/commit, digest and hosted-runner constraints. Native diagnostic root causes still marked unknown remain unknown until new bound evidence establishes them. Follow [Delivery and scan scope (English reference)](../production-delivery.md), [Validation (English reference)](../validation.md), [Build tooling security (English reference)](../frontend-build-security.md) and [Security policy (English reference)](../../SECURITY.md).

## 12. Make qualification and go/no-go explicit

Use the disposable Linux/nonroot Docker laboratory for the exact commit's required `production-qualification` job. It exercises synthetic load, ingestion/correlation interruptions, pending reclaim, process probes, physical measurements, isolated Redis pressure and cold restore. Its fixed profile is **1,000 synthetic events, 10/s, batches 10, concurrency 2**, 5-second requests, 120-second drain, 1,500-second work budget, 500 requests, 2 MiB/request and 10 GiB artifacts. Termination allowances yield a declared application ceiling of **1,512 seconds**. These are test inputs, not production capacity or RPO/RTO.

Cold restore must compare full private inventories before workers and establish **ten new distinct accepted events plus the backed-up PEL event**, each with ClickHouse persistence and PostgreSQL ingestion/correlation receipts. Pending recovery alone is insufficient. Diagnostics locate stages without proving causes or success. The synthetic quality corpus yields TP=1, FP=1, FN=2, TN=1, precision=0.5, recall=1/3, F1=0.4; unknown truth and zero denominators remain explicit. It measures normalized metadata matching, not capture, real model usage or calibrated probability.

The target runner's preflight/load/Kubernetes/IdP/evaluate procedures require a reviewed exact-context plan, dedicated collector and private evidence. Kubernetes `--execute` performs server dry-run/inventory, not deployment or HA proof. IdP without execution checks metadata/health only. **`idp --execute` is disabled on every platform**, returns `unsupported_browser_containment`, `not_evaluated`, exit 2 before browser or account-reference access. Human-authorized actual login/MFA, cookies, session/CSRF/logout and role/deactivation observations remain required. Caller-supplied success flags never become independent evidence.

| Gate | Go for the next bounded pilot stage | No-go / evidence still required |
|---|---|---|
| Installation and queues | Exact commit's mandatory gates pass; migrations, reconciliation, real readiness and synthetic end-to-end proof complete | Skipped required scenarios, missing/native failed evidence, unhealthy stores, building retention graph |
| Source and identity | Approved scopes, private credentials/spools, tested rotation/revocation; explicit positive/negative and coverage evidence | Unknown mapping promoted to identity; inventory called usage; missing live AD/Entra/IdP/MFA acceptance |
| Recovery and resources | Rehearsed restore, bounded outage/drain, measured capacity/headroom and agreed RPO/RTO at intended size | Pending-only restore, assumed AOF power-loss durability, unmeasured HA or resource coverage |
| Security and operation | Accepted bound scans/signatures where applicable; reviewed residual findings; owners and tested notification route | Scanner error/incomplete coverage, failed security gate, signature claims on PR artifacts, untested receiver |

Exit codes are 0 for measured criteria satisfied, 1 for failed measurement/criterion, 2 for missing prerequisite/evidence. Optional precision/recall/latency/recovery/restore objectives require actual measurements. A successful lab permits review of its stated evidence; production requires target-specific source, access, capacity, failure, privacy and recovery acceptance. See [Full qualification procedure (English reference)](../production-qualification.md).

## 13. Troubleshoot and maintain the pilot

| Symptom | Bounded investigation and remedy |
|---|---|
| API alive, workers unready | Inspect dependencies, actual groups and `retention_ready`; retry reconciliation after initialization or fix interrupted graph rebuild, preserving backlog |
| Ingestion 503 or backlog | Inspect exact retained caps, Redis types/memory and downstream health; keep uncertain bytes; distinguish pending/lag from retained originals |
| 401/403 collector | Check expiry/revocation/source/tenant/collector scope; restore the right key, not another enrollment's queue binding |
| Old/future event rejection | Verify source timezone/clock and server age window; never rewrite source timestamps |
| Healthy contact, no detection | Verify parser, negatives/shared signatures, unmapped Entra appId and observation provenance; silence may be legitimate |
| Spool/secret ACL refusal | Provision a trusted private path under the actual account; inspect ancestors/reparse/hardlinks without broadening rights |
| SSO 429/503 or denied login | Check shared Redis admission, exact proxy peer/issuer, active SCIM mapping and provider state; use local recovery administrator |
| Metrics absent / no notification | Verify private token copies/UIDs, scrape and complete ten-stream inventory, then receiver route; a rule alone sends nothing |

For worker failures, use [Sanitized diagnostics (English reference)](../worker-diagnostics.md); do not collect raw secrets, OAuth callback queries or personal production logs into public issues. Review collectors, access, storage growth, archives, stale risk and retention regularly. Rehearse again after source, identity, image, key, retention, topology or receiver changes. Contribute minimal synthetic reproductions through [Contribution procedures (English reference)](../../CONTRIBUTING.md) and report vulnerabilities privately through the security policy.
