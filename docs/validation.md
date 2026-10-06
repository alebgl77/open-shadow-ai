# Validation scope

The [CI workflow](../.github/workflows/ci.yml) defines Python 3.12/3.13 lint and regression checks, frontend tests and build, PowerShell validation and Docker-backed integration.

## Local frontend brace-chain verification

The 2026-10-06 Tailwind 4/Vite 6.4.4 follow-up is a new source revision, separate from the historical successful CI runs below. Its authoring-host checks use Node `22.23.2` and npm `10.9.8`. The dependency tree has no named brace-chain/parser nodes and all installed `source-map-js` paths resolve to `1.2.2`; bundled affected brace parsers remain in Vite/Rollup and are mitigated on the protected watcher paths. See [frontend build security](frontend-build-security.md).

| Check | Current status and limits |
|---|---|
| Author clean installation and suite | Offline `npm ci --no-audit` installed 318 packages from the populated cache; complete `npm ls --all` passed; all 145 tests in 12 files passed, including the existing 96 tests, 44 guard cases and five filesystem cases |
| Author guard/config verification | Actual Vite resolution verifies asynchronous root/environment mutations, option-list preservation and captured references; the guard module is included in a focused TypeScript check |
| Author build/type checks | Production build and lint passed; final artifact hashes are recorded below |
| Real filesystem watch integration | Middleware-mode self-accepting module HMR hook, cached-transform invalidation and updated code passed without TCP/WebSocket clients; opt-in build output rebuilt and default build terminated; benign Vite and private bundled Rollup `watch/add` controls observed actual glob alternatives versus literal filename/change; no stack-exhaustion reproduction is claimed |
| Dependency audit | Earlier regenerated-graph audit saved at `2026-10-06T11:49:12Z` reported zero known findings; fresh final audit is pending because sandbox registry DNS failed and automatic approval review rejected metadata disclosure to npm |
| Independent compatibility verification | Offline `npm ci --offline --no-audit` installed 318 packages; the complete development/optional dependency tree and all 145 tests in 12 files passed; production build and lint passed, including the guard TypeScript check; generated baseline/candidate static CSS passed all 83 effective palette comparisons and 15 semantic assertions covering divider width/color, fixed nested spacing, radius, fonts, focus and important zero padding; ring declarations were checked; this does not prove rendered browser equality |
| Independent security review | APPROVE for the current default resolved factory paths: bundled watcher call paths and immutable root/build/environment reference chains were reviewed with no actionable P1/P2 findings; the mitigation and private Rollup/HMR limits above remain applicable |
| Real browser comparison | Unavailable locally because browser-control sandbox initialization failed; no pixel or rendered-layout pass is claimed |
| Mandatory CI/platform checks | Final-source Ubuntu ARM frontend, Docker Alpine/musl and native Windows workflow results are pending; no mandatory gate has been weakened |

The saved baseline comes from `6f76ca89391e19cecc66f73be757c4016c815139`: CSS 28,800 bytes, SHA-256 `797f47cadf9f1e569bb2f4aec5b24e674c83b010b81e94bba5fb67a7fe11d939`. Tailwind 4 changes generated CSS. Preservation claims require semantic and supported-browser verification rather than byte comparison. Three independent local code checks passed on the same frozen version: author verification, independent compatibility QA and independent security review. The audit, rendered-browser and platform-CI checks remain pending.

The independently compared candidate stylesheet is `index-B9Vljf4J.css`, 38,281 bytes, SHA-256 `06574beb46e5c84b0efb5d926d7c29fcbb267d9b18db1bbef164de5b1ace06dc`. Initial static findings on divider color, a nested spacing variable and the rose palette were corrected before this comparison. A later source change requires another artifact comparison.

## Verified collector hardening CI run

Scoped credentials/rotation, persistent collector queues and bounded replay, operational health, and per-observation retention/pseudonymization with honest risk timestamps passed all six jobs in [CI run 37435294695](https://github.com/alebgl77/open-shadow-ai/actions/runs/37435294695) for source commit [f2c5fd8015f5d22aa919b0a1a75d17fd8d58b973](https://github.com/alebgl77/open-shadow-ai/commit/f2c5fd8015f5d22aa919b0a1a75d17fd8d58b973), on 6 October 2026. Every mandatory workflow gate executed successfully; no job or step was skipped.

| Area | Result and scope |
|---|---|
| Python 3.12 and 3.13 | Each regression suite passed 789 tests and skipped 9: eight service tests ran separately in Compose, and one Windows-only unit test requires Windows; Ruff and deployment validation passed |
| Frontend | 96 tests passed in 10 files and production build succeeded |
| Network sensor | Real offline TShark smoke passed with six observations, covering DNS, IPv6, HTTP, TLS and QUIC metadata |
| Windows 3.13 | PowerShell syntax, complete bootstrap/private-secret checks and real key-file DACL checks passed; the full native spool guard and SQLite process restart recovered exact bytes/ID under trusted user-profile ancestors outside the checkout |
| Real-store integration | 8 tests passed, 790 deselected, zero skipped, against disposable Redis, PostgreSQL and ClickHouse; scoped credential lifecycle, retention/privacy, identity provisioning and stream delivery recovery executed |
| Linux syslog volume | Two distinct containers sharing `syslog_spool` passed actual UID10001, `0700` parent and `0600` database checks, exact retained bytes/ID recovery and acknowledgement |
| Deployment and HTTP | Fresh image builds, base and optional identity startup, protected ingestion/readiness/queue/storage/detection smoke, and frontend-proxied SCIM lifecycle passed |
| Private monitoring | Two `0600` copies of one independent token owned by API UID10001 and Prometheus UID65534 passed correct-reader success and other-UID read refusal; authenticated metrics, missing/wrong/agent-key 401 refusals and metrics-token collector-administration 401 refusal passed; the actual internal Prometheus target was `up` before and after container replacement, and the exact private marker survived on `prometheus_data` |

The native Windows spool checks used real permissions, owners, path/link checks and SQLite. Positive checks covered private creation and protected descendants below both InheritOnly and InheritOnly/NoPropagate Modify templates. Negative checks covered explicit/inherited public file reads, effective inherited Modify, unsafe leaf templates, writable ancestors and untrusted owners, all three existing public SQLite sidecars, an untrusted sidecar owner, hardlinks and reparse paths. Required database absence remained a strict failure.

The deterministic disappearing-journal case uses a harness timing hook to cause a real SQLite rollback between the path check and native probe. The runner recorded a failed native probe with object/path-not-found, no access-denied result, and definitive absence from a real post-probe `lstat`; exact bytes/ID survived restart. The production guard was not replaced or weakened, and the other native safety checks ran independently. This causal test is instrumented for timing; it is not an uninstrumented race reproduction.

The final independent read-only review of authentication, migrations, privacy, delivery, health and the last source deltas approved `f2c5fd8` with no remaining actionable P1/P2 findings. Independent checks passed 164 Python tests and 19 Sources frontend tests, then eight real spool/vendor checks and the original concurrent delivery regression. The author passed 56 delivery tests (49 existing and seven new), zero skipped, in 482.94 seconds on the same frozen source. These results retain the local fixture ancestry qualifications below and complement the native CI proof.

Authoring-host evidence remains separate: independent local SQLite restart tests passed 13 cases, of which eight semantic crash/lease/quota/expiry cases explicitly assumed safe ancestors through the fixture boundary because this Windows sandbox's ancestry is unsuitable; private leaf database checks remained real. Five directory/file/ancestor/link negative cases used actual permissions/path checks. An earlier unpatched native smoke on this host refused private directory creation under local USERPROFILE with `spool_private_acl_required`, cleaned its fixture and exited nonzero. Neither that qualified local suite nor that refusal substitutes for the full native Windows runner proof above.

Docker and kubectl are unavailable on the authoring workstation; the Linux volume/service checks above ran in CI. The syslog and Prometheus checks establish persistence across disposable container replacement, not packet-loss freedom, power-loss durability or backup/restore objectives. Historical scrub on live stores, sustained load, HA, live AD/Entra/providers and fleet rollout remain separate acceptance work. Results apply to the linked source commit and workflow; later changes require their own validation. See [operations](collector-operations.md) and [capacity](capacity.md).

## Verified 0.2.0 CI run

All five jobs passed in [CI run 36280261065](https://github.com/alebgl77/open-shadow-ai/actions/runs/36280261065) for source commit [00e98d6539ac37c7f98d12f3c53d77be8a1f365d](https://github.com/alebgl77/open-shadow-ai/commit/00e98d6539ac37c7f98d12f3c53d77be8a1f365d), on 27 September 2026 in Europe/Paris (26 September UTC).

| Area | Result and scope |
|---|---|
| Python 3.12 and 3.13 | Each regression suite passed 203 tests and skipped 2 live integration tests; lint and deployment validation passed |
| Frontend | 32 tests passed and production build succeeded |
| PowerShell | Script syntax and non-mutating bootstrap/AD-export entry points passed |
| Real-store integration | 2 tests passed, 203 deselected, against disposable PostgreSQL, Redis and ClickHouse services; ingestion/correlation concurrency and identity migration/provisioning exercised |
| Docker deployment | Fresh service image builds, base Compose startup and API startup with the optional identity overlay passed |
| HTTP pipeline smoke | Protected ingestion, readiness, frontend, queue pipeline, event storage and detection persistence passed |
| Optional identity HTTP smoke | Provider metadata and SCIM authentication, Users/Groups membership, member removal, deactivation/reactivation and deletion passed through the frontend proxy against the running API and stores |

The smoke scripts reported:

```text
PASS: protected ingestion, readiness, frontend, queue pipeline, event storage, detection persistence
PASS: optional identity startup, frontend proxy, provider metadata, SCIM authentication and lifecycle
```

The two integration tests skipped in each Python regression job ran separately in the Docker integration job. The identity store test covers migration `003` on existing local accounts, collision rejection, password preservation, concurrent provisioning, atomic mutations and revocation state. The HTTP identity smoke recreates only the API with two independently generated synthetic secrets, reloads nginx and verifies SCIM through the existing frontend proxy.

OIDC sign-in tests use a signed mock provider to exercise discovery, token exchange, signing-key validation, PKCE, browser binding, replay prevention and session handoff. The Docker identity smoke uses a synthetic issuer and checks provider metadata without contacting an IdP. Neither establishes live Entra sign-in or provisioning interoperability.

These results apply to the linked source commit and workflow. Later changes and other deployment environments need their own validation. Version 0.2.0 remains a development preview.

## Additional local checks and review

The final local checks on 27 September 2026 recorded:

| Area | Result and scope |
|---|---|
| Backend | 203 tests passed, 2 live integration tests skipped locally; Ruff, compilation and dependency consistency (`pip check`) passed |
| Frontend | 32 tests passed and production build succeeded |
| Dependencies | Backend and frontend audits reported no known vulnerabilities at the time |
| Deployment tooling | YAML/XML parsing, API-only optional identity configuration, bootstrap dry run, six-secret generation and repeat-run preservation passed |

An independent read-only security/correctness review approved the implementation with no remaining P1/P2 findings. Four findings were corrected before the verified run: Entra discovery without optional PKCE metadata while retaining S256, account listings using the current role map, additive multi-valued email PATCH behavior, and session revocation on membership changes when stored roles were stale. This review is not a security certification. An audit result means no known issues were reported by that audit at that time.

## Historical 0.1.0 validation

[CI run 36277550894](https://github.com/alebgl77/open-shadow-ai/actions/runs/36277550894) passed all five jobs for [cea2bafab02bfe0298776ab4de679fd4f044acd6](https://github.com/alebgl77/open-shadow-ai/commit/cea2bafab02bfe0298776ab4de679fd4f044acd6): 72 regression tests per Python version, 13 frontend tests, one real-store integration test, Compose startup and the base HTTP pipeline smoke. That run predates OIDC/SCIM and is retained only as evidence for the earlier source revision.

## Reproduce the checks

```bash
python scripts/verify-deployment.py
python -m ruff check src tests agent/shadai_agent migrations scripts
python -m pytest -q
python -m pip check
cd frontend
npm ci
npm test
npm run build
cd ..
docker compose config --quiet
```

On Windows, also parse the PowerShell scripts and run the non-mutating entry points:

```powershell
./scripts/bootstrap.ps1 -DryRun
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export-dryrun' -WhatIf
python scripts/test-network-key-acl.py
python scripts/test-delivery-spool-acl.py --temporary-parent "$env:USERPROFILE"
```

The following service checks require a disposable Compose project after bootstrap. Never run them against production:

```bash
docker compose --profile test run --build --rm integration-test
docker compose down --volumes
docker compose up -d --build --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
python scripts/integration-smoke.py
```

The integration container exercises real database migrations, catalog persistence, stream reclaim, receipt deduplication, concurrent correlation, scoped collector credential lifecycle, retention/privacy and identity provisioning. The base smoke exercises authenticated HTTP ingestion through running workers into ClickHouse and PostgreSQL. Reset only the disposable stores between these suites, as CI does. Reproduce the two-container syslog volume check from the current workflow after building its collector image; use the same disposable project and leave its named volume intact between those two invocations.

To reproduce the optional identity smoke, use the synthetic secret-file generation and identity environment values from the [verified workflow](https://github.com/alebgl77/open-shadow-ai/blob/00e98d6539ac37c7f98d12f3c53d77be8a1f365d/.github/workflows/ci.yml). The script expects that fixture's label, role mapping and files; it is not a live-tenant acceptance tool. Keep the same disposable Compose project and stores after the base smoke, then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d --no-deps --force-recreate --wait --wait-timeout 180 api
docker compose exec -T frontend nginx -s reload
python scripts/identity-smoke.py
docker compose down --volumes
```

## Remaining validation boundaries

Docker was unavailable on the authoring workstation; Docker-backed checks passed on the Linux CI runner. Live Entra provisioning/sign-in, MFA policies, other providers, Active Directory and Microsoft Graph tenant tests remain operational acceptance work. Kubernetes server validation, identity overlays on an actual cluster and managed-fleet rollout remain unvalidated. Follow the [identity pilot checklist](sso-scim.md#pilot-acceptance).

Sustained load, scaling, backup/restore recovery objectives and operation on your infrastructure require separate validation. Provisioning-triggered revocation is effective when changes reach the application; these tests do not establish an upstream directory synchronization delay.

Isolated multi-tenancy is not implemented: this preview supports one organization per deployment. A passing CI run does not prove production throughput, security certification or universal production readiness. Use controlled pilots and record the exact commit and actual CI result when evaluating a release.
