# Validation scope

The [CI workflow](../.github/workflows/ci.yml) defines Python 3.12/3.13 lint and regression checks, frontend tests and build, PowerShell validation and Docker-backed integration.

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
python -m ruff check src tests agent/shadai_agent migrations scripts/identity-smoke.py
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
```

The following service checks require a disposable Compose project after bootstrap. Never run them against production:

```bash
docker compose --profile test run --build --rm integration-test
docker compose down --volumes
docker compose up -d --build --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
python scripts/integration-smoke.py
```

The integration container exercises real database migrations, catalog persistence, stream reclaim, receipt deduplication, concurrent correlation and identity provisioning. The base smoke exercises authenticated HTTP ingestion through running workers into ClickHouse and PostgreSQL. Reset only the disposable stores between these suites, as CI does.

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
