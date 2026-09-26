# Validation scope

The [CI workflow](../.github/workflows/ci.yml) defines Python 3.12/3.13 lint and regression checks, frontend tests and build, PowerShell validation and Docker-backed integration.

## Verified CI run

All five jobs passed in [CI run 36277550894](https://github.com/alebgl77/open-shadow-ai/actions/runs/36277550894) for source commit [cea2bafab02bfe0298776ab4de679fd4f044acd6](https://github.com/alebgl77/open-shadow-ai/commit/cea2bafab02bfe0298776ab4de679fd4f044acd6), on 27 September 2026.

| Area | Result and scope |
|---|---|
| Python 3.12 and 3.13 | Each regression suite passed 72 tests and skipped the live integration test; lint passed |
| Frontend | 13 tests passed and production build succeeded |
| PowerShell | Script syntax and non-mutating bootstrap/AD-export entry points passed |
| Real-store integration | 1 test passed, 72 deselected, against disposable PostgreSQL, Redis and ClickHouse services; migrations, catalog persistence, stream reclaim, receipt deduplication and concurrent correlation exercised |
| Docker deployment | Fresh service image builds and Compose startup passed |
| HTTP pipeline smoke | Protected ingestion, readiness, frontend, queue pipeline, event storage and detection persistence passed |

The smoke script reported:

```text
PASS: protected ingestion, readiness, frontend, queue pipeline, event storage, detection persistence
```

The skipped integration test in each Python regression job ran separately in the Docker integration job. These results apply to the linked source commit and workflow; they do not validate later code changes or every deployment environment.

## Additional local checks

The review on 27 September 2026 also recorded:

| Area | Result and scope |
|---|---|
| Backend | 72 tests passed; one live integration test skipped locally; lint and compilation clean; dependency audit reported no known vulnerabilities |
| Frontend | Build succeeded; 13 tests passed; dependency audit reported no known vulnerabilities |
| Browser review | Desktop and mobile navigation, search and detection review checked; the README uses an actual 42 KB WebP screenshot from isolated synthetic demo data |
| Deployment tooling | YAML/XML parsing, bootstrap generation and repeat-run preservation, PowerShell syntax and dry-run checks passed |
| Architecture assets | SVG visually checked for legibility; SVG and editable draw.io XML parsed |

A dependency audit result means no known issues reported by that audit at the time.

An independent read-only security/correctness review identified three blocking findings, which were corrected: workers could ingest before catalog initialization completed; governance audit data mishandled date values; and policy links were not consistently propagated to detections. Two subsequent medium-priority governance findings were also corrected. The final independent read-only review passed with the operational caveats recorded below. The first Docker smoke run additionally caught a missing-key response returning 422 instead of 401; the authentication dependency was corrected and covered by an HTTP regression before the successful run linked above. This review is not a security certification.

## Reproduce the checks

```bash
python scripts/verify-deployment.py
python -m ruff check src tests agent/shadai_agent migrations
python -m pytest -q
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

The integration container exercises real database migrations, catalog persistence, stream reclaim, receipt deduplication and concurrent correlation. The smoke script exercises authenticated HTTP ingestion through running workers into ClickHouse and PostgreSQL. Reset only the disposable stores between these suites, as CI does.

## Remaining validation boundaries

Docker was unavailable on the authoring workstation; Docker-backed checks passed on the Linux CI runner. Kubernetes server validation, live Active Directory and Microsoft Graph tenant tests, and managed-fleet rollout remain pending. Sustained load, scaling, backup/restore recovery objectives and operation on your infrastructure require separate validation.

The linked run predates the optional OIDC/SCIM implementation. Its new mocked-provider, provisioning, UI and deployment checks must pass for the preview's exact commit before release; earlier test counts are not evidence for the identity change. Live Entra provisioning/sign-in, MFA policies, other providers and Kubernetes overlays remain unvalidated in a real environment. See the [identity pilot checklist](sso-scim.md#pilot-acceptance).

Isolated multi-tenancy is not implemented: this preview supports one organization per deployment. A passing CI run does not prove production throughput, security certification or universal production readiness. Use controlled pilots and record the exact commit and actual CI result when evaluating a release.
