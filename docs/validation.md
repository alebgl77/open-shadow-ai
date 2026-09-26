# Validation scope

The [CI workflow](../.github/workflows/ci.yml) defines Python 3.12/3.13 lint and regression checks, frontend tests and build, PowerShell validation and Docker-backed integration.

## Recorded local checks

The pre-publication review on 27 September 2026 recorded:

| Area | Result and scope |
|---|---|
| Backend final local regression | 71 tests passed; one live integration test skipped; lint clean; compilation succeeded; dependency audit reported no known vulnerabilities |
| Frontend | Build succeeded; 13 tests passed; dependency audit reported no known vulnerabilities |
| Browser review | Desktop and mobile navigation, search and detection review checked; the README uses an actual 42 KB WebP screenshot from isolated synthetic demo data |
| Deployment tooling | YAML/XML parsing, bootstrap generation and repeat-run preservation, PowerShell syntax and dry-run checks passed |
| Architecture assets | SVG visually checked for legibility; SVG and editable draw.io XML parsed |

These are recorded results, not a guarantee about later edits. Re-run validation on the published commit. A dependency audit result means no known issues reported by that audit at the time.

An independent read-only security/correctness review identified three blocking findings, which were corrected: workers could ingest before catalog initialization completed; governance audit data mishandled date values; and policy links were not consistently propagated to detections. Two subsequent medium-priority governance findings were also corrected. The final independent read-only review passed with the operational caveats recorded below. This review is not a security certification; Docker-backed CI execution remains a release validation gate.

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

The first integration container is designed to exercise real database migrations, catalog persistence, stream reclaim, receipt deduplication and concurrent correlation. The smoke script is designed to exercise authenticated HTTP ingestion through running workers into ClickHouse and PostgreSQL. Reset only the disposable stores between these suites, as CI does.

Docker was unavailable on the authoring workstation. The service checks are definitions awaiting execution on a Docker-capable host; no successful live integration result is claimed here. Kubernetes server validation and live AD/Entra tests remain pending.

A green unit suite does not prove fleet rollout, production throughput, security certification or recovery objectives. Record the exact commit and actual CI result when evaluating a release.
