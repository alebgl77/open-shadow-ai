# Audit remediation: 15 October 2026

[English](audit-remediation-2026-10-15.md) | [Français](fr/audit-remediation-2026-10-15.md) | [简体中文](zh-CN/audit-remediation-2026-10-15.md)

This operator guide describes the corrected contracts for the ten findings in the whole-project audit. Each finding forms a logical change; documentation is maintained separately. It is not a release announcement, a current-head CI result or a production certification. Confirm that the deployed source contains these changes and retain its exact commit, configuration revision and build evidence. Version `0.3.0` alone does not identify them. For installation prerequisites, use the [expert handbook](en/README.md).

## 1. Logical changes and acceptance

| Finding | Corrected contract | Operational check |
|---|---|---|
| F01 — Entra privacy | Trusted `prepare_event` runs before queue serialization/retention. Enabled pseudonymization protects new identity fields at that boundary; signed preparation and exact retry bytes remain consistent. | Test a synthetic inventory with the intended privacy configuration; verify collector restart/retry behavior. Existing retained raw data is not scrubbed. |
| F02 — Password work | Each API process admits at most four concurrent bcrypt operations through one bounded service shared by login verification and administrator-created password hashing. Native work runs outside the event loop; request cancellation does not release its capacity early. | Check normal/failed login and account creation under bounded concurrency. Saturation returns `429`, unavailability `503`, both with `Retry-After: 1`. The separate peer login quota retains `429` and `Retry-After: 60`. |
| F03 — Kubernetes probes | All three worker stages use the stage-specific startup, liveness and readiness probes used by the target renderer. A live PID or reachable Redis alone cannot conceal a stalled worker. | Verify initialization, local heartbeat, stage progress and actual dependencies in the target cluster; keep writable private `/tmp` and the existing security context. |
| F04 — Maintained images | gosu selects `github.com/moby/sys/user v0.4.1` instead of `v0.1.0` for `CVE-2026-61801`. Other selected modules and compiler pins remain unchanged. All five maintained recipes advance to revision `3`. | Rebuild and examine native Linux amd64/arm64 results, final-runtime scans and provenance. Local `maintained.3` tags do not prove a published or already-remediated deployed image. |
| F05 — Repository policy | The desired `main` policy requires a PR, all 32 checks bound to GitHub Actions application `15368`, strict branch freshness and administrator enforcement; force pushes/deletion are disabled and conversations must be resolved. | Apply only after review/current-head CI, then read back effective settings. The deliberate single-maintainer approval count is `0`; it does not mandate human approval. A committed template alone enables nothing. |
| F06 — UTC bounds | Canonical timestamps that overflow during UTC normalization are invalid. External requests receive `422`; invalid internal envelopes follow permanent-invalid handling rather than transient retry. | Exercise both UTC boundary directions with synthetic timestamps and check that invalid data is not queued as accepted. |
| F07 — TCP record isolation | A malformed parser record is rejected independently so valid neighboring TCP records can continue. Delivery failures and cancellation still propagate. | Send a synthetic malformed record between valid records; separately check delivery refusal and cancellation. Do not treat parser isolation as a delivery guarantee. |
| F08 — Palo Alto source time | A valid explicit key/value time takes priority; otherwise an RFC5424 header supplies the reported time. Missing, NILVALUE `-` or invalid source times are rejected instead of replaced with import time. | Validate exporter time fields, time zones and old replay inputs before enabling collection. Malformed explicit fields are rejected even with a valid header. |
| F09 — Detection reactivation | Old backfill, regardless of strength, cannot reopen `stale` or `archived` detections. A current incoming signal reopens using the same score thresholds as a new detection. | Verify backfill and the 30-day boundary. Fresh scores below `0.70` yield `suspected`, below `0.90` yield `probable`, otherwise `high_confidence`; historical aggregate strength does not choose the reopened status. |
| F10 — Network evidence | Candidate samples merge before selection, deduplicate scoped event UUIDs, and retain the latest ten using actual UTC instants and a deterministic tie-break. Old arrivals cannot evict newer evidence merely by arriving last. | Check out-of-order, fractional/offset-time and duplicate inputs. Sample selection does not alter aggregate activity counters, receipt idempotency or evidence limits. |

These changes do not manufacture IP-to-host links, employee attribution, completed AI requests, prompts, models, token counts or source-file locations. Cartography continues to distinguish network observations from reported host installations. Analyst decisions and notes remain separate from automatic detection status.

## 2. Compatibility, privacy and source clocks

F01 affects newly prepared Entra batches; enabling pseudonymization does not rewrite historical Redis streams, AOF/backups, pending payloads already retained, event stores or exports. Preserve the matching keys and existing retention controls. Historical identification and cleanup need a separately approved, bounded maintenance plan with backup/restore and replay implications reviewed first. Do not delete retained data or rotate encryption keys merely to pass validation.

F08 intentionally rejects timestamp-free records. Configure the exporter to report a valid timestamp; do not substitute collection time to make old records appear recent. RFC5424 headers require supported calendar RFC3339 timestamps with valid offsets. Existing explicit local formats use the configured source time zone. Legacy BSD timestamps omit the year and infer it from the processing clock; they are unsuitable for unambiguous historical replay. Use a year-bearing timestamp for that purpose. Retention still evaluates the reported observation time.

F02 presents known busy/unavailable responses in English, French and Simplified Chinese without exposing raw server errors. Four slots are per API process, not a cluster-wide password quota. Correct capacity sizing still requires measurements; adding API processes changes total admitted native work. Keep existing peer limits and trusted-proxy settings.

The bootstrap correction writes LF line endings only in newly created secret files; Windows CRLF output can introduce a carriage return that ClickHouse rejects. Existing files remain byte-for-byte unchanged, so this does not repair previously generated CRLF secrets. Do not trim or replace live password files in place: affected existing installations need coordinated credential rotation consistent with store credentials and backups. Existing privacy and security checks remain in force.

## 3. Prepare and validate the source

Use a trusted checkout of the reviewed revision and a disposable development environment. The following Bash example installs the committed hash-checked dependency closure and local projects; on Windows replace the activation command with `./tmp/audit-remediation-env/Scripts/Activate.ps1` in PowerShell. Do not reuse this environment as the production runtime.

```bash
python -m venv tmp/audit-remediation-env
source tmp/audit-remediation-env/bin/activate
python -m pip install --only-binary=:all: --require-hashes -r requirements/build.txt
python -m pip install --only-binary=:all: --require-hashes -r requirements/development.txt
python -m pip install --no-deps --no-build-isolation . ./agent
git rev-parse HEAD
```

Run the focused regression groups and existing source gates from the repository root. These commands are verification procedures, not a claim that a particular current commit has passed them:

```bash
python -m pytest -q tests/test_entra_privacy.py tests/test_password_work.py tests/test_kubernetes_worker_probes.py tests/test_repository_governance.py tests/test_canonical_utc_bounds.py tests/test_syslog_record_isolation.py tests/test_paloalto_timestamps.py tests/test_detection_reactivation.py tests/test_network_evidence_ordering.py
python -m pytest -q tests/test_service_builds.py tests/test_image_scan_layout.py tests/test_monitoring_alerts.py
python -m ruff check src tests agent/shadai_agent migrations scripts
python scripts/lock-dependencies.py --check
python scripts/verify-image-pins.py
```

With the supported Node.js 22.x toolchain, validate the localized frontend too:

```bash
cd frontend
npm ci
npm test
npm run build
cd ..
```

Review complete test outcomes, including skips and environment refusals; do not sum overlapping suite counts. A local source test or cross-built binary does not replace native OCI builds, scanner evidence, real store qualification or Windows ACL checks.

Governance fixtures load only when their tests execute, allowing filtered runtime test collection without the repository-only assets while retaining all governance assertions. Verify both corrections with the relevant native runtime and Windows jobs for the reviewed exact commit.

After a qualification step fails, the workflow's displayed diagnostic step name may provide fixed codes for triage. A state of unavailable means the diagnostic is unknown; it does not identify the failure's cause. Use this metadata without downloading private reports, raw logs or mixed artifacts. These codes confer no approval or qualification authority and do not change the original failure or acceptance requirements.

Fresh qualification loads pair the UTC source-time base with a monotonic cadence anchor sampled immediately afterwards. Preparation still counts toward the original budget, deadline and measured duration. Retained manifests and retry payloads keep identical bytes and event IDs; the configured event rate remains unchanged. The verifier continues to reject negative latency without clamping.

## 4. Rebuild and redeploy deliberately

Before a maintenance window, back up stores, configuration and matching keys, rehearse restoration, and quiesce collectors/remote producers and application writers. Preserve private volumes and credentials. If upgrading from an older schema, complete the [existing upgrade procedure](deployment.md#updates) first; the commands below are not a substitute for ClickHouse/PostgreSQL/Redis migration ordering.

For an installation already on the audited schema, rebuild and restart the reviewed base services using its existing private configuration:

```bash
docker compose config --quiet
docker compose build
docker compose up -d
docker compose up -d --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
docker compose ps --all
curl --fail http://127.0.0.1:8443/health
curl --fail http://127.0.0.1:8443/ready
```

Use the same optional Compose files as the installation for SSO/monitoring; rebuild/recreate enabled collectors and both monitoring profiles through their documented procedures as applicable. A base-only restart does not update optional Prometheus/node-exporter services or remote agents. Check every deployed image against the reviewed recipe/source and its build evidence. Replacing image files does not remove older lower-layer bytes or automatically repair previously running containers. The project CI does not publish or deploy these images.

For Kubernetes, prepare a private overlay with approved immutable images, external store routes and existing secrets. Follow the [Kubernetes guide](../deploy/kubernetes/README.md) and render/server-validate that prepared configuration before applying it. For the prepared baseline:

```bash
kubectl kustomize deploy/kubernetes/base > rendered.yaml
kubectl apply --dry-run=server -k deploy/kubernetes/base
kubectl -n open-shadow-ai get pods
kubectl -n open-shadow-ai rollout status deployment/api
```

Validate each worker stage's probes and dependencies, ingress/TLS, NetworkPolicy, disruptions and restoration on the actual cluster. Startup/liveness remain local; readiness resolves mounted secrets through `/app/entrypoint.py`. Keep the 6-second probe timeout, startup interval 5 seconds/60 failures, liveness/readiness interval 10 seconds/3 failures and writable 64 MiB `/tmp`. A rendered manifest or healthy API is not cluster qualification.

## 5. Requalification and CI evidence

Rehearse on a dedicated disposable Docker environment with sufficient resources. Use a new private run directory for each run, review the plan before execution, and retain the source-bound report. These commands concern the isolated lab, never production data:

```bash
python scripts/qualification-lab.py plan --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
python scripts/qualification-lab.py run --execute --docker-context default --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
```

Follow [qualification and recovery](production-qualification.md) for deadlines, resume and verified cleanup. Native builds/scans/provenance must cover both supported Linux architectures; live AD/Entra/SSO behavior and real installation capacity/RPO/RTO need their own evidence. Do not suppress findings or relax probe, filesystem, retention or scanner guards to obtain a green result.

Check CI metadata against the reviewed exact commit:

```bash
git rev-parse HEAD
gh run list --workflow ci.yml --limit 10 --json databaseId,headSha,event,status,conclusion
```

Select the matching run/head/event and verify all 32 mandatory PR checks, including every matrix entry. After merge, check the separate main-push signing evidence for that source; an earlier green run is not evidence for a new head. Review job/step status metadata without downloading raw logs, annotations or mixed artifacts containing sensitive material.

## 6. Apply and verify repository governance

Follow [repository governance](repository-governance.md) for the exact reviewed request, preconditions and readback fields. F05 requires an authorized external application after current-head CI, not merely committing `.github/main-protection.json`. Inspect repository rulesets together with branch protection. The single-maintainer profile requires PRs and checks for administrators but deliberately does not require a human approval; raising that count needs a reviewed staffing/access decision. No repository access, merge, release, production deployment or historical-data purge is implied by this guide.
