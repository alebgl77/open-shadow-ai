# Reproducible delivery and security gates

Third-party Python dependencies are committed in `requirements/*.txt` as exact versions with SHA256 hashes. Local ShadAI projects are built from this checkout; neither `shadai` nor `shadai-agent` is downloaded from PyPI. Runtime images and external Compose services use an exact version plus the SHA256 digest of their official multiarchitecture index. This freezes dependency selection and base-image content; it does not promise identical wheel/container bytes, timestamps, compilers or interpreter patches across machines.

## Python locks

| File | Supported target / purpose |
|---|---|
| `runtime.txt` | Backend and agent runtime dependency closure, Python 3.12+, universal platform markers |
| `development.txt` | Runtime plus normal backend test/lint dependencies, Python 3.12+ |
| `agent.txt` | Standalone endpoint agent including optional Docker collection, Python 3.10+ |
| `build.txt` | Fixed pip 26.2.1, setuptools 84.0.0, wheel 0.48.0 and their closure |
| `tools.txt` | Maintenance only: uv 0.11.16 and pip-audit 2.10.1 plus their closure |

The first runtime/development resolution retained compatible versions already validated in the previous environment. Linux-only uvloop is resolved and hashed with its platform marker; it is absent on Windows. The standalone agent is resolved separately at its lower Python bound. The universal lock is not a claim that every Python implementation/future release has suitable binary wheels: CI actually exercises Linux amd64/arm64, Python 3.12/3.13 backend gates, Windows 3.13 native guards and Python 3.10 standalone installation.

Use a fresh environment, install the build toolchain and the chosen closure with pip hash checking, then build the local projects without resolving dependencies or fetching another build backend:

```sh
python -m venv tmp/delivery-env
# Use tmp/delivery-env/bin/python on Linux or Scripts/python.exe on Windows.
python -m pip install --only-binary=:all: --require-hashes -r requirements/build.txt
python -m pip install --only-binary=:all: --require-hashes -r requirements/development.txt
python -m pip install --no-deps --no-build-isolation . ./agent
python -m pip check
python scripts/lock-dependencies.py --check
```

Run these commands with the fresh environment's Python, not an unrelated activated environment. Third-party locks install wheels only, so an unavailable platform wheel fails instead of fetching unpinned third-party build dependencies. Runtime Docker builders follow the same sequence using `runtime.txt`, then copy only the runtime prefix into the final nonroot image. The test image installs `development.txt`. Application users, read-only roots, collector private spool ownership, Compose secret handling and network boundaries are unchanged.

`manifest.json` fingerprints the dependency lists, extras, Python lower bounds, build requirements, tool inputs and resolver parameters; it also fingerprints each lock's bytes. `--check` works offline and fails on metadata/lock drift. Normal lint settings and descriptions do not trigger needless dependency changes. Regeneration resolves all files in an isolated directory before replacing working locks; an interrupted copy cannot silently pass the manifest check.

For a reviewed update, install the hash-checked tools into a separate maintenance environment and run:

```sh
python -m pip install --only-binary=:all: --require-hashes -r requirements/tools.txt
python scripts/lock-dependencies.py --upgrade-package PACKAGE
python scripts/lock-dependencies.py --verify
python scripts/lock-dependencies.py --check
```

An ordinary regeneration preserves existing exact versions; `--upgrade-package` deliberately allows only the named package to move subject to metadata constraints. Edit the relevant project dependency first when its bound must change. Review every transitive change and platform marker. Updating uv itself requires updating `UV_VERSION`, `tools.in`, the complete tools lock and the manifest together with fresh regeneration evidence. The generator explicitly uses public PyPI, ignores inherited pip/uv index and override environment variables, disables automatic Python downloads and keeps its cache under ignored `tmp/production-delivery`. See [uv locking](https://docs.astral.sh/uv/pip/compile/) and [universal resolution](https://docs.astral.sh/uv/concepts/resolution/).

## Offline Windows agent

On the actual deployment Python/platform, install the hash-checked `build.txt` tools in a disposable authoring environment and run:

```sh
python scripts/build-agent-wheelhouse.py --output tmp/agent-wheelhouse
```

The output directory must be new. The script downloads only hash-allowed target wheels, builds the local agent with the fixed backend and no dependency/network resolution, records its SHA256 in `local-agent.txt` and `SHA256SUMS.json`, then proves a fresh installation using `--require-hashes --no-index --find-links`. Synthetic batching/import checks run with Python isolated from the source checkout. This is platform-specific: build separate wheelhouses for Windows/Linux and the deployment Python version/architecture; a Windows 3.10 wheelhouse is not a Windows 3.13 wheelhouse.

`Install-AgentWindows.ps1` retains its existing protected-directory/ancestor ACL checks, protected staged-wheel SHA256 verification, and `--no-index --find-links` installation. Provide its `WheelSha256` from the reviewed wheelhouse manifest and deploy only that new wheelhouse, with administrative ownership and no additional/unreviewed wheels. The installer verifies the local agent wheel but does not independently apply `agent.txt` to every dependency: the complete wheelhouse's reviewed hashes and protected content are part of its operator contract. Its native SYSTEM/task/DACL behavior remains covered by the existing Windows gates, rather than inferred from a package-resolution test.

## Images and retained build evidence

`requirements/images.json` records official Python 3.12.15 slim-trixie, Node 22.23.3 Alpine 3.24, nginx-unprivileged 1.30.5 Alpine 3.24, PostgreSQL 16.15 Alpine 3.24, ClickHouse 25.8.33.6 Alpine, Redis 7.4.11 Alpine 3.21 and Prometheus 3.15.0. Python's previously mutable `3.12-slim` alias already resolved to trixie when pinned; the supported Node major and service release lines remain the same. The image inventory also pins Trivy 0.75.0, BuildKit 0.33.1 and the Docker BuildKit Syft scanner 1.12.0. GitHub Actions are pinned to independently verified release commits; Buildx is fixed at 0.37.2.

```sh
python scripts/verify-image-pins.py
python scripts/verify-image-pins.py --registry
```

The registry check fetches only public official Docker registry metadata, verifies both the exact tag and immutable digest against the raw index SHA256, and requires Linux amd64 plus arm64. The offline check rejects mutable/unrecorded `FROM` and Compose image references. For an image update, choose a supported patch tag from its official publisher, resolve and verify the index digest/platforms, update the inventory and every corresponding reference, then run actual Compose and both native architecture builds. Updating a service image does not qualify existing database volumes: retain backups and test PostgreSQL/ClickHouse/Redis restore and migration on copied data before any production rollout. In particular, the earlier ClickHouse 25.x migration is not retroactively proven safe by pinning the current patch.

Mandatory CI builds each API/worker/collector/test/frontend image natively on amd64 and arm64 into an OCI archive, using the pinned BuildKit and SBOM generator. BuildKit adds SPDX SBOM and SLSA provenance attestations. `verify-oci-evidence.py --platform linux/amd64` (or `linux/arm64`) checks every blob SHA256 and every reachable index, manifest, config and layer descriptor for presence, size and media type. The image descriptor and config must match the explicitly selected native platform. Only a linked BuildKit attestation may use `unknown/unknown`; both the current OCI artifact layout with an empty config and the legacy image-config layout are supported. Both attestations must refer to the exact image manifest and statement subject digest. Missing image/config/layer bytes, unlinked statements, duplicate or unsafe archive paths and mismatched subjects fail. Layer hashing streams bytes; JSON documents are bounded to 128MiB (above BuildKit's 80MiB predicate limit), index depth to 16, graph descriptors to 10,000 and archive members to 100,000. OCI archives, evidence summaries and image advisory reports are retained as CI artifacts for seven days. These are build evidence and are not a claim of bit-for-bit binary reproduction. The attestation layout follows [BuildKit's pinned attestation storage contract](https://github.com/moby/buildkit/blob/v0.33.1/docs/attestations/attestation-storage.md) and [SBOM generator protocol](https://docs.docker.com/build/metadata/attestations/sbom/).

On internal pushes to `main`, a separate `signed-image-evidence` job waits for all mandatory jobs, downloads the exact scanned OCI archives, rechecks their evidence/hash, and creates official GitHub/Sigstore SLSA attestations with `actions/attest` 4.2.2 pinned to its release commit. Only this job receives `id-token: write` and `attestations: write`; no persistent signing key, registry image push or release is created. GitHub CLI 2.102.0 is downloaded from its official release and its archive SHA256 is checked against the reviewed publisher checksum before extracting only the regular verifier binary. Verification enforces the artifact digest, repository, signing workflow, source ref/commit and GitHub-hosted runner. The Sigstore bundle and verification result are retained separately. Signing or verification failure fails the internal push; a missing signature is not reported as success.

Pull requests, including external forks, always run OCI evidence, dependency, image and platform gates. They do not run the signing job because their token does not have trusted attestation permissions. Therefore PR artifacts are unsigned and signed evidence becomes available only after a successful internal `main` push. Public GitHub repositories support these [official ephemeral attestations](https://github.com/actions/attest); availability in a private repository depends on its GitHub plan and must be qualified separately.

After downloading a signed archive and its matching bundle, verify with the reviewed CLI, substituting the exact repository, source ref and commit that were accepted:

```sh
gh attestation verify runtime.oci.tar --repo OWNER/REPOSITORY \
  --signer-workflow OWNER/REPOSITORY/.github/workflows/ci.yml \
  --source-ref refs/heads/main --source-digest EXPECTED_COMMIT \
  --deny-self-hosted-runners --bundle sigstore-bundle.json --format json
```

The [official verification command](https://cli.github.com/manual/gh_attestation_verify) validates the signature and identity; a BuildKit JSON predicate alone cannot substitute for it. CI contract tests require commit-pinned actions, a single permission-scoped signing job, successful preceding gates, the exact OCI subject and these verification constraints. Fresh CI execution remains necessary to establish an actual signed attestation; local unit tests do not produce one.

## Mandatory advisory and monitoring gates

The existing backend, offline sensor, frontend, real Windows guards and Compose integration steps remain mandatory. Additional jobs verify reproducible lock regeneration, public registry pins, offline standalone agent installation on all three runner platforms, image evidence and runtime vulnerability gates. Prometheus is checked in its actual container with `promtool check config --lint-fatal` and `check rules --lint-fatal`; deterministic alert fixtures run using the pinned image with no network and read-only mounted monitoring files.

The pinned pip-audit tool queries public package/version advisory metadata for every Python closure, without installing audited dependencies. Coverage must exactly match the names and versions from the hash-checked lock after evaluating every platform marker on the job's actual interpreter; a Windows-only dependency remains required on Windows. Empty reports, skipped packages, duplicates, missing packages and wrong versions fail. Runtime and standalone-agent findings fail for high/critical advisories with published fixes; an available fix with missing or unrecognized severity also fails closed pending review. Public GitHub advisory severity is fetched by advisory ID. The frontend stores both full tooling and runtime npm advisory reports and checks their dependency count against the package lock; the runtime report gates fixable high/critical findings.

`scan-images.py --input ARCHIVE --image api|worker|collector|test|frontend --platform linux/amd64|linux/arm64` uses Trivy's complete `--list-all-pkgs` JSON inventory. Its subject/config digest and native platform must match the verified OCI archive, and its supported OS/Python package inventory must exactly match the separately generated, image-bound BuildKit SPDX SBOM. API/worker/collector additionally require the native runtime lock closure in that SBOM; the test image requires the development closure. Local ShadAI wheels are covered by the image SBOM without querying an unrelated public package of the same name. Frontend images compare installed OS packages; these checks do not claim npm coverage for minified browser bundles. Infrastructure scans include the pinned PostgreSQL, ClickHouse, Redis, Prometheus and node exporter images. Their JSON inventory must exactly match a paired Trivy CycloneDX inventory for the same immutable reference/config digest/platform. That paired inventory is a cross-check from the same scanner, not an independent security assessment. Trivy's [pinned JSON schema](https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/types/report.go) and [package/PURL contract](https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/purl/purl.go) govern these checks, including package epochs.

Fresh scans clear any previous report before invocation and retain a metadata sidecar binding the invocation, command, exact source commit/repository, scanner pin/version, scanner-script hash, input/lock/manifest hashes, report hash and expected inventory. CI passes `--source-commit` and `--repository` explicitly; local execution records the checkout's HEAD and whether source changes are present. A dirty checkout produces local development evidence, which cannot establish an immutable release proof for that HEAD. Previously retained reports without those sidecars can establish their observed advisory contents and shape, but require a fresh bound scan before publication evidence is accepted. All severities and unfixed findings remain visible. Fixable high/critical and unknown-severity image advisories fail, as do scanner/service errors or incomplete coverage. There is no blanket advisory ignore list, forced framework/Node major upgrade, or automatic remediation.

Unfixed/less severe findings remain visible in artifacts and require an explicit operational decision; passing a gate is time-specific advisory evidence, not absence of all vulnerabilities. The existing embedded `braces` 3.0.3 residual in frontend build-tool bundles remains an explicit exception requiring the established literal-path/watch restrictions and separate review. A zero named-package npm audit does not prove those bundled bytes were removed, and these gates do not erase that residual.

Before accepting a dependency/image update, run normal Ruff/backend tests, clean frontend tests/build, native Windows guards, full Compose startup/smokes, offline agent checks, both architecture image builds and all new security/evidence gates at the exact reviewed commit. Local static/unit evidence cannot replace daemon-backed builds, real-store behavior or platform-native qualification.
