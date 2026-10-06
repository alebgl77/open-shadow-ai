<p align="center"><img src="docs/assets/brand-mark.svg" width="72" alt="Open Shadow AI mark"></p>

# Open Shadow AI

[![CI](https://github.com/alebgl77/open-shadow-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/alebgl77/open-shadow-ai/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)


**Self-hosted AI discovery, with evidence behind every finding.**

Understand which AI services and tools appear in your environment, where each signal came from, and what it can actually prove. Bring together network metadata, endpoint inventory and Microsoft directory signals in an interface built for investigation.

[Get started](#get-started) · [Deployment](docs/deployment.md) · [Collector operations](docs/collector-operations.md) · [Microsoft & Active Directory](docs/microsoft.md) · [SSO & SCIM](docs/sso-scim.md) · [Architecture](docs/architecture.md) · [Français](README.fr.md)

> Early-stage software for evaluation and controlled pilots. One organization per deployment. Docker, Kubernetes and live Microsoft environments require operational validation in your environment; no certification or production SLA is claimed.

![Open Shadow AI investigation dashboard with synthetic demo data](docs/assets/dashboard-desktop.webp)

## Why this project

- **Evidence you can inspect.** Distinguish network observations, installed assets, directory inventory and instrumented usage.
- **Infrastructure you control.** Self-host the API, queue, event store and interface.
- **Progressive adoption.** Start with one log source or a small managed-device pilot.
- **An open catalog.** Review and contribute the signatures behind classifications.
- **Honest gaps.** A missing signal remains unknown; a DNS request is not a prompt or a bill.

## Try the interface

Prerequisite: **Node.js 22.22.2+ (22.x)**. Launch the isolated interface demo:

```bash
cd frontend
npm ci
npm run demo
```

Open the `/demo` route at the local address printed by the development server. This is a synthetic demo session: it needs no backend credentials and does not connect to your directories or fleet. To continue with the full installation, stop the demo server and run `cd ..` first.

## Get started

Prerequisites: Git, Python 3.12+ and a working Docker Engine with Compose v2. No Docker runtime is bundled. The initial interface binds to localhost over HTTP; remote agents require an HTTPS reverse proxy.

```bash
git clone https://github.com/alebgl77/open-shadow-ai.git
cd open-shadow-ai
bash scripts/bootstrap.sh
docker compose config --quiet
docker compose up -d --build
docker compose run --rm api python -m shadai.cli create-admin
```

On Windows, use `./scripts/bootstrap.ps1` in place of the Bash bootstrap. Both preserve existing secrets and configuration. Use `-DryRun` or `--dry-run` to preview.

Open [localhost:3000](http://localhost:3000). PostgreSQL migrations run in the `migrate` service before the API starts; both ClickHouse schema files load on a fresh event-store volume. [Updating an existing installation](docs/deployment.md#updates) requires a separate ClickHouse migration.

Enabling collectors is deliberate:

```bash
docker compose --profile syslog up -d
# After configuring Entra IDs and its separately provisioned client-secret file:
docker compose --profile entra up -d
```

AD exports and endpoint installs are operator-run workflows, documented in the [Microsoft guide](docs/microsoft.md). Installing the server does not automatically scan the fleet.

Administrators can enroll scoped collectors in **Sources & coverage**, provision their one-time keys privately and rotate or revoke them. Endpoint, network and syslog collectors have bounded persistent delivery queues; pipeline status separates pending work, retained entries and unknown capture loss. Follow the [operations guide](docs/collector-operations.md) for enrollment, restart recovery, authenticated monitoring and identity retention.

Optional [OIDC sign-in and SCIM provisioning](docs/sso-scim.md) manage access to the console, including Microsoft Entra ID. They are disabled in the base deployment and use separate credentials from the inventory collector. Local administrator sign-in remains available for recovery.

## What is delivered

| Capability | Status and practical boundary |
|---|---|
| React investigation interface, catalog and governance workflow | Implemented; evaluate with your data |
| DNS/proxy parsers and syslog collector | Implemented; parser and listener must match the source |
| [Passive network analysis](docs/network-analysis.md) | Zeek/Suricata/TShark metadata imports, optional offline PCAP or explicit live sensor, and `/network` evidence view; observed names do not prove AI requests |
| Endpoint agent | Implemented process/container/runtime/extension inventory; OS and fleet rollout verification pending |
| Microsoft Entra collector | Implemented service-principal inventory and optional grants; AI matching requires reviewed application-ID mappings; live tenant validation pending |
| On-prem Active Directory | OU-scoped read-only PowerShell exporter; RSAT/live AD validation pending |
| Generic event ingestion | Authenticated, bounded batches; custom adapters remain your integration work |
| Collector enrollment and recovery | Scoped one-time credentials, rotation/revocation, bounded local spools and explicit dead-letter replay; native/store CI results must be checked for the deployed commit |
| Model/token/cost evidence | Accepts instrumented metadata where supplied; network logs cannot produce these values |
| Other directories (LDAP, Okta, Google Workspace) | Custom ingestion contract available; native connectors planned |
| Docker Compose | Deployment package and CI service smoke provided; validate the first run |
| Kubernetes | Baseline for external stores; cluster, ingress, backup and scaling validation pending |
| OIDC SSO and SCIM 2.0 console provisioning | Implemented optional subset with Entra setup guide; live tenant interoperability validation pending |
| Isolated multi-tenancy, automated fleet management | Planned; one organization per install today |
| Inline blocking, prompt DLP, full behavioral analysis | Outside the current product |

## Architecture

![Open Shadow AI architecture](docs/assets/architecture.svg)

[Editable draw.io diagram](docs/assets/architecture.drawio) · [Mermaid and data flow](docs/architecture.md)

The Python package and environment variable prefix remain `shadai` for compatibility. The public project name is **Open Shadow AI**.

## Evidence, privacy and limits

The default configuration never stores URL paths, query strings or user agents. At ingestion, paths (without their query string) and user agents are compared in memory with catalog patterns scoped to each product's hosts; only the matched catalog entry is kept. Set `privacy.match_transient_signals: false` to skip that comparison. Treat usernames, device identifiers and directory exports as personal or organizational data. Set retention and access according to your deployment.

Per-observation identity membership expires independently (default at most 30 days); displayed counts are distinct observed identifiers, not staff headcount. Optional server pseudonymization affects new processing and does not scrub history or plaintext local spools. Risk scores retain their last calculated snapshot and expose a nullable calculation time and stale marker. Historical cleanup is an explicit bounded maintenance operation; see [identity retention and pseudonymization](docs/collector-operations.md#retain-and-pseudonymize-identities).

DNS resolution indicates contact with a domain, not a completed AI interaction. An installed extension or directory application indicates presence or permission, not usage. Model identifiers are declared evidence; token totals and costs require instrumentation. Cost calculations remain estimates unless reconciled against provider billing.

Unmanaged devices, unobserved encrypted DNS, local tools, shared domains, embedded SaaS AI and gateway bypasses can leave gaps. See the [coverage guide](docs/collectors.md) and [market analysis](docs/market-analysis.md).

## Contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md), submit a small reproducible change and include synthetic fixtures for collectors. Report vulnerabilities privately using [SECURITY.md](SECURITY.md).

Licensed under [Apache-2.0](LICENSE). Copyright Open Shadow AI contributors.

For sizing and rollout, see [capacity planning](docs/capacity.md). Throughput claims require measurements on your workload.
