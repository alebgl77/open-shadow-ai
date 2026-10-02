# Contributing to Open Shadow AI

Start with a small issue describing the user problem, available evidence and acceptance criteria. Use synthetic data throughout examples, tests and screenshots.

## Development

```bash
python -m venv .venv
# Activate the environment using your platform's normal command.
python -m pip install ".[dev]" ./agent
python -m pytest -q
python scripts/verify-deployment.py
cd frontend
npm ci
npm run build
```

Python 3.12 and 3.13 are CI targets. The interface uses Node 22 in CI. The optional integration test requires disposable PostgreSQL, Redis and ClickHouse: run `docker compose --profile test run --build --rm integration-test` after bootstrap. Never point this test at production.

## Collector changes

Document exact observed fields and permissions. Include positive, negative, malformed and duplicate fixtures. Distinguish installed/inventory from observed usage, and measured from estimated cost. Preserve event IDs on retries. Do not broaden collection of personal data without an explicit design discussion.

## Catalog changes

Edit `catalog/builtin/*.yaml` directly; `scripts/generate_catalog.py` is a historical bootstrap and would overwrite reviewed entries. An exact signature (domain, process, extension ID, OAuth application ID, local port, container pattern) must belong to a single entry, because the evidence cannot choose between two owners; CI rejects duplicates. Put an API host in the API or platform entry, not in the consumer application that may call it. URL patterns apply only on a host: `/path` on the entry's own domains, `host/path` on that host (use the latter for a product that shares its vendor's domain, such as `huggingface.co/chat`). User-agent patterns corroborate the entry's domains; an entry without domains, such as a CLI, is identified by its user agent on any host. Paths and user agents are evaluated at ingestion and then discarded, so a pattern must identify the product from the path or client name alone.

## Pull requests

Explain the concrete before/after behavior, validation commands and remaining operational gaps. Keep unrelated refactoring separate. Update adjacent docs whenever the API, configuration or deployment changes. Avoid unsupported benchmarks, certifications and comparative claims.

## License and provenance

Contributions are provided under Apache-2.0. Confirm that you have the right to contribute all code, datasets and assets. Do not copy commercial catalogs or product screenshots. See SECURITY.md for private vulnerability reporting.
