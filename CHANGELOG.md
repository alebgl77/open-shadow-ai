# Changelog

## Unreleased

- Writes commit before the API responds (FastAPI function-scoped sessions, FastAPI 0.121 or later). A failed commit, for example when deactivating an account, now returns an error instead of a success for a change that was never stored.
- Windows agent installer: the install directory must not exist and is created with a protected ACL, then every installed file is reset to Administrators ownership and re-checked; the Python home, the wheelhouse and their parent directories must not be writable or replaceable by non-administrative principals; the agent wheel is hashed on a protected copy.
- FortiGate timestamps use `eventtime` or the `tz` offset, and every syslog listener accepts a `timezone` for device-local clocks. Recent events from UTC+ devices are no longer rejected as future-dated, and one rejected line no longer drops its neighbours or the TCP connection (`shadai_events_rejected_total`). PAN-OS year-less syslog timestamps get the correct year.
- Catalog attribution no longer depends on catalog load order: shared signatures keep every owner, the most specific pattern wins, then corroboration, then the catalog ID. Domains duplicated between platform and chat entries now belong to the platform entry (`api.cohere.com`, `generativelanguage.googleapis.com`, `huggingface.co`, `api.together.xyz`); HuggingChat cannot be distinguished from Hugging Face by domain. CI rejects an exact signature claimed by two built-in entries.
- The endpoint agent splits large snapshots into batches within API limits, brings each record within the API field limits, collapses identical process observations and stops retrying client errors.
- Discoveries can be sorted by impacted users or devices, which the identity page requires; the demo adapter now rejects the sort columns the API rejects.
- Detection exports apply every discovery filter and sort, and record the filters in the audit entry.
- SCIM profile updates and changes to groups that grant no role no longer end sessions; deactivation, deletion and role reductions still do. Console sign-out now revokes the token on the server, and opening `/demo` while signed in asks before ending the workspace session.
- ClickHouse native TLS with certificate verification, private CA, mutual TLS and SNI settings; the Kubernetes baseline uses it by default on port 9440.

## 0.2.0 preview — 2026-09-27

- Optional OIDC authorization-code sign-in with PKCE S256 for pre-provisioned console users. The verified issuer and stable identity claim must match the immutable SCIM `externalId`; email does not link accounts.
- SCIM 2.0 Users/Groups subset, role mapping by group external ID and affected-session revocation when provisioning changes arrive. Reactivation does not revive old sessions.
- Microsoft Entra ID setup guide and optional Compose/Kubernetes identity overlays. Identity features remain disabled in the base configuration; local administrator recovery access remains available.
- Query-free proxy access logs and disabled callback error logs to keep OAuth codes out of bundled deployment logs.
- PostgreSQL migration `003` adds external identities and revocation state. Back up data, configuration and keys, stop application writes and complete the migration before starting the new API/workers. Review the [upgrade procedure](docs/deployment.md#updates), including username-collision checks and guarded downgrade behavior.

See the [identity setup and supported subset](docs/sso-scim.md) and [validation scope](docs/validation.md). Test a separate local recovery administrator before enabling SSO. Live Entra sign-in/provisioning, other providers and Kubernetes require operational acceptance. This preview supports one organization per deployment; SAML, multi-organization isolation and identity-provider certification are not included.

## 0.1.0 — 2026-09-27

Initial public development package for Open Shadow AI.

- Evidence-oriented inventory and discovery workflow.
- Authenticated ingestion, catalog synchronization and retryable queue processing.
- Microsoft Entra inventory collector and OU-scoped Active Directory export.
- Docker Compose baseline, external-store Kubernetes manifests and CI checks.
- English/French documentation, architecture diagrams and coverage guidance.

Docker/Kubernetes deployment, live directories and managed-fleet rollout require operational verification. This entry describes the initial development package; it is not a claim of a production release.
