# Changelog

## Unreleased

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
