# Security policy

Open Shadow AI is early-stage software for evaluation and controlled pilots. It currently supports one organization per installation. Event tenant identifiers do not establish multi-tenant isolation.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/alebgl77/open-shadow-ai/security/advisories/new) when enabled. If the private form is unavailable, request a private contact channel from the maintainer without including exploit details or sensitive data in a public issue. Do not post credentials, internal URLs, personal identifiers or production logs.

Include the affected commit, a minimal synthetic reproduction, impact and any suggested mitigation. No response-time SLA or bug bounty is currently offered.

## Deployment responsibilities

Use TLS for remote collectors, restrict access to stores and the Docker host, generate strong secrets and keep them out of Git. The collector API key is shared within an installation; per-device enrollment and automatic key rotation are future work. Limit distribution and rotate after suspected disclosure.

Treat directory exports and telemetry as sensitive. Minimize retained fields, document collection and review access. Test restore procedures with the matching encryption key. Review dependency and image updates before deployment; no signed release or certification is implied.

## Supported versions

Security fixes target the current development branch. Older tags have no support commitment. Review the exact commit and CI result before deployment.
