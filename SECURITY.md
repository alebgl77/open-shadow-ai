# Security policy

Open Shadow AI is early-stage software for evaluation and controlled pilots. It currently supports one organization per installation. Event tenant identifiers do not establish multi-tenant isolation.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/alebgl77/open-shadow-ai/security/advisories/new) when enabled. If the private form is unavailable, request a private contact channel from the maintainer without including exploit details or sensitive data in a public issue. Do not post credentials, internal URLs, personal identifiers or production logs.

Include the affected commit, a minimal synthetic reproduction, impact and any suggested mitigation. No response-time SLA or bug bounty is currently offered.

## Deployment responsibilities

Use TLS for remote collectors, restrict access to stores and the Docker host, generate strong secrets and keep them out of Git. The collector API key is shared within an installation; per-device enrollment and automatic key rotation are future work. Limit distribution and rotate after suspected disclosure.

Treat directory exports and telemetry as sensitive. Minimize retained fields, document collection and review access. Test restore procedures with the matching encryption key. Review dependency and image updates before deployment; no signed release or certification is implied.

## Console identity

OIDC and SCIM are optional and disabled by default. Use a tenant-specific HTTPS issuer and the exact public console origin. SCIM provisions console users; it does not establish identity joins with collected employees or devices. A verified stable OIDC claim must match a pre-provisioned immutable SCIM `externalId`; email-based linking and just-in-time account creation are not supported.

Protect the SCIM bearer token as an administrative credential: its holder can provision accounts and group membership. Use at least 32 random bytes, independently of the collector key, JWT key and OIDC client secret. Map roles only from reviewed immutable group external IDs. Retain and test a separate local administrator for recovery; external accounts cannot sign in with a local password or have their managed access overridden through the local user administration API.

Provisioning changes invalidate affected sessions when received by the application. Directory synchronization delays remain outside its control. MFA and Conditional Access are enforced by the identity provider; the application does not independently enforce an MFA claim. Signing out of the console does not end the identity-provider session.

Never log authorization codes, bearer tokens, cookies or client secrets. The bundled nginx omits query strings/referrers, suppresses callback error logs, and the API image disables raw access logs. Apply equivalent controls at ingress, load balancers and tracing systems. Keep TLS verification enabled. See the [identity operations guide](docs/sso-scim.md) for configuration, rotation and validation boundaries.

## Supported versions

Security fixes target the current development branch. Older tags have no support commitment. Review the exact commit and CI result before deployment.
