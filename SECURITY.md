# Security policy

Open Shadow AI is early-stage software for evaluation and controlled pilots. It currently supports one organization per installation. Event tenant identifiers do not establish multi-tenant isolation.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/alebgl77/open-shadow-ai/security/advisories/new) when enabled. If the private form is unavailable, request a private contact channel from the maintainer without including exploit details or sensitive data in a public issue. Do not post credentials, internal URLs, personal identifiers or production logs.

Include the affected commit, a minimal synthetic reproduction, impact and any suggested mitigation. No response-time SLA or bug bounty is currently offered.

## Deployment responsibilities

Use TLS for remote collectors, restrict access to stores and the Docker host, generate strong secrets and keep them out of Git. Administrators enroll immutable collector identities with source scopes and receive a credential once after commit; only its secret digest is stored. Rotate credentials within the same collector with bounded overlap, or permanently revoke the collector and all its keys. Provision private key files through an approved management channel. The shared key remains enabled for compatibility; disable `ALLOW_LEGACY_AGENT_KEY` after scoped enrollment and verification. Legacy traffic is `legacy:unattributed` and cannot claim an enrolled heartbeat. See [collector operations](docs/collector-operations.md).

Treat directory exports and telemetry as sensitive. Minimize retained fields, document collection and review access. Test restore procedures with the matching encryption key. Review dependency and image updates before deployment; no signed release or certification is implied.

Endpoint/network/syslog queues contain plaintext metadata on client disks and backups. Their private file/ancestor ownership and permission checks reject unsafe paths, symlinks, reparse points and hardlinks. Keep persistent storage private under the actual service identity; do not broaden permissions to work around a refusal. Queue limits, transport losses, expiry and storage failures bound recovery; no UDP or universal capture-loss guarantee is made.

Identity membership expires per observation. Optional `PSEUDONYMIZE_IDENTITIES` uses field-separated HMAC pseudonyms from the existing encryption key and clears personal source IP/free-form identity-provider text while retaining operational metadata. Pseudonyms are linkable data. Enabling it does not erase history, backups or client spools; the explicit historical scrub requires quiescence, bounded synchronous mutations and verified completion. Console accounts, notes and audit actors are excluded. Master-key changes require matching backup keys and an identity reconstruction plan.

`/metrics` requires an administrator console identity or a separate optional `METRICS_API_KEY[_FILE]` read-only bearer token of at least 32 characters. Agent keys are not accepted. Restrict scraper routes and keep tokens out of logs; use a private `bearer_token_file`, not public scraping.

## Console identity

OIDC and SCIM are optional and disabled by default. Use a tenant-specific HTTPS issuer and the exact public console origin. SCIM provisions console users; it does not establish identity joins with collected employees or devices. A verified stable OIDC claim must match a pre-provisioned immutable SCIM `externalId`; email-based linking and just-in-time account creation are not supported.

Protect the SCIM bearer token as an administrative credential: its holder can provision accounts and group membership. Use at least 32 random bytes, independently of the collector key, JWT key and OIDC client secret. Map roles only from reviewed immutable group external IDs. Retain and test a separate local administrator for recovery; external accounts cannot sign in with a local password or have their managed access overridden through the local user administration API.

Deprovisioning, deactivation and role reductions invalidate affected sessions when received by the application; profile synchronization does not. Directory synchronization delays remain outside its control. MFA and Conditional Access are enforced by the identity provider; the application does not independently enforce an MFA claim. Signing out of the console does not end the identity-provider session.

Console sessions use an HttpOnly, SameSite=Strict cookie that scripts cannot read; it is `__Host-` prefixed and Secure on every host except loopback (`SESSION_COOKIE_SECURE` overrides the choice). Cookie-authenticated writes must carry the session's `X-CSRF-Token`; API clients keep using bearer tokens without cookies. Signing out revokes the token on the server and deletes the cookie.

Never log authorization codes, bearer tokens, cookies or client secrets. The bundled nginx omits query strings/referrers, suppresses callback error logs, and the API image disables raw access logs. Apply equivalent controls at ingress, load balancers and tracing systems. Keep TLS verification enabled. See the [identity operations guide](docs/sso-scim.md) for configuration, rotation and validation boundaries.

## Frontend dependency maintenance

The earlier 2026-10-06 dependency repair resolved `source-map-js` to `1.2.2` for [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q) and `postcss-selector-parser` to `7.1.6` for [GHSA-rj75-hqrm-r3gf](https://github.com/advisories/GHSA-rj75-hqrm-r3gf), while retaining the original direct dependency versions.

At that revision, Tailwind CSS `3.4.19` and `postcss-nested` `6.2.0` requested parser version 6. Scoped npm overrides covered both parents. Its 96-test suite, clean installation, build and lint passed, and generated CSS remained byte-identical to its 28,800-byte baseline. Those results describe the earlier revision.

The current follow-up replaces Tailwind 3's PostCSS pipeline with Tailwind CSS and `@tailwindcss/vite` `4.3.3`, and resolves Vite to its maintained `6.4.4` patch. The obsolete parser overrides, direct PostCSS/autoprefixer dependencies and PostCSS configuration are removed. All currently installed `source-map-js` paths remain at `1.2.2`. The named npm dependency nodes `braces`, `chokidar`, `micromatch`, `fast-glob`, `postcss-nested` and `postcss-selector-parser` are absent from the regenerated lockfile and installed tree.

The [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) still lists no patched release for affected versions through `3.0.3`. Removing named npm nodes does **not** remove bundled affected code: the installed Vite bundle contains one copy, and Rollup contains two copies in its CommonJS and ESM bundles. The application now enforces literal path watching before Vite constructs its dev/build watchers, including resolved environment build options, with protected references and `disableGlobbing: true`. This blocks the identified chokidar brace-expansion route; it does not patch those bundled parsers or sandbox trusted plugins.

The earlier audit of the regenerated dependency graph, saved at `2026-10-06T11:49:12Z`, reported zero known findings. A fresh final audit is pending: sandbox DNS prevented registry access and automatic approval review rejected the external audit request because it discloses dependency metadata. Local tree/inventory checks, author tests and independent reviews have separate scopes and status in [validation](docs/validation.md). No complete security clearance or current final clean-audit claim is implied.

The frontend nginx runtime image copies only production `dist` assets from the builder. The residual bundled Node parser concerns development/build tooling; these checks do not establish a public runtime exploitation path. Review source/pattern and plugin trust. See [frontend build security](docs/frontend-build-security.md) for guard limits, browser requirements and repeatable checks.

## Supported versions

Security fixes target the current development branch. Older tags have no support commitment. Review the exact commit and CI result before deployment.
