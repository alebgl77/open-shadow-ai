<a id="admission-du-démarrage-sso"></a>
# SSO login-start admission

When OIDC is enabled, `GET /api/v1/auth/sso/login` requires atomic Redis admission before creating login state or contacting the provider. Replicas of the same installation must share Redis, `tenant_id` and the settings below. Disabled OIDC returns `404` without accessing Redis.

| Variable | Default | Bounds |
|---|---:|---|
| `OIDC_LOGIN_PEER_LIMIT` | 10 per minute | 1–1,000 |
| `OIDC_LOGIN_INSTALLATION_LIMIT` | 120 per minute | 1–10,000, at least the peer quota |
| `OIDC_LOGIN_CONCURRENCY` | 4 | 1–64 |
| `OIDC_LOGIN_TIMEOUT_SECONDS` | 12 s | 1–30 s |
| `OIDC_LOGIN_LEASE_SECONDS` | 15 s | At least the total deadline + 3 s; maximum 60 s |

Minutes are fixed windows defined by `Redis TIME`, shared by replicas. Admission consumes quotas permanently, even if the provider fails or the request is cancelled. Refusals create no peer counter, lease or OIDC state and trigger no provider discovery. A reached quota or saturated concurrency returns generic `429`, `Retry-After` between 1 and 60 seconds, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Unavailable Redis, corrupted types/values and memory refusal return `503` before state and provider access. Provider errors retain the `303` redirect to fixed `/login?sso_error=failed`, without provider details.

The peer is exclusively the normalized IP address of `request.client.host`. A missing or invalid address enters the constant `unknown` bucket. Admission code reads neither `Forwarded` nor `X-Forwarded-For`. Uvicorn or another server may determine this ASGI value at its trust boundary: when proxy headers are enabled, allow only explicitly trusted proxies and make ingress overwrite received headers. Use `--no-proxy-headers` when the strict transport peer is required; all clients behind the same proxy may then share its quota.

Each installation uses exactly three fixed keys under `oidc:admission:<SHA-256 of tenant_id>`: a minute/count `meta` hash, a `peers` hash of counters indexed by the peer's SHA-256, and a `leases` sorted set of server-generated random tokens. The installation quota bounds peer fields; concurrency bounds active leases. Lua validates all types and numeric ranges before its first write. That write charges the fixed installation counter; no peer allocation precedes it. Hashes expire after 120 s and the lease key expires after lease duration + 1 s. No secret or browser identifier appears in these keys.

The monotonic budget begins before admission and includes Redis wait, state creation and all discovery, including a slowly progressing response. Each step uses only the remaining time. Failure or cancellation deletes only state whose successful storage was acknowledged and whose browser binding still matches; it releases only its own lease. The two cleanup operations are independent, cancellation-protected and each bounded to 2 s, in parallel; they can therefore add up to 2 s to response time. Successful completion retains browser state and releases the lease.

If Redis is offline, a storage acknowledgement is lost, cleanup times out or the process stops, TTLs provide fallback; immediate deletion is not guaranteed. State remains valid for at most 300 s as before. The lease bounds cooperative application activity, not remote provider work already started before the process died. This protection covers SSO startup; it does not replace general network protection. No discovery cache is added.

`tests/test_sso_admission.py` covers the atomic model and HTTP contracts; `tests/test_oidc.py` retains signed flows, PKCE, nonce, cookies, duplicates and CSRF. `tests/test_sso_admission_integration.py` exercises real Lua on two independent connections, 50 concurrent calls, quotas, leases, corruption, outages, memory refusal, deadline, cancellation and expiry. The existing Compose job collects it with `SHADAI_INTEGRATION=1`; without that flag it explicitly skips. Docker was stopped on this change's local host, so these real Redis cases must pass CI before acceptance. Actual proxy/provider qualification, sizing and target-environment validation remain required.
