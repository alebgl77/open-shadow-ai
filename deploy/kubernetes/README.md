# Kubernetes baseline: external stores

This is a starting configuration, not a tested production distribution. It assumes a NetworkPolicy-capable CNI, external PostgreSQL/Redis/ClickHouse, private connectivity, and an ingress controller with an existing trusted TLS certificate. It does not deploy databases, operators or certificate issuance.

## Prepare

Build and push the API, worker and frontend Dockerfiles to your approved registry. No prebuilt image release is assumed. In your overlay, replace the `open-shadow-ai-api`, `open-shadow-ai-worker` and `open-shadow-ai-frontend` images with immutable registry digests. Update the migration job image too.

Create the namespace, then provision Secret `open-shadow-ai-runtime` through your secret-management system. Its required keys are:
`DATABASE_URL` (SQLAlchemy asyncpg URL), `REDIS_URL`, `CLICKHOUSE_HOST`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `JWT_SECRET`, `ENCRYPTION_KEY` (Fernet), and `AGENT_API_KEY`. Do not commit the Secret or pass values in shell history. The manifests reference an existing Secret and contain none.

The deployment is one organization. Set `SHADAI_TENANT_ID` in the ConfigMap. External store credentials must be dedicated to it. Use private encrypted connectivity appropriate to your infrastructure; verify driver TLS configuration instead of assuming port numbers enable TLS.

## Network and migrations

Replace TEST-NET CIDR `192.0.2.0/24` in `external-stores` with the actual database CIDRs and ports. It intentionally grants no usable production route by default. Adapt the DNS and ingress-controller namespace selectors to your cluster. These policies apply only if the CNI enforces them.

Apply the two ClickHouse schema files to the external database using its administration process, in order. Provision the PostgreSQL database/user, then run the migration Job:

```bash
kubectl apply -f deploy/kubernetes/base/namespace.yaml
# Provision the runtime Secret using your existing secret manager.
kubectl apply -f deploy/kubernetes/migrate.yaml
kubectl -n open-shadow-ai wait --for=condition=complete job/open-shadow-ai-migrate --timeout=180s
kubectl apply -k deploy/kubernetes/base
```

Use an overlay to set real images and database routes before running the commands. On subsequent releases use a uniquely named migration Job or replace the completed one under change control. The base starts one replica of each worker. Do not increase replicas until load, pending-event recovery and concurrent correlation have been tested.

## Ingress

Copy `ingress.example.yaml` into your private overlay and replace the hostname, ingress class and TLS Secret reference. Apply only after valid TLS and access policies exist. The frontend proxies `/api/` to the API. HTTP ports are internal; a YAML `tls` field alone does not issue a certificate.

## Optional OIDC/SCIM console access

The `sso/` overlay adds identity configuration only to the API. The base remains disabled. Before using it, replace its documentation-only tenant/client IDs, public origin, group role map and IdP egress CIDR in your private deployment configuration. Preserve your real image digests and database network rules from the base deployment procedure.

Provision an additional Secret named `open-shadow-ai-identity` in the application namespace with keys `OIDC_CLIENT_SECRET` and `SCIM_BEARER_TOKEN`, using your secret manager. The separate ConfigMap has the same name and contains only non-secret settings. The token must contain at least 32 random bytes and be independent of the runtime and collector credentials. Do not commit a Secret manifest. Existing runtime Secret requirements are unchanged.

The API needs HTTPS egress for OIDC discovery, token exchange and signing keys. Standard NetworkPolicy cannot allow hostnames: adapt `identity-egress.yaml` to approved provider routes or your CNI's FQDN policy. Its TEST-NET CIDR intentionally grants no working IdP route. No new inbound port is required; the existing frontend/ingress path serves SCIM. Configure ingress logs and tracing to exclude callback query strings and sensitive headers. See the [identity guide](../../docs/sso-scim.md) for exact URLs and Entra mappings.

```bash
kubectl kustomize deploy/kubernetes/sso > rendered-sso.yaml
kubectl apply --dry-run=server -k deploy/kubernetes/sso
```

Apply the prepared overlay only after the PostgreSQL migration Job completes. This is an example requiring cluster and identity-provider validation, not a tested production overlay.

## Validation

```bash
kubectl kustomize deploy/kubernetes/base > rendered.yaml
kubectl apply --dry-run=server -k deploy/kubernetes/base
kubectl -n open-shadow-ai get pods
kubectl -n open-shadow-ai rollout status deployment/api
```

API readiness checks database connections. Worker readiness checks Redis reachability; its process probe is not proof of processing progress. Alert on queue backlog, dead-letter entries and stale collectors separately. Check PVC/database recovery, resource pressure, disruption and restore behavior. No live cluster validation has been performed as part of this package.
