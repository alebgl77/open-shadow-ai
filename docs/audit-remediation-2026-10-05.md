# Audit remediation — 5 October 2026

This records the disposition of findings A01–A17 from the 27 September audit of
`043a537`. The remediation work starts from `9b66def`, which already contains six
of the corrections. The remaining eleven findings are addressed by this change
set. Implementation status and validation evidence are distinguished below;
CI for the final revision is pending.

## Findings and regression evidence

| Finding | Disposition | Correction and source | Evidence and limits |
|---|---|---|---|
| A01 — transaction success before commit | Already implemented upstream | Database dependencies use `scope="function"` so commit failures precede HTTP success. See [database](../src/shadai/database.py) and [API routes](../src/shadai/api/). | [Security tests](../tests/test_security.py) check dependency scopes and a failed deactivation commit; the new [note tests](../tests/test_detection_remediation.py) also verify durable rollback and HTTP failure. |
| A02 — unsafe existing Windows paths | Residual bootstrap correction in this change set | [Windows protection helper](../scripts/Protect-BootstrapWindows.ps1) validates owners, ACLs, ancestors and reparse points before [Python bootstrap](../scripts/bootstrap.py) writes secrets. New secret directories have a protected ACL. The hardened [agent installer](../scripts/Install-AgentWindows.ps1) is retained. | [Windows harness](../scripts/test-bootstrap-security.ps1) `-BoundaryOnly` passed on PowerShell 7 and Windows PowerShell 5.1: adverse explicit ACEs, owner classification, junctions and dangerous ancestor rights. The complete generation/repeat-run harness is pending in [CI](../.github/workflows/ci.yml); local workspace ancestors contain untrusted sandbox grants. |
| A03 — FortiGate timezone loss | Already implemented upstream | [FortiGate parser](../src/shadai/parsers/proxy/fortigate.py) respects device offsets/epoch values and configured source zones. | [Parser tests](../tests/test_parsers.py) cover epoch precision, `+0100`, contemporary `+0200`, seasonal Paris offsets and ingestion acceptance. |
| A04 — oversized agent snapshot | Already implemented upstream | [Agent batching](../agent/shadai_agent/main.py) bounds each request and normalizes individual records before submission. | [Agent tests](../tests/test_agent.py) validate mixed snapshots containing 1,800 processes and 700 extensions against the API schema, preserving records across batches, plus empty/duplicate/error cases. |
| A05 — arbitrary catalogue attribution | Corrected in this change set | [Matcher](../src/shadai/engine/matcher.py) explicitly reports unresolved ties. [Ingestion](../src/shadai/api/ingestion.py) and [worker](../src/shadai/workers/ingest.py) preserve the ambiguity decision after sensitive transient signals are removed. Ambiguous events remain stored without creating an attributed detection. | [Evidence regressions](../tests/test_evidence_remediation.py) and [catalogue tests](../tests/test_catalog_dashboard.py) cover order independence, discriminating evidence and no weaker fallback. Already removed URL/user-agent values cannot be recovered by a later catalogue update. |
| A06 — stronger evidence ignored | Corrected in this change set | [Correlator](../src/shadai/engine/correlator.py) retains the strongest base confidence and corresponding matched field for each source. | [Evidence regressions](../tests/test_evidence_remediation.py) cover weak/strong arrival orders and repeated signals. Existing volume and multiple-source bonuses remain separate. |
| A07 — Squid username discarded | Corrected in this change set | [Squid parser](../src/shadai/parsers/proxy/squid.py) retains the native authenticated username, treats `-` as absent and rejects incomplete native records. | [Evidence regressions](../tests/test_evidence_remediation.py) cover names, absence and malformed input without inferring identity from IP. This revision has no built-in pseudonymization mode; [collector guidance](collectors.md) describes upstream transformation. |
| A08 — shared login quota behind nginx | Corrected in this change set | [Compose](../docker-compose.yml) assigns a dedicated frontend address trusted by the API; [Uvicorn startup](../docker/Dockerfile.api) enables proxy headers and [nginx](../frontend/nginx.conf) overwrites the forwarded client address. | [Proxy tests](../tests/test_proxy_rate_limit.py) exercise the real Uvicorn middleware and login limiter: separate clients, one abusive client, and forged headers from untrusted peers. [Deployment guidance](deployment.md) covers additional TLS proxies and NAT limitations. |
| A09 — note lacks audit entry | Corrected in this change set | [Note route](../src/shadai/api/detections.py) locks the detection with `FOR UPDATE` before appending, and writes the same `update_detection` audit action as PATCH, with actor, detection, IP and `note_added: true`; note text is excluded. | [Detection regressions](../tests/test_detection_remediation.py) verify locked SQL, one committed audit and SQLite rollback of both records after audit/commit failure. A new [PostgreSQL integration](../tests/test_integration.py) observes the row-lock wait during two concurrent HTTP writes and checks preservation of both notes/audits; its CI execution is pending. |
| A10 — ClickHouse TLS unavailable | Already implemented upstream | [Configuration](../src/shadai/config.py) and [client factory](../src/shadai/database.py) expose TLS, certificate verification, CA/client certificate and hostname settings. | [Runtime tests](../tests/test_runtime_retention.py) inspect verified TLS options and reject inconsistent configuration. These tests do not establish a successful handshake or certificate rejection against a real remote ClickHouse server. |
| A11 — blocking event reads | Corrected in this change set | Both native event queries in [the detection route](../src/shadai/api/detections.py) use `asyncio.to_thread`, retaining the existing serialized client and driver timeouts. | [Detection regressions](../tests/test_detection_remediation.py) block each query in turn while another coroutine progresses; concurrent callers remain serialized. Parameters, HTTP date/UUID serialization, 404 and query-error behavior are checked. |
| A12 — legacy migration order | Corrected procedure in this change set | [Deployment instructions](deployment.md) stop writers, start stores, apply ClickHouse `002` using `exec`, then run API initialization with `--no-deps` before starting applications. | The procedure avoids waiting on the new `identity_sid` health probe before adding that column. A disposable pre-002 volume and interrupted-upgrade exercise remain pending. This condition does not apply to every 0.1 installation: published 0.1 already includes `002`. |
| A13 — redirected agent credentials | Corrected in this change set | [Agent submission](../agent/shadai_agent/main.py) disables redirects and stops on 3xx without forwarding credentials or the request body. Existing transient retry behavior is retained. | [Agent remediation tests](../tests/test_agent_remediation.py) use real Requests with an in-memory adapter, covering redirect origins/schemes/statuses and retry behavior; no external network is contacted. |
| A14 — unsupported identity-page sort | Already implemented upstream | [Detection sort contract](../src/shadai/api/detections.py) accepts `impacted_users_count` and shares the allowlist with [the frontend API](../frontend/src/api/detections.ts). | [Catalogue/API tests](../tests/test_catalog_dashboard.py) check accepted SQL ordering, deterministic ID tie-breaking and frontend enum parity. [Demo tests](../frontend/src/api/demo.test.ts) cover the synthetic API behavior. |
| A15 — internal links reload session | Corrected in this change set | [Extensions](../frontend/src/pages/Extensions.tsx), [OAuth apps](../frontend/src/pages/OAuthApps.tsx) and [Local AI](../frontend/src/pages/LocalAI.tsx) use React Router links with their original destinations/filters. [Login copy](../frontend/src/pages/Login.tsx) now reflects upstream cookie session restoration. | Six [navigation tests](../frontend/src/pages/Navigation.test.tsx) verify intercepted navigation and unchanged demo/live auth state. A browser check confirmed demo → Extensions → filtered Discoveries with the demo preserved. |
| A16 — actions on previous filter results | Corrected in this change set | [Discovery list](../frontend/src/pages/DiscoveryList.tsx) announces updates, disables both exports and selection/actions on placeholder results, closes obsolete export confirmation and scopes selection to current query/visible IDs. | [Component tests](../frontend/src/pages/DiscoveryList.test.tsx) delay filter/page responses, attempt stale exports/selections, then verify fresh-row export/mutation. Refetch preserves valid selections while removed IDs stay unselected; loading/error states remain explicit. |
| A17 — export ignores risk filter | Already implemented upstream | [Server export](../src/shadai/api/exports.py) reuses the [discovery filter implementation](../src/shadai/api/detections.py), including risk ranges. | [API tests](../tests/test_catalog_dashboard.py) check all filter predicates, rejection of invalid risk and audit metadata. [Frontend export tests](../frontend/src/pages/DiscoveryList.test.tsx) check the request filters and audited export confirmation. |

## Validation status

The following local results were recorded while preparing this change set:

| Check | Recorded result |
|---|---|
| Frontend | `npm test`: 59 tests passed across 8 files; `npm run build`: TypeScript and Vite passed. |
| Detection, governance and security regressions | `python -m pytest tests/test_detection_remediation.py tests/test_governance.py tests/test_security.py tests/test_integration.py -q`: 53 passed, including 11 new detection regressions; 3 integrations skipped without services. |
| Evidence and agent regressions | `python -m pytest tests/test_evidence_remediation.py tests/test_agent_remediation.py tests/test_catalog_dashboard.py tests/test_transient_signals.py tests/test_parsers.py tests/test_agent.py -q`: 100 passed. |
| Proxy and session regressions | `python -m pytest tests/test_proxy_rate_limit.py tests/test_sessions.py -q`: 15 passed, including integration collection with an isolated copy of the proxy tests and no deployment assets. |
| Windows permission boundaries | `scripts/test-bootstrap-security.ps1 -BoundaryOnly`: passed on PowerShell 7 and Windows PowerShell 5.1 outside the sandbox. This does not execute the full secret-generation/repeat-run path. |
| Windows subprocess and cleanup regressions | The harness exercises PowerShell 7 → Python → Windows PowerShell 5.1 with an inherited Core module path, checking child module-path isolation without changing either parent environment. The cleanup prefix now normalizes trailing separators; parsing and 9 in-memory boundary cases passed on both PowerShell versions, including drive roots and sibling refusal, without deleting files. Complete bootstrap execution remains pending in CI. |
| Changed Python files | Targeted Ruff checks and formatting checks passed for the completed API/evidence/proxy lots. |
| Final complete regression run | `python -m pytest -q`: 323 passed, 3 integrations skipped, 2 warnings, 17.73 seconds. These totals include the subsets above. |
| Final combined lint and review | Ruff passed for `src`, `tests`, `agent/shadai_agent` and `scripts/bootstrap.py`. Independent code review approved after the ancestor-permission and concurrent-note fixes; no remaining code blocker was reported. |
| Final CI and real-store checks | Pending. Record the tested commit, run link and job results after execution. |

The [first CI run](https://github.com/alebgl77/open-shadow-ai/actions/runs/37367556770)
exposed Windows subprocess module-path compatibility and collection-time reads of
deployment files absent from the integration image. Both have been corrected;
the complete CI rerun is still pending. That first run is not a complete success.

On the Windows workstation, Python tests used unique `--basetemp` directories
under `tmp/`. Frontend commands used the installed Node executable and npm CLI;
esbuild required execution outside the filesystem sandbox. The API subset emitted
existing Starlette deprecation and SHA384 test-key warnings.

## Qualification boundaries

The new transaction tests use SQLite, native ClickHouse calls use controlled test
doubles, and agent redirect tests use an in-memory transport. Their results do not
replace PostgreSQL/ClickHouse integration or deployment tests. The existing
[validation history](validation.md) applies only to its recorded revisions and
does not validate this change set.

Complete Windows bootstrap and installer rollout, legacy-volume migration, verified remote ClickHouse
TLS, live Entra/Active Directory/Microsoft Graph, Kubernetes deployment,
managed-fleet rollout, sustained load and restoration on target infrastructure
need their own recorded acceptance. No security certification or universal
production-readiness claim is made by this report.
