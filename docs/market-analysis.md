# Market and positioning

Research checked 26 September 2026. This comparison describes vendor documentation, not an independent performance benchmark. Product capabilities and licenses evolve.

## Competitive landscape

| Product | Documented strength | Implication for Open Shadow AI |
|---|---|---|
| Microsoft Defender for Cloud Apps + Purview | SaaS AI discovery, risk catalog, sanction/block workflows and data protection; third-party interaction visibility has onboarding prerequisites. Discovery correlates traffic with a catalog. [Microsoft AI discovery](https://learn.microsoft.com/en-us/security/security-for-ai/discover), [Cloud Discovery](https://learn.microsoft.com/en-us/defender-cloud-apps/set-up-cloud-discovery) | Reuse existing telemetry with inspectable rules. Do not claim Microsoft covers only Copilot. |
| Netskope | SaaS controls, personal/corporate instance awareness and DLP; endpoint discovery includes agents, local LLMs, MCP and extensions. Signature, profile, OS and container boundaries remain documented. [GenAI security](https://www.netskope.com/products/securing-generative-ai), [Client AI Discovery](https://docs.netskope.com/en/netskope-client-ai-discovery) | Local agent discovery is not an exclusive feature. Community-maintained signatures and explicit evidence boundaries are defensible choices. |
| Zscaler | AI discovery, user/group controls, prompt/response classification, inline DLP and developer-tool protection. [AI Access Security](https://www.zscaler.com/products-and-solutions/ai-access-security) | Position this project as complementary visibility, not a replacement for an enterprise security platform. |
| Prompt Security / SentinelOne | Employee/developer/application/agent controls. Browser and endpoint sensors provide interaction-level context. [Platform](https://www.sentinelone.com/platform/securing-ai-prompt/), [sensor architecture](https://prompt.security/blog/the-key-layer-in-ai-security-browser-and-endpoint-sensors) | DNS metadata is not equivalent to prompt inspection or real-time protection. |
| Cloudflare AI Gateway | Request-level logs, token/cost metadata and optional payload retention. Costs are explicitly estimates and require supporting model/token data. [Logging](https://developers.cloudflare.com/ai-gateway/observability/logging/), [costs](https://developers.cloudflare.com/ai-gateway/observability/costs/) | Gateway visibility is useful for instrumented traffic; by architectural inference it does not discover requests that bypass the gateway. |
| LiteLLM | Open-source, self-hosted SDK/gateway, provider normalization, cost tracking, logging and guardrails; commercial features/support also exist. [Official repository](https://github.com/BerriAI/litellm) | Integrate gateway telemetry rather than rebuilding an entire gateway for visibility. |

Catalog counts and marketing claims such as “complete coverage” are deliberately not compared: different vendors count services, applications, signatures and controls differently.

## Achievable differentiation

The proposed combination is self-hosting, inspectable evidence, a community catalog and gradual integration into existing IT. No individual property is asserted to be unique.

1. Every finding should expose source, observation time, rule version, confidence and limits.
2. Coverage should show collector health and blind spots, so “no telemetry” never becomes “no AI.”
3. Defaults should minimize retained content and support controlled retention.
4. Directory and endpoint inventory should stay distinct from network and instrumented usage.
5. Small teams should be able to evaluate one source without replacing their security stack.
6. Larger teams should receive explicit production gates: identity, isolation, backups, scaling, monitoring and key lifecycle.

These are positioning and acceptance targets. The README delivered/planned matrix is the source of truth for implementation status.

## Naming

The project uses **Open Shadow AI** in full, with the descriptor “Self-hosted AI discovery, with evidence behind every finding.” Searches for the exact phrase and `open-shadow-ai`, including indexed GitHub results, did not establish an exact repository collision. Native GitHub search/API was inaccessible during this check; this is incomplete research, not trademark clearance.

Nearby names already exist: [Open-Shadow talent directory](https://www.open-shadow.com/) and [Open Shadow AI presence management](https://www.openshadow.io/). Avoid abbreviating the project to OpenShadow or implying affiliation with these services.

## Evidence rules and enterprise gates

A DNS query is a domain-resolution observation. Proxy metadata adds only the fields actually logged. Endpoint discovery first proves presence/configuration. Directory objects prove inventory or permission. Instrumented traffic can expose declared model IDs and token data, but not necessarily the provider's internal model routing. Calculated costs remain estimates until reconciled with billing.

Initial limitations include unmanaged/off-network devices, unobserved encrypted DNS, shared or unknown domains, embedded SaaS AI, gateway bypasses and uncollected local tools. Hybrid AD/Entra identity mappings require validation.

For startups, prioritize a clear first-source workflow. For enterprise pilots, require a tested restore, explicit organizational scope, least privilege, TLS, collector-key lifecycle, auditability and measured load limits. SSO/SCIM and multi-organization isolation remain planned. Avoid “better than all,” “zero blind spots,” “automatic compliance” and “enterprise-ready” without evidence.
