# Collectors and evidence

| Source | Delivered entry point | Evidence | Important boundary |
|---|---|---|---|
| BIND DNS | syslog; `bind_query_log` | Network metadata | Resolution is not a completed AI call |
| Windows DNS debug | syslog; `windows_dns_debug` | Network metadata | Requires actual debug-log format and forwarding |
| Squid | syslog; `squid_access_log` | Network metadata | Visible requests depend on proxy coverage |
| Palo Alto | syslog; `paloalto_url_log` | Network metadata | Select the supported URL-log format |
| FortiGate | syslog; `fortigate_webfilter` | Network metadata | Web-filter logs, not every traffic log format |
| Endpoint | `shadai-agent` | Installed/running asset inventory | Visibility depends on OS and permissions |
| AD | PowerShell export | Directory inventory | Object presence is not AI use |
| Entra | `python -m shadai.collectors.entra` | Application/permission inventory | No live request or billing evidence |
| Instrumented/custom source | authenticated event API | Explicitly supplied evidence | Native vendor adapters are not automatic |

A source configuration is not a universal connector factory. The delivered YAML loader instantiates syslog listeners. Entra is a separate process. File watching and native connectors to other directories/gateways remain planned.

## Listener configuration

Copy the example and choose the parser matching your source. The default listener is TCP/1514; the Compose syslog profile binds it to localhost. Remote forwarding requires an explicitly selected private bind address and firewall allowlist. Do not expose unauthenticated plaintext syslog to an untrusted network. Put a trusted TLS syslog relay in front when needed.

Many devices log their local wall clock without an offset. Set `timezone` on the listener to the device's IANA zone (for example `Europe/Paris`); the default is `UTC`. A wrong zone shifts every event and can push recent ones outside the accepted window (at most five minutes ahead, `ingestion_max_age_days` behind). FortiGate `eventtime` (epoch, seconds to nanoseconds) and `tz` fields take precedence when present; PAN-OS ISO timestamps ending in `Z` are already UTC. For year-less BSD syslog timestamps, the most recent matching date is used.

Events outside that window are dropped individually and counted in `shadai_events_rejected_total{source_type}`; neighbouring lines and the TCP connection are unaffected. A rising counter usually means a zone or clock mismatch on the source.

URL paths and user agents never leave the ingestion boundary. Syslog collectors and `POST /api/v1/ingest/events` compare them in memory with the active catalog (paths without their query string or fragment), keep only the matched catalog entry and signal type, and then discard them. URL patterns count only on the product's hosts, so a generic path such as `/v1/chat/completions` on an internal gateway is not attributed to a public service. This is what distinguishes HuggingChat from other Hugging Face traffic. The collector reads the catalog from PostgreSQL at the catalog reload interval; while the database is unavailable, events are still ingested and matched on their retained fields. Set `privacy.match_transient_signals: false` to turn the comparison off.

## Generic inventory ingestion

`POST /api/v1/ingest/events` takes `X-API-Key` using the deployment's `AGENT_API_KEY`. The body contains one to 500 events. Event timestamps must have a timezone; event IDs are UUIDs and must be reused for retries. Unknown fields are rejected.

```json
{
  "events": [
    {
      "event_id": "1417353f-e215-4c72-b57b-bda28d3d7d5e",
      "timestamp": "2026-09-27T00:00:00Z",
      "source_type": "directory",
      "evidence_type": "inventory",
      "tenant_id": "default",
      "collector_id": "ad-pilot",
      "identity_provider": "active_directory",
      "identity_object_id": "7bbc7258-8c5e-40c6-8833-067089e28a50",
      "identity_sid": "S-1-5-21-111111111-222222222-333333333-1001",
      "device_id": "ad:7bbc7258-8c5e-40c6-8833-067089e28a50",
      "hostname": "pilot.example.test",
      "user_id": "",
      "username": ""
    }
  ]
}
```

This is synthetic data. `tenant_id` must match `SHADAI_TENANT_ID`; omitting it uses the configured organization. It is a scope guard, not an isolation boundary.

For full instrumented fields, consult the running [API schema](http://localhost:8443/api/docs). Only provide model/token/cost values supported by the originating telemetry. A model label is not proof of a provider's internal routing. Missing values remain unknown; estimated cost is not an invoice.

## Coverage checks

Verify the collector's last event and inspect a known synthetic case from source to stored evidence. Include non-AI negatives and shared-domain cases. Endpoint installation, consent grants and DNS prefetching can otherwise be mistaken for active usage. No individual source provides complete visibility.
