# Collectors and evidence

| Source | Delivered entry point | Evidence | Important boundary |
|---|---|---|---|
| BIND DNS | syslog; `bind_query_log` | Network metadata | Resolution is not a completed AI call |
| Windows DNS debug | syslog; `windows_dns_debug` | Network metadata | Requires actual debug-log format and forwarding |
| Squid | syslog; `squid_access_log` | Network metadata | Visible requests depend on proxy coverage |
| Palo Alto | syslog; `paloalto_url_log` | Network metadata | Select the supported URL-log format |
| FortiGate | syslog; `fortigate_webfilter` | Network metadata | Web-filter logs, not every traffic log format |
| Passive network sensor | `python -m shadai.collectors.network` | DNS/TLS/QUIC/HTTP observations | Imported metadata only; optional TShark capture requires deliberate placement |
| Endpoint | `shadai-agent` | Installed/running asset inventory; per-installation browser extension state | Visibility depends on OS and permissions; an installation is not usage |
| AD | PowerShell export | Directory inventory | Object presence is not AI use |
| Entra | `python -m shadai.collectors.entra` | Application/permission inventory | No live request or billing evidence |
| Instrumented/custom source | authenticated event API | Explicitly supplied evidence | Native vendor adapters are not automatic |

A source configuration is not a universal connector factory. The delivered YAML loader instantiates syslog listeners. Entra is a separate process. File watching and native connectors to other directories/gateways remain planned.

The [network analysis guide](network-analysis.md) covers Zeek JSONL, Suricata EVE and TShark field imports, local offline PCAP analysis, CSV export and explicitly selected live interfaces. All four protocols use `source_type: "network"` and `evidence_type: "observation"`; `collector_id` records the stable sensor ID. TCP, UDP and IPv4/IPv6 are supported where the selected source observes them. No AD/DHCP or IP-to-employee join is performed.

Network import uses the authenticated event API. The collector sends only canonical metadata; raw payloads and PCAP files are not uploaded. Replay preserves source timestamps and source event IDs when sensor, tenant, site and parser inputs remain the same. Scoped server IDs also bind that UUID to the immutable collector and tenant. Old events can fall outside the ingestion acceptance window. Persisted source logs support replay; endpoint/network/syslog collectors retain prepared batches in bounded private SQLite spools across restarts. Capture before enqueue and transport loss remain outside that guarantee. See [collector operations](collector-operations.md) for limits, binding, recovery and monitoring; a sensor's last observation does not establish complete coverage.

## Listener configuration

Copy the example and choose the parser matching your source. The default listener is TCP/1514; the Compose syslog profile binds it to localhost. Remote forwarding requires an explicitly selected private bind address and firewall allowlist. Do not expose unauthenticated plaintext syslog to an untrusted network. Put a trusted TLS syslog relay in front when needed.

Many devices log their local wall clock without an offset. Set `timezone` on the listener to the device's IANA zone (for example `Europe/Paris`); the default is `UTC`. A wrong zone shifts every event and can push recent ones outside the accepted window (at most five minutes ahead, `ingestion_max_age_days` behind). FortiGate `eventtime` (epoch, seconds to nanoseconds) and `tz` fields take precedence when present; PAN-OS ISO timestamps ending in `Z` are already UTC. For year-less BSD syslog timestamps, the most recent matching date is used.

Events outside that window are dropped individually and counted in `shadai_events_rejected_total{source_type}`; neighbouring lines and the TCP connection are unaffected. A rising counter usually means a zone or clock mismatch on the source.

URL paths and user agents never leave the ingestion boundary. Syslog collectors and `POST /api/v1/ingest/events` compare them in memory with the active catalog (paths without their query string or fragment), keep only the matched catalog entry and signal type, and then discard them. URL patterns count only on the product's hosts, so a generic path such as `/v1/chat/completions` on an internal gateway is not attributed to a public service. This is what distinguishes HuggingChat from other Hugging Face traffic. The collector reads the catalog from PostgreSQL at the catalog reload interval; while the database is unavailable, events are still ingested and matched on their retained fields. Set `privacy.match_transient_signals: false` to turn the comparison off.

Shared signatures need discriminating evidence: a more specific match or additional signal types can identify one product. Equally supported candidates remain unattributed; catalog order and identifiers do not break ties. The event is still ingested. If transient URL or User-Agent evidence is ambiguous, ingestion preserves `match_field: "ambiguous"`, an empty catalog ID and zero match confidence. The worker keeps that state and creates no detection from weaker retained evidence. A later catalog update cannot resolve those events retroactively because their paths and user agents were discarded.

Squid's native user field is mapped to `username`; `-` leaves it empty. The client IP is not treated as a user identity. Optional server `PSEUDONYMIZE_IDENTITIES` aliases personal identity fields and clears personal source IP; it does not authenticate a supplied name. Protect source logs and local spools independently, since server activation does not scrub their plaintext metadata.

The endpoint agent sends telemetry only to its configured URL and refuses every HTTP redirect, including redirects on the same origin. Configure the final telemetry endpoint directly. Discovery verifies the collector binding and server age ceiling before transmission, including after an offline first start. Retryable delivery failures retain queued work; terminal invalid batches are separated from retries. Monitor rejection, expiry, overflow and storage failures, and restore the correct principal rather than reusing its queue for another enrollment.

The agent's browser extension inventory runs under the service account (SYSTEM on Windows, root elsewhere), so it enumerates every local user profile on the host rather than the service account's own home: the Windows profile list (user and Entra ID accounts only), the POSIX account database plus the users directory for directory-bound accounts. For each user it reads every Chromium-family user-data root (Chrome, Chromium, Edge, Brave, Vivaldi, Opera, Arc, all channels, snap and flatpak installs, and any other Chromium build found by its `Local State`), every Firefox-family profile (Firefox, LibreWolf, Waterfox, Zen) and, on macOS, Safari app extensions in their host applications. Only extension metadata is read: the manifest and its locale table, the `extensions.settings` table of Chromium preferences (for the real enabled state, install source and install time), Firefox's `extensions.json` and Safari's extension state. Browsing history, cookies, storage and sign-in data are never opened; the rest of a preferences file is discarded unread. Since agent 0.3.0 (extension wire v2) the telemetry batch carries one record per installation: the extension id, name and browser plus its version, enabled state, install source (store, user, unpacked, external, policy, component, orphan, or unknown when the state could not be read), install time (Chromium only today), owning user and profile. The same extension in two profiles or two user accounts of one host is two records; an older agent still sends one id/name/browser record per host, which the server stores with an empty version, user and profile. The owning user is the home directory name and is an identity: the server pseudonymises it like process usernames when `PSEUDONYMIZE_IDENTITIES` is on. The profile is the profile directory name (`Default`, `Profile 1`, `abcd.default-release`); the agent never reads profile display names or signed-in accounts. Permissions and the Safari host application stay local to the agent and never leave the host. One snapshot carries at most 5,000 installations; past that the agent logs the count and sends the first 5,000. An installed extension is presence evidence, not usage: repeated inventory polls do not raise a detection's confidence. The server keeps the current state of each installation; see [browser extension inventory](#browser-extension-inventory).

The installed-agent acceptance helper adds `timeout_phase` and `timeout_seconds` only for a caught timeout in a known active operation: `private_directory` (15 seconds on Windows), or `venv`, `offline_install`, `dependency_check` and `worker` (120 seconds). The values come from fixed helper state, never exception command or output text. `private_directory` includes its preparation work; its phase does not prove PowerShell was reached. These fields identify the active operation and configured budget, not the inner timeout cause. Intent flags such as `offline_require_hashes` and `native_guards_mocked` do not prove installation or native guards ran; completed `workers` provide the worker evidence.

## Generic inventory ingestion

`POST /api/v1/ingest/events` takes `X-API-Key`, preferably an administrator-enrolled credential with the matching source scope. The legacy shared key remains a compatibility option and is always unattributed. The body contains one to 500 events; scoped authorization validates the whole batch atomically. Event timestamps must have a timezone; source event IDs are UUIDs and must be reused for retries. Unknown fields are rejected. [Enrollment and rotation](collector-operations.md#enroll-a-collector) also covers private key files, expiry and revocation.

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

This is synthetic data; replace its timestamp with the real observation time for a pilot test. `tenant_id` must match `SHADAI_TENANT_ID`; omitting it uses the configured organization. A scoped credential must bind `ad-pilot` and include `directory`. It is a scope guard, not an isolation boundary.

For full instrumented fields, consult the running [API schema](http://localhost:8443/api/docs). Only provide model/token/cost values supported by the originating telemetry. A model label is not proof of a provider's internal routing. Missing values remain unknown; estimated cost is not an invoice.

## Browser extension inventory

The ingest worker turns every browser inventory event that names an extension (`source_type: "browser"`, `evidence_type: "inventory"`, non-empty `extension_id`), matched against the catalog or not, into PostgreSQL state. `extension_inventory` holds one row per installation, keyed by a digest of the tenant, the keyed device and user digests, the browser, the profile and the extension id. Each row carries the state that installation last reported (name, version, enabled state, install source, install time), its first and last snapshot times, the catalog entry its extension matched and the post-privacy host and user labels of the latest event. `extension_version_changes` gains one row each time an installation reports a different version; `from_version` is null when the previous snapshot reported no version and `to_version` is null when the new one reports none. ClickHouse keeps every raw event for `events_days`. Both tables are written in the transaction that records the ingest receipt, so a redelivered event changes nothing and a ClickHouse or queue failure leaves no partial state. An event older than the identity window, or older than the state already recorded, never changes a row. Events sent to `POST /api/v1/ingest/events` with the same fields (`extension_version`, `extension_enabled`, `extension_install_source`, `extension_installed_at`, `browser_profile`, with a timezone on `extension_installed_at`) follow the same path; no other event feeds the inventory.

A row describes the latest snapshot that listed the installation. Removing an extension from a profile writes no removal row: once its host sends a newer snapshot that lists other installations but not this one, the API reports `present_in_latest_snapshot: false` (the console shows *Absent from the latest snapshot*), and the row expires with the identity window. An empty `install_source` and a null `enabled` or `version` mean *Not reported*: agents older than 0.3.0 send none of them, and their rows are host-level, without user or profile. `unknown` means the agent could not read the install source. `installed_at` comes from Chromium preferences only; Firefox and Safari rows leave it empty. Beta, dev and canary channels are reported under their browser brand.

The owning user is a home-directory name, whereas process events carry the operating system account (`DOMAIN\user` on Windows), so one person can appear as two identifiers and a detection's user count can include both. The two are not merged.

The read API uses console authentication. Rows outside the identity window, or written under a previous encryption key, are never returned, even before the daily purge deletes them. An invalid `enabled`, `install_source`, `catalog_match` or sort value returns `422`.

| Endpoint | Role | Content |
|---|---|---|
| `GET /api/v1/extensions/inventory` | analyst, admin | Installations, filtered by `host` (substring of the label), `browser` (comma list), `enabled` (`true`, `false`, `unknown`), `install_source` (comma list of `store`, `user`, `unpacked`, `external`, `policy`, `component`, `orphan`, `unknown`), `catalog_match` (`matched`, `unmatched`), `extension_id` and `search` (substring of the name or id); `page`, `page_size` 1–100 (default 25), `sort_by` (`last_seen_at`, `first_seen_at`, `extension_name`, `browser`, `version`, `installed_at`, `host_label`) and `sort_order`. Each item carries `present_in_latest_snapshot` and the `detection_id` of the discovery its extension matched |
| `GET /api/v1/extensions/inventory/summary` | any signed-in role | Counts of installations, hosts, extensions and catalog matches; counts by browser, enabled state (`true`, `false`, `unknown`) and install source (`""` is *Not reported*); version changes over the last seven days; the limitations of the evidence. Never a host, user or profile value |
| `GET /api/v1/extensions/inventory/{inventory_key}/versions` | analyst, admin | One installation and its version changes inside the identity window, newest first; `404` once it is no longer visible |
| `GET /api/v1/extensions/version-changes` | analyst, admin | Version changes newest first, filtered by `host`, `browser` (comma list) and `extension_id`; `since` and `until` (ISO 8601, UTC when no offset is given) are clamped to the identity window and the current time, and the response echoes the effective window; `page`, `page_size` 1–100 |
| `POST /api/v1/exports/extension-inventory?format=csv` (or `json`) | analyst, admin | Every installation matching the inventory filters and sort, with `Cache-Control: no-store`. The CSV starts with the anti-HR warning line and the JSON carries it as `warning`. Each export is recorded in the audit log as `export_extension_inventory` with its format, filters and row count |

Every read response and the JSON export carry `identity_window` (`days`, `as_of`) and `identity_mode` (`pseudonymized` or `raw`), the current privacy configuration. Labels follow the latest event of each installation, so after a mode change a row keeps its previous label form until its next snapshot. The console's **Extensions** page keeps the catalog matches as its default view and adds **Inventory** (`/extensions?view=inventory`) and **Version changes** (`/extensions?view=changes`, over 24, 72 or 168 hours) for analysts and administrators; viewers see a permission notice. **Export page** saves the visible rows locally; **Export all** runs the audited server export after the anti-HR notice. The console never substitutes sample data when the API fails.

A discovery matched through a browser extension shows version evidence that names no host, user or profile. The browser section of its evidence holds `version_changes`, the ten most recent `{from_version, to_version, observed_at}` entries oldest first, and `versions`, the number of hosts per last reported version (at most ten; `""` counts installations that reported none). `GET /api/v1/detections/{detection_id}/timeline` adds an `extension_version_change` entry, with `browser`, `from_version` and `to_version`, for each of the ten newest changes, for every role. Both read the inventory within the identity window and the current encryption key and add no detection confidence; inventory polls do not count as event volume either. The correlation and ingest workers run in parallel, so the correlation of an event may read the inventory before that event's own ingest transaction has committed; a version change then appears on the detection from the extension's next browser event.

## Coverage checks

Verify the collector's last event and inspect a known synthetic case from source to stored evidence. Include non-AI negatives and shared-domain cases. Endpoint installation, consent grants and DNS prefetching can otherwise be mistaken for active usage. No individual source provides complete visibility.
