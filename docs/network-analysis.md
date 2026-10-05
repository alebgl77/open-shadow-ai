# Passive network analysis

Open Shadow AI imports DNS, TLS, QUIC and HTTP metadata, associates visible hostnames with the reviewed catalog, and exposes the evidence at **Explore → Network** (`/network`). This records observations of service names, not completed AI requests, prompts, model choices, tokens or cost. Repeated network observations do not increase confidence.

## Choose a vantage point

Deploy the sensor where it can observe the intended traffic: a switch SPAN port, a network TAP or a deliberately configured cloud traffic mirror. Record the location, capture scope and limitations in your operational inventory, and keep its `--sensor-id` stable. The collector persists that ID as `collector_id`, with `site_id`, timestamp, parser version, protocol and IPv4/IPv6 addresses. Installation does not discover or configure network infrastructure.

A gateway is one option alongside endpoint inventory, browser telemetry, instrumented applications and proxy logs. Combine evidence according to its provenance. This collector performs no TLS interception, AD/DHCP lookup or automatic IP-to-employee mapping. An address can represent a resolver, NAT gateway, shared host or changing lease.

Prefer persisted Zeek or Suricata metadata logs for replayable collection. Live capture can lose observations during downtime, restart or delivery failure; it has no durable buffer. Monitor the source process and capture coverage separately. A sensor's last observed event is not a heartbeat or proof of health.

## Import supported metadata

Install the Python package using the [deployment instructions](deployment.md), then run these commands from the repository root. Zeek/Suricata log imports need no packet capture driver. TShark is an optional system dependency for `--pcap` and `--interface`; install and validate it separately using the [Wireshark TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html). `--tshark-binary` selects its executable.

| `--format` | Input | Retained naming evidence |
|---|---|---|
| `zeek-dns` | JSONL `dns.log` | `query`; a DNS transaction may include a response but is not a connection |
| `zeek-tls` | JSONL `ssl.log` | `server_name` when supplied |
| `zeek-http` | JSONL `http.log` | `host`, with optional method |
| `zeek-quic` | JSONL `quic.log` | `server_name` when supplied by that Zeek version |
| `suricata` | EVE JSONL | DNS v2 `query` / v3 `request` names, TLS/QUIC `sni`, HTTP `hostname` |
| `tshark` | Header-bearing CSV/TSV field export | DNS query, TLS ClientHello SNI, QUIC-dissection SNI or HTTP Host |

Configure Zeek JSON logging with `LogAscii::use_json=T`; traditional Zeek TSV logs are not these adapters' input. See [Zeek log formats](https://docs.zeek.org/en/v7.2.2/log-formats.html) and [QUIC log fields](https://docs.zeek.org/en/v7.2.2/logs/quic.html). Older logs without QUIC `server_name` remain unnamed. Suricata DNS answers are filtered; v3 can carry multiple questions. TLS, HTTP and QUIC field availability depends on source configuration and version. See the [Suricata EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html).

Start by inspecting canonical metadata locally:

```bash
python -m shadai.collectors.network --help
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format zeek-tls --input ssl.jsonl --dry-run --csv-output network-observations.csv
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format suricata --input eve.json --dry-run
```

`--input -` reads standard input. `--dry-run` writes canonical metadata JSONL to standard output without API delivery. `--csv-output` writes a metadata CSV in either mode; it contains observation IDs, timestamps, sensor/site IDs, protocol, addresses, port and observed names, without catalog enrichment or AI usage metrics. Choose an output path different from the input. Protect both exports as organizational data.

Valid records preserve original source timestamps; JSON timestamp strings must include a timezone, while Zeek/TShark epoch values are interpreted as UTC. DNS/TLS/QUIC/HTTP events share `source_type: "network"`, uppercase `protocol` and `evidence_type: "observation"`. Unsupported or malformed records are skipped with aggregate counters on standard error. Exit status is `0` for success, `2` if records were rejected, or `1` for an input/configuration/delivery failure. Check the counters even on a successful run; not every source record produces an observation.

To deliver a reviewed log, provision a private file containing the deployment's agent API key, accessible only to the collector account. Use `--api-key-file`, `AGENT_API_KEY_FILE`, or a securely supplied `AGENT_API_KEY`; never pass the secret as a command-line value. The following paths and HTTPS origin are deployment examples, not bundled files:

```bash
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format zeek-tls --input ssl.jsonl --api-url https://shadai.example.test --api-key-file /etc/shadai/network-agent.key --ca-file /etc/shadai/organization-ca.pem
```

HTTPS always validates the certificate and hostname. Omit `--ca-file` when the system trust store already recognizes the server. Redirects are refused; configure the final origin or exact `/api/v1/ingest/events` URL. Plain HTTP requires both a loopback URL and `--allow-http-loopback`, for local development only. Batches contain at most 500 events and 900 KiB, within the API's existing 2 MiB request limit.

By default, the server fills the configured tenant; an explicit `--tenant-id` must agree with it. Keep sensor, tenant, site and parser settings consistent when replaying the same metadata: event UUIDs remain stable, including after renaming an input file, and retries reuse the exact batch bytes. The ingestion window rejects timestamps more than five minutes ahead or older than configured `ingestion_max_age_days`. Do not change source timestamps to make an old replay appear current. Duplicate IDs are deduplicated in observation counts.

## Analyze an offline PCAP

Use a locally retained, authorized capture. TShark extracts fields locally; the collector does not upload the PCAP, raw packets or payloads. This command reads a file and never starts live capture:

```bash
python -m shadai.collectors.network --sensor-id lab-offline --pcap sample.pcapng --dry-run --csv-output offline-observations.csv
```

The collector requests metadata fields including `frame.time_epoch`, `frame.number`, `frame.protocols`, IPv4/IPv6 addresses, TCP/UDP destination ports, DNS query/response flags, TLS handshake/SNI fields and HTTP Host/method. A TShark field export using those headers can be imported with `--format tshark --input fields.tsv`; the collector's canonical CSV is a different format. QUIC is classified only when TShark's dissector identifies QUIC; UDP port 443 alone does not establish the protocol or an AI service. Captured handshakes and available dissectors determine whether SNI can be extracted.

Generate a Wireshark/TShark **display filter** from the local YAML catalog:

```bash
python -m shadai.collectors.network --sensor-id lab-offline --print-filter --catalog-builtin catalog/builtin --catalog-local catalog/local
```

Paste its standard output into Wireshark's display-filter bar. It compares DNS queries, TLS SNI and HTTP Host using domain-label boundaries and includes subdomains; it is not a packet capture filter. It reads the configured YAML snapshot, not database-only custom signatures. It cannot show unnamed handshakes or recover encrypted names, and a filtered view cannot establish complete coverage.

## Optional explicit live sensor

After validating capture permission, interface selection and mirror coverage in your environment, an operator may choose a live interface. The following is an opt-in example; replace the interface and deployment paths deliberately:

```bash
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --interface eth1 --duration 600 --api-url https://shadai.example.test --api-key-file /etc/shadai/network-agent.key --ca-file /etc/shadai/organization-ca.pem
```

`--input`, `--pcap` and `--interface` are mutually exclusive. Live capture accepts a duration of 1–3600 seconds, default 600. Its capture filter includes **TCP and UDP**, and field extraction supports IPv4 and IPv6. The collector does not write a raw PCAP or request TLS key logging. Driver installation, elevated capture permissions, mirroring and unattended service setup remain operator responsibilities; no live capture is started by installing the server.

## Interpret the evidence

TLS encryption hides application content. Visible SNI or HTTP Host can associate a service, but cannot identify a prompt, model, token count, cost or employee. DNS resolution may be prefetching or cached lookup activity without a connection. Different sources and multiple protocol observations can refer to the same activity; do not sum them into AI request counts.

Encrypted Client Hello (ECH) protects the inner hostname. An offered ECH extension may be GREASE and does not prove server acceptance; an outer name need not identify the intended service. Missing SNI alone does not diagnose ECH. The collector suppresses outer SNI when its supported metadata identifies an ECH offer, and reports an offer counter with acceptance unknown. Version-dependent dissector/log fields can leave ECH undetected. These distinctions follow [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html).

DNS over HTTPS hides the queried names from this passive DNS adapter. Seeing a resolver's SNI does not recover those queries; destination SNI may also be unavailable. There is no guarantee of recovering all DoH traffic or its names. Shared CDNs, remote workers, VPNs, NAT, local models, encrypted DNS and unmirrored segments leave additional gaps. IP addresses and TLS fingerprints alone are not catalog identities.

Analysts and administrators can inspect `/network`; viewer accounts cannot read its observations. The view offers 24/72/168-hour windows, protocol filters and pagination. Overview counts cover all protocols in the selected window; the protocol filter applies to event rows. Counts distinguish imported observations, observed names, catalog associations and unmatched observations. TLS/QUIC observations without a usable hostname remain visible and unattributed. An empty selection cannot prove the absence of traffic or AI use.

Event details expose the source timestamp, protocol, IPv4/IPv6 endpoints, observed hostname, sensor ID, parser version and event UUID. Catalog associations use stored match IDs, with names/categories from the current catalog where available; removed or unavailable labels fall back to observed names. The collector's CSV is a separate metadata export. The sensor summary is limited to 100 collectors in the window and shows last observed timestamps, not operational health.

The read APIs are `GET /api/v1/network/overview?hours=24` and `GET /api/v1/network/events?hours=24&protocol=TLS&page=1&page_size=20`, using console authentication with analyst/admin authorization. `hours` is bounded to 1–168 and `page_size` to 1–100. Existing syslog DNS/proxy sources keep their own source types and are not retroactively relabeled into this view.

## Reviewed catalog coverage

Domain signatures associate names with a service family, including sites, authentication or updates; they do not prove inference. Shared signatures remain ambiguous without discriminating evidence. Verified additions preserve existing family IDs:

| Family | Added domains or alias | Primary evidence |
|---|---|---|
| Supermaven | `supermaven.com`; legacy autocomplete entry | [Sunsetting Supermaven](https://supermaven.com/blog/sunsetting-supermaven): existing Neovim/JetBrains customers retain free inference; new subscriptions closed |
| Udio | `udio.com` | [Create your first song](https://help.udio.com/en/articles/10715838-create-your-first-song) |
| fal.ai | `fal.ai`, `fal.run` (including `queue.fal.run`) | [Queue API documentation](https://fal.ai/docs/documentation/model-apis/inference/queue) |
| Codeium | `windsurf.com`, `codeiumdata.com`; Windsurf alias | [Official desktop network troubleshooting](https://docs.devin.ai/desktop/troubleshooting/windsurf-common-issues) |
| Grok | `grok.com` | [Official Grok site](https://x.ai/grok) |
| Cursor | `cursor.com`, `cursorapi.com` | [Network configuration](https://prod.cursor.com/docs/enterprise/network-configuration), [security](https://www.cursor.com/security) |

Suno already includes `suno.com` and `app.suno.ai`. Generic infrastructure parents, guessed service endpoints, CDN IP ranges and fingerprints are not added by this coverage update. Review changes in `catalog/builtin` and keep deployment catalog synchronization current.
