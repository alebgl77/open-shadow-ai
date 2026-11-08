# Product intent

Open Shadow AI is a self-hosted, open source evidence and governance console for IT administrators and security analysts.

**See the evidence. Govern the AI.**

The primary workflow is to review observed AI signals, inspect the evidence and source limitations, classify the tool, and record a decision. It is not a prompt firewall, DLP enforcement engine, employee scoring product, or certification of enterprise readiness.

## Metric contract

- Overview counts come from the backend summary and cover retained detections. They are not derived from a truncated table.
- Trend counts reflect first-observed detections during the displayed period.
- Evidence counts, source-reported model identity, tokens and reported cost cover the explicit 30-day evidence window. Missing cost or token measurements appear as unknown, never zero.
- A known domain identifies a service signal, not its model, prompts, tokens or data disclosure. A source-reported model name is not independently attested.
- Active source status means recent ingestion, not complete deployment coverage.
- Identity signals are explicitly a bounded sample of up to 100 detections. Type-specific lists disclose their maximum window and link to the full searchable discovery list.

## Reviewer demo

Run `npm ci` and `npm run demo` in `frontend`, or open `/demo` on a running frontend. The login page also offers **Explore the demo**. Entry is always explicit. Synthetic data is never substituted after a live API failure. A persistent workspace banner and source labels distinguish the demo, and changes remain in memory until reload or reset. No credentials or network sources are needed.

## Access and limitations

The browser restores a valid live session after reload using its HttpOnly cookie. The profile and CSRF token stay in memory, and session changes clear cached queries. The backend is the authority for role enforcement; frontend viewers cannot use review mutation controls. Console account and governance-policy administration use the backend API. Source ingestion is configured at deployment time; the console reports received evidence.

Export page downloads the discoveries displayed on the current page. For analysts and administrators, Export all sends the current filters to the live API, exports every matching discovery, and records an audit entry. Demo exports contain synthetic records, and demo audit entries stay in memory. The CSV encoders escape formula-like text when generating a file. Spreadsheet software can change this escaping when it saves the file again.

Review failures are visible and preserve the current note. The console does not provide an atomic multi-record review operation: a partial bulk failure refreshes records and reports the failure count.
