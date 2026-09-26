# Draft collection notice

Complete and review this template for your actual deployment before sharing it. It is an operational drafting aid, not a determination of legal basis or compliance.

## Organization and purpose

[Organization] uses Open Shadow AI to inventory selected AI-related assets and investigate signals from approved sources. Describe the concrete purposes, authorized teams and prohibited secondary uses here.

## Scope and collected fields

List the collectors actually enabled, their devices/OUs/accounts, and collection intervals. Depending on configuration, telemetry can include timestamps, service domains, network volumes, usernames, device identifiers, process names, extension IDs, directory GUIDs/SIDs and application permissions.

The provided default configuration strips query parameters and avoids retaining URL paths. Explain any departures. The current metadata workflow does not intentionally collect prompt or response bodies. Verify the actual forwarded log format before making that assurance to employees.

Directory objects, installed extensions and network lookups are inventory/observation signals; they do not prove a person used a model or sent particular content.

## Retention, access and handling

Document the configured retention for events, detections, audit records, receipts, export files and backups. Confirm deletion in the deployed system rather than assuming a configuration field covers every copy.

List authorized roles, administrators, hosting locations, service providers, export recipients and incident-handling contacts. Application audit entries are not a tamper-proof audit system and do not establish that every read is logged.

## Contact and review

Provide the responsible organization's contact and its process for access, correction, questions and complaints. Have the organization's privacy/legal and employee-representation processes determine the applicable legal basis, notices, consultation and rights handling.

Last reviewed: [date]. Deployment scope/version: [scope and commit]. Responsible owner: [name or role].
