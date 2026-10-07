# Compose worker diagnostics

When the mandatory Compose readiness wait fails, CI collects an allowlisted snapshot of `ingest-worker` and `correlation-worker` and retains `compose-worker-diagnostic.json` as an artifact when present. The original wait exit code remains the job failure even if collection fails. Startup order, readiness thresholds and the 180-second wait remain unchanged.

For the same explicit project in the intended Docker context, run:

```sh
python scripts/diagnose-compose-workers.py --project open-shadow-ai --output artifacts/compose-worker-diagnostic.json
```

The diagnostic requires the project and output arguments. It accepts only these two fixed workers and requires one full container ID, exact Compose project/service labels and name, an immutable image ID and a creation identity before executing existing startup, liveness and readiness probes. It reinspects that identity after every execution and stops a worker on identity drift. Readiness uses the existing secret-resolving entrypoint without printing its inputs.

The snapshot contains only allowlisted container state, health/restart counts, bounded exact probe exit codes, and a validated private probe record summary: validity, initialization, phase and rounded heartbeat/poll/cycle ages capped at 97,200 seconds. The existing record reader validates private file permissions, the live PID/start identity, boot identity and monotonic times. Environment, command configuration, mounts, health logs, Docker logs, probe output, PIDs, UUIDs, timestamps and secrets are excluded.

Collection has a total monotonic 30-second budget. Every Docker client has at most five seconds within the remaining budget; captured stdout is bounded to 16 KiB per command, stderr is discarded, and timeout/overflow clients are killed and reaped. The record command has a four-second POSIX alarm, performs no writes and makes no additional Redis requests. The final JSON is at most 8 KiB. Errors use only `missing_container`, `invalid_identity`, `identity_changed`, `timeout`, `nonzero`, `invalid_record`, `output_budget` and `deadline`.

The artifact describes state observed during that collection. Without a retained snapshot from an earlier failed run, its historical root cause cannot be inferred. Local tests exercise collection boundaries and CI failure handling; actual Docker startup and worker readiness still require the mandatory daemon-backed CI run.
