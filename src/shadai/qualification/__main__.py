"""Qualification commands with honest prerequisite and proof exit codes."""

import argparse
import asyncio
import json

from shadai.qualification.journal import atomic_json
from shadai.qualification.schemas import QualificationError


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bounded lab/target qualification")
    commands = parser.add_subparsers(dest="command", required=True)
    quality = commands.add_parser("quality")
    quality.add_argument("--corpus", required=True)
    quality.add_argument("--catalog", required=True)
    quality.add_argument("--output", required=True)
    fixture = commands.add_parser("fixture")
    fixture.add_argument(
        "action", choices=("initialize", "pipeline", "enroll", "inventory", "verify_load", "seed_pending", "physical")
    )
    fixture.add_argument("--directory", default="/qualification")
    fixture.add_argument("--run-id", required=True)
    fixture.add_argument("--case", default="baseline")
    snapshot = commands.add_parser("snapshot")
    snapshot.add_argument("action", choices=("export", "import"))
    snapshot.add_argument("--archive", required=True)
    snapshot.add_argument("--volume", default="/volume")
    snapshot.add_argument("--sha256")
    snapshot.add_argument("--max-bytes", type=int, required=True)
    target = commands.add_parser("target")
    target.add_argument("action", choices=("plan", "preflight", "load", "kubernetes", "idp", "evaluate"))
    target.add_argument("--plan", required=True)
    target.add_argument("--execute", action="store_true")
    target.add_argument("--output", required=True)
    target.add_argument("--evidence")
    args = parser.parse_args(argv)
    try:
        if args.command == "quality":
            from shadai.qualification.quality import evaluate_quality

            atomic_json(args.output, evaluate_quality(args.corpus, args.catalog))
            return 0
        if args.command == "fixture":
            from shadai.qualification.fixtures import fixture

            result = asyncio.run(fixture(args.action, args.directory, args.run_id, case=args.case))
        elif args.command == "snapshot":
            from shadai.qualification.snapshot import export_volume, import_volume

            if args.action == "export":
                result = export_volume(args.volume, args.archive, args.max_bytes)
                atomic_json(str(args.archive) + ".manifest.json", result)
            else:
                import_volume(args.archive, args.volume, args.sha256, args.max_bytes)
                result = {"imported": True}
        else:
            from shadai.qualification.target import target_action

            result = target_action(args.action, args.plan, args.execute, args.evidence)
            atomic_json(args.output, result)
            return result["exit_code"]
        print(json.dumps(result, default=str, separators=(",", ":")))
        return 0
    except Exception as exc:
        # No credentials, DSNs, event payloads or upstream error text.
        reason = ("unsupported_browser_containment"
                  if isinstance(exc, QualificationError) and exc.args == ("unsupported_browser_containment",)
                  else type(exc).__name__)
        error = {"schema": 1, "status": "not_evaluated", "reason": reason, "exit_code": 2}
        if getattr(args, "output", None):
            atomic_json(args.output, error)
        print(json.dumps(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
