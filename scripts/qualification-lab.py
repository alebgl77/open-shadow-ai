"""Stdlib host entry point: explicit isolated lab plan/run/resume/clean."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from shadai.qualification.lab import Laboratory, safe_exception_type  # noqa: E402
from shadai.qualification.schemas import QualificationError, canonical_bytes, load_profile  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "run", "resume", "clean"))
    parser.add_argument("--profile", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--docker-context")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--remove-volumes", action="store_true")
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.profile)
        if profile["scope"] != "disposable_lab":
            raise QualificationError("Lab commands require disposable_lab scope")
        if args.action == "plan" or not args.execute:
            if args.action == "clean":
                from shadai.qualification.journal import RunJournal

                lab = Laboratory(ROOT, args.run_dir, profile, args.docker_context)
                lab.journal = RunJournal.resume(args.run_dir, profile, lab.config_hash, args.docker_context)
                print(json.dumps(lab.clean(remove_volumes=args.remove_volumes)))
                return 2
            print(
                json.dumps(
                    {
                        "schema": 1,
                        "scope": "disposable_lab",
                        "executed": False,
                        "profile_sha256": hashlib.sha256(canonical_bytes(profile)).hexdigest(),
                        "scenarios": profile["scenarios"],
                        "actions": [
                            "create private owned projects",
                            "load/outage/pressure",
                            "cold restore",
                            "verify exact IDs",
                        ],
                        "remove_volumes": args.remove_volumes,
                        "exit_code": 2,
                    }
                )
            )
            return 2
        lab = Laboratory(ROOT, args.run_dir, profile, args.docker_context)
        if args.action == "clean":
            from shadai.qualification.journal import RunJournal

            lab.journal = RunJournal.resume(args.run_dir, profile, lab.config_hash, args.docker_context)
            print(json.dumps(lab.clean(execute=True, remove_volumes=args.remove_volumes)))
            return 0
        return lab.execute(resume=args.action == "resume")
    except Exception as exc:
        print(json.dumps({"schema": 1, "status": "not_evaluated", "reason": safe_exception_type(exc), "exit_code": 2}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
