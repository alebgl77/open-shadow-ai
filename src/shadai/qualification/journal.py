"""Atomic run journal and strict Docker resource identity checks, stdlib only."""

import hashlib
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from shadai.qualification.schemas import QualificationError, canonical_bytes, read_json, strict_object

LABEL = "com.shadai.qualification."


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(canonical_bytes(value))
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def resource_identity(kind, inspection, run_id, role, project):
    labels = inspection.get("Config", {}).get("Labels", {}) if kind == "container" else inspection.get("Labels", {})
    expected = {LABEL + "run": run_id, LABEL + "role": role, "com.docker.compose.project": project}
    if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in expected.items()):
        raise QualificationError("Foreign resource or qualification label mismatch")
    identifier = inspection.get("Id") if kind != "volume" else inspection.get("Name")
    created = inspection.get("Created") if kind != "volume" else inspection.get("CreatedAt")
    if not identifier or not created or kind not in {"container", "network", "volume"}:
        raise QualificationError("Resource identity or creation proof is absent")
    return {
        "kind": kind,
        "id": identifier,
        "created": created,
        "labels": expected,
        "service": labels.get("com.docker.compose.service"),
        "role": role,
        "project": project,
    }


def verify_resource(record, inspection):
    current = resource_identity(
        record["kind"], inspection, record["labels"][LABEL + "run"], record["role"], record["project"]
    )
    if current != record:
        raise QualificationError("Resource was replaced or changed after journaling")
    return current


class RunJournal:
    def __init__(self, directory, value):
        self.directory, self.value = Path(directory), value

    @classmethod
    def create(cls, directory, profile, config_hash, context):
        directory = Path(directory).absolute()
        if directory.exists() or any(parent.is_symlink() for parent in (directory, *directory.parents)):
            raise QualificationError("Run directory must be new and must not traverse links")
        directory.mkdir(mode=0o700, parents=True)
        os.chmod(directory, 0o700)
        run_id = str(uuid4())
        value = {
            "schema": 1,
            "run_id": run_id,
            "created": datetime.now(UTC).isoformat(),
            "phase": "created",
            "config_sha256": config_hash,
            "profile_sha256": hashlib.sha256(canonical_bytes(profile)).hexdigest(),
            "context": context,
            "projects": {"source": "shadai-q-" + run_id, "restore": "shadai-q-" + run_id + "-restore"},
            "resources": [],
            "history": [],
            "completed": [],
            "cancelled": False,
        }
        journal = cls(directory, value)
        journal.save()
        return journal

    @classmethod
    def resume(cls, directory, profile, config_hash, context):
        directory = Path(directory).absolute()
        if directory.is_symlink() or not stat.S_ISDIR(directory.lstat().st_mode):
            raise QualificationError("Unsafe run directory")
        if (
            any(parent.is_symlink() for parent in directory.parents)
            or os.name == "posix"
            and (directory.stat().st_mode & 0o077 or directory.stat().st_uid != os.getuid())
        ):
            raise QualificationError("Resume directory must remain private and owned")
        value = read_json(directory / "journal.json", 4 * 1048576)
        strict_object(
            value,
            {
                "schema",
                "run_id",
                "created",
                "phase",
                "config_sha256",
                "profile_sha256",
                "context",
                "projects",
                "resources",
                "history",
                "completed",
                "cancelled",
            },
        )
        UUID(value["run_id"])
        if value["projects"] != {
            "source": "shadai-q-" + value["run_id"],
            "restore": "shadai-q-" + value["run_id"] + "-restore",
        }:
            raise QualificationError("Journal project identity changed")
        if (
            value["schema"] != 1
            or value["config_sha256"] != config_hash
            or value["context"] != context
            or value["profile_sha256"] != hashlib.sha256(canonical_bytes(profile)).hexdigest()
        ):
            raise QualificationError("Resume configuration or context differs from the recorded run")
        return cls(directory, value)

    def save(self):
        atomic_json(self.directory / "journal.json", self.value)

    def phase(self, name, *, completed=False):
        self.value["phase"] = name
        self.value["history"].append({"phase": name, "at": datetime.now(UTC).isoformat()})
        if completed and name not in self.value["completed"]:
            self.value["completed"].append(name)
        self.save()

    def add_resources(self, records):
        known = {(item["kind"], item["id"]): item for item in self.value["resources"]}
        for record in records:
            key = record["kind"], record["id"]
            if key in known and known[key] != record:
                raise QualificationError("Journal resource identity changed")
            known[key] = record
        self.value["resources"] = list(known.values())
        self.save()
