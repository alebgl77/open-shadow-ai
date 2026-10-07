"""Real archive bytes at a modeled Docker tmpfs lifecycle; native Docker remains CI."""

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_qualification_pressure_diagnostics import CliModel, create_lab

from shadai.qualification.lab import (
    EXPORT_ARCHIVE_LIMIT,
    EXPORT_METADATA_MARGIN,
    EXPORT_SNAPSHOT_CODE,
    Docker,
    DockerOperationError,
    Laboratory,
)
from shadai.qualification.schemas import QualificationError
from shadai.qualification.snapshot import digest_file, export_volume


class ArchiveCli(CliModel):
    """Only replace Docker execution; real ownership, journal, tar, hash and copy checks run."""

    def __init__(self, lab):
        super().__init__(lab)
        self.source = lab.directory.parent / "source-volume"
        self.source.mkdir()
        (self.source / "appendonly.aof").write_bytes(b"owned AOF\r\n\x1a")
        self.roots = {next(iter(self.volumes)): self.source}
        self.commands, self.mounts, self.temporary = {}, {}, {}
        self.after_create = self.capture_failure = self.copy_failure = self.copy_damage = None
        self.created_mutation = None
        self.refuse_output_remove = False
        self.helper_replacement = False
        self.create_seen = []
        for row in self.containers.values():
            if row["Config"]["Labels"].get("com.docker.compose.service") == "labredis-pressure":
                row["State"]["Running"] = False

    def runner(self, command, **kwargs):
        args = command[3:]
        kind, operation = args[:2]
        if operation == "inspect" and kind == "container" and self.helper_replacement and \
                self.lab.docker.checkpoint == "pressure_export_copy_inspect":
            self.containers[args[2]]["Created"] = "replaced-container"
        if operation == "inspect" and self.capture_failure and \
                self.lab.docker.checkpoint == "pressure_export_volume_capture":
            raise self.capture_failure
        if operation == "cp":
            self.calls.append(tuple(args))
            self.pairs.append((self.lab.docker.checkpoint, "container_cp"))
            if self.copy_failure:
                raise self.copy_failure
            identifier, path = args[2].split(":", 1)
            root = (self.mounts[identifier].get("/export") if path == "/export/archive.tar"
                    else self.temporary[identifier])
            archive = root / "archive.tar" if root else None
            if archive is None or not archive.exists():
                return self.response(code=1, stderr="No such archive after helper exit")
            data = archive.read_bytes()
            if self.copy_damage == "partial":
                data = data[:-1]
            elif self.copy_damage == "hash":
                data = bytes([data[0] ^ 1]) + data[1:]
            with Path(args[3]).open("xb") as output:
                output.write(data)
            return self.response()
        if operation == "rm" and kind == "volume":
            name = args[2]
            if "_export_" in name and (self.refuse_output_remove or any(
                name in [entry["Name"] for entry in row.get("Mounts", [])]
                for row in self.containers.values()
            )):
                return self.response(code=1, stderr="Owned export volume is still in use")
            result = super().runner(command, **kwargs)
            if "_export_" in name:
                root = self.roots.pop(name)
                for path in root.iterdir():
                    path.unlink()
                root.rmdir()
            return result
        result = super().runner(command, **kwargs)
        if result.returncode:
            return result
        if operation == "create":
            self.create_seen.append(kind)
            if kind == "volume":
                name = args[-1]
                root = self.lab.directory.parent / name
                root.mkdir()
                self.roots[name] = root
            else:
                identifier = result.stdout
                image_index = args.index("sha256:" + "b" * 64)
                self.commands[identifier] = args[image_index + 1:]
                mounts = {}
                for index, value in enumerate(args):
                    if index and args[index - 1] == "--mount":
                        fields = dict(part.split("=", 1) for part in value.split(",") if "=" in part)
                        mounts[fields["dst"]] = self.roots[fields["src"]]
                self.mounts[identifier] = mounts
                self.containers[identifier]["Mounts"] = [{"Type": "volume", "Name": fields["src"]}
                    for index, value in enumerate(args) if index and args[index - 1] == "--mount"
                    for fields in [dict(part.split("=", 1) for part in value.split(",") if "=" in part)]]
                temporary = self.lab.directory.parent / ("tmpfs-" + identifier[:8])
                temporary.mkdir()
                self.temporary[identifier] = temporary
            if self.created_mutation and self.created_mutation[0] == kind:
                row = self.volumes[args[-1]] if kind == "volume" else self.containers[result.stdout]
                if self.created_mutation[1] == "labels":
                    labels = row["Labels"] if kind == "volume" else row["Config"]["Labels"]
                    labels["com.shadai.qualification.run"] = "foreign"
                elif self.created_mutation[1] == "image":
                    row["Image"] = "sha256:" + "f" * 64
                else:
                    row["Name" if kind == "volume" else "Id"] = "untrusted-identifier"
            if self.after_create and self.after_create[0] == kind:
                raise self.after_create[1]
        if kind == "container" and operation == "start":
            identifier = args[2]
            invocation = self.commands[identifier]
            path = invocation[invocation.index("--archive") + 1]
            root = self.mounts[identifier]["/export"] if path.startswith("/export/") else self.temporary[identifier]
            self.result = export_volume(self.source, root / "archive.tar", int(invocation[-1]))
        if kind == "container" and operation == "wait":
            identifier = args[2]
            temporary = self.temporary[identifier]
            # A stopped Docker container has no surviving tmpfs mount/files.
            for path in temporary.iterdir():
                path.unlink()
            temporary.rmdir()
        return result


@pytest.fixture
def export_lab(tmp_path, monkeypatch):
    lab, _ = create_lab(tmp_path, monkeypatch, lab_type=Laboratory)
    cli = ArchiveCli(lab)
    lab.docker = Docker(lab.context, runner=cli.runner)
    return lab, cli


def test_owned_archive_survives_helper_stop_with_byte_exact_copy_and_source_unchanged(export_lab):
    lab, cli = export_lab
    before = (cli.source / "appendonly.aof").read_bytes()
    expected_limit = min(lab.artifact_remaining(), EXPORT_ARCHIVE_LIMIT)
    with lab.pressure_diagnostics("export"):
        result = lab.archive_store("labredis-pressure")
    archive = lab.directory / result["archive"]
    assert archive.stat().st_size == result["bytes"] and digest_file(archive) == result["sha256"]
    assert (cli.source / "appendonly.aof").read_bytes() == before
    assert not any("_export_" in row["id"] for row in lab.journal.value["resources"])
    assert "d" * 64 not in cli.containers
    create = next(call for call in cli.calls if call[:2] == ("container", "create"))
    assert "--read-only" in create and create[create.index("--network") + 1] == "none"
    assert create[create.index("--cap-drop") + 1] == "ALL"
    assert create[create.index("--cap-add") + 1] == "DAC_READ_SEARCH"
    assert create[create.index("--tmpfs") + 1] == "/tmp:rw,size=1073741824"
    mounts = [value for index, value in enumerate(create) if index and create[index - 1] == "--mount"]
    assert len(mounts) == 2 and mounts[0].endswith(",dst=/volume,readonly")
    assert mounts[1].endswith(",dst=/export,volume-nocopy") and "readonly" not in mounts[1]
    invocation = cli.commands["d" * 64]
    assert invocation[:2] == ["-c", EXPORT_SNAPSHOT_CODE]
    cap = int(invocation[2])
    assert cap == expected_limit and 0 < cap <= EXPORT_ARCHIVE_LIMIT
    assert invocation[3:] == ["snapshot", "export", "--archive", "/export/archive.tar", "--max-bytes",
                              str(cap - EXPORT_METADATA_MARGIN)]
    copied = next(call for call in cli.calls if call[:2] == ("container", "cp"))
    assert copied[2] == "d" * 64 + ":/export/archive.tar"
    assert cli.calls.index(copied) > next(index for index, call in enumerate(cli.calls)
                                          if call[:2] == ("container", "wait"))


@pytest.mark.parametrize("kind", ["volume", "container"])
@pytest.mark.parametrize("primary", [DockerOperationError("docker_nonzero", 17), KeyboardInterrupt(), SystemExit(23)])
def test_lost_create_response_captures_owned_exact_resource_for_global_cleanup(export_lab, kind, primary):
    lab, cli = export_lab
    cli.after_create = kind, primary
    with pytest.raises(type(primary)) as caught:
        with lab.pressure_diagnostics("export"):
            lab.archive_store("labredis-pressure")
    assert caught.value is primary
    exported = [row for row in lab.journal.value["resources"] if "_export_" in row["id"] or row["id"] == "d" * 64]
    assert len(exported) == (1 if kind == "volume" else 2)
    owned_ids = {row["id"] for row in exported}
    assert lab.clean(execute=True, remove_volumes=True)["cleaned"]
    assert not owned_ids.intersection(cli.volumes) and "d" * 64 not in cli.containers
    assert not (lab.directory / "labredis-pressure-cold.tar").exists()


@pytest.mark.parametrize("primary", [DockerOperationError("docker_nonzero", 17), KeyboardInterrupt(), SystemExit(23)])
@pytest.mark.parametrize("secondary", [DockerOperationError("docker_timeout"), KeyboardInterrupt(), SystemExit(29)])
def test_failed_capture_preserves_primary_or_secondary_cancellation(export_lab, primary, secondary):
    lab, cli = export_lab
    cli.after_create, cli.capture_failure = ("volume", primary), secondary
    cancellation = isinstance(secondary, (KeyboardInterrupt, SystemExit))
    with pytest.raises(type(secondary) if cancellation else type(primary)) as caught:
        with lab.pressure_diagnostics("export"):
            lab.archive_store("labredis-pressure")
    assert caught.value is (secondary if cancellation else primary)
    assert "owned_export_capture_failed" in primary.__notes__
    assert lab.failure["stage"] == "pressure_export_volume_create"
    assert lab.failure["secondary"][0]["stage"] == "pressure_export_volume_capture"
    assert lab.write_report() != 0


@pytest.mark.parametrize("damage", ["partial", "hash"])
def test_partial_or_changed_archive_is_refused_and_owned_resources_remain_cleanable(export_lab, damage):
    lab, cli = export_lab
    cli.copy_damage = damage
    with pytest.raises(QualificationError):
        lab.archive_store("labredis-pressure")
    assert any("_export_" in row["id"] for row in lab.journal.value["resources"])
    assert lab.clean(execute=True, remove_volumes=True)["cleaned"]
    assert not any("_export_" in name for name in cli.volumes)


def test_replaced_helper_is_refused_before_copy_and_never_removed(export_lab):
    lab, cli = export_lab
    cli.helper_replacement = True
    with pytest.raises(QualificationError, match="replaced"):
        with lab.pressure_diagnostics("export"):
            lab.archive_store("labredis-pressure")
    assert not any(call[:2] == ("container", "cp") for call in cli.calls)
    with pytest.raises(QualificationError, match="replaced"):
        lab.clean(execute=True, remove_volumes=True)
    assert "d" * 64 in cli.containers


def test_export_collision_fails_before_creation_and_preserves_foreign_volume(export_lab, monkeypatch):
    lab, cli = export_lab
    monkeypatch.setattr("shadai.qualification.lab.uuid4", lambda: SimpleNamespace(hex="1" * 32))
    name = lab.journal.value["projects"]["source"] + "_export_" + "1" * 32
    foreign = {"Name": name, "CreatedAt": "foreign", "Labels": {"owner": "foreign"}}
    cli.volumes[name] = foreign
    with pytest.raises(QualificationError, match="already exists"):
        lab.archive_store("labredis-pressure")
    assert cli.create_seen == [] and cli.volumes[name] is foreign
    assert not any(row["id"] == name for row in lab.journal.value["resources"])


@pytest.mark.parametrize("kind,mutation", [("volume", "labels"), ("volume", "identifier"), ("container", "labels"),
                                          ("container", "image"), ("container", "identifier")])
def test_capture_never_adopts_foreign_or_wrong_image_resources(export_lab, kind, mutation):
    lab, cli = export_lab
    cli.created_mutation = kind, mutation
    with pytest.raises(QualificationError):
        lab.archive_store("labredis-pressure")
    if kind == "volume":
        assert not any("_export_" in row["id"] for row in lab.journal.value["resources"])
        assert lab.clean(execute=True, remove_volumes=True)["cleaned"]
        assert any("_export_" in name for name in cli.volumes)
    else:
        assert not any(row["id"] == "d" * 64 for row in lab.journal.value["resources"])
        with pytest.raises(DockerOperationError):
            lab.clean(execute=True, remove_volumes=True)
        assert "d" * 64 in cli.containers and any("_export_" in name for name in cli.volumes)


@pytest.mark.parametrize("primary", [DockerOperationError("docker_nonzero", 17), KeyboardInterrupt(), SystemExit(23)])
def test_copy_error_or_cancel_retains_exact_owned_cleanup_records(export_lab, primary):
    lab, cli = export_lab
    cli.copy_failure = primary
    with pytest.raises(type(primary)) as caught:
        lab.archive_store("labredis-pressure")
    assert caught.value is primary
    assert any(row["id"] == "d" * 64 for row in lab.journal.value["resources"])
    assert any("_export_" in row["id"] for row in lab.journal.value["resources"])
    assert lab.clean(execute=True, remove_volumes=True)["cleaned"]
    assert "d" * 64 not in cli.containers and not any("_export_" in name for name in cli.volumes)


def test_refused_export_volume_cleanup_cannot_return_a_successful_archive(export_lab):
    lab, cli = export_lab
    cli.refuse_output_remove = True
    with pytest.raises(DockerOperationError):
        lab.archive_store("labredis-pressure")
    assert "d" * 64 not in cli.containers
    assert any("_export_" in row["id"] for row in lab.journal.value["resources"])
    with pytest.raises(DockerOperationError):
        lab.clean(execute=True, remove_volumes=True)
    assert lab.journal.value["phase"] != "cleaned"


def test_export_helper_collision_preserves_foreign_helper_and_cleans_only_owned_output(export_lab, monkeypatch):
    lab, cli = export_lab
    monkeypatch.setattr("shadai.qualification.lab.uuid4", lambda: SimpleNamespace(hex="1" * 32))
    name = lab.journal.value["projects"]["source"] + "-export-" + "1" * 32
    foreign = {"Id": "9" * 64, "Name": "/" + name, "Created": "foreign", "Config": {"Labels": {}}}
    cli.containers[foreign["Id"]] = foreign
    with pytest.raises(QualificationError, match="already exists"):
        lab.archive_store("labredis-pressure")
    assert cli.create_seen == ["volume"]
    assert lab.clean(execute=True, remove_volumes=True)["cleaned"]
    assert cli.containers[foreign["Id"]] is foreign
    assert not any("_export_" in name for name in cli.volumes)


@pytest.mark.parametrize("available", [-1, 0, 1, EXPORT_METADATA_MARGIN])
def test_insufficient_output_cap_is_refused_before_any_creation(export_lab, monkeypatch, available):
    lab, cli = export_lab
    monkeypatch.setattr(lab, "artifact_remaining", lambda **kwargs: available)
    with pytest.raises(QualificationError, match="artifact budget"):
        lab.archive_store("labredis-pressure")
    assert cli.create_seen == [] and not cli.calls


@pytest.mark.skipif(os.name != "posix", reason="real inherited RLIMIT_FSIZE proof requires POSIX")
@pytest.mark.parametrize("bytes_requested", [4096, 16384])
def test_archive_writer_receives_hard_limit_in_exact_bytes_before_first_write(tmp_path, bytes_requested):
    target = tmp_path / "bounded-output.tar"
    # Only the application entry is substituted with a real tar writer. The
    # approved wrapper, actual resource.setrlimit and kernel file limit all run.
    harness = """import io,runpy,sys,tarfile
target=sys.argv[1]; requested=int(sys.argv[2]); code=sys.argv[3]
def writer(*args,**kwargs):
    with tarfile.open(target,'w') as archive:
        member=tarfile.TarInfo('payload');member.size=requested
        archive.addfile(member,io.BytesIO(b'x'*requested))
runpy.run_module=writer
sys.argv=['-c','12288','snapshot','export']
exec(code)
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", harness, str(target), str(bytes_requested),
                             EXPORT_SNAPSHOT_CODE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=5, check=False)
    assert result.returncode == (0 if bytes_requested == 4096 else 1)
    assert target.stat().st_size <= 12288
    if bytes_requested == 4096:
        assert target.stat().st_size == 10240


def test_export_helper_command_uses_effective_owned_volume_and_no_bind(export_lab):
    lab, cli = export_lab
    lab.archive_store("labredis-pressure")
    creation = next(call for call in cli.calls if call[:2] == ("container", "create"))
    assert not any("type=bind" in value for value in creation)
    assert sum(value == "--mount" for value in creation) == 2
    assert not any("--env" in value or "--privileged" in value for value in creation)
    assert cli.create_seen == ["volume", "container"]
