"""Global deadlines, restore success and cumulative private artifact boundaries."""

import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from shadai.qualification import lab as lab_module
from shadai.qualification import quality, schemas, target
from shadai.qualification.fixtures import expected_load_ids
from shadai.qualification.lab import Laboratory
from shadai.qualification.processes import run_browser_group
from shadai.qualification.schemas import QualificationError, load_profile

ROOT = Path(__file__).resolve().parents[1]


def laboratory(tmp_path):
    profile = load_profile(ROOT / "deploy/qualification/profiles/lab-smoke.json")
    return Laboratory(ROOT, tmp_path, profile, "exact-context")


def test_target_kube_subprocesses_share_one_budget(tmp_path, monkeypatch):
    profile = load_profile(ROOT / "deploy/qualification/profiles/target-plan.json")
    profile["limits"]["max_wall_seconds"] = 1
    profile["target"] = {"kubernetes_context": "exact", "namespace": "exact"}
    plan = tmp_path / "target.json"
    plan.write_text(json.dumps(profile))
    now, calls = [100], []
    monkeypatch.setattr(target.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(target, "kube_document", lambda _: {})

    def runner(command, **kwargs):
        calls.append(kwargs["timeout"])
        now[0] += 0.26
        return SimpleNamespace(returncode=0, stdout='{"items":[]}')

    monkeypatch.setattr(target.subprocess, "run", runner)
    with pytest.raises(QualificationError, match="wall budget"):
        target.target_action("kubernetes", plan, execute=True)
    assert len(calls) == 4 and calls == sorted(calls, reverse=True)
    assert calls[0] == 1 and calls[-1] < 0.23


def test_target_preparation_already_consumes_action_deadline(tmp_path, monkeypatch):
    profile = load_profile(ROOT / "deploy/qualification/profiles/target-plan.json")
    profile["limits"]["max_wall_seconds"] = 1
    now = [0]
    monkeypatch.setattr(target.time, "monotonic", lambda: now[0])

    def prepared(_):
        now[0] = 2
        return profile

    monkeypatch.setattr(target, "load_profile", prepared)
    with pytest.raises(QualificationError, match="wall budget"):
        target.target_action("plan", tmp_path / "unused")


def test_lab_sleep_and_probe_clip_same_remaining_budget(tmp_path, monkeypatch):
    lab = laboratory(tmp_path)
    now, slept, timeouts = [0], [], []
    lab.deadline = 0.25
    monkeypatch.setattr(lab_module.time, "monotonic", lambda: now[0])

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(lab_module.time, "sleep", sleep)
    monkeypatch.setattr(lab_module, "verify_resource", lambda *a: None)
    lab.docker = SimpleNamespace(
        inspect=lambda *a: {},
        runner=lambda *a, **k: timeouts.append(k["timeout"]) or SimpleNamespace(returncode=0),
    )
    assert lab.probe_status({"id": "owned", "service": "ingest-worker"}, "liveness")
    assert timeouts == [0.25]
    with pytest.raises(QualificationError, match="wall budget"):
        lab.sleep(32)
    assert slept == [0.25]


def fresh_result(count=10):
    return {"accepted": count, "accepted_scoped_ids": [f"new-{index}" for index in range(count)]}


def restored_result():
    return {
        "expected_logical_events": 11,
        "persisted": 11,
        "receipts": 11,
        "correlation_receipts": 11,
        "missing": [],
        "missing_receipts": [],
        "missing_correlations": [],
        "restored_pending_fixture_persisted": True,
    }


@pytest.mark.parametrize("count", [0, 1, 9])
def test_pending_recovery_alone_or_partial_fresh_load_cannot_pass(count):
    fresh = fresh_result(count)
    with pytest.raises(AssertionError):
        Laboratory.verify_fresh_restore(fresh, restored_result())
    with pytest.raises(QualificationError):
        expected_load_ids(fresh, pending="pending")


def test_restore_exact_ten_new_plus_pending_requires_all_three_stores():
    fresh, verification = fresh_result(), restored_result()
    Laboratory.verify_fresh_restore(fresh, verification)
    assert expected_load_ids(fresh, pending="pending") == set(fresh["accepted_scoped_ids"]) | {"pending"}
    for key in ("persisted", "receipts", "correlation_receipts", "expected_logical_events"):
        broken = {**verification, key: 10}
        with pytest.raises(AssertionError):
            Laboratory.verify_fresh_restore(fresh, broken)
    with pytest.raises(AssertionError):
        Laboratory.verify_fresh_restore(fresh, {**verification, "restored_pending_fixture_persisted": False})
    duplicated = {"accepted": 10, "accepted_scoped_ids": ["new-0"] * 10}
    with pytest.raises(QualificationError):
        expected_load_ids(duplicated, pending="pending")


@pytest.mark.parametrize("existing,archive,allowed", [(800000, 500000, False), (100000, 200000, True)])
def test_cumulative_archive_budget_checked_before_copy(tmp_path, monkeypatch, existing, archive, allowed):
    lab = laboratory(tmp_path)
    lab.profile["limits"]["max_disk_bytes"] = 1048576
    (tmp_path / "retained").write_bytes(b"x" * existing)
    calls = []
    monkeypatch.setattr(lab_module, "verify_resource", lambda *a: None)
    monkeypatch.setattr(lab, "remove", lambda record: None)

    def call(*args, **kwargs):
        calls.append(args)
        if args[1] == "wait":
            return "0"
        if args[1] == "logs":
            return json.dumps({"bytes": archive})
        if args[1] == "cp":
            (tmp_path / "owned.tar").write_bytes(b"x" * archive)
        return ""

    lab.docker = SimpleNamespace(inspect=lambda *a: {}, call=call)
    if allowed:
        assert lab.helper_result({"id": "owned-helper"}, copy_archive="owned.tar")["bytes"] == archive
        assert lab.retained_bytes() == existing + archive
    else:
        with pytest.raises(QualificationError, match="remaining artifact budget"):
            lab.helper_result({"id": "owned-helper"}, copy_archive="owned.tar")
        assert not (tmp_path / "owned.tar").exists()
        assert not any(args[1] == "cp" for args in calls)


def test_archive_export_reserves_metadata_and_rejects_exhaustion_before_helper(tmp_path, monkeypatch):
    lab = laboratory(tmp_path)
    lab.profile["limits"]["max_disk_bytes"] = 16 * 1048576
    (tmp_path / "retained").write_bytes(b"x" * (4 * 1048576))
    assert lab.artifact_remaining(reserve=10 * 1048576) == 2 * 1048576
    lab.profile["limits"]["max_disk_bytes"] = 5 * 1048576
    monkeypatch.setattr(lab, "run_owned", lambda *a, **k: pytest.fail("No helper after exhausted artifact budget"))
    with pytest.raises(QualificationError, match="artifact budget"):
        lab.archive_store("redis")


def test_frozen_catalog_ignores_unhashed_local_override_and_rejects_duplicate_ids(tmp_path):
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    data = (ROOT / "catalog/builtin/openai-api.yaml").read_bytes()
    (catalog / "entry.yaml").write_bytes(data)
    override = catalog / "__no_local_overrides__"
    override.mkdir()
    altered = yaml.safe_load(data)
    altered["signatures"]["domains"] = ["unhashed.invalid"]
    (override / "entry.yaml").write_text(yaml.safe_dump(altered))
    corpus = ROOT / "deploy/qualification/corpora/synthetic-reference.jsonl"
    result = quality.evaluate_quality(corpus, catalog)
    assert result["global"]["tp"] == 1
    assert result["catalog_sha256"] == {"entry.yaml": hashlib.sha256(data).hexdigest()}
    (catalog / "duplicate.yaml").write_bytes(data)
    with pytest.raises(QualificationError, match="duplicate item"):
        quality.frozen_matcher(catalog)


def test_corpus_digest_is_from_the_same_evaluated_bytes(tmp_path, monkeypatch):
    original = (ROOT / "deploy/qualification/corpora/synthetic-reference.jsonl").read_bytes()
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_bytes(original)
    matcher = quality.frozen_matcher

    def after_corpus_read(catalog):
        corpus.write_bytes(b"subsequent different file contents")
        return matcher(catalog)

    monkeypatch.setattr(quality, "frozen_matcher", after_corpus_read)
    result = quality.evaluate_quality(corpus, ROOT / "catalog/builtin")
    assert result["corpus_sha256"] == hashlib.sha256(original).hexdigest()
    assert result["coverage"]["total"] == 6


def test_catalog_mapping_uses_the_single_hashed_read_even_if_path_changes(tmp_path, monkeypatch):
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    path = catalog / "entry.yaml"
    original = (ROOT / "catalog/builtin/openai-api.yaml").read_bytes()
    path.write_bytes(original)
    validate = quality.CatalogYAMLEntry.model_validate
    calls = []

    def validating(data):
        calls.append(data)
        altered = copy.deepcopy(data)
        altered["signatures"]["domains"] = ["unhashed.invalid"]
        path.write_text(yaml.safe_dump(altered))
        return validate(data)

    monkeypatch.setattr(quality.CatalogYAMLEntry, "model_validate", validating)
    result = quality.evaluate_quality(ROOT / "deploy/qualification/corpora/synthetic-reference.jsonl", catalog)
    assert len(calls) == 1 and result["global"]["tp"] == 1
    assert result["catalog_sha256"] == {"entry.yaml": hashlib.sha256(original).hexdigest()}


@pytest.mark.parametrize("kind,limit", [("profile", 65536), ("yaml", 1048576), ("corpus", 64 * 1048576)])
def test_oversized_inputs_rejected_before_parse_or_index(tmp_path, monkeypatch, kind, limit):
    path = tmp_path / ("input.yaml" if kind == "yaml" else "input")
    with path.open("wb") as output:
        output.truncate(limit + 1)
    if kind == "profile":
        monkeypatch.setattr(schemas.json, "loads", lambda *a, **k: pytest.fail("No parse beyond byte limit"))

        def action():
            return schemas.read_json(path)
    elif kind == "yaml":
        monkeypatch.setattr(quality.yaml, "safe_load", lambda *a, **k: pytest.fail("No parse beyond byte limit"))

        def action():
            return quality.frozen_matcher(tmp_path)
    else:
        monkeypatch.setattr(quality.json, "loads", lambda *a, **k: pytest.fail("No parse beyond byte limit"))

        def action():
            return quality.read_corpus(path)

    with pytest.raises(QualificationError, match="bounded regular"):
        action()


def test_bounded_reader_uses_maximum_plus_one_and_rejects_directory(tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b"bounded")
    original, sizes = os.fdopen, []

    class ReadWitness:
        def __init__(self, descriptor, mode):
            self.source = original(descriptor, mode)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.source.close()

        def fileno(self):
            return self.source.fileno()

        def read(self, size):
            sizes.append(size)
            return self.source.read(size)

    monkeypatch.setattr(schemas.os, "fdopen", ReadWitness)
    assert schemas.bounded_read(path, 10) == b"bounded" and sizes == [11]
    with pytest.raises(QualificationError, match="regular"):
        schemas.bounded_read(tmp_path, 10)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO/symlink and O_NOFOLLOW/O_NONBLOCK boundary")
def test_fifo_symlink_and_file_replaced_by_fifo_never_block(tmp_path, monkeypatch):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    link = tmp_path / "link"
    link.symlink_to(fifo)
    before = time.monotonic()
    for path in (fifo, link):
        with pytest.raises(QualificationError, match="regular"):
            schemas.bounded_read(path, 10)
    assert time.monotonic() - before < 0.5
    path = tmp_path / "regular"
    path.write_bytes(b"one")
    original = os.open

    def swapped(name, flags, *args, **kwargs):
        if Path(name) == path:
            path.unlink()
            os.mkfifo(path)
            assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(schemas.os, "open", swapped)
    before = time.monotonic()
    with pytest.raises(QualificationError, match="regular-file boundary"):
        schemas.bounded_read(path, 10)
    assert time.monotonic() - before < 0.5


@pytest.mark.skipif(os.name != "posix", reason="Optional browser group cleanup requires POSIX; no Windows launch")
@pytest.mark.parametrize("mode", ["timeout", "cancel", "parent_exit"])
def test_posix_browser_descendants_cleaned_and_foreign_group_preserved(tmp_path, mode):
    pidfile = tmp_path / "descendant.pid"
    script = tmp_path / "browser-witness.py"
    script.write_text(
        "import pathlib,subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\n"
        f"pathlib.Path({str(pidfile)!r}).write_text(str(child.pid))\n"
        + ("" if mode == "parent_exit" else "time.sleep(30)\n")
    )
    foreign = subprocess.Popen([sys.executable, "-I", "-c", "import time;time.sleep(30)"], start_new_session=True)
    cancelled = threading.Event()
    timer = threading.Timer(0.4, cancelled.set) if mode == "cancel" else None
    if timer:
        timer.start()
    before = time.monotonic()
    try:
        if mode == "parent_exit":
            run_browser_group([sys.executable, "-I", str(script)], deadline=before + 3, cancelled=cancelled)
        else:
            with pytest.raises(QualificationError):
                run_browser_group([sys.executable, "-I", str(script)], deadline=before + 0.7, cancelled=cancelled)
        assert time.monotonic() - before < 2.3
        assert foreign.poll() is None
        assert pidfile.exists()
        pid = int(pidfile.read_text())
        state = Path(f"/proc/{pid}/stat")
        assert not state.exists() or state.read_text().split(")", 1)[1].strip().startswith("Z")
    finally:
        if timer:
            timer.cancel()
        os.killpg(foreign.pid, signal.SIGKILL)
        foreign.wait(timeout=1)


@pytest.mark.skipif(os.name == "posix", reason="Windows prerequisite witness")
def test_optional_browser_refuses_windows_before_launch(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("Browser launch forbidden on Windows"))
    with pytest.raises(QualificationError, match="POSIX"):
        run_browser_group(["node"], deadline=time.monotonic() + 5)
