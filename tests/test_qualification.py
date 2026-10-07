"""Qualification safety and hand-computed measurements, without fabricated Docker proof."""

import copy
import json
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import yaml

from shadai.qualification.journal import LABEL, RunJournal, resource_identity, verify_resource
from shadai.qualification.lab import Docker, Laboratory
from shadai.qualification.load import LoadSender, NoRedirect, endpoint, fixtures
from shadai.qualification.physical import compare_scrape
from shadai.qualification.quality import evaluate_quality, metrics, read_corpus
from shadai.qualification.schemas import QualificationError, load_profile, read_json, report, validate_profile
from shadai.qualification.snapshot import digest_file, export_volume, import_volume, validate_members
from shadai.qualification.target import kube_document, target_action

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy/qualification/profiles/lab-smoke.json"
CORPUS = ROOT / "deploy/qualification/corpora/synthetic-reference.jsonl"


@pytest.fixture
def profile():
    return load_profile(PROFILE)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True),
        ("schema", 2),
        ("scope", "production"),
        ("scenarios", ["baseline", "baseline"]),
        ("unexpected", 1),
    ],
)
def test_profile_strict_versions_and_fields(profile, field, value):
    profile[field] = value
    with pytest.raises(QualificationError):
        validate_profile(profile)


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), 0, 10000001])
def test_profile_budget_invalid(profile, value):
    profile["load"]["total_events"] = value
    with pytest.raises(QualificationError):
        validate_profile(profile)


def test_json_duplicate_and_nonfinite(tmp_path):
    for payload in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
        path = tmp_path / "input.json"
        path.write_text(payload)
        with pytest.raises(QualificationError):
            read_json(path)


def test_requested_missing_proof_and_unexecuted_never_pass(profile):
    assert report(profile, [])["exit_code"] == 2
    with pytest.raises(QualificationError):
        report(profile, [{"scenario": "baseline", "status": "passed", "executed": False, "required": True}])
    assert (
        report(profile, [{"scenario": "baseline", "status": "failed", "executed": True, "required": True}])["exit_code"]
        == 1
    )


def test_explicit_objective_missing_or_failed_cannot_pass(profile):
    profile["scenarios"] = ["baseline"]
    profile["objectives"] = {"max_http_p95_seconds": 0.1}
    scenario = {"scenario": "baseline", "status": "passed", "executed": True, "required": True}
    assert report(profile, [scenario])["exit_code"] == 2
    scenario["measurements"] = {"load": {"http_latency_p95_seconds": 0.2}}
    assert report(profile, [scenario])["exit_code"] == 1
    scenario["measurements"]["load"]["http_latency_p95_seconds"] = 0.05
    assert report(profile, [scenario])["exit_code"] == 0


def inspection(run, role="source", created="date", identifier="owned-id"):
    return {
        "Id": identifier,
        "Created": created,
        "Config": {
            "Labels": {
                LABEL + "run": run,
                LABEL + "role": role,
                "com.docker.compose.project": "shadai-q-" + run,
                "com.docker.compose.service": "api",
            }
        },
        "State": {"Running": False},
    }


@pytest.mark.parametrize("change", ["run", "role", "project", "id", "created"])
def test_foreign_replaced_resources_refused(change):
    run = str(uuid4())
    original = inspection(run)
    recorded = resource_identity("container", original, run, "source", "shadai-q-" + run)
    mutated = copy.deepcopy(original)
    if change == "id":
        mutated["Id"] = "reused-name-new-id"
    elif change == "created":
        mutated["Created"] = "later"
    else:
        key = {"run": LABEL + "run", "role": LABEL + "role", "project": "com.docker.compose.project"}[change]
        mutated["Config"]["Labels"][key] = "foreign"
    with pytest.raises(QualificationError):
        verify_resource(recorded, mutated)


def test_journal_resume_binding_and_cancellation_retains_resources(tmp_path, profile):
    directory = tmp_path / "private-run"
    journal = RunJournal.create(directory, profile, "config", "exact-context")
    recorded = resource_identity(
        "container",
        inspection(journal.value["run_id"]),
        journal.value["run_id"],
        "source",
        journal.value["projects"]["source"],
    )
    journal.add_resources([recorded])
    journal.value["cancelled"] = True
    journal.phase("cancelled")
    resumed = RunJournal.resume(directory, profile, "config", "exact-context")
    assert resumed.value["resources"] == [recorded] and resumed.value["cancelled"]
    with pytest.raises(QualificationError):
        RunJournal.resume(directory, profile, "changed", "exact-context")


def test_cleanup_reinspection_idempotence_and_opt_in_volumes(tmp_path, profile):
    lab = Laboratory(ROOT, tmp_path / "run", profile, "exact-context")
    lab.journal = RunJournal.create(lab.directory, profile, lab.config_hash, lab.context)
    run = lab.journal.value["run_id"]
    original = inspection(run)
    recorded = resource_identity("container", original, run, "source", "shadai-q-" + run)
    lab.journal.add_resources([recorded])
    calls = []

    class FakeDocker:
        def inspect(self, *args, **kwargs):
            return original if recorded in lab.journal.value["resources"] else None

        def call(self, *args):
            calls.append(args)

    lab.docker = FakeDocker()
    assert lab.clean()["resources"] == [recorded] and not calls
    assert lab.clean(execute=True)["cleaned"]
    assert calls == [("container", "rm", "owned-id")]
    assert lab.clean(execute=True)["cleaned"] and len(calls) == 1


def test_docker_context_always_explicit_and_errors_sanitized():
    commands = []

    def runner(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=1, stderr="secret-provider-error", stdout="")

    with pytest.raises(QualificationError) as error:
        Docker("ctx", runner=runner).call("info")
    assert commands == [["docker", "--context", "ctx", "info"]]
    assert "secret" not in str(error.value)


def test_docker_missing_volume_is_absent_but_daemon_down_is_failure():
    def runner(command, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="Error response from daemon: get owned: no such volume")

    assert Docker("ctx", runner=runner).inspect("volume", "owned", absent=True) is None

    def down(command, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="Cannot connect to the Docker daemon")

    with pytest.raises(QualificationError):
        Docker("ctx", runner=down).inspect("volume", "owned", absent=True)


def test_exact_retry_fixtures_distinct_scoped_runs_and_no_redirect(profile):
    run = str(uuid4())
    args = (run, "baseline", profile, "scoped", "2026-01-01T00:00:00+00:00")
    first = fixtures(*args)
    assert first == fixtures(*args)
    ids = [event["event_id"] for batch in first for event in json.loads(batch)["events"]]
    assert len(ids) == len(set(ids)) == 1000
    assert first != fixtures(str(uuid4()), *args[1:])
    assert NoRedirect().redirect_request(None, None, None, None, None, None) is None
    with pytest.raises(QualificationError):
        endpoint("https://user:secret@target.invalid")


def test_load_retries_same_bytes_unique_acceptance_and_budget(tmp_path, profile, monkeypatch):
    profile["load"].update(total_events=10, batch_size=10)
    profile["limits"]["max_requests"] = 2
    payloads = []

    def request(self, url, **kwargs):
        payloads.append(kwargs["body"])
        return (503, b"", "none") if len(payloads) == 1 else (202, b'{"received":10}', "none")

    monkeypatch.setattr("shadai.qualification.http_transport.HttpTransport.request", request)
    result = LoadSender(profile, str(uuid4()), "retry", tmp_path, "scoped").run("http://127.0.0.1:1234", "private")
    assert result["attempted"] == result["accepted"] == 10
    assert result["requests"] == 2 and result["http_status_counts"] == {"503": 1, "202": 1}
    assert payloads[0] == payloads[1] and len(set(result["accepted_scoped_ids"])) == 10


def test_load_cancelled_and_byte_budget_never_submit(tmp_path, profile, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "shadai.qualification.http_transport.HttpTransport.request", lambda *a, **k: calls.append("network")
    )
    sender = LoadSender(profile, str(uuid4()), "cancel", tmp_path, "scoped")
    sender.stop()
    result = sender.run("http://127.0.0.1:1234", "private")
    assert result["requests"] == 0 and result["attempted"] == 0 and result["cancelled"]
    profile["limits"]["max_request_bytes"] = 1
    before = len(calls)
    with pytest.raises(QualificationError):
        LoadSender(profile, str(uuid4()), "tiny", tmp_path, "scoped").run("http://127.0.0.1:1234", "private")
    assert len(calls) == before


def tar_member(name, kind=tarfile.REGTYPE, link=""):
    entry = tarfile.TarInfo(name)
    entry.type, entry.linkname, entry.mode = kind, link, 0o600
    return entry


@pytest.mark.parametrize(
    "member",
    [
        tar_member("../escape"),
        tar_member("/absolute"),
        tar_member("safe", tarfile.SYMTYPE, "../../escape"),
        tar_member("safe", tarfile.SYMTYPE, "/absolute"),
        tar_member("pipe", tarfile.FIFOTYPE),
        tar_member("device", tarfile.CHRTYPE),
        tar_member("hard", tarfile.LNKTYPE, "missing"),
    ],
)
def test_archive_malicious_refused_before_destination_mutation(tmp_path, member):
    archive = tmp_path / "bad.tar"
    with tarfile.open(archive, "w") as output:
        output.addfile(member)
    destination = tmp_path / "empty"
    destination.mkdir()
    with pytest.raises(QualificationError):
        import_volume(archive, destination, digest_file(archive), 1048576)
    assert list(destination.iterdir()) == []


def test_archive_clickhouse_internal_symlink_and_transitive_escape():
    members = [
        tar_member("store", tarfile.DIRTYPE),
        tar_member("store/uuid", tarfile.DIRTYPE),
        tar_member("data/shadai/events", tarfile.SYMTYPE, "../../store/uuid"),
    ]
    assert validate_members(members, 1024) == 0
    members.append(tar_member("store/uuid", tarfile.SYMTYPE, "../../outside"))
    with pytest.raises(QualificationError):
        validate_members(members, 1024)


def test_archive_roundtrip_and_corrupt_hash(tmp_path):
    source, restored = tmp_path / "source", tmp_path / "restored"
    source.mkdir(mode=0o700)
    restored.mkdir()
    (source / "sub").mkdir(mode=0o700)
    (source / "sub/data").write_bytes(b"cold-store-bytes")
    archive = tmp_path / "owned.tar"
    proof = export_volume(source, archive, 1048576)
    assert proof["unpacked_bytes"] == 16
    if os.name == "posix":
        import_volume(archive, restored, proof["sha256"], 1048576)
        assert (restored / "sub/data").read_bytes() == b"cold-store-bytes"
        assert restored.stat().st_mode & 0o777 == source.stat().st_mode & 0o777
    with pytest.raises(QualificationError):
        import_volume(archive, restored, "0" * 64, 1048576)


def test_archive_uid_overflow_and_compression_refused_before_writes(tmp_path):
    member = tar_member("file")
    member.uid = 2**40
    with pytest.raises(QualificationError):
        validate_members([member], 1048576)
    archive = tmp_path / "compressed.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        output.addfile(tar_member("file"))
    destination = tmp_path / "empty"
    destination.mkdir()
    with pytest.raises(tarfile.ReadError):
        import_volume(archive, destination, digest_file(archive), 1048576)
    assert list(destination.iterdir()) == []


def test_quality_reference_hand_math_and_unknown_family():
    measured = evaluate_quality(CORPUS, ROOT / "catalog/builtin")
    assert {key: measured["global"][key] for key in ("tp", "fp", "fn", "tn")} == {"tp": 1, "fp": 1, "fn": 2, "tn": 1}
    assert measured["global"]["precision"] == 0.5
    assert measured["global"]["recall"] == 1 / 3
    assert measured["global"]["f1"] == 0.4
    assert measured["labelling_coverage"] == 5 / 6
    assert measured["coverage"]["no_observable_signal"] == 1
    assert measured["families"]["unknown"]["recall"] is None
    assert measured["catalog_sha256"] and all(
        set(case) == {"case_id", "status", "attribution"} for case in measured["cases"]
    )
    assert metrics({})["undefined"] == {key: "zero_denominator" for key in ("precision", "recall", "f1")}


def test_quality_ambiguity_is_positive_false_negative(tmp_path):
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    entry = yaml.safe_load((ROOT / "catalog/builtin/openai-api.yaml").read_text())
    for index in (1, 2):
        entry["id"] = "synthetic-" + str(index)
        (catalog / f"{index}.yaml").write_text(yaml.safe_dump(entry))
    result = evaluate_quality(CORPUS, catalog)
    assert result["coverage"]["ambiguous"] == 2
    assert result["global"]["fn"] == 3 and result["global"]["tp"] == 0


def test_quality_duplicate_id_rejected(tmp_path):
    corpus = tmp_path / "duplicate.jsonl"
    lines = CORPUS.read_text().splitlines()
    corpus.write_text("\n".join([lines[0], lines[1], lines[1]]))
    with pytest.raises(QualificationError):
        read_corpus(corpus)


def target_profile():
    return load_profile(ROOT / "deploy/qualification/profiles/target-plan.json")


def test_missing_target_is_honest_and_no_execution(tmp_path):
    plan = ROOT / "deploy/qualification/profiles/target-plan.json"
    assert target_action("plan", plan)["exit_code"] == 2
    assert target_action("load", plan)["exit_code"] == 2
    assert target_action("evaluate", plan)["exit_code"] == 2
    with pytest.raises(QualificationError):
        kube_document(target_profile())


def test_caller_written_success_is_not_live_target_evidence(tmp_path):
    import hashlib

    from shadai.qualification.schemas import canonical_bytes

    profile = target_profile()
    fake = {
        "schema": 1,
        "scope": "target",
        "profile_sha256": hashlib.sha256(canonical_bytes(profile)).hexdigest(),
        "scenarios": [
            {"scenario": name, "status": "passed", "executed": True, "required": True} for name in profile["scenarios"]
        ],
    }
    path = tmp_path / "self-asserted.json"
    path.write_text(json.dumps(fake))
    result = target_action("evaluate", ROOT / "deploy/qualification/profiles/target-plan.json", evidence=path)
    assert result["exit_code"] == 2


def valid_kube():
    profile = target_profile()
    profile["installation"] = "installation-a"
    profile["target"] = {
        "namespace": "install-a",
        "kubernetes_context": "operator-context",
        "origin": "https://console.operator.invalid",
        "issuer": "https://idp.operator.invalid",
        "stores": {name: "dedicated-" + name for name in ("postgres", "redis", "clickhouse")},
        "images": {
            name: "registry.operator.invalid/shadai:" + name + "@sha256:" + "a" * 64
            for name in ("api", "frontend", "worker")
        },
        "egress_cidrs": ["192.0.2.1/32"],
        "runtime_secret_name": "runtime-a",
        "tls_secret_name": "tls-a",
        "ingress_namespace": "ingress-a",
        "ingress_pod_selector": {"app.kubernetes.io/name": "operator-ingress"},
    }
    return profile


def test_kube_replicas_pdb_anti_affinity_probe_and_private_ingress():
    document = kube_document(valid_kube())
    deployments = [item for item in document["items"] if item["kind"] == "Deployment"]
    assert [item["spec"]["replicas"] for item in deployments] == [2, 2, 2, 2, 1]
    for item in deployments:
        assert item["spec"]["strategy"]["rollingUpdate"] == {"maxSurge": 0, "maxUnavailable": 1}
        assert (
            item["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"][
                "requiredDuringSchedulingIgnoredDuringExecution"
            ][0]["topologyKey"]
            == "kubernetes.io/hostname"
        )
    frontend = next(item for item in deployments if item["metadata"]["name"] == "frontend")
    assert len(frontend["spec"]["template"]["spec"]["volumes"]) == 1
    assert len([item for item in document["items"] if item["kind"] == "PodDisruptionBudget"]) == 4
    policy = next(item for item in document["items"] if item["kind"] == "NetworkPolicy")
    boundary = policy["spec"]["ingress"][0]["from"][0]
    assert set(boundary) == {"namespaceSelector", "podSelector"}


@pytest.mark.parametrize(
    "field,value",
    [
        ("egress_cidrs", ["0.0.0.0/0"]),
        ("ingress_pod_selector", {}),
        ("runtime_secret_name", "CHANGEME"),
        ("origin", "https://example.com"),
    ],
)
def test_kube_rejects_implicit_or_placeholder_boundaries(field, value):
    profile = valid_kube()
    profile["target"][field] = value
    with pytest.raises(QualificationError):
        kube_document(profile)


def test_physical_series_comparison_and_missing_unknown():
    scrape = "\n".join(
        [
            "node_memory_MemTotal_bytes 1000",
            "node_memory_MemAvailable_bytes 500",
            'node_filesystem_size_bytes{mountpoint="/"} 10000',
            'node_filesystem_avail_bytes{mountpoint="/"} 4000',
        ]
    )
    proof = compare_scrape(scrape, {"MemTotal": 1000, "MemAvailable": 500}, {"size": 10000, "available": 4000})
    assert proof["filesystem_sum"] is False
    with pytest.raises(QualificationError):
        compare_scrape("", {}, {})
