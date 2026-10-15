"""Keep the reviewed main protection request aligned with actual PR check names."""

import copy
import importlib.util
import itertools
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
APP_ID = 15368
REVIEW_POLICY = {
    "dismiss_stale_reviews": True,
    "require_code_owner_reviews": False,
    "required_approving_review_count": 0,
    "require_last_push_approval": False,
}


@pytest.fixture
def repository_assets():
    policy = json.loads((ROOT / ".github/main-protection.json").read_text(encoding="utf-8"))
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    return policy, workflow


def pr_contexts(workflow):
    """Expand only literal matrices; refuse unsupported naming/conditional changes."""
    contexts = []
    for job_id, job in workflow["jobs"].items():
        if job_id == "signed-image-evidence":
            assert job["if"] == "github.event_name == 'push'"
            continue
        assert "if" not in job and "name" not in job
        matrix = job.get("strategy", {}).get("matrix")
        if matrix is None:
            contexts.append(job_id)
            continue
        assert type(matrix) is dict and matrix
        assert not {"include", "exclude"}.intersection(matrix)
        for values in matrix.values():
            assert type(values) is list and values
            assert all(type(value) is str and value for value in values)
            assert len(values) == len(set(values))
        for combination in itertools.product(*matrix.values()):
            contexts.append(f"{job_id} ({', '.join(combination)})")
    assert len(contexts) == len(set(contexts))
    return set(contexts)


def assert_policy(policy, workflow):
    assert set(policy) == {
        "required_status_checks", "enforce_admins", "required_pull_request_reviews", "restrictions",
        "required_conversation_resolution", "allow_force_pushes", "allow_deletions",
    }
    status = policy["required_status_checks"]
    assert set(status) == {"strict", "checks"}
    assert status["strict"] is True
    checks = status["checks"]
    assert type(checks) is list and len(checks) == 32
    for check in checks:
        assert set(check) == {"context", "app_id"}
        assert type(check["context"]) is str
        assert type(check["app_id"]) is int and check["app_id"] == APP_ID
    contexts = [check["context"] for check in checks]
    assert len(contexts) == len(set(contexts))
    assert set(contexts) == pr_contexts(workflow)
    assert policy["enforce_admins"] is True
    reviews = policy["required_pull_request_reviews"]
    assert type(reviews) is dict and set(reviews) == set(REVIEW_POLICY)
    for key, expected in REVIEW_POLICY.items():
        assert type(reviews[key]) is type(expected) and reviews[key] == expected
    assert policy["restrictions"] is None
    assert policy["required_conversation_resolution"] is True
    assert policy["allow_force_pushes"] is False
    assert policy["allow_deletions"] is False


def test_main_policy_matches_every_pr_job_and_its_publisher(repository_assets):
    policy, workflow = repository_assets
    assert_policy(policy, workflow)


def test_workflow_retains_reviewed_literal_gate_surface(repository_assets):
    _, workflow = repository_assets
    jobs = workflow["jobs"]
    expected_matrices = {
        "python": {"python-version": ["3.12", "3.13"]},
        "dependency-security": {"os": ["ubuntu-latest", "windows-latest"]},
        "agent-offline": {"os": ["ubuntu-latest", "ubuntu-24.04-arm", "windows-latest"]},
        "image-security": {
            "os": ["ubuntu-latest", "ubuntu-24.04-arm"],
            "image": ["api", "worker", "collector", "test", "frontend"],
        },
        "derived-service-builds": {
            "os": ["ubuntu-latest", "ubuntu-24.04-arm"],
            "service": ["postgres", "clickhouse", "redis", "node-exporter", "prometheus"],
        },
    }
    singles = {"compose-integration", "frontend", "network-sensor", "powershell", "production-qualification"}
    assert set(jobs) == singles | set(expected_matrices) | {"signed-image-evidence"}
    for job_id, matrix in expected_matrices.items():
        actual = jobs[job_id]["strategy"]["matrix"]
        assert actual == matrix and list(actual) == list(matrix)
    for job_id in singles:
        assert "matrix" not in jobs[job_id].get("strategy", {})
    assert set(jobs["signed-image-evidence"]["needs"]) == singles | set(expected_matrices)
    assert len(pr_contexts(workflow)) == 32
    assert all(not context.startswith("signed-image-evidence") for context in pr_contexts(workflow))


@pytest.mark.parametrize(("path", "value"), [
    (("required_status_checks", "strict"), False),
    (("required_status_checks", "contexts"), []),
    (("required_status_checks", "contexts"), ["frontend"]),
    (("required_status_checks", "checks", 0, "app_id"), -1),
    (("required_status_checks", "checks", 0, "app_id"), True),
    (("required_status_checks", "checks", 0, "context"), "frontend"),
    (("required_status_checks", "checks", 0, "context"), "signed-image-evidence"),
    (("enforce_admins",), False),
    (("required_pull_request_reviews",), None),
    (("required_pull_request_reviews", "dismiss_stale_reviews"), False),
    (("required_pull_request_reviews", "required_approving_review_count"), False),
    (("required_pull_request_reviews", "required_approving_review_count"), 1),
    (("required_pull_request_reviews", "bypass_pull_request_allowances"), {"users": ["example"]}),
    (("restrictions",), {"users": ["example"]}),
    (("required_conversation_resolution",), False),
    (("allow_force_pushes",), True),
    (("allow_deletions",), True),
    (("bypass_actors",), [{"actor_id": APP_ID}]),
])
def test_main_policy_rejects_gate_and_profile_drift(path, value, repository_assets):
    original_policy, workflow = repository_assets
    policy = copy.deepcopy(original_policy)
    target = policy
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(AssertionError):
        assert_policy(policy, workflow)


def test_missing_required_check_is_rejected(repository_assets):
    original_policy, workflow = repository_assets
    policy = copy.deepcopy(original_policy)
    policy["required_status_checks"]["checks"].pop()
    with pytest.raises(AssertionError):
        assert_policy(policy, workflow)


@pytest.mark.parametrize("change", ["matrix", "new-job", "name", "conditional", "signing-on-pr"])
def test_workflow_drift_requires_a_reviewed_policy_update(change, repository_assets):
    policy, original_workflow = repository_assets
    workflow = copy.deepcopy(original_workflow)
    jobs = workflow["jobs"]
    if change == "matrix":
        jobs["python"]["strategy"]["matrix"]["python-version"].append("3.14")
    elif change == "new-job":
        jobs["additional-check"] = {"runs-on": "ubuntu-latest", "steps": []}
    elif change == "name":
        jobs["frontend"]["name"] = "renamed-frontend"
    elif change == "conditional":
        jobs["frontend"]["if"] = "github.event_name == 'push'"
    else:
        del jobs["signed-image-evidence"]["if"]
    with pytest.raises((AssertionError, KeyError)):
        assert_policy(policy, workflow)


@pytest.mark.parametrize("missing", [
    (".github/main-protection.json",),
    (".github/workflows/ci.yml",),
    (".github/main-protection.json", ".github/workflows/ci.yml"),
], ids=["policy-missing", "workflow-missing", "both-missing"])
def test_governance_assets_are_required_only_when_selected(tmp_path, missing):
    source = tmp_path / "tests/test_repository_governance.py"
    source.parent.mkdir()
    shutil.copyfile(__file__, source)
    for relative in (".github/main-protection.json", ".github/workflows/ci.yml"):
        if relative not in missing:
            asset = tmp_path / relative
            asset.parent.mkdir(parents=True, exist_ok=True)
            asset.write_text("{}\n", encoding="utf-8")

    spec = importlib.util.spec_from_file_location("isolated_repository_governance", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    command = [sys.executable, "-m", "pytest", "-q", "--noconftest", "-p", "no:cacheprovider"]
    collected = subprocess.run([*command, "--collect-only", "-m", "integration", str(source)],
                               cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert collected.returncode == 5 and "error" not in collected.stdout.lower(), (
        collected.stdout + collected.stderr
    )
    selected = subprocess.run([*command, f"{source}::test_main_policy_matches_every_pr_job_and_its_publisher"],
                              cwd=tmp_path, capture_output=True, text=True, timeout=30)
    diagnostic = selected.stdout + selected.stderr
    assert selected.returncode == 1 and "FileNotFoundError" in diagnostic, diagnostic
    assert Path(missing[0]).name in diagnostic, diagnostic
