"""No automatic browser launch can produce an uncontained identity witness."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from shadai.qualification import __main__ as cli
from shadai.qualification import target
from shadai.qualification.schemas import QualificationError, load_profile

ROOT = Path(__file__).resolve().parents[1]


def plan_file(tmp_path):
    profile = load_profile(ROOT / "deploy/qualification/profiles/target-plan.json")
    profile["target"] = {"api_url": "https://console.operator.invalid", "issuer": "https://idp.operator.invalid",
                         "secret_files": {"identity_account": "synthetic-unused-private-reference",
                                          "run_directory_marker": "synthetic-unused-marker"}}
    path = tmp_path / "target.json"
    path.write_text(json.dumps(profile))
    return path


def test_execute_refuses_before_any_child_or_secret_reference(tmp_path, monkeypatch):
    plan = plan_file(tmp_path)
    child, request, secret = Mock(side_effect=AssertionError("No child")), Mock(), Mock()
    monkeypatch.setattr(target.subprocess, "Popen", child)
    monkeypatch.setattr(target.subprocess, "run", child)
    monkeypatch.setattr(target, "bounded_get", request)
    monkeypatch.setattr(target, "private_reference", secret)
    with pytest.raises(QualificationError, match="^unsupported_browser_containment$"):
        target.target_action("idp", plan, execute=True)
    child.assert_not_called()
    request.assert_not_called()
    secret.assert_not_called()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["target.json"]


def test_cli_execute_is_not_evaluated_exit_two_without_provider_data(tmp_path, monkeypatch, capsys):
    plan, output = plan_file(tmp_path), tmp_path / "refusal.json"
    child = Mock(side_effect=AssertionError("No child"))
    monkeypatch.setattr(target.subprocess, "Popen", child)
    assert cli.main(["target", "idp", "--execute", "--plan", str(plan), "--output", str(output)]) == 2
    result = json.loads(output.read_text())
    assert result == {"schema": 1, "status": "not_evaluated",
                      "reason": "unsupported_browser_containment", "exit_code": 2}
    text = capsys.readouterr().out
    assert json.loads(text) == result and "operator.invalid" not in text and "synthetic-unused" not in text
    child.assert_not_called()


@pytest.mark.parametrize("exception", [
    QualificationError("synthetic-long-secret-" + "x" * 1000),
    QualificationError("unsupported_browser_containment", "synthetic-second-argument"),
    ValueError("unsupported_browser_containment"),
])
def test_other_error_messages_stay_sanitized(tmp_path, monkeypatch, capsys, exception):
    output = tmp_path / "refusal.json"
    def rejected(*args, **kwargs):
        raise exception
    monkeypatch.setattr(target, "target_action", rejected)
    assert cli.main(["target", "idp", "--plan", str(tmp_path / "unused"), "--output", str(output)]) == 2
    result = json.loads(output.read_text())
    assert result["reason"] == type(exception).__name__ and result["status"] == "not_evaluated"
    text = output.read_text() + capsys.readouterr().out
    assert "synthetic-" not in text and "unsupported_browser_containment" not in text


def test_readonly_idp_keeps_bounded_exact_metadata_preflight(tmp_path, monkeypatch):
    plan = plan_file(tmp_path)
    calls = []
    monkeypatch.setattr("shadai.qualification.provenance.source_stamp", lambda: {"revision": "synthetic"})
    def get(url, timeout, *, deadline):
        calls.append((url, timeout, deadline))
        if url.endswith("openid-configuration"):
            return 200, {"issuer": "https://idp.operator.invalid",
                         **{field: "https://idp.operator.invalid/" + field for field in
                            ("authorization_endpoint", "token_endpoint", "jwks_uri")}}
        return 200, {"status": "ready"}
    monkeypatch.setattr(target, "bounded_get", get)
    child = Mock(side_effect=AssertionError("No browser"))
    monkeypatch.setattr(target.subprocess, "Popen", child)
    result = target.target_action("idp", plan)
    assert len(calls) == 3 and all(timeout == 5 for _, timeout, _ in calls)
    assert len({deadline for _, _, deadline in calls}) == 1
    assert result["exit_code"] == 2 and result["scenarios"][0]["status"] == "not_evaluated"
    assert result["scenarios"][0]["measurements"]["issuer_metadata"] is True
    assert "unsupported_browser_containment" in result["missing_evidence"]
    child.assert_not_called()
