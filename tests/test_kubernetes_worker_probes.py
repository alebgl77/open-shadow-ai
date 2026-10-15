"""Shipped worker manifests must check their own progress with bounded probes."""

from pathlib import Path

import pytest
import yaml

from shadai.qualification.schemas import load_profile
from shadai.qualification.target import kube_document

ROOT = Path(__file__).resolve().parents[1]
STAGES = ("ingest", "correlation", "purge")


@pytest.fixture
def worker_deployments():
    baseline = list(yaml.safe_load_all((ROOT / "deploy/kubernetes/base/workloads.yaml").read_text(encoding="utf-8")))
    profile = load_profile(ROOT / "deploy/qualification/profiles/target-plan.json")
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
    target = kube_document(profile)["items"]
    return {
        stage: (
            next(item for item in baseline if item["metadata"]["name"] == stage + "-worker"),
            next(item for item in target if item["kind"] == "Deployment" and item["metadata"]["name"] == stage),
        )
        for stage in STAGES
    }


@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("mode,period,failures", [("startup", 5, 60), ("liveness", 10, 3), ("readiness", 10, 3)])
def test_baseline_and_target_use_the_same_stage_specific_bounded_probe(
    worker_deployments, stage, mode, period, failures,
):
    command = ["python", "-m", "shadai.workers.probe", mode, "--stage", stage]
    if mode == "readiness":
        command = ["python", "/app/entrypoint.py", *command]
    expected = {
        "exec": {"command": command},
        "periodSeconds": period,
        "timeoutSeconds": 6,
        "failureThreshold": failures,
    }
    for deployment in worker_deployments[stage]:
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        assert container[mode + "Probe"] == expected


@pytest.mark.parametrize("stage", STAGES)
def test_worker_probes_keep_private_writable_storage_and_unprivileged_identity(worker_deployments, stage):
    baseline, target = worker_deployments[stage]
    assert baseline["spec"]["replicas"] == 1
    assert target["spec"]["replicas"] == (1 if stage == "purge" else 2)
    for deployment in (baseline, target):
        pod = deployment["spec"]["template"]["spec"]
        assert pod["securityContext"] == {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "runAsGroup": 10001,
            "fsGroup": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        container = pod["containers"][0]
        module = "correlate" if stage == "correlation" else stage
        assert container["args"] == ["python", "-m", "shadai.workers." + module]
        assert container["securityContext"] == {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        }
        assert next(mount for mount in container["volumeMounts"] if mount["mountPath"] == "/tmp") == {
            "name": "tmp", "mountPath": "/tmp",
        }
        assert next(volume for volume in pod["volumes"] if volume["name"] == "tmp")["emptyDir"]["sizeLimit"] == "64Mi"
    baseline_pod = baseline["spec"]["template"]["spec"]
    assert baseline_pod["automountServiceAccountToken"] is False
    assert {"secretRef": {"name": "open-shadow-ai-runtime"}} in baseline_pod["containers"][0]["envFrom"]
    target_pod = target["spec"]["template"]["spec"]
    assert {"name": "runtime", "mountPath": "/run/secrets", "readOnly": True} in (
        target_pod["containers"][0]["volumeMounts"]
    )
    assert next(volume for volume in target_pod["volumes"] if volume["name"] == "runtime")["secret"] == {
        "secretName": "runtime-a", "defaultMode": 0o440,
    }
