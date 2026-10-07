"""Exact, bounded target checks; absent live evidence cannot be qualified by a lab."""

import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from shadai.qualification.http_transport import HttpTransport
from shadai.qualification.load import LoadSender
from shadai.qualification.processes import remaining
from shadai.qualification.schemas import QualificationError, canonical_bytes, load_profile, read_json, report

PLACEHOLDER = re.compile(r"example\.(?:com|org|test)|REPLACE|CHANGEME|<|>|\$\{", re.I)
NAMES = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")
IMAGES = re.compile(r"[a-z0-9./:_-]+@sha256:[a-f0-9]{64}")
LABEL_KEY = re.compile(r"(?:[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?/)?[A-Za-z0-9](?:[-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?")
LABEL_VALUE = re.compile(r"[A-Za-z0-9](?:[-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?")


def exact_https(value, *, origin=False):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or PLACEHOLDER.search(value)
        or origin
        and parsed.path not in {"", "/"}
    ):
        raise QualificationError("An exact operator HTTPS target is required")
    return value.rstrip("/")


def private_reference(path):
    path = Path(path)
    if not path.is_absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise QualificationError("Secret reference must be absolute and cannot traverse links")
    metadata = path.stat()
    parent = path.parent.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > 65536
        or os.name == "posix"
        and (metadata.st_mode & 0o077 or metadata.st_uid != os.getuid())
        or os.name == "posix"
        and (parent.st_mode & 0o077 or parent.st_uid != os.getuid())
    ):
        raise QualificationError("Secret reference must be a private bounded owned file")
    return path


def bounded_get(url, timeout, *, deadline=None):
    deadline = deadline if deadline is not None else time.monotonic() + timeout
    status, body, error = HttpTransport().request(url, deadline=deadline, timeout=timeout)
    if error != "none" or not 200 <= status < 300:
        raise QualificationError("Target HTTP proof is unavailable within its deadline")
    try:
        content = json.loads(body)
    except ValueError:
        raise QualificationError("Target HTTP proof is malformed") from None
    if not isinstance(content, dict):
        raise QualificationError("Target HTTP proof is malformed")
    return status, content


def kube_document(profile):
    target = profile.get("target", {})
    for key in (
        "namespace",
        "kubernetes_context",
        "stores",
        "images",
        "egress_cidrs",
        "ingress_namespace",
        "ingress_pod_selector",
        "runtime_secret_name",
        "tls_secret_name",
    ):
        if not target.get(key):
            raise QualificationError("Kubernetes parameters are absent")
    namespace = target["namespace"]
    if (
        not NAMES.fullmatch(namespace)
        or not LABEL_VALUE.fullmatch(profile["installation"])
        or PLACEHOLDER.search(target["kubernetes_context"])
    ):
        raise QualificationError("Invalid explicit Kubernetes boundary")
    origin = exact_https(target.get("origin", ""), origin=True)
    exact_https(target.get("issuer", ""))
    host = urlsplit(origin).hostname
    secret, tls_secret = target["runtime_secret_name"], target["tls_secret_name"]
    dns_subdomain = re.compile(r"[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?")
    if (
        not dns_subdomain.fullmatch(secret)
        or not dns_subdomain.fullmatch(tls_secret)
        or PLACEHOLDER.search(secret)
        or PLACEHOLDER.search(tls_secret)
    ):
        raise QualificationError("Existing runtime/TLS Secret names are required")
    if (
        not NAMES.fullmatch(target["ingress_namespace"])
        or not 1 <= len(target["ingress_pod_selector"]) <= 8
        or any(
            not LABEL_KEY.fullmatch(key) or not LABEL_VALUE.fullmatch(value)
            for key, value in target["ingress_pod_selector"].items()
        )
    ):
        raise QualificationError("Exact ingress controller namespace and pod selector are required")
    if set(target["stores"]) != {"postgres", "redis", "clickhouse"} or any(
        PLACEHOLDER.search(item) or not item for item in target["stores"].values()
    ):
        raise QualificationError("Dedicated external store identifiers are required")
    cidrs = []
    for value in target["egress_cidrs"]:
        network = ipaddress.ip_network(value, strict=True)
        if network.prefixlen == 0:
            raise QualificationError("Unrestricted target egress is refused")
        cidrs.append({"ipBlock": {"cidr": str(network)}})
    if not cidrs:
        raise QualificationError("Explicit store and IdP egress addresses are required")
    if set(target["images"]) != {"api", "frontend", "worker"} or any(
        not IMAGES.fullmatch(value) or PLACEHOLDER.search(value) for value in target["images"].values()
    ):
        raise QualificationError("Every runtime image must be an immutable operator image")
    documents = []
    for name, stage, image, replicas in (
        ("api", None, "api", 2),
        ("frontend", None, "frontend", 2),
        ("ingest", "ingest", "worker", 2),
        ("correlation", "correlation", "worker", 2),
        ("purge", "purge", "worker", 1),
    ):
        labels = {
            "app.kubernetes.io/name": "shadai",
            "app.kubernetes.io/component": name,
            "app.kubernetes.io/instance": profile["installation"],
        }
        env = [
            {"name": "SHADAI_TENANT_ID", "value": profile["installation"]},
            {"name": "ALLOW_LEGACY_AGENT_KEY", "value": "false"},
            {"name": "SESSION_COOKIE_SECURE", "value": "true"},
        ]
        for field, key in (
            ("DATABASE_URL", "database_url"),
            ("REDIS_URL", "redis_url"),
            ("CLICKHOUSE_HOST", "clickhouse_host"),
            ("CLICKHOUSE_USER", "clickhouse_user"),
            ("CLICKHOUSE_DATABASE", "clickhouse_database"),
        ):
            env.append({"name": field, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}})
        for field, key in (
            ("JWT_SECRET_FILE", "jwt_secret"),
            ("ENCRYPTION_KEY_FILE", "encryption_key"),
            ("CLICKHOUSE_PASSWORD_FILE", "ch_password"),
        ):
            env.append({"name": field, "value": "/run/secrets/" + key})
        if name == "api":
            env += [
                {"name": "OIDC_ENABLED", "value": "true"},
                {"name": "OIDC_ISSUER", "value": target["issuer"]},
                {"name": "OIDC_PUBLIC_BASE_URL", "value": origin},
                {"name": "OIDC_CLIENT_SECRET_FILE", "value": "/run/secrets/oidc_client_secret"},
                {"name": "OIDC_CLIENT_ID", "valueFrom": {"secretKeyRef": {"name": secret, "key": "oidc_client_id"}}},
            ]
        container = {
            "name": name,
            "image": target["images"][image],
            "env": env,
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
            "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "2", "memory": "1Gi"}},
            "volumeMounts": [
                {"name": "tmp", "mountPath": "/tmp"},
                {"name": "runtime", "mountPath": "/run/secrets", "readOnly": True},
            ],
        }
        if stage:
            module = "correlate" if stage == "correlation" else stage
            container["args"] = ["python", "-m", "shadai.workers." + module]
            for mode, key, period in (
                ("startup", "startupProbe", 5),
                ("liveness", "livenessProbe", 10),
                ("readiness", "readinessProbe", 10),
            ):
                command = ["python", "-m", "shadai.workers.probe", mode, "--stage", stage]
                if mode == "readiness":
                    command = ["python", "/app/entrypoint.py", *command]
                container[key] = {
                    "exec": {"command": command},
                    "periodSeconds": period,
                    "timeoutSeconds": 6,
                    "failureThreshold": 60 if mode == "startup" else 3,
                }
        else:
            port = 8080 if name == "frontend" else 8443
            container["ports"] = [{"containerPort": port}]
            for mode, path in (("startup", "/health"), ("liveness", "/health"), ("readiness", "/ready")):
                container[mode + "Probe"] = {
                    "httpGet": {"path": "/health" if name == "frontend" else path, "port": port},
                    "periodSeconds": 10,
                    "timeoutSeconds": 5,
                    "failureThreshold": 30 if mode == "startup" else 3,
                }
            documents.append(
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {"selector": labels, "ports": [{"port": port, "targetPort": port}]},
                }
            )
        if name == "frontend":
            container["env"] = []
            container["volumeMounts"] = [{"name": "tmp", "mountPath": "/tmp"}]
        pod = {
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10001 if name != "frontend" else 101,
                "runAsGroup": 10001 if name != "frontend" else 101,
                "fsGroup": 10001 if name != "frontend" else 101,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [container],
            "volumes": [
                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
                {"name": "runtime", "secret": {"secretName": secret, "defaultMode": 0o440}},
            ],
            "affinity": {
                "podAntiAffinity": {
                    "requiredDuringSchedulingIgnoredDuringExecution": [
                        {"labelSelector": {"matchLabels": labels}, "topologyKey": "kubernetes.io/hostname"}
                    ]
                }
            },
        }
        if name == "frontend":
            pod["volumes"] = pod["volumes"][:1]
        documents.append(
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": name, "namespace": namespace},
                "spec": {
                    "replicas": replicas,
                    "selector": {"matchLabels": labels},
                    "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1}},
                    "template": {"metadata": {"labels": labels}, "spec": pod},
                },
            }
        )
        if replicas == 2:
            documents.append(
                {
                    "apiVersion": "policy/v1",
                    "kind": "PodDisruptionBudget",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {"minAvailable": 1, "selector": {"matchLabels": labels}},
                }
            )
    documents.append(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"name": "shadai", "namespace": namespace},
            "spec": {
                "tls": [{"hosts": [host], "secretName": tls_secret}],
                "rules": [
                    {
                        "host": host,
                        "http": {
                            "paths": [
                                {
                                    "path": "/api",
                                    "pathType": "Prefix",
                                    "backend": {"service": {"name": "api", "port": {"number": 8443}}},
                                },
                                {
                                    "path": "/",
                                    "pathType": "Prefix",
                                    "backend": {"service": {"name": "frontend", "port": {"number": 8080}}},
                                },
                            ]
                        },
                    }
                ],
            },
        }
    )
    documents.append(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "shadai-private", "namespace": namespace},
            "spec": {
                "podSelector": {"matchLabels": {"app.kubernetes.io/instance": profile["installation"]}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {"kubernetes.io/metadata.name": target["ingress_namespace"]}
                                },
                                "podSelector": {"matchLabels": target["ingress_pod_selector"]},
                            },
                            {"podSelector": {"matchLabels": {"app.kubernetes.io/instance": profile["installation"]}}},
                        ]
                    }
                ],
                "egress": [
                    {"to": cidrs, "ports": [{"protocol": "TCP", "port": value} for value in (443, 5432, 6379, 9000)]},
                    {
                        "to": [
                            {
                                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                            }
                        ],
                        "ports": [{"protocol": protocol, "port": 53} for protocol in ("UDP", "TCP")],
                    },
                ],
            },
        }
    )
    return {"apiVersion": "v1", "kind": "List", "items": documents}


def target_action(action, plan, execute=False, evidence=None):
    started = time.monotonic()
    profile = load_profile(plan)
    deadline = started + profile["limits"]["max_wall_seconds"]
    remaining(deadline)
    if profile["scope"] != "target":
        raise QualificationError("Target command requires target scope")
    if action == "idp" and execute:
        # Chromium detaches beyond the generic owned process-group boundary.
        # Refuse before GET, executable launch or private account references.
        raise QualificationError("unsupported_browser_containment")
    target = profile.get("target", {})
    proofs, missing, scenarios = {}, [], []
    if action == "plan":
        return report(profile, [], evidence={"planned_only": True, "actions": profile["scenarios"]})
    if action == "evaluate":
        supplied = read_json(evidence, 4 * 1048576) if evidence else {}
        expected = hashlib.sha256(canonical_bytes(profile)).hexdigest()
        if (
            supplied.get("schema") != 1
            or supplied.get("scope") != "target"
            or supplied.get("profile_sha256") != expected
        ):
            return report(profile, [], missing=["target-bound-evidence"])
        if any(item.get("status") == "passed" for item in supplied.get("scenarios", [])):
            # A caller-written success flag is not independent store, cluster or
            # identity proof. Current target actions deliberately leave these
            # live prerequisites open; the operator's reviewed observations
            # remain separate evidence, never a synthetic automatic promotion.
            return report(profile, [], missing=["independently-verified-live-target-proof"])
        # Evaluation never upgrades an incomplete action report or imports lab proof.
        return report(
            profile,
            supplied.get("scenarios", []),
            evidence=supplied.get("evidence", {}),
            missing=supplied.get("missing_evidence", []),
        )
    if action == "kubernetes":
        document = kube_document(profile)
        proofs["rendered"] = document
        if execute:
            context, namespace = target["kubernetes_context"], target["namespace"]
            command = ["kubectl", "--context", context, "--namespace", namespace]
            dryrun = subprocess.run(
                [*command, "apply", "--dry-run=server", "-f", "-"],
                input=json.dumps(document),
                text=True,
                capture_output=True,
                timeout=min(60, remaining(deadline)),
            )
            if dryrun.returncode:
                raise QualificationError("Kubernetes server dry-run failed")
            remaining(deadline)
            objects = {}
            for resource in ("nodes", "pods", "endpointslices", "networkpolicies"):
                result = subprocess.run(
                    [*command, "get", resource, "-o", "json"],
                    text=True,
                    capture_output=True,
                    timeout=min(30, remaining(deadline)),
                )
                if result.returncode or len(result.stdout) > 4 * 1048576:
                    raise QualificationError("Kubernetes scheduling proof unavailable")
                remaining(deadline)
                objects[resource] = json.loads(result.stdout)
            proofs["server_dry_run"] = True
            proofs["object_inventory_sha256"] = hashlib.sha256(canonical_bytes(objects)).hexdigest()
            proofs["node_count"] = len(objects["nodes"].get("items", []))
            missing += ["live-scheduling-probes-networkpolicy-tls", "maintenance-failover-objectives"]
        else:
            missing.append("server-dry-run-and-live-target")
    elif action in {"preflight", "idp"}:
        origin = exact_https(target.get("api_url", ""), origin=True)
        for path in ("/health", "/ready"):
            status, body = bounded_get(origin + path, 5, deadline=deadline)
            proofs[path] = {"http_status": status, "ready": body.get("status") in {"ok", "ready"}}
        if action == "idp":
            issuer = exact_https(target.get("issuer", ""))
            status, metadata = bounded_get(issuer + "/.well-known/openid-configuration", 5, deadline=deadline)
            if status != 200 or metadata.get("issuer") != issuer:
                raise QualificationError("IdP metadata issuer differs from the exact operator target")
            for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                exact_https(metadata.get(field, ""))
            proofs["issuer_metadata"] = True
            missing += [
                "unsupported_browser_containment",
                "dedicated-scim-account-human-login-mfa",
                "fresh-roundtrip-session-me-csrf-logout",
                "role-deactivation-separately-authorized",
            ]
        else:
            missing += ["dedicated-store-identities", "live-persistence-and-objectives"]
    elif action == "load":
        if not execute:
            return report(profile, [], missing=["explicit-load-execution"])
        refs = target.get("secret_files", {})
        credential = read_json(private_reference(refs.get("collector_key", "")))
        if set(credential) != {"collector_id", "api_key", "run_id"} or not credential["collector_id"]:
            raise QualificationError("Existing dedicated collector credential is required")
        UUID(credential["run_id"])
        output = private_reference(refs.get("run_directory_marker", "")).parent
        bounded_profile = {**profile, "limits": {**profile["limits"], "max_wall_seconds": remaining(deadline)}}
        sender = LoadSender(bounded_profile, credential["run_id"], "target-load", output, credential["collector_id"])
        try:
            proofs["load"] = sender.run(target.get("api_url", ""), credential["api_key"], deadline=deadline)
        finally:
            sender.stop()
        missing += ["target-receipts-unique-persistence-and-end-to-end-latency", "explicit-objectives"]
    scenario = {"preflight": "baseline", "load": "baseline", "kubernetes": "kubernetes", "idp": "idp"}[action]
    scenarios.append(
        {
            "scenario": scenario,
            "required": True,
            "executed": action != "kubernetes" or execute,
            "status": "not_evaluated",
            "measurements": proofs,
        }
    )
    return report(profile, scenarios, evidence={"target_installation": profile["installation"]}, missing=missing)
