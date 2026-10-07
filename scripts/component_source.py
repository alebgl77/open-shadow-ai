"""Bind reviewed BuildKit recipes to a selected OCI root filesystem.

BuildKit provenance is observed evidence until separately authenticated by CI.
This verifier does not infer an observed binary version or unpack image layers.
"""

import base64
import hashlib
import json
import re
from pathlib import Path

GO_ENV = ["PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "GOLANG_VERSION=1.26.6", "GOPATH=/go", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off",
          "GOWORK=off", "GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org",
          "GOFLAGS=-mod=readonly", "GOTELEMETRY=off"]
PG_ENV = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "GOSU_VERSION=1.19",
          "LANG=en_US.utf8", "PG_MAJOR=16", "PG_VERSION=16.15",
          "PG_SHA256=c1575341fa7bd40f5274ea465b34390f4dc64cdd0770af327005caaeb9f6b7ed",
          "DOCKER_PG_LLVM_DEPS=llvm21-dev \t\tclang21", "PGDATA=/var/lib/postgresql/data"]
GZIP_TYPES = {"application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.oci.image.layer.v1.tar+gzip"}
LAYER_TYPES = GZIP_TYPES | {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+zstd"}
SOURCES = {
    "postgres": ("gosu", "6456aaa0f3c854d199d0f037f068eb97515b7513",
                 "33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b", "/usr/local/bin/gosu"),
    "node-exporter": ("node-exporter", "6044da783597cc3b57aef7580ddcdcff58a4ee99",
                      "cfec7478aa9bfd011f29df084584b7c7b68dfef85a24d28e9d6d5f88224f83c3", "/bin/node_exporter"),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_identifier(reference):
    if reference.startswith(("golang:", "postgres:")):
        reference = "docker.io/library/" + reference
    return "docker-image://" + reference


def expected_graph(recipe, dockerignore, platform, component):
    """Exact ports, actions, commands, environment and mounts for the closed recipes."""
    instructions = recipe.decode("utf-8").replace("\\\n", "").splitlines()
    runs = [line[4:] for line in instructions if line.startswith("RUN ")]
    bases = [line.split()[1] for line in instructions if line.startswith("FROM ")]
    if len(runs) != 3 or len(bases) != 2:
        raise ValueError("Unsupported maintained recipe template")
    native_platform = {"Architecture": platform.split("/")[1], "OS": "linux"}
    graph = []

    def add(body, inputs=None, *, native=False, terminal=False):
        op = {"Op": body}
        if not terminal:
            op["constraints"] = {}
        if native:
            op["platform"] = native_platform
        node = {"id": f"step{len(graph)}", "op": op}
        if inputs:
            node["inputs"] = inputs
        graph.append(node)

    def copy(source, destination, input_port=0, output_port=0):
        return {"input": input_port, "secondaryInput": 1, "output": output_port,
                "Action": {"copy": {"src": source, "dest": destination, "mode": -1,
                           "followSymlink": True, "dirCopyContents": True, "allowWildcard": True,
                           "allowEmptyWildcard": True, "createDestPath": True, "timestamp": -1}}}

    def run(command, environment, cwd="/src", user=None):
        meta = {"args": ["/bin/sh", "-c", command], "env": environment, "cwd": cwd,
                "removeMountStubsRecursive": True}
        if user:
            meta["user"] = user
        return {"exec": {"meta": meta, "mounts": [{"dest": "/"}]}}

    add({"source": {"identifier": source_identifier(bases[1])}}, native=True)
    add({"source": {"identifier": source_identifier(bases[0])}}, native=True)
    add({"file": {"actions": [{"input": 0, "secondaryInput": -1, "output": 0,
         "Action": {"mkdir": {"path": "/src", "mode": 493, "makeParents": True, "timestamp": -1}}}]}}, ["step1:0"])
    add(run(runs[0], GO_ENV), ["step2:0"], native=True)
    directory = f"requirements/service-builds/{component}"
    # Docker's ignore parser removes a leading/trailing slash for these fixed patterns.
    excluded = [line.strip().strip("/") for line in dockerignore.decode("utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
    add({"source": {"identifier": "local://context", "attrs": {
        "local.excludepatterns": json.dumps(excluded, separators=(",", ":")),
        "local.followpaths": json.dumps([f"{directory}/{file}" for file in ("go.mod", "go.sum", "modules.txt")],
                                       separators=(",", ":")), "local.sharedkeyhint": "context"}}})
    add({"file": {"actions": [copy(f"/{directory}/go.mod", "/src/", output_port=-1),
         copy(f"/{directory}/go.sum", "/src/", input_port=2)]}}, ["step3:0", "step4:0"])
    add({"file": {"actions": [copy(f"/{directory}/modules.txt", "/locked-modules.txt")]}}, ["step5:0", "step4:0"])
    add(run(runs[1], GO_ENV), ["step6:0"], native=True)
    binary = "gosu" if component == "gosu" else "node_exporter"
    destination = "/usr/local/bin/gosu" if component == "gosu" else "/bin/node_exporter"
    add({"file": {"actions": [copy(f"/out/{binary}", destination)]}}, ["step0:0", "step7:0"])
    licenses = f"/usr/local/share/licenses/shadai/{component}/"
    add({"file": {"actions": [copy("/src/LICENSE", licenses + "LICENSE")]}}, ["step8:0", "step7:0"])
    add({"file": {"actions": [copy("/usr/local/go/LICENSE", licenses + "GO-LICENSE")]}}, ["step9:0", "step7:0"])
    add({"file": {"actions": [copy("/out/GO-MODULES.txt", licenses, output_port=-1),
         copy("/out/THIRD-PARTY-NOTICES.txt", licenses, input_port=2)]}}, ["step10:0", "step7:0"])
    add(run(runs[2], PG_ENV if component == "gosu" else
            ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"], cwd="/",
            user=None if component == "gosu" else "nobody"), ["step11:0"], native=True)
    add({}, ["step12:0"], terminal=True)
    return graph


def typed_equal(actual, expected):
    """JSON flags, ports and descriptor numbers cannot alias bool/int/float."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(type(key) is str and
            typed_equal(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(typed_equal(left, right)
            for left, right in zip(actual, expected, strict=True))
    return actual == expected


def bind(predicate, *, service, platform, selected_manifest, root, service_manifest, expected_source):
    """Refuse missing, disconnected, ambiguous or stale BuildKit source evidence."""
    component, commit, archive_hash, path = SOURCES[service]
    component_record = service_manifest["components"][component]
    if component_record["commit"] != commit or component_record["source_sha256"] != archive_hash:
        raise ValueError("Source projection release mismatch")
    recipe_path = service_manifest["services"][service]["dockerfile"]
    recipe = (root / recipe_path).read_bytes()
    recipe_hash = sha(recipe)
    if recipe_hash != service_manifest["files"][recipe_path]:
        raise ValueError("Source projection recipe hash mismatch")
    lock_hashes = {}
    for filename in ("go.mod", "go.sum", "modules.txt"):
        name = f"requirements/service-builds/{component}/{filename}"
        lock_hashes[name] = sha((root / name).read_bytes())
        if lock_hashes[name] != service_manifest["files"][name] or lock_hashes[name].encode() not in recipe:
            raise ValueError("Source projection module hash mismatch")
    definition = predicate.get("buildDefinition", {})
    if definition.get("buildType") != "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md":
        raise ValueError("Unsupported source projection provenance")
    config = definition.get("internalParameters", {}).get("buildConfig", {})
    metadata = predicate.get("runDetails", {}).get("metadata", {}).get("buildkit_metadata", {})
    infos = metadata.get("source", {}).get("infos")
    if not isinstance(infos, list) or len(infos) != 1 or infos[0].get("filename") != Path(recipe_path).name or \
            infos[0].get("language") != "Dockerfile":
        raise ValueError("Missing or ambiguous embedded source recipe")
    try:
        embedded = base64.b64decode(infos[0]["data"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Invalid embedded source recipe") from error
    if embedded != recipe:
        raise ValueError("Embedded source recipe is stale or different")
    external = definition.get("externalParameters", {})
    if external.get("configSource") != {"path": Path(recipe_path).name} or \
            external.get("request", {}).get("root", {}).get("configSource") != {"path": Path(recipe_path).name}:
        raise ValueError("Source projection recipe location mismatch")
    observed_source = external.get("request", {}).get("root", {}).get("request", {}).get("args", {})
    source_url = "https://github.com/" + expected_source["repository"]
    if observed_source.get("vcs:revision") != expected_source["commit"] or \
            observed_source.get("vcs:source") != source_url or \
            metadata.get("vcs", {}).get("revision") != expected_source["commit"] or \
            metadata.get("vcs", {}).get("source") != source_url:
        raise ValueError("Observed BuildKit source hints differ from invocation")
    expected_external = {"configSource": {"path": Path(recipe_path).name}, "request": {
        "frontend": "dockerfile.v0", "locals": [{"name": "context"}, {"name": "dockerfile"}],
        "root": {"configSource": {"path": Path(recipe_path).name}, "request": {"args": {
            "vcs:localdir:context": ".", "vcs:localdir:dockerfile": "deploy/service-builds",
            "vcs:revision": expected_source["commit"], "vcs:source": source_url}}}, "compatibilityVersion": 30}}
    if not typed_equal(external, expected_external):
        raise ValueError("Source projection build invocation differs from reviewed template")
    graph = config.get("llbDefinition")
    expected = expected_graph(recipe, (root / ".dockerignore").read_bytes(), platform, component)
    if not typed_equal(graph, expected):
        raise ValueError("Source projection BuildKit dataflow differs from reviewed recipe")
    mapping = config.get("digestMapping")
    if not isinstance(mapping, dict) or len(mapping) != len(expected) or \
            set(mapping.values()) != {n["id"] for n in expected} or \
            any(not isinstance(k, str) or len(k) != 71 or not k.startswith("sha256:") or
                any(c not in "0123456789abcdef" for c in k[7:]) for k in mapping):
        raise ValueError("Ambiguous source projection node identities")
    alternatives = metadata.get("layers", {}).get("step12:0")
    if not isinstance(alternatives, list) or len(alternatives) != 1 or not isinstance(alternatives[0], list):
        raise ValueError("Ambiguous terminal source projection layer stack")
    layers = selected_manifest.get("layers")
    if not isinstance(layers, list) or not layers or len(layers) != len(alternatives[0]):
        raise ValueError("Source projection does not reach selected root filesystem")
    def same_descriptor(observed, exported):
        left, right = observed.get("mediaType"), exported.get("mediaType")
        return typed_equal(observed.get("digest"), exported.get("digest")) and \
            type(exported.get("size")) is int and typed_equal(observed.get("size"), exported.get("size")) and \
            left in LAYER_TYPES and right in LAYER_TYPES and (left == right or {left, right} == GZIP_TYPES)

    if any(not same_descriptor(observed, exported) for observed, exported in zip(alternatives[0], layers, strict=True)):
        raise ValueError("Source projection terminal layer descriptor mismatch")
    previous_size = None
    binary_copy_layer = None
    for step in range(8, 13):
        candidates = metadata.get("layers", {}).get(f"step{step}:0")
        if not isinstance(candidates, list) or len(candidates) != 1 or not isinstance(candidates[0], list) or \
                not candidates[0] or len(candidates[0]) > len(layers) or \
                previous_size is not None and len(candidates[0]) != previous_size + 1 or \
                any(not same_descriptor(left, right) for left, right in zip(candidates[0], layers)):
            raise ValueError("Source projection copy/licence/smoke layer chain is discontinuous")
        previous_size = len(candidates[0])
        if step == 8:
            binary_copy_layer = candidates[0][-1]["digest"]
    return {"claim_kind": "observed_build_source_projection", "authenticated_provenance": False,
            "source_component": component, "source_commit": commit, "source_archive_sha256": archive_hash,
            "recipe": recipe_path, "recipe_sha256": recipe_hash, "module_hashes": lock_hashes,
            "binary_path": path, "binary_version_claim": None,
            "binary_copy_layer": binary_copy_layer, "dockerignore_sha256": sha((root / ".dockerignore").read_bytes()),
            "checkout_commit": expected_source["commit"], "repository": expected_source["repository"],
            "vcs_evidence_kind": "unauthenticated_observed_buildkit_hints",
            "terminal": "step13", "rootfs_output": "step12:0",
            "build_graph_sha256": sha(json.dumps(graph, sort_keys=True, separators=(",", ":")).encode())}


def expected_clickhouse_graph(recipe, platform):
    instructions = recipe.decode("utf-8").replace("\\\n", "").splitlines()
    runs = [line[4:] for line in instructions if line.startswith("RUN ")]
    bases = [line.split()[1] for line in instructions if line.startswith("FROM ")]
    mount = "--mount=type=bind,from=packages,source=/packages,target=/packages,ro"
    if len(runs) != 2 or len(bases) != 2 or runs[1].split(None, 1)[0] != mount:
        raise ValueError("Unsupported declared principal recipe template")
    native = {"Architecture": platform.split("/")[1], "OS": "linux"}
    def node(index, body, inputs=None):
        value = {"id": f"step{index}", "op": {"Op": body, "constraints": {}, "platform": native}}
        if inputs:
            value["inputs"] = inputs
        return value
    def run(command, environment, cwd, mounts):
        return {"exec": {"meta": {"args": ["/bin/sh", "-c", command], "cwd": cwd, "env": environment,
                                  "removeMountStubsRecursive": True}, "mounts": mounts}}
    return [node(0, {"source": {"identifier": "docker-image://docker.io/" + bases[1]}}),
            node(1, {"source": {"identifier": source_identifier(bases[0])}}),
            node(2, run(runs[0], GO_ENV[:2] + ["GOTOOLCHAIN=local", "GOPATH=/go",
                                             "TARGETARCH=" + platform.split("/")[1]], "/go", [{"dest": "/"}]),
                 ["step1:0"]),
            node(3, run(runs[1].split(None, 1)[1], ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=en_US.UTF-8", "LANGUAGE=en_US:en", "LC_ALL=en_US.UTF-8", "TZ=UTC",
                "CLICKHOUSE_CONFIG=/etc/clickhouse-server/config.xml"], "/", [{"dest": "/"},
                {"dest": "/packages", "input": 1, "output": -1, "readonly": True, "selector": "/packages"}]),
                 ["step0:0", "step2:0"]),
            {"id": "step4", "inputs": ["step3:0"], "op": {"Op": {}}}]


def bind_clickhouse(predicate, *, platform, selected_manifest, root, service_manifest, expected_source, expected_ci):
    """Bind a declared publisher identity; never assert source reproduction or authentication."""
    record = service_manifest["services"]["clickhouse"]
    if record["functional_version"] != "25.8.33.6" or record["base"] != "clickhouse-base":
        raise ValueError("Declared principal release/base differs")
    path = record["dockerfile"]
    recipe = (root / path).read_bytes()
    if sha(recipe) != service_manifest["files"][path]:
        raise ValueError("Declared principal recipe hash differs")
    definition = predicate.get("buildDefinition", {})
    build_type = "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
    internal = definition.get("internalParameters", {})
    metadata = predicate.get("runDetails", {}).get("metadata", {}).get("buildkit_metadata", {})
    infos = metadata.get("source", {}).get("infos")
    if definition.get("buildType") != build_type or not isinstance(infos, list) or len(infos) != 1 or \
            infos[0].get("filename") != Path(path).name or infos[0].get("language") != "Dockerfile":
        raise ValueError("Declared principal embedded recipe/provenance missing")
    if base64.b64decode(infos[0]["data"], validate=True) != recipe:
        raise ValueError("Declared principal embedded recipe is stale")
    url = "https://github.com/" + expected_source["repository"]
    external = {"configSource": {"path": Path(path).name}, "request": {"frontend": "dockerfile.v0",
        "locals": [{"name": "context"}, {"name": "dockerfile"}], "root": {"configSource": {"path": Path(path).name},
        "request": {"args": {"vcs:localdir:context": ".", "vcs:localdir:dockerfile": "deploy/service-builds",
        "vcs:revision": expected_source["commit"], "vcs:source": url}}}, "compatibilityVersion": 30}}
    if not typed_equal(definition.get("externalParameters"), external) or metadata.get("vcs", {}).get("revision") != \
            expected_source["commit"] or metadata.get("vcs", {}).get("source") != url or any(
            internal.get("github_" + key) != value for key, value in expected_ci.items()):
        raise ValueError("Declared principal invocation/native CI identity differs")
    expected_graph = expected_clickhouse_graph(recipe, platform)
    config = internal.get("buildConfig", {})
    graph = config.get("llbDefinition")
    if not typed_equal(graph, expected_graph):
        raise ValueError("Declared principal BuildKit dataflow differs")
    mapping = config.get("digestMapping")
    if not isinstance(mapping, dict) or len(mapping) != 5 or set(mapping.values()) != {n["id"] for n in graph} or \
            any(not re.fullmatch(r"sha256:[a-f0-9]{64}", name) for name in mapping):
        raise ValueError("Declared principal node identities differ")
    images = json.loads((root / "requirements/images.json").read_bytes())
    references = [images[name]["reference"] for name in ("clickhouse-base", "golang", "sbom-generator")]
    expected_dependencies = []
    for reference in references:
        image, digest = reference.split("@")
        name, version = image.rsplit(":", 1)
        expected_dependencies.append({"uri": f"pkg:docker/{name}@{version}?digest={digest}&platform=" +
                                      platform.replace("/", "%2F"), "digest": {"sha256": digest[7:]}})
    if not typed_equal(sorted(definition.get("resolvedDependencies", []), key=lambda item: item["uri"]),
                       sorted(expected_dependencies, key=lambda item: item["uri"])):
        raise ValueError("Declared principal official base/tool/platform bindings differ")
    layers = selected_manifest["layers"]
    stacks = metadata.get("layers", {})
    for name, terminal in (("step0:0", False), ("step3:0", True)):
        choices = stacks.get(name)
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], list) or not choices[0] or \
                len(choices[0]) != len(layers) - (0 if terminal else 1):
            raise ValueError("Declared principal base/rootFS layer chain differs")
        for left, right in zip(choices[0], layers):
            a, b = left.get("mediaType"), right.get("mediaType")
            if not typed_equal(left.get("digest"), right.get("digest")) or type(right.get("size")) is not int or \
                    not typed_equal(left.get("size"), right.get("size")) or \
                    a not in LAYER_TYPES or b not in LAYER_TYPES or a != b and {a, b} != GZIP_TYPES:
                raise ValueError("Declared principal ordered layer descriptor differs")
    return {"claim_kind": "declared_principal_recipe_base_association", "authenticated_provenance": False,
            "publisher_signature": "unverified", "recipe": path, "recipe_sha256": sha(recipe),
            "functional_version": "25.8.33.6", "publisher_base": references[0], "platform": platform,
            "checkout_commit": expected_source["commit"], "repository": expected_source["repository"],
            "ci": expected_ci, "terminal": "step4", "rootfs_output": "step3:0",
            "build_graph_sha256": sha(json.dumps(graph, sort_keys=True, separators=(",", ":")).encode())}


def subject_documents(layout, image_manifest):
    """Read only verified metadata blobs; never unpack a layer or invent an output label."""
    directory = layout.layout_path
    image_key = image_manifest
    if re.fullmatch(r"[a-f0-9]{64}", image_manifest):
        image_manifest = "sha256:" + image_manifest

    def blob(identifier):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", identifier):
            raise ValueError("Invalid source evidence blob identifier")
        path = directory / "blobs" / "sha256" / identifier[7:]
        if path.stat().st_size > 128 * 1024 * 1024:
            raise ValueError("Source evidence JSON exceeds budget")
        data = path.read_bytes()
        if sha(data) != identifier[7:]:
            raise ValueError("Source evidence blob changed")
        return json.loads(data)

    manifest = blob(image_manifest)
    config = blob(manifest["config"]["digest"])
    provenance, sboms, visited = [], [], set()

    def visit(descriptor):
        identifier = descriptor["digest"]
        if identifier in visited:
            return
        visited.add(identifier)
        document = blob(identifier)
        if "manifests" in document:
            for child in document["manifests"]:
                visit(child)
        elif "layers" in document:
            for layer in document["layers"]:
                if layer.get("mediaType") != "application/vnd.in-toto+json":
                    continue
                statement = blob(layer["digest"])
                if not any(s.get("digest", {}).get("sha256") == image_manifest[7:]
                           for s in statement.get("subject", [])):
                    continue
                record = {"blob": layer["digest"], "statement": statement}
                if statement.get("predicateType") == "https://slsa.dev/provenance/v1":
                    provenance.append(record)
                elif statement.get("predicateType") == "https://spdx.dev/Document":
                    sboms.append(record)

    index = json.loads((directory / "index.json").read_bytes())
    for child in index["manifests"]:
        visit(child)
    if len(provenance) != 1 or len(sboms) != 1 or \
            sboms[0]["statement"]["predicate"] != layout.evidence["sboms"][image_key]:
        raise ValueError("Missing or ambiguous subject-bound source/SBOM document")
    return {"manifest": manifest, "config": config, "provenance": provenance[0], "sbom": sboms[0]}
