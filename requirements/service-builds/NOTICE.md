# Maintained service recipe 2

These recipes preserve PostgreSQL 16.15, Redis 7.4.11, ClickHouse 25.8.33.6,
gosu 1.19 and node_exporter 1.12.1. They replace the final executable or
OpenSSL/zlib libraries that the mandatory security gate found vulnerable. They
are maintained project builds, not new releases from those publishers.

Source archives are bound to the official release commits and SHA256 bytes
in `manifest.json`. Go 1.26.9 is the official multiarch image recorded in
`requirements/images.json`; automatic toolchain downloads are disabled.
`go.mod`, `go.sum` and `modules.txt` fix the module graph. Go verifies downloads
through `proxy.golang.org` and `sum.golang.org`, verifies the module cache,
checks the complete selected graph and builds with `-mod=readonly`,
`CGO_ENABLED=0`, `-trimpath` and `-buildvcs=false`.

Both publisher sources are unchanged. Recipe 2 compiles both binaries with
Go 1.26.9, the fixed standard library reported for CVE-2026-78667,
CVE-2026-78669, CVE-2026-97031, CVE-2026-78659, CVE-2026-78660, CVE-2026-94440
and CVE-2026-97030, which the security gate found in recipe 1's Go 1.26.6
binaries. gosu updates only x/sys 0.1.0 to 0.44.0, the fixed version reported
for CVE-2026-39824; that module requires the Go language directive to move
from 1.20 to 1.25.0. Its module graph is otherwise unchanged from recipe 1.
node_exporter updates x/net 0.57.0 to 0.60.0, the fixed version reported for
CVE-2026-78669, CVE-2026-78659 and CVE-2026-78660 in that module. x/net 0.60.0
requires x/crypto 0.57.0 (superseding recipe 1's 0.56.0, which fixed
CVE-2026-56855 and CVE-2026-78662), x/sys 0.47.0 to 0.48.0 and x/text 0.42.0
(superseding recipe 1's 0.41.0); x/text 0.42.0 requires x/sync 0.22.0 to
0.23.0. Its Go language directive stays at the required 1.26.0. Those modules'
own requirements also move x/term to 0.46.0, x/mod to 0.41.0 and x/tools to
0.49.0 in the complete selected graph; none of the three is built into the
binary. No other selected module version changes in either maintained build.
The reviewed `go.mod.diff` and upstream module files record that difference.
The node_exporter binary reports `1.12.1-shadai.2`; gosu retains its upstream
1.19 version and reports the new compiler. Image labels identify maintenance
recipe 2 and the upstream source commit.

The module-level GO-2026-5932 advisory remains visible: x/crypto's OpenPGP
packages are unmaintained and have no fixed version. Updating x/crypto does
not resolve that advisory or establish whether those specific imports are
used in a binary. Native bound scans and separate coverage analysis remain
required; unknown main-module versions in generated SBOMs are not invented.
The x/sys advisory concerns Windows NewNTUnicodeString; its module update
does not establish that this Windows function is present in a Linux binary.

OpenSSL APKs come from the official Alpine repository for the runtime's
existing distribution and native architecture. Redis uses 3.3.7-r2 on Alpine
3.21. ClickHouse uses 3.5.9-r0 on Alpine 3.24: 3.5.8-r0 is the advisory's
minimum fixed version, but its arm64 libcrypto3 package is no longer available.
Every APK has an independent SHA256 pin and an official RSA signature.
`apk add --no-network` still verifies that signature against the base image's
trusted keys. No global upgrade or untrusted-package option is used.

PostgreSQL and ClickHouse also install zlib 1.3.2-r1 from Alpine 3.24;
Redis installs the same patch release from Alpine 3.21. The four native
APK archives are pinned independently by architecture, SHA256 and size.
Their observed metadata declares the Zlib license and only the matching
musl runtime dependency. This patch targets CVE-2026-85091, whose fixed
package version is 1.3.2-r1. Native builds must verify the official APK
signatures, exact installed version and bound final-runtime scans before
remediation is established. Local archive/hash checks do not verify a
signature or prove the rebuilt image is free of the advisory.

gosu and node_exporter are Apache-2.0 licensed. Their unmodified publisher
LICENSE files are retained here and copied into their runtime images.
The runtime also contains the Go toolchain's BSD license, the selected module
graph and third-party LICENSE/NOTICE/COPYING/COPYRIGHT files collected from
the verified module cache. Base image and Alpine package licenses remain
those supplied by their official publishers.

The local Compose tags name a recipe version; they do not claim immutable
output digests before building. OCI archives, their measured config/manifest
digests, linked SBOM/provenance and complete final-runtime security reports
are required in CI on both supported architectures. Replacing a file in an
image layer does not physically remove its earlier bytes from lower layers.
These recipes do not claim bit-for-bit OS or binary reproduction, or freedom
from all advisories. Fixable high/critical runtime advisories must still fail.

To maintain a recipe, review a targeted publisher release/package update,
resolve its raw official index on both architectures, verify source archives
and signed APK bytes, regenerate the isolated readonly Go graph if needed,
review the dependency difference and refresh every input SHA256 in the
manifest. Bump the maintenance recipe/tag and its verifier contract together.
Run the offline/registry verifier, service-build tests, native OCI evidence
and security gates, then qualify Compose startup and copied-volume restore.
Publishing or deploying an output image is a separate operation. Kubernetes
requires reviewed immutable external image references; these local recipe
tags do not satisfy that contract.

Primary sources: [gosu 1.19](https://github.com/tianon/gosu/releases/tag/1.19),
[node_exporter 1.12.1](https://github.com/prometheus/node_exporter/releases/tag/v1.12.1),
[Go downloads](https://go.dev/dl/), [Go checksum database](https://go.dev/ref/mod#authenticating),
[Alpine package repositories](https://dl-cdn.alpinelinux.org/alpine/),
[x/sys advisory](https://pkg.go.dev/vuln/GO-2026-5024),
[x/crypto SSH advisories](https://pkg.go.dev/vuln/GO-2026-6354),
[second SSH advisory](https://pkg.go.dev/vuln/GO-2026-6355),
[OpenPGP residual](https://pkg.go.dev/vuln/GO-2026-5932).
