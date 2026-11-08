"""Install the reviewed Trixie security packages without invoking vulnerable APT."""

from hashlib import sha256
from pathlib import Path
from subprocess import check_output, run
from tempfile import TemporaryDirectory
from urllib.request import urlopen

ARCHIVE = "https://security.debian.org/debian-security/pool/updates/main"
# DSA-6549-1, DSA-6607-1 and DSA-6613-1. Verify all bytes before invoking dpkg.
# Digests and sizes come from the signed trixie-security indexes for each architecture.
PACKAGES = (
    ("x/xz-utils/liblzma5_5.8.1-1+deb13u2", {
        "amd64": ("b38acab30f295bf1066a6632e31cbd0a1980f2924b38040cda131d5dea5384ec", 309696),
        "arm64": ("88f3aa499dc30edf01b9209ab40f11e37edfbecef971f84f4721de1874ed4827", 302984),
    }),
    ("z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+deb13u1", {
        "amd64": ("8c27c342230503b73dfde629642c3b352e87b554e06d60cf58772f236a305ceb", 88720),
        "arm64": ("0e41b3d7ad8ad7fcd36dd4d61ca91a70018478fc4af652e044f4be770784ddff", 85028),
    }),
    ("a/apt/libapt-pkg7.0_3.0.4", {
        "amd64": ("577eb8f489de419290102364892dbd13ca256297b61f96d61b114fd4ac18be41", 1113872),
        "arm64": ("39e4d074bc4f2081666a3625561a430fedb0c85b1a6a657c02760383232304bd", 978204),
    }),
    ("a/apt/apt_3.0.4", {
        "amd64": ("15c2030e0fb46580af4f1b4cc303f4bd26da781b004e99763bc9eff7cf8e19b8", 1453228),
        "arm64": ("9a3ee57117d1d8e086e2d8917cd3e85e8f76da25dd18a898085759668dc5c71f", 1362704),
    }),
)


def main() -> None:
    arch = check_output(["dpkg", "--print-architecture"], text=True).strip()
    if arch not in ("amd64", "arm64"):
        raise SystemExit(f"Unsupported Debian security package architecture: {arch}")
    with TemporaryDirectory(prefix="shadai-debian-security-") as directory:
        packages = []
        for package, pins in PACKAGES:
            digest, size = pins[arch]
            name = f"{package}_{arch}.deb"
            with urlopen(f"{ARCHIVE}/{name}", timeout=45) as response:
                data = response.read(size + 1)
            if len(data) != size or sha256(data).hexdigest() != digest:
                raise SystemExit(f"Debian security package verification failed: {name}")
            path = Path(directory) / Path(name).name
            path.write_bytes(data)
            packages.append(path)
        # APT pre-depends on the matching configured libapt package.
        for package in packages:
            run(["dpkg", "--install", package], check=True)


if __name__ == "__main__":
    main()
