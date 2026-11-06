"""The Debian bootstrap verifies the whole package set before any installation."""

from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
from subprocess import CalledProcessError
from urllib.error import URLError

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "docker/install-debian-security.py"


@pytest.fixture
def installer(monkeypatch):
    spec = spec_from_file_location("install_debian_security", INSTALLER)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    # Synthetic bytes exercise the check independently of mirror availability.
    packages = {}
    pins = []
    for stem, _ in module.PACKAGES:
        architectures = {}
        for arch in ("amd64", "arm64"):
            data = f"{stem}/{arch}".encode()
            architectures[arch] = sha256(data).hexdigest(), len(data)
            packages[f"{module.ARCHIVE}/{stem}_{arch}.deb"] = data
        pins.append((stem, architectures))

    monkeypatch.setattr(module, "PACKAGES", pins)
    monkeypatch.setattr(module, "urlopen", lambda url, timeout: BytesIO(packages[url]))
    return module, packages


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_debian_security_configures_package_predependencies_in_order(installer, monkeypatch, arch):
    module, _ = installer
    monkeypatch.setattr(module, "check_output", lambda args, text: arch + "\n")
    installed = []

    def install(args, check):
        command, action, path = args
        assert (command, action, check) == ("dpkg", "--install", True)
        assert path.is_file()
        installed.append(path)

    monkeypatch.setattr(module, "run", install)
    module.main()

    assert [path.name for path in installed] == [
        f"liblzma5_5.8.1-1+deb13u2_{arch}.deb",
        f"libapt-pkg7.0_3.0.4_{arch}.deb",
        f"apt_3.0.4_{arch}.deb",
    ]
    assert all(not path.exists() for path in installed)


@pytest.mark.parametrize("failure", ["same-size-tamper", "missing"])
def test_debian_security_rejects_a_bad_download_before_installing_anything(installer, monkeypatch, failure):
    module, packages = installer
    monkeypatch.setattr(module, "check_output", lambda args, text: "amd64\n")
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: pytest.fail("Unexpected dpkg installation"))

    def download(url, timeout):
        data = packages[url]
        if "libapt-pkg7.0" in url:
            if failure == "missing":
                raise URLError("Unavailable")
            data = b"x" + data[1:]
        return BytesIO(data)

    monkeypatch.setattr(module, "urlopen", download)
    if failure == "missing":
        with pytest.raises(URLError, match="Unavailable"):
            module.main()
    else:
        with pytest.raises(SystemExit, match="verification failed"):
            module.main()


def test_debian_security_rejects_unsupported_arch_before_fetching(installer, monkeypatch):
    module, _ = installer
    monkeypatch.setattr(module, "check_output", lambda args, text: "s390x\n")
    monkeypatch.setattr(module, "urlopen", lambda *args, **kwargs: pytest.fail("Unexpected package fetch"))
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: pytest.fail("Unexpected dpkg installation"))
    with pytest.raises(SystemExit, match="Unsupported Debian security package architecture"):
        module.main()


def test_debian_security_stops_on_dpkg_failure_and_cleans_temporary_files(installer, monkeypatch):
    module, _ = installer
    monkeypatch.setattr(module, "check_output", lambda args, text: "arm64\n")
    attempted = []

    def install(args, check):
        attempted.append(args[2])
        raise CalledProcessError(2, "dpkg")

    monkeypatch.setattr(module, "run", install)
    with pytest.raises(CalledProcessError):
        module.main()
    assert len(attempted) == 1 and not attempted[0].parent.exists()
