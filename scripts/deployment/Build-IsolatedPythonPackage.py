"""Build a reproducible Linux x64 / Python 3.11 Flex package from committed inputs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path

from pip._vendor.packaging.markers import default_environment
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.specifiers import SpecifierSet


ROOT = Path(__file__).resolve().parents[2]
SOURCE = "function-app/python/keyvault-passkey-http/src/"
LOCK = "scripts/deployment/python-linux311-requirements.lock"
BUILDER = "scripts/deployment/Build-IsolatedPythonPackage.py"
EXCLUDED = {".funcignore", ".gitignore", "local.settings.json", "local.settings.sample.json"}
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def run(*args: str, capture: bool = False) -> str:
    result = subprocess.run(args, cwd=ROOT, check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else ""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_wheels(lock_text: str, wheelhouse: Path) -> dict[str, bytes]:
    expected = {}
    for line in lock_text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})", line)
        if not match:
            raise ValueError(f"Invalid wheel lock entry: {line}")
        name = normalize_name(match[1])
        if name in expected:
            raise ValueError(f"Duplicate locked dependency: {name}")
        expected[name] = (match[2], match[3])

    target = default_environment()
    target.update({
        "implementation_name": "cpython",
        "os_name": "posix",
        "platform_machine": "x86_64",
        "platform_system": "Linux",
        "python_full_version": "3.11.0",
        "python_version": "3.11",
        "sys_platform": "linux",
        "extra": "",
    })
    files = {}
    found = set()
    for wheel in sorted(wheelhouse.glob("*.whl")):
        data = wheel.read_bytes()
        digest = sha256(data)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            metadata_paths = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
            if len(metadata_paths) != 1:
                raise ValueError(f"Wheel has no unique METADATA: {wheel.name}")
            metadata = archive.read(metadata_paths[0]).decode("utf-8")
            name_match = re.search(r"^Name: (.+)$", metadata, re.MULTILINE)
            version_match = re.search(r"^Version: (.+)$", metadata, re.MULTILINE)
            if not name_match or not version_match:
                raise ValueError(f"Wheel metadata is incomplete: {wheel.name}")
            name = normalize_name(name_match[1].strip())
            if name not in expected or expected[name] != (version_match[1].strip(), digest):
                raise ValueError(f"Wheel is absent from the reviewed hash lock: {wheel.name}")
            if name in found:
                raise ValueError(f"Duplicate wheel: {name}")
            found.add(name)
            metadata_headers = Parser().parsestr(metadata, headersonly=True)
            python_specifier = metadata_headers.get("Requires-Python")
            if python_specifier and not SpecifierSet(python_specifier).contains("3.11.0"):
                raise ValueError(f"Wheel does not support Python 3.11: {wheel.name}")
            for dependency in metadata_headers.get_all("Requires-Dist", []):
                requirement = Requirement(dependency)
                if requirement.marker and not requirement.marker.evaluate(target):
                    continue
                dependency_name = normalize_name(requirement.name)
                if dependency_name not in expected or not requirement.specifier.contains(expected[dependency_name][0]):
                    raise ValueError(f"Missing Linux/Python 3.11 dependency of {name}: {dependency}")
            for member in archive.infolist():
                path = member.filename
                if member.is_dir():
                    continue
                if path.startswith("/") or "\\" in path or ".." in path.split("/") or ".data/" in path:
                    raise ValueError(f"Unsupported wheel path: {path}")
                if path in files:
                    raise ValueError(f"Two wheels provide the same file: {path}")
                files[path] = archive.read(member)
    if found != set(expected):
        raise ValueError(f"Wheelhouse does not match lock: missing {sorted(set(expected) - found)}")
    return files


def validate_direct_requirements(source_text: str, lock_text: str) -> None:
    versions = {}
    for line in lock_text.splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^ ]+) --hash=sha256:[0-9a-f]{64}", line)
        if match:
            versions[normalize_name(match[1])] = match[2]
    for line in source_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        name = normalize_name(requirement.name)
        if requirement.marker or requirement.url or requirement.extras:
            raise ValueError(f"Unsupported direct requirement: {line}")
        if name not in versions or not requirement.specifier.contains(versions[name]):
            raise ValueError(f"Locked version does not satisfy source requirement: {line}")


def committed_sources(revision: str) -> list[str]:
    raw = subprocess.run(
        ["git", "ls-tree", "-rz", revision, "--", SOURCE],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    entries = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, path = item.split(b"\t", 1)
        mode, kind, _ = metadata.split(b" ", 2)
        if mode not in (b"100644", b"100755") or kind != b"blob":
            raise ValueError(f"Unsupported Git source entry: {path.decode()}")
        relative = path.decode("utf-8")[len(SOURCE) :]
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise ValueError(f"Invalid Function source path: {relative}")
        if Path(relative).name not in EXCLUDED:
            entries.append(relative)
    if "host.json" not in entries or "requirements.txt" not in entries:
        raise ValueError("Committed Python Functions root files are missing")
    return sorted(entries)


def add_entry(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data, compresslevel=9)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()

    wheelhouse = args.wheelhouse.resolve(strict=True)
    if not wheelhouse.is_dir():
        raise ValueError("Wheelhouse must be a directory")
    output = args.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=True)
    package = output / "released-package.zip"
    if package.exists():
        raise FileExistsError(package)

    revision = run("git", "rev-parse", "HEAD", capture=True)
    dirty = run("git", "status", "--porcelain", "--untracked-files=all", "--", SOURCE, LOCK, BUILDER, capture=True)
    if dirty:
        raise ValueError("Function source, wheel lock, or builder has local changes; review and commit them first")
    entries = committed_sources(revision)
    lock_bytes = subprocess.run(
        ["git", "show", f"{revision}:{LOCK}"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    lock_text = lock_bytes.decode("utf-8")
    if not re.search(r"^azure-functions==\S+ --hash=sha256:[0-9a-f]{64}$", lock_text, re.MULTILINE):
        raise ValueError("Linux wheel lock is missing azure-functions or a SHA-256 hash")

    with tempfile.TemporaryDirectory(prefix="kvpp-python311-") as temporary:
        temp = Path(temporary)
        lock_path = temp / "requirements.lock"
        lock_path.write_bytes(lock_bytes)
        # Pip checks the complete dependency graph and Linux wheel tags. The final
        # package reads wheel bytes directly, avoiding host-specific Windows scripts.
        run(
            sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
            "--disable-pip-version-check", "--no-index", "--find-links", str(wheelhouse),
            "--require-hashes", "--platform", "manylinux2014_x86_64",
            "--python-version", "3.11", "--implementation", "cp", "--abi", "cp311",
            "--only-binary=:all:", "-r", str(lock_path),
        )
        dependency_files = locked_wheels(lock_text, wheelhouse)
        if not any(path.endswith(".so") for path in dependency_files):
            raise ValueError("Linux native dependencies were not found")

        source_zip = temp / "source.zip"
        run("git", "archive", "--format=zip", "--output", str(source_zip), f"{revision}:{SOURCE.rstrip('/')}")
        with zipfile.ZipFile(source_zip) as source, zipfile.ZipFile(package, "x") as release:
            validate_direct_requirements(source.read("requirements.txt").decode("utf-8"), lock_text)
            for relative in entries:
                add_entry(release, relative, source.read(relative))
            for relative, data in sorted(dependency_files.items()):
                add_entry(release, f".python_packages/lib/site-packages/{relative}", data)

    manifest = {
        "sourceRevision": revision,
        "wheelLockSha256": sha256(lock_bytes),
        "packageFile": package.name,
        "sha256": sha256(package.read_bytes()),
        "sourceFileCount": len(entries),
        "dependencyFileCount": len(dependency_files),
        "target": "Linux x86_64 / CPython 3.11 / manylinux2014",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
