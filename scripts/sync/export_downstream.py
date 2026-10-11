#!/usr/bin/env python3
"""Offline, manifest-only export of canonical files into sibling checkouts.

Examples (from the research-passkeys checkout):
  python3 scripts/sync/export_downstream.py --target-root .. --check
  python3 scripts/sync/export_downstream.py --target-root .. --apply
  python3 scripts/sync/export_downstream.py --refresh-hashes

No mode is implicit. Refresh only updates hashes in ``files``; historical
``removed`` hashes and all mappings/metadata stay unchanged. ``preserved``
entries protect paths (including their children) without enforcing their bytes.
When ``generated_compatibility`` is true, all generated compatibility files must
match the trusted sibling renderer before any mode, including hash refresh.
All inputs are preflighted before changes, and symlink paths are refused, even
when the link points inside a checkout. Run with quiescent local checkouts:
this is not a transaction or a defense against concurrent filesystem changes.
Exit codes: 0 = success/current, 1 = drift, 2 = invalid input or I/O failure.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePath, PurePosixPath
import re
import stat
import sys
import tempfile


REPOSITORIES = frozenset(("nathanmcnulty", "action-passkey-login"))
MANIFEST_PATH = "scripts/sync/downstream-manifest.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# The trusted sibling renderer reads these canonical inputs. Validate containment
# before it opens them, even when a generic manifest does not export the inputs.
RENDER_INPUTS = (
    "github/action-passkey-login/PasskeyLogin.ps1",
    "powershell/scripts/entra/reference/Initialize-EntraPasskeyKeyVault.ps1",
    "powershell/scripts/entra/reference/Register-EntraSoftwarePasskey.ps1",
)
WINDOWS_DEVICES = frozenset(("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$")) | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "123456789\u00b9\u00b2\u00b3"
}


class SyncError(Exception):
    """An unsafe or invalid export was refused."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative_path(value, label):
    """Accept only unambiguous, portable, repository-relative POSIX paths."""
    if (not isinstance(value, str) or not value
            or any(character in value for character in '\\:<>"|?*')):
        raise SyncError(f"{label}: expected a safe relative POSIX path")
    parts = value.split("/")
    if any(part.casefold() in ("", ".", "..", ".git")
           or part.endswith((".", " "))
           or part.split(".")[0].rstrip().upper() in WINDOWS_DEVICES for part in parts):
        raise SyncError(f"{label}: unsafe relative path {value!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SyncError(f"{label}: control characters are not allowed in paths")
    return PurePosixPath(value)


def is_link(info):
    """Treat Windows junctions and other reparse points as unsafe links too."""
    return (stat.S_ISLNK(info.st_mode)
            or bool(getattr(info, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))


def directory_root(value):
    """Require a real existing directory, without symlink ancestors."""
    path = Path(os.path.abspath(value))
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            raise SyncError(f"Directory does not exist: {component}") from None
        if is_link(info):
            raise SyncError(f"Symlink directory or reparse point is not allowed: {component}")
        if not component.is_dir():
            raise SyncError(f"Directory does not exist: {component}")
    return path


def checked_path(root, relative):
    """Validate existing components; missing parents are allowed for exports."""
    relative = relative_path(str(relative), "path")
    current = root
    if is_link(root.lstat()) or not root.is_dir():
        raise SyncError(f"Unsafe or missing root directory: {root}")
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if is_link(info):
            raise SyncError(f"Symlink path or reparse point is not allowed: {current}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise SyncError(f"Parent is not a directory: {current}")
        if index == len(relative.parts) - 1 and not stat.S_ISREG(info.st_mode):
            raise SyncError(f"Expected a regular file: {current}")
    return current


def read_file(path):
    """Read an existing regular file without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise SyncError(f"Expected a regular file: {path}")
        return stream.read()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SyncError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def valid_hash(value, label):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise SyncError(f"{label}: sha256 must be 64 lowercase hexadecimal characters")


def load_manifest(root):
    path = checked_path(root, MANIFEST_PATH)
    manifest = json.loads(read_file(path), object_pairs_hook=unique_object)
    if not isinstance(manifest, dict) or type(manifest.get("version")) is not int:
        raise SyncError("Manifest version must be the integer 1")
    if manifest["version"] != 1:
        raise SyncError("Unsupported manifest version; expected 1")
    if ("generated_compatibility" in manifest
            and type(manifest["generated_compatibility"]) is not bool):
        raise SyncError("generated_compatibility must be a boolean")
    destinations = []
    for section in ("files", "removed", "preserved"):
        entries = manifest.get(section)
        if not isinstance(entries, list):
            raise SyncError(f"Manifest {section} must be an array")
        for index, entry in enumerate(entries):
            label = f"{section}[{index}]"
            if not isinstance(entry, dict):
                raise SyncError(f"{label}: expected an object")
            repository = entry.get("repository")
            if not isinstance(repository, str) or repository not in REPOSITORIES:
                raise SyncError(f"{label}: unknown repository {repository!r}")
            relative = relative_path(entry.get("path"), label)
            folded_relative = PurePosixPath(str(relative).casefold())
            if section == "files":
                relative_path(entry.get("source"), f"{label}.source")
            if section != "preserved" or "sha256" in entry:
                valid_hash(entry.get("sha256"), label)
            for previous_repo, previous_path, previous_section in destinations:
                if previous_repo != repository:
                    continue
                folded_previous = PurePosixPath(str(previous_path).casefold())
                if (folded_relative == folded_previous or folded_relative in folded_previous.parents
                        or folded_previous in folded_relative.parents):
                    raise SyncError(
                        f"Overlapping destinations: {repository}/{relative} ({section}) "
                        f"and {repository}/{previous_path} ({previous_section})"
                    )
            destinations.append((repository, relative, section))
    return manifest


def load_renderer():
    """Load code only from this utility's package, never from --research-root."""
    path = Path(__file__).resolve().with_name("render_compatibility.py")
    spec = importlib.util.spec_from_file_location("_passkey_sync_renderer", path)
    if spec is None or spec.loader is None:
        raise SyncError(f"Cannot load the trusted compatibility renderer: {path}")
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    return renderer


def verify_generated_compatibility(root, manifest):
    if not manifest.get("generated_compatibility", False):
        return
    for relative in RENDER_INPUTS:
        # read_file also requires existence and a regular file before rendering.
        read_file(checked_path(root, relative))
    outputs = load_renderer().render(root)
    if not isinstance(outputs, dict) or not outputs:
        raise SyncError("Compatibility renderer returned no output files")
    stale = []
    for relative, expected in outputs.items():
        if isinstance(relative, PurePath):
            relative = relative.as_posix()
        if not isinstance(expected, bytes):
            raise SyncError("Compatibility renderer must return byte-exact output")
        relative = relative_path(relative, "generated output")
        path = checked_path(root, relative)
        if not path.exists() or read_file(path) != expected:
            stale.append(str(relative))
    if stale:
        raise SyncError(
            "Stale generated compatibility files: " + ", ".join(sorted(stale))
            + "; run scripts/sync/render_compatibility.py before refreshing hashes or exporting"
        )


def source_bytes(root, manifest, verify=True):
    result = {}
    for entry in manifest["files"]:
        source = entry["source"]
        if source not in result:
            result[source] = read_file(checked_path(root, source))
        actual = digest(result[source])
        if verify and actual != entry["sha256"]:
            raise SyncError(
                f"Source hash mismatch: {source} (expected {entry['sha256']}, got {actual}); "
                "review source changes before using --refresh-hashes"
            )
    return result


def atomic_write(root, relative, data):
    path = checked_path(root, relative)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    path.parent.mkdir(parents=True, exist_ok=True)
    path = checked_path(root, relative)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".passkey-sync-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.chmod(temporary, mode)
        checked_path(root, relative)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def refresh_hashes(root, manifest):
    sources = source_bytes(root, manifest, verify=False)
    changed = 0
    for entry in manifest["files"]:
        actual = digest(sources[entry["source"]])
        if entry["sha256"] != actual:
            entry["sha256"] = actual
            changed += 1
    if changed:
        data = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        atomic_write(root, MANIFEST_PATH, data)
    print(f"Refreshed {changed} source hash(es); mappings and removal hashes unchanged.")
    return 0


def preflight(root, target_root, manifest):
    """Read and validate everything before returning an ordered mutation plan."""
    sources = source_bytes(root, manifest)
    repositories = {
        entry["repository"] for section in ("files", "removed") for entry in manifest[section]
    }
    roots = {name: directory_root(target_root / name) for name in sorted(repositories)}
    plan = []
    for section in ("files", "removed"):
        for entry in manifest[section]:
            repository, relative = entry["repository"], entry["path"]
            path = checked_path(roots[repository], relative)
            existing = read_file(path) if path.exists() else None
            if section == "files":
                data = sources[entry["source"]]
                if existing != data:
                    reason = "missing" if existing is None else "content differs"
                    plan.append((repository, relative, "WRITE", data, reason))
            elif existing is not None:
                if digest(existing) != entry["sha256"]:
                    raise SyncError(f"Refusing unknown removal content: {repository}/{relative}")
                plan.append((repository, relative, "REMOVE", existing, "obsolete file exists"))
    return roots, sorted(plan, key=lambda item: (item[0], item[1]))


def synchronize(root, target_root, manifest, apply=False):
    roots, plan = preflight(root, target_root, manifest)
    if not apply:
        for repository, relative, operation, data, reason in plan:
            print(f"DRIFT {repository}/{relative}: {reason}")
        if not plan:
            print("Up to date.")
        return 1 if plan else 0
    for repository, relative, operation, data, reason in plan:
        if operation == "WRITE":
            atomic_write(roots[repository], relative, data)
        else:
            path = checked_path(roots[repository], relative)
            if not path.exists():
                continue
            # Recheck immediately before unlinking, and never remove a directory.
            if read_file(path) != data:
                raise SyncError(f"Removal content changed during export: {repository}/{relative}")
            path.unlink()
        print(f"{operation} {repository}/{relative}")
    if not plan:
        print("Up to date.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="report drift without changing files")
    mode.add_argument("--apply", action="store_true", help="export bytes and remove only known obsolete files")
    mode.add_argument("--refresh-hashes", action="store_true", help="refresh only canonical file hashes")
    parser.add_argument("--target-root", type=Path, help="directory containing downstream repository checkouts")
    parser.add_argument("--research-root", type=Path, default=Path(__file__).absolute().parents[2],
                        help="canonical checkout (defaults to this script's repository)")
    args = parser.parse_args(argv)
    if not args.refresh_hashes and args.target_root is None:
        parser.error("--target-root is required with --check or --apply")
    if args.refresh_hashes and args.target_root is not None:
        parser.error("--refresh-hashes does not use --target-root")
    try:
        root = directory_root(args.research_root)
        manifest = load_manifest(root)
        verify_generated_compatibility(root, manifest)
        if args.refresh_hashes:
            return refresh_hashes(root, manifest)
        target_root = directory_root(args.target_root)
        return synchronize(root, target_root, manifest, apply=args.apply)
    except (SyncError, OSError, ValueError, ImportError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
