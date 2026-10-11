#!/usr/bin/env python3
"""Offline regression tests: python3 -m unittest discover -s scripts/sync -v."""

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import export_downstream as sync


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # Resolve platform aliases in the test fixture, not in the utility.
        self.base = Path(self.temporary.name).resolve()
        self.research = self.base / "research-passkeys"
        self.targets = self.base / "targets"
        self.research.mkdir()
        self.targets.mkdir()
        for name in sync.REPOSITORIES:
            (self.targets / name).mkdir()
        self.data = b"first\r\nsecond\n\x00\xff"
        self.write(self.research / "canonical/source.bin", self.data)
        self.manifest = {
            "version": 1,
            "files": [{
                "source": "canonical/source.bin",
                "repository": "nathanmcnulty",
                "path": "export/copy.bin",
                "sha256": sync.digest(self.data),
            }],
            "removed": [],
            "preserved": [],
        }
        self.save_manifest()

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    @property
    def destination(self):
        return self.targets / "nathanmcnulty/export/copy.bin"

    @property
    def manifest_path(self):
        return self.research / sync.MANIFEST_PATH

    def save_manifest(self):
        self.write(self.manifest_path, (json.dumps(self.manifest, indent=2) + "\n").encode())

    def run_sync(self, mode="--check", extra=()):
        arguments = ["--research-root", str(self.research), mode]
        if mode != "--refresh-hashes":
            arguments += ["--target-root", str(self.targets)]
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = sync.main(arguments + list(extra))
        return result, output.getvalue(), errors.getvalue()

    def assert_error(self, expected):
        result, output, errors = self.run_sync("--apply")
        self.assertEqual(result, 2, (output, errors))
        self.assertIn(expected, errors)
        self.assertFalse(self.destination.exists(), "preflight must prevent partial writes")

    def symlink(self, link, target, directory=False):
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"Symlinks unavailable: {error}")

    def add_removal(self, data=b"known obsolete bytes", path="old.txt"):
        entry = {"repository": "action-passkey-login", "path": path, "sha256": sync.digest(data)}
        self.manifest["removed"].append(entry)
        self.save_manifest()
        return self.targets / entry["repository"] / path

    def generated_fixture(self):
        """Use the real trusted renderer and canonical inputs in an isolated root."""
        actual_root = Path(sync.__file__).resolve().parents[2]
        for relative in sync.RENDER_INPUTS:
            self.write(self.research / relative, (actual_root / relative).read_bytes())
        outputs = sync.load_renderer().render(self.research)
        for relative, data in outputs.items():
            self.write(self.research / relative, data)
        relative, data = next(iter(outputs.items()))
        self.manifest["files"].append({
            "source": relative.as_posix(), "repository": "action-passkey-login",
            "path": "compatibility/PasskeyLogin.ps1", "sha256": sync.digest(data),
        })
        self.manifest["generated_compatibility"] = True
        self.save_manifest()
        return relative

    def test_check_detects_missing_without_mutation(self):
        before = self.manifest_path.read_bytes()
        result, output, errors = self.run_sync()
        self.assertEqual(result, 1)
        self.assertIn("DRIFT nathanmcnulty/export/copy.bin: missing", output)
        self.assertEqual(errors, "")
        self.assertFalse(self.destination.parent.exists())
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_apply_is_byte_exact_and_idempotent(self):
        self.assertEqual(self.run_sync("--apply")[0], 0)
        self.assertEqual(self.destination.read_bytes(), self.data)
        before = self.destination.stat().st_mtime_ns
        self.assertEqual(self.run_sync(), (0, "Up to date.\n", ""))
        self.assertEqual(self.run_sync("--apply"), (0, "Up to date.\n", ""))
        self.assertEqual(self.destination.stat().st_mtime_ns, before)
        self.assertEqual(list(self.targets.rglob(".passkey-sync-*")), [])

    def test_check_detects_tampering_and_apply_repairs_it(self):
        self.write(self.destination, b"drift")
        result, output, errors = self.run_sync()
        self.assertEqual(result, 1)
        self.assertIn("content differs", output)
        self.assertEqual(self.destination.read_bytes(), b"drift")
        self.assertEqual(self.run_sync("--apply")[0], 0)
        self.assertEqual(self.destination.read_bytes(), self.data)

    def test_duplicate_source_can_map_to_distinct_targets(self):
        second = dict(self.manifest["files"][0], repository="action-passkey-login", path="copy.bin")
        self.manifest["files"].append(second)
        self.save_manifest()
        self.assertEqual(self.run_sync("--apply")[0], 0)
        self.assertEqual(self.destination.read_bytes(), self.data)
        self.assertEqual((self.targets / "action-passkey-login/copy.bin").read_bytes(), self.data)

    def test_output_order_is_deterministic(self):
        self.manifest["files"].append(dict(self.manifest["files"][0], path="aaa.bin"))
        self.save_manifest()
        first = self.run_sync()
        self.manifest["files"].reverse()
        self.save_manifest()
        self.assertEqual(self.run_sync(), first)
        self.assertEqual(first[1].splitlines()[0], "DRIFT nathanmcnulty/aaa.bin: missing")

    def test_source_hash_mismatch_blocks_all_mutations(self):
        self.write(self.research / "canonical/other.bin", b"unreviewed")
        self.manifest["files"].append(dict(self.manifest["files"][0], source="canonical/other.bin", path="other.bin"))
        self.save_manifest()
        self.assert_error("Source hash mismatch")

    def test_missing_source_blocks_all_mutations(self):
        self.manifest["files"].append(dict(self.manifest["files"][0], source="missing", path="other.bin"))
        self.save_manifest()
        self.assert_error("No such file")

    def test_known_removal_is_reported_then_unlinked(self):
        old = self.add_removal(path="old/file.txt")
        self.write(old, b"known obsolete bytes")
        result, output, errors = self.run_sync()
        self.assertEqual(result, 1)
        self.assertIn("obsolete file exists", output)
        self.assertTrue(old.exists())
        self.assertEqual(self.run_sync("--apply")[0], 0)
        self.assertFalse(old.exists())
        self.assertTrue(old.parent.is_dir(), "empty directories must never be recursively removed")
        self.assertEqual(self.run_sync()[0], 0)

    def test_missing_removal_is_ok(self):
        self.add_removal()
        self.assertEqual(self.run_sync("--apply")[0], 0)
        self.assertEqual(self.run_sync()[0], 0)

    def test_unknown_removal_hash_blocks_all_changes(self):
        old = self.add_removal()
        self.write(old, b"locally modified, do not delete")
        self.assert_error("Refusing unknown removal content")
        self.assertEqual(old.read_bytes(), b"locally modified, do not delete")

    def test_missing_or_invalid_removal_hash_is_rejected(self):
        old = self.add_removal()
        self.write(old, b"known obsolete bytes")
        for value in (None, "", "unknown", "f" * 63, "F" * 64, 7):
            with self.subTest(value=value):
                self.manifest["removed"][0]["sha256"] = value
                self.save_manifest()
                self.assert_error("sha256")
                self.assertTrue(old.exists())

    def test_directory_is_never_removed(self):
        old = self.add_removal()
        old.mkdir()
        (old / "important.txt").write_text("keep")
        self.assert_error("Expected a regular file")
        self.assertEqual((old / "important.txt").read_text(), "keep")

    def test_unlisted_and_preserved_files_are_untouched(self):
        preserved = self.targets / "nathanmcnulty/keep/README.md"
        unlisted = self.targets / "action-passkey-login/unlisted.txt"
        self.write(preserved, b"personal documentation")
        self.write(unlisted, b"not managed")
        self.manifest["preserved"] = [{"repository": "nathanmcnulty", "path": "keep", "reason": "downstream owned"}]
        self.save_manifest()
        self.assertEqual(self.run_sync("--apply")[0], 0)
        self.assertEqual(preserved.read_bytes(), b"personal documentation")
        self.assertEqual(unlisted.read_bytes(), b"not managed")

    def test_preserved_hash_is_not_enforced(self):
        self.manifest["preserved"] = [{"repository": "nathanmcnulty", "path": "README.md", "sha256": "0" * 64}]
        self.save_manifest()
        self.write(self.targets / "nathanmcnulty/README.md", b"downstream edits")
        self.assertEqual(self.run_sync("--apply")[0], 0)

    def test_duplicate_and_prefix_destinations_are_rejected(self):
        for path in ("export/copy.bin", "export", "export/copy.bin/nested", "EXPORT/COPY.BIN"):
            with self.subTest(path=path):
                self.manifest["files"] = [self.manifest["files"][0], dict(self.manifest["files"][0], path=path)]
                self.save_manifest()
                self.assert_error("Overlapping destinations")

    def test_copy_remove_overlap_is_rejected(self):
        self.manifest["removed"] = [{key: value for key, value in self.manifest["files"][0].items() if key != "source"}]
        self.save_manifest()
        self.assert_error("Overlapping destinations")

    def test_preserved_overlap_is_rejected(self):
        self.manifest["preserved"] = [{"repository": "nathanmcnulty", "path": "export"}]
        self.save_manifest()
        self.assert_error("Overlapping destinations")

    def test_unknown_repository_is_rejected_in_every_section(self):
        for section in ("files", "removed", "preserved"):
            with self.subTest(section=section):
                bad = dict(self.manifest["files"][0], repository="other-repository")
                before = copy.deepcopy(self.manifest)
                self.manifest[section].append(bad)
                self.save_manifest()
                self.assert_error("unknown repository")
                self.manifest = before

    def test_unsafe_paths_are_rejected(self):
        paths = ("../outside", "/absolute", "a/../outside", "./file", "a//b", "a/", "",
                 "a\\b", "C:/drive", "file:stream", ".git/config", "a/.git/config", "a\x00b", "a\nb",
                 ".GIT/config", ".git./config", ".git /config", "NUL", "CON.txt", "COM1/file", "a?b")
        original = dict(self.manifest["files"][0])
        for field in ("source", "path"):
            for path in paths:
                with self.subTest(field=field, path=path):
                    self.manifest["files"][0] = dict(original, **{field: path})
                    self.save_manifest()
                    self.assert_error("path")

    def test_traversal_removal_is_rejected(self):
        self.add_removal(path="../outside.txt")
        self.assert_error("unsafe relative path")

    def test_source_file_symlink_is_rejected(self):
        source = self.research / "canonical/source.bin"
        source.unlink()
        external = self.base / "outside.bin"
        external.write_bytes(self.data)
        self.symlink(source, external)
        self.assert_error("Symlink path")

    def test_source_directory_symlink_is_rejected(self):
        source = self.research / "canonical/source.bin"
        source.unlink()
        source.parent.rmdir()
        external = self.base / "outside"
        external.mkdir()
        (external / "source.bin").write_bytes(self.data)
        self.symlink(source.parent, external, directory=True)
        self.assert_error("Symlink path")

    def test_target_file_symlink_is_rejected_without_changing_referent(self):
        outside = self.base / "outside.bin"
        outside.write_bytes(b"keep")
        self.symlink(self.destination, outside)
        result, output, errors = self.run_sync("--apply")
        self.assertEqual(result, 2)
        self.assertIn("Symlink path", errors)
        self.assertEqual(outside.read_bytes(), b"keep")
        self.assertTrue(self.destination.is_symlink())

    def test_target_directory_symlink_is_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        self.symlink(self.destination.parent, outside, directory=True)
        self.assert_error("Symlink path")
        self.assertEqual(list(outside.iterdir()), [])

    def test_contained_and_dangling_symlinks_are_also_rejected(self):
        inside = self.targets / "nathanmcnulty/inside"
        inside.mkdir()
        self.symlink(self.destination.parent, inside, directory=True)
        self.assert_error("Symlink path")
        self.destination.parent.unlink()
        self.symlink(self.destination, self.base / "nonexistent")
        self.assert_error("Symlink path")

    def test_symlink_removal_is_rejected(self):
        old = self.add_removal()
        outside = self.base / "outside.bin"
        outside.write_bytes(b"known obsolete bytes")
        self.symlink(old, outside)
        self.assert_error("Symlink path")
        self.assertTrue(old.is_symlink())
        self.assertEqual(outside.read_bytes(), b"known obsolete bytes")

    def test_repository_symlink_is_rejected(self):
        repository = self.targets / "nathanmcnulty"
        repository.rmdir()
        outside = self.base / "outside"
        outside.mkdir()
        self.symlink(repository, outside, directory=True)
        self.assert_error("Symlink directory")

    def test_windows_reparse_points_are_treated_as_links(self):
        with patch.object(sync.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True):
            self.assertTrue(sync.is_link(SimpleNamespace(st_mode=sync.stat.S_IFDIR, st_file_attributes=0x400)))
            self.assertFalse(sync.is_link(SimpleNamespace(st_mode=sync.stat.S_IFDIR, st_file_attributes=0)))

    def test_root_symlink_and_symlink_ancestor_are_rejected(self):
        alias = self.base / "alias"
        self.symlink(alias, self.targets, directory=True)
        self.targets = alias
        self.assert_error("Symlink directory")
        parent_alias = self.base / "parent-alias"
        self.symlink(parent_alias, self.base, directory=True)
        self.targets = parent_alias / "targets"
        self.assert_error("Symlink directory")

    def test_missing_repository_is_not_created(self):
        (self.targets / "nathanmcnulty").rmdir()
        self.assert_error("Directory does not exist")

    def test_invalid_destination_parent_blocks_all_writes(self):
        self.write(self.targets / "action-passkey-login/not-directory", b"keep")
        self.manifest["files"].append(dict(self.manifest["files"][0], repository="action-passkey-login", path="not-directory/file"))
        self.save_manifest()
        self.assert_error("Parent is not a directory")

    def test_refresh_hashes_needs_no_targets_and_changes_no_mappings(self):
        self.manifest["files"].append(dict(self.manifest["files"][0], repository="action-passkey-login", path="copy.bin"))
        self.manifest["removed"] = [{"repository": "nathanmcnulty", "path": "old.bin", "sha256": "0" * 64}]
        self.manifest["preserved"] = [{"repository": "nathanmcnulty", "path": "README.md", "note": "keep it"}]
        self.manifest["description"] = "Extra metadata survives."
        self.save_manifest()
        self.write(self.research / "canonical/source.bin", b"reviewed new canonical content")
        before = copy.deepcopy(self.manifest)
        for entry in before["files"]:
            entry["sha256"] = sync.digest(b"reviewed new canonical content")
        self.targets.rename(self.base / "hidden-targets")
        result, output, errors = self.run_sync("--refresh-hashes")
        self.assertEqual(result, 0, errors)
        self.assertIn("Refreshed 2 source hash(es)", output)
        self.assertEqual(json.loads(self.manifest_path.read_bytes()), before)
        self.assertFalse(self.targets.exists())
        timestamp = self.manifest_path.stat().st_mtime_ns
        self.assertEqual(self.run_sync("--refresh-hashes")[0], 0)
        self.assertEqual(self.manifest_path.stat().st_mtime_ns, timestamp)

    def test_refresh_preflights_all_sources(self):
        self.write(self.research / "canonical/source.bin", b"new content")
        self.manifest["files"].append(dict(self.manifest["files"][0], source="missing", path="second.bin"))
        self.save_manifest()
        before = self.manifest_path.read_bytes()
        self.assertEqual(self.run_sync("--refresh-hashes")[0], 2)
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_generated_compatibility_consistency_allows_current_exports(self):
        relative = self.generated_fixture()
        self.assertEqual(self.run_sync("--apply")[0], 0)
        self.assertEqual(self.run_sync(), (0, "Up to date.\n", ""))
        self.assertEqual(
            (self.targets / "action-passkey-login/compatibility/PasskeyLogin.ps1").read_bytes(),
            (self.research / relative).read_bytes(),
        )

    def test_stale_generated_bytes_block_check_apply_and_hash_refresh(self):
        relative = self.generated_fixture()
        stale = b"stale rendered output with an otherwise correct manifest hash"
        self.write(self.research / relative, stale)
        self.manifest["files"][-1]["sha256"] = sync.digest(stale)
        self.save_manifest()
        before = self.manifest_path.read_bytes()
        for mode in ("--check", "--apply", "--refresh-hashes"):
            with self.subTest(mode=mode):
                result, output, errors = self.run_sync(mode)
                self.assertEqual(result, 2)
                self.assertIn("Stale generated compatibility files", errors)
                self.assertFalse(self.destination.exists())
                self.assertFalse((self.targets / "action-passkey-login/compatibility").exists())
                self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_canonical_changes_require_rerender_before_hash_refresh(self):
        self.generated_fixture()
        canonical = self.research / sync.RENDER_INPUTS[0]
        canonical.write_bytes(canonical.read_bytes() + b"\n# A reviewed canonical change.\n")
        before = self.manifest_path.read_bytes()
        result, output, errors = self.run_sync("--refresh-hashes")
        self.assertEqual(result, 2)
        self.assertIn("Stale generated compatibility files", errors)
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.assertFalse(self.destination.exists())

    def test_missing_generated_output_fails_closed(self):
        relative = self.generated_fixture()
        (self.research / relative).unlink()
        self.assert_error("Stale generated compatibility files")

    def test_renderer_is_loaded_from_trusted_package_not_research_root(self):
        self.generated_fixture()
        untrusted = self.research / "scripts/sync/render_compatibility.py"
        self.write(untrusted, b"raise RuntimeError('Do not load target checkout code')\n")
        self.assertEqual(self.run_sync("--apply")[0], 0)
        self.assertNotEqual(Path(sync.load_renderer().__file__).resolve(), untrusted.resolve())

    def test_renderer_input_and_output_symlinks_are_rejected(self):
        relative = self.generated_fixture()
        for candidate in (self.research / sync.RENDER_INPUTS[0], self.research / relative):
            with self.subTest(path=candidate):
                original = candidate.read_bytes()
                external = self.base / "external-render-input"
                external.write_bytes(original)
                candidate.unlink()
                self.symlink(candidate, external)
                self.assert_error("Symlink path")
                candidate.unlink()
                candidate.write_bytes(original)

    def test_generated_flag_requires_boolean_and_false_is_generic(self):
        for flag in (None, "true", 1, 0, [], {}):
            with self.subTest(flag=flag):
                self.manifest["generated_compatibility"] = flag
                self.save_manifest()
                self.assert_error("generated_compatibility must be a boolean")
        self.manifest["generated_compatibility"] = False
        self.save_manifest()
        self.assertEqual(self.run_sync("--apply")[0], 0)

    def test_renderer_failure_prevents_hash_refresh_and_all_mutations(self):
        self.generated_fixture()
        before = self.manifest_path.read_bytes()
        with patch.object(sync, "load_renderer", side_effect=ImportError("unavailable renderer")):
            for mode in ("--apply", "--refresh-hashes"):
                result, output, errors = self.run_sync(mode)
                self.assertEqual(result, 2)
                self.assertIn("unavailable renderer", errors)
                self.assertFalse(self.destination.exists())
                self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_manifest_symlink_is_rejected(self):
        outside = self.base / "manifest.json"
        self.manifest_path.rename(outside)
        self.symlink(self.manifest_path, outside)
        self.assert_error("Symlink path")

    def test_invalid_json_schema_and_duplicate_keys_are_rejected(self):
        for contents in (b"{", b"[]", b'{"version":true}', b'{"version":2}',
                         b'{"version":1,"version":1}',
                         b'{"version":1,"files":{},"removed":[],"preserved":[]}'):
            with self.subTest(contents=contents):
                self.manifest_path.write_bytes(contents)
                result, output, errors = self.run_sync("--apply")
                self.assertEqual(result, 2)
                self.assertTrue(errors.startswith("ERROR:"))
                self.assertFalse(self.destination.exists())

    def test_cli_requires_explicit_mode_and_targets(self):
        script = Path(sync.__file__)
        cases = ([], ["--check"], ["--apply", "--check"],
                 ["--refresh-hashes", "--target-root", str(self.targets)])
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, str(script), *arguments], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
