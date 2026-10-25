"""A future manager-only Release advances while its audited backend stays put.

Synthetic Git objects and APK metadata isolate the resolver policy. Real APK
cryptographic verification and binary parsing are covered by test_release_apk.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github/workflows/scripts"))
import release_target as policy


def git_sha(contents):
    return hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest()


def source_tree(changes=None, removed=()):
    files = {
        "kernel/Kbuild": b"VERSION_TAG := 4.2.1\nkernelsu-objs += core/init.o\n",
        "kernel/Makefile": b"KSU_VERSION := 40994\nccflags-y += -DCONFIG_KSU\n",
        "kernel/core/init.c": b"void init(void) { install_hooks(); }\n",
        "uapi/supercall.h": b"static const unsigned UAPI = 5;\n",
        "kernel/include/uapi": b"../../uapi",
        **{path: b"unchanged kernel interaction\n" for path in policy.INTERACTION_PATHS},
    }
    files.update(changes or {})
    for path in removed:
        files.pop(path)
    blobs = {git_sha(contents): contents for contents in files.values()}
    entries = [{"path": path, "type": "blob", "mode": "120000" if path == "kernel/include/uapi" else "100644",
                "sha": git_sha(contents)} for path, contents in files.items()]
    return {"truncated": False, "tree": entries}, blobs


class LatestReleasePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tree, self.blobs = source_tree()
        self.fingerprint = policy.source_fingerprint(self.tree, self.blobs.__getitem__)
        self.apk = b"downloaded official fixture bytes"
        self.digest = hashlib.sha256(self.apk).hexdigest()
        self.certificate = "9" * 64
        self.downloads = []
        self.baseline = policy.ReleaseTarget(
            tag="v4.2.1", release_commit="1" * 40, manager_version=40994,
            backend_tag="v4.2.1", source_fingerprint=self.fingerprint,
            version=40994, uapi=5, features=7, kernelsu_commit="a" * 40,
            susfs_commit="b" * 40, susfs_version="v2.3.0", patch_commit="c" * 40,
            common_commit="d" * 40, anykernel_commit="e" * 40,
            kernel_tuple=("android12", "5.10", "209", "2024-05"), revision="r13",
            apk_name="SukiSU_v4.2.1_40994-release.apk", apk_sha256="8" * 64,
            manager_certificate_sha256=self.certificate)
        self.release = {"draft": False, "prerelease": False, "tag_name": "v4.2.2", "assets": [{
            "name": "SukiSU_v4.2.2_40995-release.apk", "digest": "sha256:" + self.digest,
            "size": len(self.apk), "browser_download_url":
                "https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/download/v4.2.2/SukiSU_v4.2.2_40995-release.apk"}]}
        self.metadata = {"package": "com.sukisu.ultra", "version_name": "v4.2.2", "version_code": 40995,
                         "uapi": 5, "certificate_sha256": self.certificate, "sha256": self.digest}

    @contextmanager
    def environment(self, release=None, tree=None, blobs=None, metadata=None, commit=None):
        release = self.release if release is None else release
        tree = self.tree if tree is None else tree
        blobs = self.blobs if blobs is None else blobs
        metadata = self.metadata if metadata is None else metadata
        calls = []

        def api(endpoint):
            calls.append(endpoint)
            if endpoint == "commits/v4.2.2":
                return {"sha": commit or "2" * 40}
            if endpoint == f"git/trees/{commit or '2' * 40}?recursive=1":
                return tree
            if endpoint in ("releases/latest", "releases/tags/v4.2.2"):
                return release
            raise AssertionError("Unexpected official endpoint: " + endpoint)

        def download(command, **kwargs):
            self.downloads.append(command)
            self.assertEqual(command[:4], ["gh", "release", "download", "v4.2.2"])
            directory = Path(command[command.index("--dir") + 1])
            filename = command[command.index("--pattern") + 1]
            (directory / filename).write_bytes(self.apk)
            return subprocess.CompletedProcess(command, 0, "", "")

        with ExitStack() as stack:
            stack.enter_context(patch.object(policy, "load_release_target", return_value=self.baseline))
            stack.enter_context(patch.object(policy, "github_api", side_effect=api))
            stack.enter_context(patch.object(policy, "_read_blob", side_effect=blobs.__getitem__))
            stack.enter_context(patch.object(policy.subprocess, "run", side_effect=download))
            stack.enter_context(patch.object(policy, "inspect_release_apk", return_value=metadata))
            yield calls

    def test_future_manager_only_release_advances_without_relabeling_backend(self):
        with self.environment():
            target = policy._resolve(self.release)
        self.assertEqual((target.tag, target.manager_version, target.release_commit), ("v4.2.2", 40995, "2" * 40))
        self.assertEqual((target.version, target.backend_tag, target.uapi), (40994, "v4.2.1", 5))
        self.assertEqual(target.full_version, "v4.2.1-aaaaaaaa@builtin")
        self.assertEqual(target.pins, self.baseline.pins)

    def test_official_stable_revision_release_is_accepted(self):
        release = deepcopy(self.release)
        release['tag_name'] = 'v4.2.1-r1'
        asset = release['assets'][0]
        asset['name'] = 'SukiSU_v4.2.1-r1_41049-release.apk'
        asset['browser_download_url'] = ('https://github.com/SukiSU-Ultra/SukiSU-Ultra/'
            'releases/download/v4.2.1-r1/' + asset['name'])
        tag, version, found = policy.release_asset(release)
        self.assertEqual((tag, version), ('v4.2.1-r1', 41049))
        self.assertEqual(found, asset)

    def test_backported_kernel_identity_is_explicit_and_immutable(self):
        from dataclasses import replace
        upstream = 'ff7dfe2dbc39f78a08ee6fcff23bc615b0f54ea2'
        target = replace(self.baseline, tag='v4.2.1-r2', backend_tag='v4.2.1-r2',
                         version=41068, manager_version=41068, features=10004,
                         apk_name='SukiSU_v4.2.1-r2_41068-release.apk',
                         avc_backport_commit=upstream)
        self.assertEqual(target.full_version, 'v4.2.1-r2-aaaaaaaa+avc-ff7dfe2d@builtin')
        self.assertEqual(target.pins['avc_backport_commit'], upstream)
        self.assertNotIn('avc_backport_commit', self.baseline.pins)
        self.assertEqual(self.baseline.full_version, 'v4.2.1-aaaaaaaa@builtin')
        with patch.object(policy, 'load_release_target', return_value=target):
            policy.validate_target(target)
            for changed in (None, 'f' * 40):
                with self.assertRaisesRegex(ValueError, 'Backend recipe'):
                    policy.validate_target(replace(target, avc_backport_commit=changed))
        for invalid in ('abc', '', 1):
            with self.assertRaisesRegex(ValueError, 'backport'):
                policy._shape(replace(target, avc_backport_commit=invalid))

    def test_latest_entrypoint_actually_queries_latest(self):
        with self.environment() as calls:
            target = policy.resolve_latest_release()
        self.assertEqual(calls[0], "releases/latest")
        self.assertEqual(target.manager_version, 40995)

    def test_changed_kernel_uapi_or_interaction_source_stops_before_download(self):
        for path in ("kernel/core/init.c", "uapi/supercall.h", *sorted(policy.INTERACTION_PATHS)):
            tree, blobs = source_tree({path: b"changed behavior\n"})
            self.downloads.clear()
            with self.subTest(path=path), self.environment(tree=tree, blobs=blobs), \
                    self.assertRaisesRegex(ValueError, "implementation"):
                policy._resolve(self.release)
            self.assertEqual(self.downloads, [])

    def test_future_apk_with_uapi6_is_refused_even_with_unchanged_source(self):
        with self.environment(metadata=dict(self.metadata, uapi=6)), self.assertRaisesRegex(ValueError, "UAPI"):
            policy._resolve(self.release)

    def test_apk_certificate_digest_package_and_embedded_versions_must_match(self):
        for key, value in (("certificate_sha256", "0" * 64), ("sha256", "0" * 64),
                           ("package", "me.weishu.kernelsu"), ("version_name", "v4.2.1"), ("version_code", 40994)):
            with self.subTest(key=key), self.environment(metadata=dict(self.metadata, **{key: value})), \
                    self.assertRaisesRegex(ValueError, "APK"):
                policy._resolve(self.release)

    def test_wrong_filename_tag_or_version_does_not_match_actual_apk(self):
        for filename in ("SukiSU_v4.2.1_40995-release.apk", "SukiSU_v4.2.2_40996-release.apk"):
            release = deepcopy(self.release)
            release["assets"][0]["name"] = filename
            release["assets"][0]["browser_download_url"] = (
                "https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/download/v4.2.2/" + filename)
            with self.subTest(filename=filename), self.environment(release=release), self.assertRaises(ValueError):
                policy._resolve(release)

    def test_prerelease_draft_and_nonstable_tag_are_refused(self):
        for change in ({"prerelease": True}, {"draft": True}, {"tag_name": "v4.2.2-rc1"}, {"prerelease": None}):
            release = dict(self.release, **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy.release_asset(release)

    def test_multiple_apks_missing_digest_bad_origin_and_size_are_refused(self):
        variants = []
        release = deepcopy(self.release)
        release["assets"].append(dict(release["assets"][0], name="SukiSU_v4.2.2_40996-release.apk"))
        variants.append(release)
        missing_digest = deepcopy(self.release)
        del missing_digest["assets"][0]["digest"]
        variants.append(missing_digest)
        for changes in ({"digest": None}, {"digest": "sha256:" + "g" * 64},
                        {"browser_download_url": "https://example.invalid/manager.apk"},
                        {"size": 0}, {"size": True}):
            release = deepcopy(self.release)
            release["assets"][0].update(changes)
            variants.append(release)
        for release in variants:
            with self.subTest(release=release), self.assertRaises(ValueError):
                policy.release_asset(release)

    def test_incomplete_tree_or_missing_required_files_is_refused(self):
        for truncated in (True, None):
            with self.subTest(truncated=truncated), self.assertRaises(ValueError):
                policy.source_fingerprint(dict(self.tree, truncated=truncated), self.blobs.__getitem__)
        for removed in ("kernel/Kbuild", "kernel/Makefile", *sorted(policy.INTERACTION_PATHS)):
            tree, blobs = source_tree(removed=(removed,))
            with self.subTest(removed=removed), self.assertRaises(ValueError):
                policy.source_fingerprint(tree, blobs.__getitem__)

    def test_only_version_label_assignments_are_ignored(self):
        tree, blobs = source_tree({"kernel/Kbuild": b"VERSION_TAG := 4.2.2\nkernelsu-objs += core/init.o\n",
                                   "kernel/Makefile": b"KSU_VERSION := 40995\nccflags-y += -DCONFIG_KSU\n"})
        self.assertEqual(policy.source_fingerprint(tree, blobs.__getitem__), self.fingerprint)
        with self.environment(tree=tree, blobs=blobs):
            self.assertEqual(policy._resolve(self.release).version, 40994)

    def test_build_flags_deleted_files_and_changed_symlink_are_not_ignored(self):
        cases = [source_tree({"kernel/Kbuild": b"VERSION_TAG := 4.2.2\nccflags-y += -DNEW_HOOK\n"}),
                 source_tree({"kernel/Makefile": b"KSU_VERSION := 40995\nccflags-y += -DNEW_ABI\n"}),
                 source_tree({"kernel/new_hook.c": b"void new_hook(void);\n"}),
                 source_tree(removed=("kernel/core/init.c",)),
                 source_tree({"kernel/include/uapi": b"../../different-uapi"})]
        mode_tree = deepcopy(self.tree)
        mode_tree["tree"][0]["mode"] = "100755"
        cases.append((mode_tree, self.blobs))
        for tree, blobs in cases:
            with self.subTest(tree=tree), self.environment(tree=tree, blobs=blobs), self.assertRaises(ValueError):
                policy._resolve(self.release)

    def test_tree_duplicates_submodules_and_bad_blob_hashes_are_refused(self):
        duplicate = deepcopy(self.tree)
        duplicate["tree"].append(duplicate["tree"][0])
        submodule = deepcopy(self.tree)
        submodule["tree"].append({"path": "kernel/external", "type": "commit", "mode": "160000", "sha": "a" * 40})
        bad_hash = deepcopy(self.tree)
        bad_hash["tree"][0]["sha"] = "not-a-git-object"
        for tree in (duplicate, submodule, bad_hash):
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                policy.source_fingerprint(tree, self.blobs.__getitem__)

    def test_snapshot_verification_uses_the_pinned_tag_not_latest(self):
        with self.environment():
            target = policy._resolve(self.release)
        with self.environment() as calls:
            self.assertEqual(policy.verify_release_snapshot(target), target)
        self.assertEqual(calls[0], "releases/tags/v4.2.2")
        self.assertNotIn("releases/latest", calls)

    def test_moved_tag_and_replaced_release_asset_invalidate_snapshot(self):
        with self.environment():
            target = policy._resolve(self.release)
        with self.environment(commit="3" * 40), self.assertRaisesRegex(ValueError, "snapshot"):
            policy.verify_release_snapshot(target)
        release = deepcopy(self.release)
        release["assets"][0]["digest"] = "sha256:" + "4" * 64
        with self.environment(release=release, metadata=dict(self.metadata, sha256="4" * 64)), \
                self.assertRaisesRegex(ValueError, "snapshot"):
            policy.verify_release_snapshot(target)


if __name__ == "__main__":
    unittest.main()
