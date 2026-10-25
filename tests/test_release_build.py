"""Only the audited latest Release recipe may enter the strict build pipeline."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / ".github/workflows/scripts"
sys.path.insert(0, str(SCRIPTS))
with patch("urllib.request.urlopen", side_effect=OSError("offline test")):
    import config
    import kernel_builder
    import build


def release_config(**changes):
    return config.BuildConfig(**changes)


class ReleaseBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        original_cwd = Path.cwd()
        self.addCleanup(lambda: os.chdir(original_cwd))
        self.builder = kernel_builder.KernelBuilder(release_config(), self.temp.name)

    def write(self, relative, text):
        dest = self.builder.work_dir / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
        return dest

    def test_default_recipe_is_the_only_supported_target(self):
        target = self.builder.config.target
        self.assertEqual(target.kernelsu_commit, "ce75122bec7423e0f1fa06e3e9a174085c5231ab")
        self.assertEqual((target.version, target.uapi), (41068, 6))
        self.assertEqual(self.builder.config.to_dict()["release_tag"], "v4.2.1-r2")
        self.assertEqual((self.builder.config.android_version, self.builder.config.kernel_version,
                          self.builder.config.sub_level, self.builder.config.os_patch_level,
                          self.builder.config.revision), ("android12", "5.10", "209", "2024-05", "r13"))
        self.assertFalse(self.builder.config.use_kpm)

    def test_configuration_has_no_custom_source_or_dev_inputs(self):
        for changes in ({"kernelsu_commit": "a" * 40}, {"susfs_commit": "a" * 40},
                        {"kernelsu_version": "Dev(开发)"}, {"revision": "r12"},
                        {"sub_level": "208"}, {"use_kpm": True},
                        {"make_release": True}, {"official_40971_5": True},
                        {"release_4_2_1": True}, {"custom_version": "fake"}):
            with self.subTest(changes=changes), self.assertRaises(TypeError):
                release_config(**changes)
        from dataclasses import replace
        with self.assertRaises(ValueError):
            release_config(target=replace(self.builder.config.target, kernelsu_commit="a" * 40))

    def test_manager_only_release_is_selected_without_relabeling_the_backend(self):
        from dataclasses import replace
        baseline = self.builder.config.target
        latest = replace(baseline, tag="v4.2.2", release_commit="a" * 40,
                         manager_version=40995, apk_name="SukiSU_v4.2.2_40995-release.apk",
                         apk_sha256="b" * 64)
        config_for_latest = release_config(target=latest)
        with patch.object(build, "resolve_latest_release", return_value=latest) as resolve:
            selected = build.create_build_config(argparse.Namespace())
        resolve.assert_called_once_with()
        self.assertEqual(selected.target, latest)
        self.assertEqual(config_for_latest.target.version, 41068)
        self.assertEqual(config_for_latest.target.backend_tag, "v4.2.1-r2")
        self.assertEqual(config_for_latest.target.full_version, "v4.2.1-r2-ce75122b+avc-ff7dfe2d@builtin")
        self.assertEqual(config_for_latest.to_dict()["manager_version"], 40995)
        for field_name in ("kernelsu_commit", "common_commit", "susfs_commit", "patch_commit", "anykernel_commit", "avc_backport_commit"):
            with self.subTest(field=field_name), self.assertRaises(ValueError):
                release_config(target=replace(latest, **{field_name: "c" * 40}))
        for changes in ({"version": 40995}, {"backend_tag": "v4.2.2"}, {"source_fingerprint": "c" * 64}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                release_config(target=replace(latest, **changes))

    def test_changed_latest_release_cannot_replace_the_selected_snapshot_mid_build(self):
        from dataclasses import replace
        different = replace(self.builder.config.target, tag="v4.2.2", release_commit="a" * 40,
                            manager_version=40995, apk_name="SukiSU_v4.2.2_40995-release.apk",
                            apk_sha256="b" * 64)
        with patch.object(build, "resolve_latest_release", return_value=different):
            with self.assertRaisesRegex(ValueError, "does not match"):
                build.build_single(self.builder.config, self.temp.name, dry_run=True)
        with patch.object(kernel_builder, "resolve_latest_release", return_value=different), \
                patch.object(self.builder, "clone_repositories") as clone:
            result = self.builder.build()
        self.assertFalse(result.success)
        clone.assert_not_called()

    def test_cli_rejects_legacy_profiles_matrix_and_source_overrides(self):
        for arguments in (["--release-4-2-1"], ["--official-40971-5"],
                          ["--ksu-version", "Dev(开发)"], ["--ksu-commit", "a" * 40],
                          ["--susfs-commit", "a" * 40], ["--custom-version", "fake"],
                          ["--matrix", "android15-6.6"], ["--all"],
                          ["--android", "android15"], ["--revision", "r12"]):
            with self.subTest(arguments=arguments), patch.object(sys, "argv", ["build.py"] + arguments):
                with self.assertRaises(SystemExit):
                    build.parse_args()

    def test_dry_run_checks_latest_release_and_propagates_unknown_release(self):
        with patch.object(build, "resolve_latest_release", side_effect=ValueError("unadapted Release")):
            with self.assertRaisesRegex(ValueError, "unadapted Release"):
                build.build_single(release_config(), self.temp.name, dry_run=True)
        with patch.object(build, "resolve_latest_release", return_value=self.builder.config.target):
            result = build.build_single(release_config(), self.temp.name, dry_run=True)
        self.assertTrue(result.success)
        self.assertEqual(result.config.target.tag, "v4.2.1-r2")

    def test_direct_build_rejects_unadapted_release_before_clone(self):
        with patch.object(kernel_builder, "resolve_latest_release", side_effect=ValueError("unadapted Release")), \
                patch.object(self.builder, "clone_repositories") as clone:
            result = self.builder.build()
        self.assertFalse(result.success)
        self.assertIn("unadapted Release", result.message)
        clone.assert_not_called()

    def test_missing_and_invalid_patch_are_fatal(self):
        self.write("KernelSU/kernel/include/uapi/supercall.h", "DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 6);\n")
        missing = Path(self.temp.name) / "missing.patch"
        with patch.object(kernel_builder, "RELEASE_PATCH", missing):
            with self.assertRaisesRegex(RuntimeError, "patch is missing"):
                self.builder.apply_pinned_patch()
        invalid = Path(self.temp.name) / "invalid.patch"
        invalid.write_text("not a patch\n")
        with patch.object(kernel_builder, "RELEASE_PATCH", invalid):
            with self.assertRaises(subprocess.CalledProcessError):
                self.builder.apply_pinned_patch()

    def test_missing_common_compatibility_patch_is_fatal_before_applying(self):
        missing = Path(self.temp.name) / 'missing-common.patch'
        with patch.object(kernel_builder, 'COMMON_PATCH', missing), \
                patch.object(self.builder, '_run_cmd') as run:
            with self.assertRaisesRegex(RuntimeError, 'common compatibility patch is missing'):
                self.builder.apply_common_compatibility_patch()
        run.assert_not_called()

    def test_all_external_repositories_checkout_and_assert_the_exact_recipe(self):
        target = self.builder.config.target
        for repo in (self.builder.susfs_dir, self.builder.sukisu_patch_dir, self.builder.anykernel_dir):
            (repo / ".git").mkdir(parents=True)
        with patch.object(kernel_builder, "resolve_latest_release", return_value=target), \
                patch.object(self.builder, "_run_cmd", return_value=argparse.Namespace(stdout="")) as run, \
                patch.object(self.builder, "_assert_git_head") as verify:
            self.builder.clone_repositories()
        for commit in (target.susfs_commit, target.patch_commit, target.anykernel_commit):
            self.assertIn(f"git checkout --detach {commit}", [call.args[0] for call in run.call_args_list])
            self.assertIn(commit, [call.args[1] for call in verify.call_args_list])

    def real_git_input(self, destination):
        destination.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(destination)], check=True)
        (destination / "tracked.txt").write_text("committed input\n")
        subprocess.run(["git", "-C", str(destination), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(destination), "-c", "user.name=Test",
                        "-c", "user.email=test@example.com", "commit", "-qm", "baseline"], check=True)
        return subprocess.run(["git", "-C", str(destination), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()

    def test_correct_head_with_dirty_dependency_input_is_rejected_before_any_fetch(self):
        from dataclasses import replace
        for dirty_name in ("susfs4ksu", "SukiSU_patch", "AnyKernel3"):
            for dirty_kind in ("tracked", "untracked", "ignored"):
                with self.subTest(repository=dirty_name, changes=dirty_kind), tempfile.TemporaryDirectory() as directory:
                    builder = kernel_builder.KernelBuilder(release_config(), directory)
                    heads = {repo.name: self.real_git_input(repo) for repo in
                             (builder.susfs_dir, builder.sukisu_patch_dir, builder.anykernel_dir)}
                    target = replace(builder.config.target, susfs_commit=heads["susfs4ksu"],
                                     patch_commit=heads["SukiSU_patch"], anykernel_commit=heads["AnyKernel3"])
                    # A local fixture recipe pins each actual temporary repository HEAD.
                    builder.config = argparse.Namespace(target=target, kernel_branch="gki-android12-5.10")
                    dirty = Path(directory) / dirty_name
                    if dirty_kind == "ignored":
                        with (dirty / ".git/info/exclude").open("a") as excludes:
                            excludes.write("\nImage.gz\n")
                        file = dirty / "Image.gz"
                    else:
                        file = dirty / ("tracked.txt" if dirty_kind == "tracked" else "untracked.txt")
                    file.write_text("user modification\n")
                    run_real = builder._run_cmd
                    commands = []
                    def record(command, **kwargs):
                        commands.append(command)
                        if " status " in command or " rev-parse " in command:
                            return run_real(command, **kwargs)
                        return argparse.Namespace(stdout="", returncode=0)
                    with patch.object(kernel_builder, "resolve_latest_release", return_value=target), \
                            patch.object(builder, "_run_cmd", side_effect=record):
                        with self.assertRaisesRegex(RuntimeError, "clean|dirty|untracked"):
                            builder.clone_repositories()
                    self.assertFalse(any("fetch" in cmd or "checkout" in cmd for cmd in commands))
                    self.assertEqual(file.read_text(), "user modification\n")
                    self.assertEqual(subprocess.run(["git", "-C", str(dirty), "rev-parse", "HEAD"],
                        check=True, capture_output=True, text=True).stdout.strip(), heads[dirty_name])
                    os.chdir(self.builder.workspace)

    def test_dirty_common_or_kernelsu_is_rejected_before_source_reuse(self):
        for method_name, relative in (("init_and_sync_kernel", "common"), ("add_kernelsu", "KernelSU")):
            with self.subTest(source=relative), tempfile.TemporaryDirectory() as directory:
                builder = kernel_builder.KernelBuilder(release_config(), directory)
                source = builder.work_dir / relative
                self.real_git_input(source)
                (source / "tracked.txt").write_text("preserved source change\n")
                run_real = builder._run_cmd
                commands = []
                def record(command, **kwargs):
                    commands.append(command)
                    if " status " in command:
                        return run_real(command, **kwargs)
                    raise AssertionError("Source reuse reached a mutation before checking cleanliness")
                with patch.object(builder, "_run_cmd", side_effect=record):
                    with self.assertRaisesRegex(RuntimeError, "clean|dirty|untracked"):
                        getattr(builder, method_name)()
                self.assertEqual((source / "tracked.txt").read_text(), "preserved source change\n")
                os.chdir(self.builder.workspace)

    def test_real_anykernel_zip_contains_current_image_at_target_path(self):
        import zipfile
        self.write("Image", "current kernel image fixture")
        self.write("Image-gz", "stale unsupported variant")
        self.builder.anykernel_dir.mkdir()
        (self.builder.anykernel_dir / "anykernel.sh").write_text("#!/bin/sh\n")
        artifacts = self.builder.create_anykernel_zips()
        self.assertEqual(artifacts, [str(self.builder.work_dir / self.builder.config.target.archive_name)])
        with zipfile.ZipFile(artifacts[0]) as package:
            self.assertEqual(package.read("Image"), b"current kernel image fixture")
        with self.assertRaisesRegex(RuntimeError, "fresh ZIP"):
            self.builder.create_anykernel_zips()

    def test_empty_summary_and_stale_config_cannot_be_reported_successful(self):
        with self.assertRaises(ValueError):
            build.print_summary([])
        for name in ("Image", "vmlinux", "System.map"):
            self.write(f"out/android12-5.10/dist/{name}", "compiled fixture")
        self.write("out/other/common/.config", "CONFIG_KSU=y\nCONFIG_KSU_SUSFS=y\n")
        with self.assertRaisesRegex(RuntimeError, "common/\\.config is missing"):
            self.builder.verify_pinned_outputs()

    def test_existing_out_is_rejected_before_any_clone(self):
        (self.builder.work_dir / "out").mkdir()
        with patch.object(self.builder, "clone_repositories") as clone:
            result = self.builder.build()
        self.assertFalse(result.success)
        self.assertIn("fresh output directory", result.message)
        clone.assert_not_called()

    def test_clone_failure_and_wrong_git_head_remain_fatal(self):
        failure = subprocess.CalledProcessError(128, "git clone")
        with patch.object(kernel_builder, "resolve_latest_release", return_value=self.builder.config.target), \
                patch.object(self.builder, "_run_cmd", side_effect=failure) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.builder.clone_repositories()
        self.assertTrue(run.call_args.kwargs["check"])
        with patch.object(self.builder, "_run_cmd", return_value=argparse.Namespace(stdout="bad")):
            with self.assertRaisesRegex(RuntimeError, "HEAD mismatch"):
                self.builder._assert_git_head(Path("KernelSU"), self.builder.config.target.kernelsu_commit)

    def test_setup_download_and_checkout_use_new_exact_pin(self):
        (self.builder.work_dir / "KernelSU").mkdir()
        with patch.object(self.builder, "_run_cmd") as run, \
                patch.object(self.builder, "_assert_git_head") as verify, \
                patch.object(self.builder, "_assert_git_clean"):
            self.builder.add_kernelsu()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(self.builder.config.target.kernelsu_commit, commands[0])
        self.assertIn(self.builder.config.target.kernelsu_commit, commands[1])
        self.assertEqual(commands[2], f"git checkout {self.builder.config.target.kernelsu_commit}")
        verify.assert_called_once_with(self.builder.work_dir / "KernelSU", self.builder.config.target.kernelsu_commit)

    def test_manager_only_release_keeps_native_uapi_and_rejects_older_baseline(self):
        from dataclasses import replace
        self.builder.config = release_config(target=replace(
            self.builder.config.target, tag="v4.2.2", release_commit="a" * 40,
            manager_version=40995, apk_name="SukiSU_v4.2.2_40995-release.apk", apk_sha256="b" * 64))
        header = self.write("KernelSU/kernel/include/uapi/supercall.h",
                            "DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 6);\n")
        makefile = self.write("KernelSU/kernel/Makefile",
                             "KSU_VERSION     := $(if $(LOCAL_COUNT),$(shell expr $(VERSION_BASE) + $(LOCAL_COUNT) - $(VERSION_OFFSET)),13000)\n"
                             "VERSION_TAG     := $(or $(KSU_GITHUB_VER),$(git_latest_tag),4.2.1)\n"
                             "KSU_VERSION_FULL := $(if $(call git_short_sha),v$(VERSION_TAG)-$(call git_short_sha)@$(call git_branch),v$(VERSION_TAG)-$(REPO_NAME)-unknown@unknown)\n"
                             'KSU_GITHUB_VER   := $(shell $(CURL_BIN) -s "$(GITHUB_API_BASE)/releases/latest" 2>/dev/null)\n')
        patch_file = Path(self.temp.name) / "release.patch"
        import difflib
        original_makefile = makefile.read_text()
        patch_file.write_text(''.join(difflib.unified_diff(
            original_makefile.splitlines(True),
            ('# audited source patch\n' + original_makefile).splitlines(True),
            fromfile='a/kernel/Makefile', tofile='b/kernel/Makefile')))
        original_header = header.read_bytes()
        with patch.object(kernel_builder, "RELEASE_PATCH", patch_file):
            self.builder.apply_pinned_patch()
        self.assertEqual(header.read_bytes(), original_header)
        self.assertIn("KSU_VERSION     := 41068\n", makefile.read_text())
        self.assertIn("VERSION_TAG     := 4.2.1-r2\n", makefile.read_text())
        self.assertIn("KSU_VERSION_FULL := v4.2.1-r2-ce75122b+avc-ff7dfe2d@builtin\n", makefile.read_text())
        self.assertNotIn("/releases/latest", makefile.read_text())
        self.assertIn("KSU_GITHUB_VER   := 4.2.1-r2\n", makefile.read_text())
        self.assertNotIn("4.2.2", makefile.read_text())
        self.assertNotIn("40995", makefile.read_text())
        header.write_text("DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 5);\n")
        with patch.object(kernel_builder, "RELEASE_PATCH", patch_file), \
                patch.object(self.builder, "_run_cmd") as run:
            with self.assertRaisesRegex(RuntimeError, "native UAPI baseline"):
                self.builder.apply_pinned_patch()
        run.assert_not_called()

    def test_missing_or_failing_release_contract_stops_both_stages(self):
        missing = Path(self.temp.name) / "missing.py"
        with patch.object(kernel_builder, "RELEASE_CONTRACT", missing):
            for method in (self.builder.test_pinned_contract, self.builder.verify_pinned_sources):
                with self.subTest(method=method), self.assertRaisesRegex(RuntimeError, "missing"):
                    method()
        contract = Path(self.temp.name) / "contract.py"
        contract.write_text("raise SystemExit(1)\n")
        with patch.object(kernel_builder, "RELEASE_CONTRACT", contract):
            for method in (self.builder.test_pinned_contract, self.builder.verify_pinned_sources):
                with self.subTest(method=method), self.assertRaises(subprocess.CalledProcessError):
                    method()

    def test_distinct_release_contract_is_run_before_and_after_common_hooks(self):
        contract = Path(self.temp.name) / "contract.py"
        contract.write_text("# test contract\n")
        with patch.object(kernel_builder, "RELEASE_CONTRACT", contract), \
                patch.object(self.builder, "_run_cmd") as run:
            self.builder.test_pinned_contract()
            self.builder.verify_pinned_sources()
        before, after = [call.args[0] for call in run.call_args_list]
        self.assertIn("--host-header", before)
        self.assertIn("--common", after)
        for command in (before, after):
            self.assertIn(str(contract), command)
            self.assertIn(str(self.builder.work_dir / "KernelSU"), command)

    def test_failing_c_contract_stops_build_before_source_hooks_or_compiler(self):
        from contextlib import ExitStack
        failure = subprocess.CalledProcessError(1, "real C contract")
        with ExitStack() as stack:
            stack.enter_context(patch.object(kernel_builder, "resolve_latest_release", return_value=self.builder.config.target))
            for name in ("clone_repositories", "setup_repo_tool", "init_and_sync_kernel", "add_kernelsu", "apply_pinned_patch"):
                stack.enter_context(patch.object(self.builder, name))
            stack.enter_context(patch.object(self.builder, "test_pinned_contract", side_effect=failure))
            hooks = stack.enter_context(patch.object(self.builder, "apply_susfs_patches"))
            compiler = stack.enter_context(patch.object(self.builder, "build_kernel"))
            result = self.builder.build()
        self.assertFalse(result.success)
        hooks.assert_not_called()
        compiler.assert_not_called()

    def test_defconfig_explicitly_disables_kpm_and_debug(self):
        dest = self.write("common/arch/arm64/configs/gki_defconfig", "CONFIG_KSU_DEBUG=y\n")
        self.builder.configure_kernel()
        for key in ("CONFIG_KPM", "CONFIG_KSU_DEBUG"):
            self.assertEqual([line for line in dest.read_text().splitlines()
                              if line.startswith(key + "=")][-1], key + "=n")

    def test_output_gate_requires_all_binaries_and_generated_susfs_config(self):
        for name in ("Image", "vmlinux", "System.map"):
            self.write(f"out/android12-5.10/dist/{name}", "compiled fixture")
        dest = self.write("out/android12-5.10/common/.config", "CONFIG_KSU=y\n")
        with self.assertRaisesRegex(RuntimeError, "does not enable"):
            self.builder.verify_pinned_outputs()
        for enabled in ("CONFIG_KSU_DEBUG", "CONFIG_KPM"):
            dest.write_text(f"CONFIG_KSU=y\nCONFIG_KSU_SUSFS=y\n{enabled}=y\n")
            with self.assertRaisesRegex(RuntimeError, "KSU_DEBUG or KPM"):
                self.builder.verify_pinned_outputs()
        dest.write_text("CONFIG_KSU=y\nCONFIG_KSU_SUSFS=y\n# CONFIG_KPM is not set\n")
        with self.assertRaisesRegex(RuntimeError, 'CONFIG_KPROBES'):
            self.builder.verify_pinned_outputs()
        dest.write_text(dest.read_text() + 'CONFIG_KPROBES=y\n')
        self.assertEqual(self.builder.verify_pinned_outputs().name, "Image")
        (self.builder.work_dir / "out/android12-5.10/dist/System.map").write_text("")
        with self.assertRaisesRegex(RuntimeError, "System.map"):
            self.builder.verify_pinned_outputs()

    def test_release_manifest_records_exact_target_and_independent_evidence(self):
        from dataclasses import replace
        self.builder.config = release_config(target=replace(
            self.builder.config.target, tag="v4.2.2", release_commit="a" * 40,
            manager_version=40995, apk_name="SukiSU_v4.2.2_40995-release.apk", apk_sha256="b" * 64))
        self.write("KernelSU/kernel/Makefile", "KSU_VERSION := 41068\n")
        self.write("sukisu-setup.sh", "# setup\n")
        self.write("release-resolved-manifest.xml", "<manifest/>\n")
        source_contract = Path(self.temp.name) / "contract.py"
        source_contract.write_text("# contract\n")
        uapi_patch = Path(self.temp.name) / "patch.diff"
        uapi_patch.write_text("patch\n")
        with patch.object(kernel_builder, "RELEASE_CONTRACT", source_contract), \
                patch.object(kernel_builder, "RELEASE_PATCH", uapi_patch), \
                patch.object(self.builder, "_assert_git_head") as verify, \
                patch.object(self.builder, "_run_cmd", return_value=argparse.Namespace(stdout="f" * 40)):
            self.builder.write_pinned_manifest()
        self.assertEqual(len(verify.call_args_list), 5)
        data = json.loads((self.builder.work_dir / "release-manifest.json").read_text())
        self.assertEqual(data["kernelsu_commit"], self.builder.config.target.kernelsu_commit)
        self.assertIn("KernelSU 41068 / UAPI 6", data["target"])
        self.assertEqual(len(data["source_contract_sha256"]), 64)
        self.assertEqual(data["release_tag"], "v4.2.2")
        self.assertEqual(data["release_commit"], "a" * 40)
        self.assertEqual(data["builtin_compatibility_commit"], self.builder.config.target.kernelsu_commit)
        self.assertEqual(data["anykernel_commit"], self.builder.config.target.anykernel_commit)
        self.assertEqual(data["manager_version"], self.builder.config.target.manager_version)
        self.assertEqual(data["backend_tag"], "v4.2.1-r2")
        self.assertEqual(data["backend_version"], 41068)
        self.assertEqual(data["avc_backport_commit"], "ff7dfe2dbc39f78a08ee6fcff23bc615b0f54ea2")
        snapshot = json.loads((self.builder.work_dir / "release-target.json").read_text())
        self.assertEqual(snapshot["tag"], self.builder.config.target.tag)
        self.assertEqual(snapshot["manager_version"], self.builder.config.target.manager_version)
        self.assertEqual(snapshot["version"], 41068)
        self.assertEqual(snapshot["kernelsu_commit"], self.builder.config.target.kernelsu_commit)


if __name__ == "__main__":
    unittest.main()
