"""The release 4.2.1 target must select real sources and retain strict gates."""
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
    values = dict(android_version="android12", kernel_version="5.10", sub_level="209",
                  os_patch_level="2024-05", revision="r13", use_kpm=False,
                  make_release=False, release_4_2_1=True,
                  kernelsu_commit=config.RELEASE_4_2_1_KSU_COMMIT,
                  susfs_commit=config.RELEASE_4_2_1_TARGET.susfs_commit)
    values.update(changes)
    return config.BuildConfig(**values)


class Release421Tests(unittest.TestCase):
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

    def test_release_selects_new_builtin_and_uapi5_independently_of_legacy(self):
        target = self.builder.config.pinned_target
        self.assertEqual(target.kernelsu_commit, "ee35e65428054476c279eae59f7f2bba272040b9")
        self.assertNotEqual(target.kernelsu_commit, config.OFFICIAL_40971_5_KSU_COMMIT)
        self.assertEqual((target.version, target.uapi), (40994, 5))
        self.assertEqual(self.builder.config.to_dict()["release_4_2_1"], True)
        self.assertNotIn("official_40971_5", self.builder.config.to_dict())
        ordinary = config.BuildConfig("android12", "5.10", "209", "2024-05")
        self.assertFalse(ordinary.pinned_build)
        self.assertTrue(ordinary.use_kpm)
        self.assertTrue(ordinary.make_release)

    def test_release_rejects_old_and_uapi6_sources_or_weakened_target(self):
        for changes in ({"kernelsu_commit": config.OFFICIAL_40971_5_KSU_COMMIT},
                        {"kernelsu_commit": "7f1c299af463d008e66e714077eb6a8079ff722b"},
                        {"susfs_commit": "a" * 40}, {"revision": "r12"},
                        {"sub_level": "208"}, {"use_kpm": True},
                        {"make_release": True}, {"official_40971_5": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                release_config(**changes)

    def test_cli_profiles_are_mutually_exclusive_and_config_selects_release(self):
        command = ["build.py", "--release-4-2-1", "--android", "android12",
                   "--kernel", "5.10", "--sub-level", "209", "--os-patch", "2024-05",
                   "--revision", "r13", "--no-kpm", "--no-release", "--ksu-commit",
                   config.RELEASE_4_2_1_KSU_COMMIT, "--susfs-commit",
                   config.RELEASE_4_2_1_TARGET.susfs_commit]
        with patch.object(sys, "argv", command):
            self.assertTrue(build.create_build_config(build.parse_args()).release_4_2_1)
        with patch.object(sys, "argv", command + ["--official-40971-5"]):
            with self.assertRaises(SystemExit):
                build.parse_args()

    def test_existing_out_is_rejected_before_any_clone(self):
        (self.builder.work_dir / "out").mkdir()
        with patch.object(self.builder, "clone_repositories") as clone:
            result = self.builder.build()
        self.assertFalse(result.success)
        self.assertIn("fresh output directory", result.message)
        clone.assert_not_called()

    def test_clone_failure_and_wrong_git_head_remain_fatal(self):
        failure = subprocess.CalledProcessError(128, "git clone")
        with patch.object(self.builder, "_run_cmd", side_effect=failure) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.builder.clone_repositories()
        self.assertTrue(run.call_args.kwargs["check"])
        with patch.object(self.builder, "_run_cmd", return_value=argparse.Namespace(stdout="bad")):
            with self.assertRaisesRegex(RuntimeError, "HEAD mismatch"):
                self.builder._assert_git_head(Path("KernelSU"), config.RELEASE_4_2_1_KSU_COMMIT)

    def test_setup_download_and_checkout_use_new_exact_pin(self):
        (self.builder.work_dir / "KernelSU").mkdir()
        with patch.object(self.builder, "_run_cmd") as run, \
                patch.object(self.builder, "_assert_git_head") as verify:
            self.builder.add_kernelsu()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(config.RELEASE_4_2_1_KSU_COMMIT, commands[0])
        self.assertIn(config.RELEASE_4_2_1_KSU_COMMIT, commands[1])
        self.assertEqual(commands[2], f"git checkout {config.RELEASE_4_2_1_KSU_COMMIT}")
        verify.assert_called_once_with(self.builder.work_dir / "KernelSU", config.RELEASE_4_2_1_KSU_COMMIT)

    def test_patch_updates_real_header_and_version_and_rejects_uapi6_baseline(self):
        header = self.write("KernelSU/kernel/include/uapi/supercall.h",
                            "DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 2);\n")
        makefile = self.write("KernelSU/kernel/Makefile",
                             "KSU_VERSION     := $(if $(LOCAL_COUNT),$(shell expr $(VERSION_BASE) + $(LOCAL_COUNT) - $(VERSION_OFFSET)),13000)\n"
                             "VERSION_TAG     := $(or $(KSU_GITHUB_VER),$(git_latest_tag),4.2.1)\n"
                             "KSU_VERSION_FULL := $(if $(call git_short_sha),v$(VERSION_TAG)-$(call git_short_sha)@$(call git_branch),v$(VERSION_TAG)-$(REPO_NAME)-unknown@unknown)\n"
                             'KSU_GITHUB_VER   := $(shell $(CURL_BIN) -s "$(GITHUB_API_BASE)/releases/latest" 2>/dev/null)\n')
        patch_file = Path(self.temp.name) / "release.patch"
        patch_file.write_text(
            "diff --git a/kernel/include/uapi/supercall.h b/kernel/include/uapi/supercall.h\n"
            "--- a/kernel/include/uapi/supercall.h\n"
            "+++ b/kernel/include/uapi/supercall.h\n"
            "@@ -1 +1,2 @@\n"
            "-DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 2);\n"
            "+DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 5);\n"
            "+DECLARE(__u32, KSU_GET_INFO_FLAG_BUNDLED, (1U << 4));\n")
        with patch.object(kernel_builder, "RELEASE_4_2_1_PATCH", patch_file):
            self.builder.apply_pinned_patch()
        self.assertIn("KERNEL_SU_UAPI_VERSION, 5", header.read_text())
        self.assertIn("KSU_VERSION     := 40994\n", makefile.read_text())
        self.assertIn("VERSION_TAG     := 4.2.1\n", makefile.read_text())
        self.assertIn("KSU_VERSION_FULL := v4.2.1-ee35e654@builtin\n", makefile.read_text())
        self.assertNotIn("/releases/latest", makefile.read_text())
        header.write_text("DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 6);\n")
        with patch.object(kernel_builder, "RELEASE_4_2_1_PATCH", patch_file), \
                patch.object(self.builder, "_run_cmd") as run:
            with self.assertRaisesRegex(RuntimeError, "UAPI2 baseline"):
                self.builder.apply_pinned_patch()
        run.assert_not_called()

    def test_missing_or_failing_release_contract_stops_both_stages(self):
        missing = Path(self.temp.name) / "missing.py"
        with patch.object(kernel_builder, "RELEASE_4_2_1_CONTRACT", missing):
            for method in (self.builder.test_pinned_contract, self.builder.verify_pinned_sources):
                with self.subTest(method=method), self.assertRaisesRegex(RuntimeError, "missing"):
                    method()
        contract = Path(self.temp.name) / "contract.py"
        contract.write_text("raise SystemExit(1)\n")
        with patch.object(kernel_builder, "RELEASE_4_2_1_CONTRACT", contract):
            for method in (self.builder.test_pinned_contract, self.builder.verify_pinned_sources):
                with self.subTest(method=method), self.assertRaises(subprocess.CalledProcessError):
                    method()

    def test_distinct_release_contract_is_run_before_and_after_common_hooks(self):
        contract = Path(self.temp.name) / "contract.py"
        contract.write_text("# test contract\n")
        with patch.object(kernel_builder, "RELEASE_4_2_1_CONTRACT", contract), \
                patch.object(self.builder, "_run_cmd") as run:
            self.builder.test_pinned_contract()
            self.builder.verify_pinned_sources()
        before, after = [call.args[0] for call in run.call_args_list]
        self.assertIn("--host-header", before)
        self.assertIn("--common", after)
        for command in (before, after):
            self.assertIn(str(contract), command)
            self.assertIn(str(self.builder.work_dir / "KernelSU"), command)

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
        self.assertEqual(self.builder.verify_pinned_outputs().name, "Image")
        (self.builder.work_dir / "out/android12-5.10/dist/System.map").write_text("")
        with self.assertRaisesRegex(RuntimeError, "System.map"):
            self.builder.verify_pinned_outputs()

    def test_release_manifest_records_exact_target_and_independent_evidence(self):
        self.write("KernelSU/kernel/Makefile", "KSU_VERSION := 40994\n")
        self.write("sukisu-setup.sh", "# setup\n")
        self.write("release-4.2.1-resolved-manifest.xml", "<manifest/>\n")
        source_contract = Path(self.temp.name) / "contract.py"
        source_contract.write_text("# contract\n")
        uapi_patch = Path(self.temp.name) / "patch.diff"
        uapi_patch.write_text("patch\n")
        with patch.object(kernel_builder, "RELEASE_4_2_1_CONTRACT", source_contract), \
                patch.object(kernel_builder, "RELEASE_4_2_1_PATCH", uapi_patch), \
                patch.object(self.builder, "_assert_git_head") as verify, \
                patch.object(self.builder, "_run_cmd", return_value=argparse.Namespace(stdout="f" * 40)):
            self.builder.write_pinned_manifest()
        self.assertEqual(len(verify.call_args_list), 4)
        data = json.loads((self.builder.work_dir / "release-4.2.1-manifest.json").read_text())
        self.assertEqual(data["kernelsu_commit"], config.RELEASE_4_2_1_KSU_COMMIT)
        self.assertIn("KernelSU 40994 / UAPI 5", data["target"])
        self.assertEqual(len(data["source_contract_sha256"]), 64)
        self.assertFalse((self.builder.work_dir / "40971-5-manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
