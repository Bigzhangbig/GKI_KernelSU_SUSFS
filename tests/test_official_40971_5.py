"""Regression tests for the pinned, manually dispatched 40971-5 build."""

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


def target_config(**changes):
    values = dict(android_version="android12", kernel_version="5.10", sub_level="209",
                  os_patch_level="2024-05", revision="r13",
                  kernelsu_commit=config.OFFICIAL_40971_5_KSU_COMMIT,
                  susfs_commit=config.OFFICIAL_40971_5_SUSFS_COMMIT,
                  use_kpm=False, make_release=False, official_40971_5=True)
    values.update(changes)
    return config.BuildConfig(**values)


class Official409715Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original_cwd = Path.cwd()
        self.addCleanup(lambda: __import__("os").chdir(self.original_cwd))
        self.builder = kernel_builder.KernelBuilder(target_config(), self.temp.name)

    def write(self, relative, content):
        path = self.builder.work_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_wrong_tuple_or_pin_is_rejected(self):
        for change in ({"sub_level": "208"}, {"kernelsu_commit": "a" * 40},
                       {"susfs_commit": "b" * 40}, {"revision": "r12"},
                       {"use_kpm": True}, {"make_release": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                target_config(**change)

    def test_uapi2_fixture_fails_source_verification(self):
        self.write("KernelSU/kernel/include/uapi/supercall.h",
                   "DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 2);\n")
        with self.assertRaisesRegex(RuntimeError, "supercall.h"):
            self.builder.verify_official_40971_5_sources()

    def test_missing_patch_stops_before_apply(self):
        self.write("KernelSU/kernel/include/uapi/supercall.h",
                   "DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 2);\n")
        with patch.object(kernel_builder, "OFFICIAL_40971_5_PATCH", Path(self.temp.name) / "missing.patch"):
            with self.assertRaisesRegex(RuntimeError, "patch is missing"):
                self.builder.apply_official_40971_5_patch()

    def test_failed_patch_is_fatal(self):
        self.write("KernelSU/kernel/include/uapi/supercall.h",
                   "DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 2);\n")
        invalid = Path(self.temp.name) / "invalid.patch"
        invalid.write_text("not a patch\n")
        with patch.object(kernel_builder, "OFFICIAL_40971_5_PATCH", invalid):
            with self.assertRaises(subprocess.CalledProcessError):
                self.builder.apply_official_40971_5_patch()

    def test_clone_failure_is_not_ignored(self):
        failure = subprocess.CalledProcessError(128, "git clone")
        with patch.object(self.builder, "_run_cmd", side_effect=failure) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.builder.clone_repositories()
        self.assertTrue(run.call_args.kwargs["check"])

    def test_anykernel_zip_is_written_to_the_target_build_directory(self):
        self.write("Image", "kernel image fixture")
        self.builder.anykernel_dir.mkdir()
        (self.builder.anykernel_dir / "anykernel.sh").write_text("#!/bin/sh\n")
        artifacts = self.builder.create_anykernel_zips()
        self.assertEqual(len(artifacts), 1)
        self.assertTrue(Path(artifacts[0]).is_file())
        self.assertEqual(Path(artifacts[0]).parent, self.builder.work_dir)

    def test_existing_target_output_is_rejected_before_cloning(self):
        (self.builder.work_dir / "out").mkdir()
        with patch.object(self.builder, "clone_repositories") as clone:
            result = self.builder.build()
        self.assertFalse(result.success)
        self.assertIn("fresh output directory", result.message)
        clone.assert_not_called()

    def test_actual_contract_is_required_after_patch(self):
        with patch.object(self.builder, "_run_cmd") as run:
            self.builder.test_official_40971_5_contract()
        self.assertIn("--host-header", run.call_args.args[0])
        self.assertIn(str(self.builder.work_dir / "KernelSU"), run.call_args.args[0])

    def test_output_gate_uses_only_the_target_generated_config(self):
        for name in ("Image", "vmlinux", "System.map"):
            self.write(f"out/android12-5.10/dist/{name}", "compiled fixture")
        self.write("out/other/common/.config", "CONFIG_KSU=y\nCONFIG_KSU_SUSFS=y\n")
        with self.assertRaisesRegex(RuntimeError, "common/\\.config is missing"):
            self.builder.verify_official_40971_5_outputs()
        generated = self.write("out/android12-5.10/common/.config",
                               "CONFIG_KSU=y\nCONFIG_KSU_SUSFS=y\nCONFIG_KPM=y\n")
        with self.assertRaisesRegex(RuntimeError, "KPM"):
            self.builder.verify_official_40971_5_outputs()
        generated.write_text("CONFIG_KSU=y\nCONFIG_KSU_SUSFS=y\n# CONFIG_KPM is not set\n")
        self.assertEqual(self.builder.verify_official_40971_5_outputs().name, "Image")

    def test_valid_patch_and_expected_sources_pass(self):
        ksu = self.builder.work_dir / "KernelSU"
        header = self.write("KernelSU/kernel/include/uapi/supercall.h",
                            "DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 2);\n")
        self.write("KernelSU/kernel/Makefile",
                   "KSU_VERSION     := $(if $(LOCAL_COUNT),$(shell expr $(VERSION_BASE) + $(LOCAL_COUNT) - $(VERSION_OFFSET)),13000)\n")
        self.write("KernelSU/kernel/supercall/dispatch.c",
                   "case EVENT_SERVICES: { services_started = true; return 1; }\n"
                   "{ .cmd = KSU_IOCTL_GET_WRAPPER_FD, .allow_su_session = true }\n"
                   "{ .cmd = KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT, .allow_su_session = true }\n"
                   "ksu_ioctl_handlers[i].allow_su_session && ksu_is_su_session_fd(filp)\n")
        self.write("KernelSU/kernel/infra/file_wrapper.c",
                   "old_cred = override_creds(ksu_cred);\n"
                   "wrapper_file = make_wrapper();\n"
                   "revert_creds(old_cred);\n")
        self.write("KernelSU/kernel/manager/apk_sign.c",
                   '{ 0x35c, "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef" },\n')
        self.write("KernelSU/kernel/feature/sucompat.c",
                   "int ksu_handle_execveat_sucompat(void *p) {\n"
                   "if (!(__ksu_is_allow_uid_for_current(current_uid().val))) return -EINVAL;\n"
                   "if (current_chrooted()) { return -EINVAL; }\n"
                   "if (ret) { return -EINVAL; } return 0; }\n"
                   "int ksu_handle_post_execveat_sucompat(void *p) {\n"
                   "if (*retval >= 0) { (void)ksu_install_su_fd(); } }\n")
        self.write("common/fs/exec.c",
                   "bool is_su_session = false;\n"
                   "if (likely(susfs_is_current_proc_no_su())) goto orig_flow;\n"
                   "if (static_branch_likely(&ksu_su_compat_enabled)) {\n"
                   "is_su_session = !ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
                   "is_su_session = !ksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags); }\n"
                   "retval = bprm_execve(bprm, fd, filename, flags);\n"
                   "#ifdef CONFIG_KSU_SUSFS\n"
                   "if (unlikely(is_su_session))\n"
                   "(void)ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval);\n")
        self.write("common/include/linux/susfs.h", '#define SUSFS_VERSION "v2.3.0"\n')
        self.write("common/Makefile", "VERSION = 5\nPATCHLEVEL = 10\nSUBLEVEL = 209\n")
        self.write("common/arch/arm64/configs/gki_defconfig", "CONFIG_KSU=y\nCONFIG_KSU_SUSFS=y\n")
        subprocess.run(["git", "init", "-q", str(ksu)], check=True)
        subprocess.run(["git", "-C", str(ksu), "add", "kernel"], check=True)
        subprocess.run(["git", "-C", str(ksu), "-c", "user.name=Test", "-c", "user.email=test@example.com",
                        "commit", "-qm", "baseline"], check=True)
        header.write_text("DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 5);\n"
                          "DECLARE(__u32, KSU_GET_INFO_FLAG_BUNDLED, (1U << 4));\n")
        patch_text = subprocess.run(["git", "-C", str(ksu), "diff", "--", "kernel/include/uapi/supercall.h"],
                                    check=True, capture_output=True, text=True).stdout
        patch_file = Path(self.temp.name) / "uapi5.patch"
        patch_file.write_text(patch_text)
        subprocess.run(["git", "-C", str(ksu), "checkout", "--", "kernel/include/uapi/supercall.h"], check=True)
        with patch.object(kernel_builder, "OFFICIAL_40971_5_PATCH", patch_file):
            self.builder.apply_official_40971_5_patch()
            self.builder.verify_official_40971_5_sources()
        makefile = ksu / "kernel/Makefile"
        makefile.write_text(makefile.read_text().replace("40971", "40972"))
        with self.assertRaisesRegex(RuntimeError, "Makefile"):
            self.builder.verify_official_40971_5_sources()
        config_data = self.builder.config.to_dict()
        self.assertEqual(config_data["susfs_commit"], config.OFFICIAL_40971_5_SUSFS_COMMIT)
        self.assertTrue(config_data["official_40971_5"])


if __name__ == "__main__":
    unittest.main()
