"""Keep artifact gates strict while Release metadata is supplied by the recipe."""
from dataclasses import replace
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / ".github/workflows/scripts"
sys.path.insert(0, str(SCRIPTS))
import artifact_checks as checks
from release_target import load_release_target


class ArtifactChecksTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        # An independent input shows ZIP/config/cert checks follow the supplied
        # target, rather than accidentally accepting only the current recipe.
        self.target = replace(load_release_target(), manager_certificate_sha256="a" * 64,
                              susfs_version="9.8.7", kernel_tuple=("android99", "6.1", "23", "2099-01"))
        enabled = ("KPROBES", "KSU", "KSU_SUSFS", "KSU_SUSFS_SUS_PATH", "KSU_SUSFS_SUS_MOUNT",
                   "KSU_SUSFS_SUS_MAP", "KSU_SUSFS_SPOOF_UNAME", "KSU_SUSFS_OPEN_REDIRECT")
        self.config = "".join(f"CONFIG_{name}=y\n" for name in enabled)
        self.config += "# CONFIG_KPM is not set\n# CONFIG_KSU_DEBUG is not set\n"
        (self.folder / "kernel.config").write_text(self.config)
        self.image = bytearray(64)
        self.image[0x38:0x3c] = b"ARMd"
        self.image += b"IKCFG_ST" + gzip.compress(self.config.encode()) + b"IKCFG_ED"
        self.image += b"a" * 64 + b" v9.8.7 Linux version 6.1.23-android99-test\0"
        self.archive()

    def archive(self):
        with zipfile.ZipFile(self.folder / self.target.archive_name, "w") as archive:
            archive.writestr("Image", self.image)
            archive.writestr("anykernel.sh", "#!/bin/sh\n")

    def test_config_cert_kernel_and_susfs_follow_target(self):
        image, proof = checks.check_archive(self.folder, self.target)
        self.assertEqual(image, bytes(self.image))
        self.assertEqual(proof["susfs_version_string"], "v9.8.7")
        with self.assertRaisesRegex(RuntimeError, "certificate"):
            checks.check_archive(self.folder, replace(self.target, manager_certificate_sha256="b" * 64))
        with self.assertRaisesRegex(RuntimeError, "SuSFS version"):
            checks.check_archive(self.folder, replace(self.target, susfs_version="1.2.3"))
        other = replace(self.target, kernel_tuple=("android88", "6.1", "23", "2099-01"))
        (self.folder / other.archive_name).write_bytes((self.folder / self.target.archive_name).read_bytes())
        with self.assertRaisesRegex(RuntimeError, "release string"):
            checks.check_archive(self.folder, other)

    def test_actual_image_config_and_arm64_header_are_required(self):
        (self.folder / "kernel.config").write_text(self.config + "CONFIG_EXTRA=y\n")
        with self.assertRaisesRegex(RuntimeError, "config differs"):
            checks.check_archive(self.folder, self.target)
        (self.folder / "kernel.config").write_text(self.config)
        self.image[0x38] ^= 1
        self.archive()
        with self.assertRaisesRegex(RuntimeError, "ARM64"):
            checks.check_archive(self.folder, self.target)

    def test_kpm_debug_and_disabled_susfs_are_rejected(self):
        original_image = bytes(self.image)
        for key, before, after in (
                ("CONFIG_KPROBES", "CONFIG_KPROBES=y", "# CONFIG_KPROBES is not set"),
                ("CONFIG_KPM", "# CONFIG_KPM is not set", "CONFIG_KPM=y"),
                ("CONFIG_KSU_DEBUG", "# CONFIG_KSU_DEBUG is not set", "CONFIG_KSU_DEBUG=y"),
                ("CONFIG_KSU_SUSFS", "CONFIG_KSU_SUSFS=y", "# CONFIG_KSU_SUSFS is not set")):
            with self.subTest(key=key):
                config = self.config.replace(before, after)
                (self.folder / "kernel.config").write_text(config)
                start = original_image.index(b"IKCFG_ST") + len(b"IKCFG_ST")
                end = original_image.index(b"IKCFG_ED", start)
                self.image = original_image[:start] + gzip.compress(config.encode()) + original_image[end:]
                self.archive()
                with self.assertRaisesRegex(RuntimeError, key):
                    checks.check_archive(self.folder, self.target)

    def test_zip_crc_failure_is_fatal(self):
        path = self.folder / self.target.archive_name
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo("Image")
        raw = bytearray(path.read_bytes())
        offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
        raw[offset] ^= 1
        path.write_bytes(raw)
        with self.assertRaisesRegex(RuntimeError, "ZIP CRC"):
            checks.check_archive(self.folder, self.target)

    def test_manifest_pins_and_release_identity_are_required(self):
        resolved = self.folder / checks.RESOLVED_NAME
        resolved.write_text("<manifest/>\n")
        manifest = dict(self.target.pins,
                        target=f"{self.target.archive_name.removesuffix('-AnyKernel3.zip')} / KernelSU {self.target.version} / UAPI {self.target.uapi} / SUSFS {self.target.susfs_version}",
                        resolved_toolchain_manifest_sha256=checks.sha256(resolved),
                        release_tag=self.target.tag, release_commit=self.target.release_commit,
                        manager_version=self.target.manager_version, backend_tag=self.target.backend_tag,
                        backend_version=self.target.version, backend_source_commit=self.target.kernelsu_commit,
                        source_fingerprint=self.target.source_fingerprint, full_version=self.target.full_version,
                        official_manager_apk_sha256=self.target.apk_sha256,
                        official_manager_certificate_sha256=self.target.manager_certificate_sha256,
                        build_config=dict(release=True, use_kpm=False, make_release=False))
        path = self.folder / checks.MANIFEST_NAME
        (self.folder / "build-result.json").write_text(json.dumps(
            dict(total=1, success=1, failed=0, results=[dict(success=True)])))
        path.write_text(json.dumps(manifest))
        checks.check_manifest(self.folder, self.target)
        for field, value in (("patch_commit", "0" * 40), ("anykernel_commit", "0" * 40),
                             ("release_tag", "v0.0.0"), ("release_commit", "0" * 40),
                             ("manager_version", 99999), ("backend_version", 99999),
                             ("source_fingerprint", "f" * 64), ("official_manager_apk_sha256", "f" * 64),
                             ("build_config", dict(release=False, use_kpm=False, make_release=False))):
            with self.subTest(field=field):
                path.write_text(json.dumps(dict(manifest, **{field: value})))
                with self.assertRaises(RuntimeError):
                    checks.check_manifest(self.folder, self.target)

    def test_checksum_set_duplicates_and_tampering_are_rejected(self):
        for path in self.folder.iterdir():
            path.unlink()
        artifact = self.folder / "artifact"
        artifact.write_bytes(b"artifact")
        line = f"{checks.sha256(artifact)}  artifact\n"
        sums = self.folder / "SHA256SUMS.txt"
        sums.write_text(line)
        checks.check_original_sums(self.folder, {"artifact"})
        sums.write_text(line + line)
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            checks.check_original_sums(self.folder, {"artifact"})
        sums.write_text(line)
        artifact.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
            checks.check_original_sums(self.folder, {"artifact"})
        with self.assertRaisesRegex(RuntimeError, "checksum set"):
            checks.check_original_sums(self.folder, {"artifact", "missing"})

    def test_thinlto_function_names_exclude_cfi_and_similar_symbols(self):
        self.assertEqual(checks.function_target("do_extension$" + "a" * 32), "do_extension")
        for name in ("do_extension.cfi_jt", "do_extension$abc", "do_extension$" + "A" * 32,
                     "prefix_do_extension", "do_extension_extra"):
            with self.subTest(name=name):
                self.assertIsNone(checks.function_target(name))


if __name__ == "__main__":
    unittest.main()
