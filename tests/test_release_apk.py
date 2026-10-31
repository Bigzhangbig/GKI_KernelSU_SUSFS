"""Portable APK metadata parsing, refusal cases, and optional signed-APK check.

Set RELEASE_APK_FIXTURE and APKSIGNER to run the real official APK integration.
Synthetic fixtures test binary parsers and library selection; mocks isolate the
external signature verifier, whose real behavior is covered by integration.
"""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github/workflows/scripts"))
from release_apk import inspect_release_apk, parse_binary_manifest, parse_manager_uapi


def manifest(utf8=True, duplicate=False):
    strings = ["manifest", "package", "com.sukisu.ultra", "versionCode", "versionName",
               "v4.2.1", "http://schemas.android.com/apk/res/android"]
    offsets, data = [], b""
    for value in strings:
        offsets.append(len(data))
        encoded = value.encode("utf-8" if utf8 else "utf-16le")
        data += (bytes([len(value), len(encoded)]) + encoded + b"\0" if utf8 else
                 struct.pack("<H", len(value)) + encoded + b"\0\0")
    pool_size = 28 + len(strings) * 4 + len(data)
    pool = struct.pack("<HHIIIIII", 1, 28, pool_size, len(strings), 0,
                       0x100 if utf8 else 0, 28 + len(strings) * 4, 0)
    pool += struct.pack("<" + "I" * len(offsets), *offsets) + data
    def attr(ns, name, typ, value):
        return struct.pack("<IIIHBBI", ns, name, 0xffffffff, 8, 0, typ, value)
    attrs = [attr(0xffffffff, 1, 3, 2), attr(6, 3, 0x10, 40994), attr(6, 4, 3, 5)]
    if duplicate:
        attrs.append(attrs[1])
    start = struct.pack("<HHIII", 0x102, 16, 36 + 20 * len(attrs), 1, 0xffffffff)
    start += struct.pack("<IIHHHHHH", 0xffffffff, 0, 20, 20, len(attrs), 0, 0, 0)
    start += b"".join(attrs)
    end = struct.pack("<HHIIIII", 0x103, 16, 24, 1, 0xffffffff, 0xffffffff, 0)
    return struct.pack("<HHI", 3, 8, 8 + len(pool) + len(start) + len(end)) + pool + start + end


def manager_elf(code=None, duplicate=False):
    # A small ELF64 shared library with real section/symbol table layouts.
    if code is None:
        code = struct.pack("<II", 0x528000a0, 0xd65f03c0)  # mov w0,#5; ret
    name = b"Java_com_sukisu_ultra_Natives_getManagerUAPIVersion"
    names = b"\0.shstrtab\0.dynstr\0.dynsym\0.text\0"
    strings = b"\0" + name + b"\0"
    symbols = bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 4, 0x1000, len(code))
    if duplicate:
        symbols += symbols[24:]
    chunks = [b"", names, strings, symbols, code]
    offsets, data = [0], bytes(64)
    for chunk in chunks[1:]:
        offsets.append(len(data))
        data += chunk
    shoff = len(data)
    sections = bytes(64)
    for index, (name_offset, typ, flags, address, link, entsize) in enumerate([
            (1, 3, 0, 0, 0, 0), (11, 3, 0, 0, 0, 0),
            (19, 11, 0, 0, 2, 24), (27, 1, 6, 0x1000, 0, 0)], 1):
        sections += struct.pack("<IIQQQQIIQQ", name_offset, typ, flags, address,
                                offsets[index], len(chunks[index]), link, 0, 1, entsize)
    header = b"\x7fELF\x02\x01\x01" + bytes(9)
    header += struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 5, 1)
    return header + data[64:] + sections


class BinaryMetadataTests(unittest.TestCase):
    def test_manifest_utf8_and_utf16(self):
        for utf8 in (True, False):
            self.assertEqual(parse_binary_manifest(manifest(utf8)),
                             {"package": "com.sukisu.ultra", "version_name": "v4.2.1",
                              "version_code": 40994})

    def test_manifest_rejects_truncation_invalid_pool_and_duplicate_attributes(self):
        bad_offset = bytearray(manifest())
        struct.pack_into("<I", bad_offset, 28, 0xfffffff0)  # string data start
        unclosed = bytearray(manifest()[:-24])
        struct.pack_into("<I", unclosed, 4, len(unclosed))
        bad_index = bytearray(manifest())
        pool_size, = struct.unpack_from("<I", bad_index, 12)
        struct.pack_into("<I", bad_index, 8 + pool_size + 36 + 16, 0xfffffff0)
        for data in (manifest()[:-1], bytes(bad_offset), bytes(unclosed), bytes(bad_index),
                     manifest(duplicate=True), b"<manifest/>"):
            with self.subTest(data=data[:16]), self.assertRaises(ValueError):
                parse_binary_manifest(data)

    def test_actual_arm64_constant_return_and_bti(self):
        self.assertEqual(parse_manager_uapi(manager_elf()), 5)
        self.assertEqual(parse_manager_uapi(manager_elf(struct.pack(
            "<III", 0xd503245f, 0x528000c0, 0xd65f03c0))), 6)

    def test_elf_rejects_unknown_code_multiple_symbols_and_bad_metadata(self):
        bad_machine = bytearray(manager_elf())
        struct.pack_into("<H", bad_machine, 18, 62)
        bad_offset = bytearray(manager_elf())
        struct.pack_into("<Q", bad_offset, 40, 0xffffffffffffffff)
        missing_symbol = manager_elf().replace(b"getManagerUAPIVersion", b"getUnknownUAPIVersion")
        for data in (manager_elf(struct.pack("<II", 0x528000a1, 0xd65f03c0)),
                     manager_elf(struct.pack("<II", 0x528000a0, 0xd61f0000)),
                     manager_elf(struct.pack("<II", 0x52800000, 0xd65f03c0)),
                     manager_elf(duplicate=True), bytes(bad_machine), bytes(bad_offset),
                     manager_elf()[:-1], missing_symbol, b"not ELF"):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                parse_manager_uapi(data)


class SignatureRefusalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.apk = Path(self.temp.name) / "unsigned-fixture.apk"
        with zipfile.ZipFile(self.apk, "w") as z:
            z.writestr("AndroidManifest.xml", manifest())
            z.writestr("lib/arm64-v8a/libkernelsu.so", manager_elf())

    def test_failed_signature_verification_is_never_parsed_as_trusted(self):
        # Even apparently valid certificate text cannot override a failed verifier.
        fake = subprocess.CompletedProcess([], 1, "Number of signers: 1\nSigner #1 certificate SHA-256 digest: " + "a" * 64, "invalid")
        with patch("release_apk.subprocess.run", return_value=fake) as run:
            with self.assertRaisesRegex(ValueError, "signature"):
                inspect_release_apk(self.apk, apksigner="apksigner")
            self.assertEqual(run.call_args.args[0], ["apksigner", "verify", "--verbose", "--print-certs", str(self.apk)])

    def test_missing_signer_dependency_fails_closed(self):
        with patch("release_apk.subprocess.run", side_effect=FileNotFoundError), self.assertRaisesRegex(ValueError, "apksigner"):
            inspect_release_apk(self.apk, apksigner="missing-apksigner")

    def test_signer_timeout_fails_closed(self):
        with patch("release_apk.subprocess.run", side_effect=subprocess.TimeoutExpired("apksigner", 60)), \
                self.assertRaisesRegex(ValueError, "apksigner"):
            inspect_release_apk(self.apk, apksigner="apksigner")

    def test_successful_command_without_one_unambiguous_signer_is_rejected(self):
        verified_v2 = "Verified using v2 scheme (APK Signature Scheme v2): true\n"
        for output in ("Verifies", "Number of signers: 2\nSigner #1 certificate SHA-256 digest: " + "a" * 64,
                       "Number of signers: 1\nSigner #1 certificate SHA-256 digest: " + "a" * 64 +
                       "\nSigner #1 certificate SHA-256 digest: " + "b" * 64):
            with self.subTest(output=output), patch("release_apk.subprocess.run", return_value=
                    subprocess.CompletedProcess([], 0, verified_v2 + output, "")), self.assertRaises(ValueError):
                inspect_release_apk(self.apk, apksigner="apksigner")

    def test_v1_only_signature_is_not_usable_by_the_builtin_kernel(self):
        output = ("Verified using v2 scheme (APK Signature Scheme v2): false\n"
                  "Number of signers: 1\nSigner #1 certificate SHA-256 digest: " + "a" * 64)
        with patch("release_apk.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")), \
                self.assertRaisesRegex(ValueError, "v2"):
            inspect_release_apk(self.apk, apksigner="apksigner")


class NativeLibrarySelectionTests(unittest.TestCase):
    def inspect_libraries(self, libraries):
        with tempfile.TemporaryDirectory() as temporary:
            apk = Path(temporary) / "synthetic.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", manifest())
                for name, data in libraries.items():
                    archive.writestr(name, data)
            with patch("release_apk._verify_signature", return_value="a" * 64):
                return inspect_release_apk(apk)

    def test_randomized_name_is_selected_by_exact_exported_symbol(self):
        unrelated = manager_elf().replace(b"getManagerUAPIVersion", b"getUnknownUAPIVersion")
        result = self.inspect_libraries({
            "lib/arm64-v8a/libunrelated.so": unrelated,
            "lib/arm64-v8a/librandomized.so": manager_elf(struct.pack(
                "<II", 0x528000c0, 0xd65f03c0)),
            "lib/x86_64/libkernelsu.so": b"not an ARM64 library"})
        self.assertEqual(result["uapi"], 6)

    def test_original_library_name_remains_supported(self):
        self.assertEqual(self.inspect_libraries({
            "lib/arm64-v8a/libkernelsu.so": manager_elf()})["uapi"], 5)

    def test_no_exact_symbol_or_wrong_abi_is_rejected(self):
        wrong_symbol = manager_elf().replace(b"getManagerUAPIVersion", b"getUnknownUAPIVersion")
        for libraries in ({"lib/arm64-v8a/libkernelsu.so": wrong_symbol},
                          {"lib/arm64-v8a/libdecoy.so": wrong_symbol +
                           b"Java_com_sukisu_ultra_Natives_getManagerUAPIVersion\0"},
                          {"lib/x86_64/libkernelsu.so": manager_elf()},
                          {"assets/libkernelsu.so": manager_elf()}):
            with self.subTest(libraries=list(libraries)), self.assertRaisesRegex(ValueError, "Missing.*UAPI"):
                self.inspect_libraries(libraries)

    def test_two_candidates_are_rejected_even_when_they_agree(self):
        with self.assertRaisesRegex(ValueError, "ambiguous|Ambiguous"):
            self.inspect_libraries({"lib/arm64-v8a/libkernelsu.so": manager_elf(),
                                    "lib/arm64-v8a/librandomized.so": manager_elf()})

    def test_invalid_candidate_cannot_be_ignored_in_favor_of_valid_library(self):
        bad_code = manager_elf(struct.pack("<II", 0x528000a1, 0xd65f03c0))
        for invalid in (bad_code, manager_elf(duplicate=True), b"not ELF"):
            with self.subTest(invalid=invalid[:20]), self.assertRaises(ValueError):
                self.inspect_libraries({"lib/arm64-v8a/libkernelsu.so": manager_elf(),
                                        "lib/arm64-v8a/librandomized.so": invalid})


@unittest.skipUnless(os.environ.get("RELEASE_APK_FIXTURE"), "set RELEASE_APK_FIXTURE for a real signed APK")
class OfficialApkIntegration(unittest.TestCase):
    def test_real_official_apk_signature_metadata_and_machine_code(self):
        result = inspect_release_apk(Path(os.environ["RELEASE_APK_FIXTURE"]))
        official = {
            "c7f69280cf468e8415c585ff31f963d0147386831217a1e89b822afddc5f40ed":
                ("v4.2.1", 40994, 5),
            "73a0a2d91f06445ac841ea81ea600f0ae9d3997cbf45e58aaa27b9a600779dcb":
                ("v4.2.1-r1", 41049, 6),
            "f60ba9fd7c3d8fe3966d7641ab755176f80100bcb8e9fa28d48856ecf931f464":
                ("v4.2.1-r2", 41068, 6),
            "a928eb57ad34b105233f92dcd55e54dd883482e417970276329a7d0f0979e212":
                ("v4.3.0", 41100, 6)}
        self.assertIn(result["sha256"], official, "Unreviewed official APK fixture")
        name, code, uapi = official[result["sha256"]]
        self.assertEqual(result, {
            "package": "com.sukisu.ultra", "version_name": name, "version_code": code,
            "uapi": uapi, "certificate_sha256": "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef",
            "sha256": result["sha256"]})


if __name__ == "__main__":
    unittest.main()
