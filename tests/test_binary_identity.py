"""Machine-code fixtures preserve the clang 12 GET_INFO instructions from run 38142403369.

ADRP and the copy BL are relocated for the compact Image fixture. Tests alter the
actual referenced record/store instruction, never a textual version marker.
"""
import hashlib
import json
import os
import struct
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / ".github/workflows/scripts"
sys.path.insert(0, str(SCRIPTS))
from kernel_binary_identity import verify_get_info_identity as check_identity
from release_target import load_release_target

TARGET = load_release_target()

def verify_get_info_identity(image, function, metadata, **overrides):
    expected = dict(expected_version=TARGET.version, expected_uapi=TARGET.uapi,
                    expected_features=TARGET.features, expected_full_version=TARGET.full_version)
    expected.update(overrides)
    return check_identity(image, function, metadata, **expected)

REAL_40971_CODE = bytes.fromhex(
    "3f2303d5ffc300d15e8600f8fd7b02a9fd830091097900b0c887009029011391"
    "084947f92a2540a90b4138d5a8831ff8eaa700a968c143f9e9a70090aa588b52"
    "8a4fa172080540b929d142b90b7d05536a7daa9b0bd490524afd67d32b00a072"
    "48a10b1b3f01086b6100005448008052e80f00b9a80080d2a800c0f2e1230091"
    "02028052e80b00f9ee2ece97600100b5a98700f0a8835ff8294947f93f0108eb"
    "61010054fd7b42a95e8e5ff8ffc30091bf2303d5c0035fd6007700b000883191"
    "3d03d297a0018012f2ffff17e7800f94")

# Real Release clang 12 handler from ee35e654, including the inlined bounded
# dynamic-manager scan, LDARB, opaque read-lock calls, and BRK bounds trap.
REAL_40994_CODE = bytes.fromhex(
    "3f2303d5ff4301d15e8600f8fd7b02a9f51b00f9f44f04a9fd830091e97800f0"
    "a88700f029411c91086941f92a2540a90b4138d5f30300aaa8831ff8eaa700a9"
    "68c143f9aa588b528a4fa172090540b948a800d008d142b92b7d05536a7daa9b"
    "0bd490522b00a0724afd67d31f05003154a50b1bc00000541f01146b81000054"
    "48008052e80f00b92400001448b500b00861329108fddf080804003640b500b0"
    "00703291e44d1b9448b500d0087549b9e80200344ab500b0e9031faa35008052"
    "4ae132913f4100f1a00500544b0140b97f01146be0000054290500913f0108eb"
    "f5279f1a1f0109eb4a310391c1feff5440b500b000703291594e1b94f5000036"
    "e80f40b908011f32dfffff1740b500b000703291524e1b94e80080d2a800c0f2"
    "e123009102028052e00313aae80b00f99a23ce97a00100b5a98700f0a8835ff8"
    "296941f93f0108ebc1010054fd7b42a9f44f44a9f51b40f95e8e5ff8ff430191"
    "bf2303d5c0035fd60077009000183991e7f7d197a0018012f0ffff1740a22ad4"
    "54810f94")

FULL = b"v4.2.1-ee35e654@builtin\0"


def fixture(version=40994, features=7, uapi=5):
    image = bytearray(0x5000)
    code = bytearray(REAL_40971_CODE)
    # ADRP x9, page 0x3000 from PC 0x1014, followed by the real ADD #0x4c0.
    struct.pack_into("<I", code, 20, 0xd0000009)
    struct.pack_into("<I", code, 116, 0xd2800008 | features << 5)
    struct.pack_into("<I", code, 120, 0xf2c00008 | uapi << 5)
    struct.pack_into("<I", code, 136, 0x94000000 | (0x8000 - 0x1088) // 4)
    image[0x1000:0x1000 + len(code)] = code
    struct.pack_into("<IIII", image, 0x34c0, version, 0, 0, 0)
    image[0x4000:0x4000 + len(FULL)] = FULL
    function = dict(symbol="do_get_info$ff6ba518b5bff4dead3fe5c5d44cdbb1",
                    address="0x1000", size=len(code), image_offset="0x1000",
                    hex=code.hex(), sha256=hashlib.sha256(code).hexdigest())
    metadata = dict(text_base="0x0", copy_to_user_address="0x8000",
                    sections={".rodata": dict(address="0x3000", size=0x1000)})
    return image, function, metadata


def rewrite_code(image, function, offset, instruction):
    struct.pack_into("<I", image, 0x1000 + offset, instruction)
    code = bytes(image[0x1000:0x1000 + function["size"]])
    function.update(hex=code.hex(), sha256=hashlib.sha256(code).hexdigest())


def vector_fixture(dynamic_manager=False, split_record=False):
    image, function, metadata = fixture()
    words = list(struct.unpack("<5I", REAL_40971_CODE[:20]))
    words += [0xd0000009, 0x91130129]  # relocated ADRP x9; ADD x9,#0x4c0
    if split_record:
        # MOV w8,#40994; STR x8,[sp]; LDR d0,[x9,#8]; STR d0,[sp,#8].
        words += [0x52800008 | 40994 << 5, 0xf90003e8, 0xfd400520, 0xfd0007e0]
    else:
        words += [0x3dc00120, 0x3d8003e0]  # LDR q0,[x9]; STR q0,[sp]
    if dynamic_manager:
        words += [0xaa0003f3, 0x52807d00]  # preserve arg in x19; manager(uid=1000)
        pc = 0x1000 + len(words) * 4
        words += [0x94000000 | (0x9000 - pc) // 4]
        words += [0x34000060, 0x52800048, 0xb90007e8, 0xaa1303e0]
        # CBZ w0 skips MOV w8,#2; STR w8,[sp,#4]; restore arg.
    words += [0x910003e1, 0x52800202]  # x1=SP, w2=16
    pc = 0x1000 + len(words) * 4
    words += [0x94000000 | (0x8000 - pc) // 4, 0xd65f03c0]
    code = struct.pack("<" + "I" * len(words), *words)
    image[0x1000:0x1000 + len(code)] = code
    struct.pack_into("<IIII", image, 0x34c0, 40994, 0, 7, 5)
    function.update(hex=code.hex(), size=len(code), sha256=hashlib.sha256(code).hexdigest())
    return image, function, metadata


def release_loop_fixture():
    image, function, metadata = fixture()
    code = bytearray(REAL_40994_CODE)
    struct.pack_into("<I", code, 28, 0xd0000009)  # ADRP x9 to compact rodata page
    struct.pack_into("<I", code, 304, 0x94000000 | (0x8000 - 0x1130) // 4)
    image[0x1000:0x1000 + len(code)] = code
    image[0x3710:0x3720] = bytes.fromhex("22a00000000000000000000000000000")
    function.update(symbol="do_get_info$a951cada9256be24c0a7a862ad805380",
                    hex=code.hex(), size=len(code), sha256=hashlib.sha256(code).hexdigest())
    metadata["copy_to_user_addresses"] = ["0x9000", "0x8000"]
    return image, function, metadata


class BinaryIdentityTests(unittest.TestCase):
    def test_copy_symbol_candidate_set_is_authoritative_and_legacy_still_works(self):
        image, function, metadata = fixture()
        metadata.update(copy_to_user_addresses=["0x9000", "0x8000"], copy_to_user_address="0x9000")
        self.assertEqual(verify_get_info_identity(bytes(image), function, metadata)["version"], 40994)
        metadata["copy_to_user_addresses"] = ["0x9000"]
        with self.assertRaisesRegex(ValueError, "copy call target mismatch"):
            verify_get_info_identity(bytes(image), function, metadata)
        metadata["copy_to_user_addresses"] = []
        with self.assertRaises(ValueError):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_real_compiler_manager_loop_and_conditional_trap_are_analyzed(self):
        image, function, metadata = release_loop_fixture()
        proof = verify_get_info_identity(bytes(image), function, metadata)
        self.assertEqual((proof["version"], proof["features"], proof["uapi_version"]), (40994, 7, 5))
        self.assertIn("0x117c", proof["trap_terminal_image_offsets"])
        # Manager=true now writes into version instead of flags; joins must not hide it.
        rewrite_code(image, function, 132, 0xb9000be8)
        with self.assertRaisesRegex(ValueError, "version"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_trap_only_path_cannot_count_as_proven_copy(self):
        image, function, metadata = fixture()
        rewrite_code(image, function, 0, 0xd4200000)
        with self.assertRaisesRegex(ValueError, "no proven 16-byte record copy"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_real_release_packaged_image(self):
        base = Path(os.environ.get("RELEASE_BINARY_FIXTURE_DIR", Path(__file__).parent / "fixtures/release"))
        proof_file = base / "binary-proof.json"
        archive = base / TARGET.archive_name
        if not proof_file.is_file() or not archive.is_file():
            self.skipTest("local CI artifact unavailable; relocated real compiled loop fixture still runs")
        import zipfile
        proof = json.loads(proof_file.read_text())
        metadata = proof["elf_address_metadata"]
        functions = proof.get("linked_functions_match_packaged_image", proof.get("linked_functions"))
        with zipfile.ZipFile(archive) as z:
            image = z.read("Image")
        result = verify_get_info_identity(image, functions[0], metadata)
        self.assertEqual(result["function_sha256"], functions[0]["sha256"])
        self.assertEqual(result["version"], 40994)

    def test_referenced_record_and_store_prove_identity(self):
        image, function, metadata = fixture()
        proof = verify_get_info_identity(bytes(image), function, metadata)
        self.assertEqual((proof["version"], proof["features"], proof["uapi_version"]), (40994, 7, 5))
        self.assertEqual(proof["function_sha256"], hashlib.sha256(bytes.fromhex(function["hex"])).hexdigest())
        self.assertEqual(proof["rodata_reads"][0]["image_offset"], "0x34c0")
        self.assertEqual(proof["full_version"]["image_offset"], "0x4000")
        self.assertTrue(proof["records"])

    def test_complete_q_record_and_split_d_record_are_decoded(self):
        for split in (False, True):
            with self.subTest(split=split):
                image, function, metadata = vector_fixture(split_record=split)
                proof = verify_get_info_identity(bytes(image), function, metadata)
                self.assertEqual(proof["version"], 40994)
                self.assertEqual(proof["records"][0]["bytes_hex"], "22a00000000000000700000005000000")

    def test_opaque_call_invalidates_q_constants_in_v8_and_v16(self):
        # AAPCS64 preserves only low D8..D15, and none of V16..V31.
        # A whole Q record loaded before an opaque call cannot remain proven.
        for vector_reg in (8, 16):
            with self.subTest(vector_reg=vector_reg):
                image, function, metadata = vector_fixture()
                words = list(struct.unpack("<7I", bytes.fromhex(function["hex"])[:28]))
                words += [0x3dc00120 | vector_reg, 0xaa0003f3]  # LDR Qn,[x9]; save arg
                pc = 0x1000 + len(words) * 4
                words += [0x94000000 | (0x9000 - pc) // 4]  # opaque manager call
                words += [0x3d8003e0 | vector_reg, 0xaa1303e0, 0x910003e1, 0x52800202]
                pc = 0x1000 + len(words) * 4
                words += [0x94000000 | (0x8000 - pc) // 4, 0xd65f03c0]
                code = struct.pack("<" + "I" * len(words), *words)
                image[0x1000:0x1000 + len(code)] = code
                function.update(hex=code.hex(), size=len(code), sha256=hashlib.sha256(code).hexdigest())
                with self.assertRaisesRegex(ValueError, "not a proven constant"):
                    verify_get_info_identity(bytes(image), function, metadata)

    def test_dynamic_manager_call_preserves_record_on_every_branch(self):
        image, function, metadata = vector_fixture(dynamic_manager=True)
        proof = verify_get_info_identity(bytes(image), function, metadata)
        # The fixed-point join may forget the runtime manager bit. Identity
        # fields must stay exact even when flags become an unknown byte pattern.
        self.assertTrue(proof["records"])
        self.assertTrue(all(record["flags"] in (0, 2, None) for record in proof["records"]))
        self.assertEqual((proof["version"], proof["features"], proof["uapi_version"]), (40994, 7, 5))
        # Change only manager=true branch to clobber version with 2 instead of flags.
        rewrite_code(image, function, 56, 0xb90003e8)  # STR w8,[sp]
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_old_40971_referenced_version_cannot_pass_with_new_decoy_elsewhere(self):
        image, function, metadata = fixture(version=40971, features=5)
        struct.pack_into("<IIII", image, 0x3800, 40994, 0, 7, 5)
        with self.assertRaisesRegex(ValueError, "version"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_changed_uapi_and_feature_stores_are_rejected(self):
        for features, uapi in ((7, 6), (5, 5)):
            with self.subTest(features=features, uapi=uapi):
                image, function, metadata = fixture(features=features, uapi=uapi)
                with self.assertRaises(ValueError):
                    verify_get_info_identity(bytes(image), function, metadata)

    def test_store_to_wrong_record_offset_is_rejected(self):
        image, function, metadata = fixture()
        # STR x8 [sp,#24] leaves returned features/uapi zero in the actual record.
        rewrite_code(image, function, 132, 0xf9000fe8)
        with self.assertRaises(ValueError):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_unknown_instruction_clobber_cannot_preserve_stale_constant(self):
        image, function, metadata = fixture()
        # UDF is intentionally unsupported; interpreting it as a no-op is unsafe.
        rewrite_code(image, function, 128, 0x00000000)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_function_binding_is_checked_independently(self):
        image, function, metadata = fixture()
        image[0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, "function bytes"):
            verify_get_info_identity(bytes(image), function, metadata)
        image, function, metadata = fixture()
        metadata["text_base"] = "0x1000"
        with self.assertRaisesRegex(ValueError, "offset"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_copy_symbol_address_and_actual_call_target_are_required(self):
        image, function, metadata = fixture()
        metadata.pop("copy_to_user_address")
        with self.assertRaisesRegex(ValueError, "metadata is required"):
            verify_get_info_identity(bytes(image), function, metadata)
        image, function, metadata = fixture()
        rewrite_code(image, function, 136, 0x94000000)
        with self.assertRaisesRegex(ValueError, "copy call target mismatch"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_literal_full_version_is_required(self):
        image, function, metadata = fixture()
        image[0x4000:0x4000 + len(FULL)] = b"x" * len(FULL)
        with self.assertRaisesRegex(ValueError, "full version"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_out_of_range_rodata_reference_is_rejected(self):
        image, function, metadata = fixture()
        metadata["sections"][".rodata"]["size"] = 0x4c8
        with self.assertRaisesRegex(ValueError, "rodata"):
            verify_get_info_identity(bytes(image), function, metadata)

    def test_real_old_packaged_image_fails_new_identity(self):
        base = Path(os.environ.get("PREVIOUS_BINARY_FIXTURE_DIR", Path(__file__).parent / "fixtures/previous"))
        if not (base / "Image").is_file():
            self.skipTest("local prior packaged Image unavailable; compact machine-code fixture still runs")
        proof = json.loads((base / "binary-proof.json").read_text())
        function = proof["linked_functions_match_packaged_image"][0]
        metadata = dict(proof["elf_address_metadata"], copy_to_user_address="0xffffffc0080bfc14")
        image = (base / "Image").read_bytes()
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            verify_get_info_identity(image, function, metadata)
        actual = verify_get_info_identity(image, function, metadata, expected_version=40971,
                                          expected_features=5, expected_full_version="v4.2.0-6c284e95@HEAD")
        self.assertEqual(actual["version"], 40971)


if __name__ == "__main__":
    unittest.main()
