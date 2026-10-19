"""Verify release421 build, manifest, config and linked code; export compact files."""
import argparse
import json
from pathlib import Path
import shutil

import inspect_40971_5_artifacts as base
from kernel_binary_identity import verify_get_info_identity

MANIFEST = "release-4.2.1-manifest.json"
RESOLVED = "release-4.2.1-resolved-manifest.xml"
PINS = {**base.PINS, "kernelsu_commit": "ee35e65428054476c279eae59f7f2bba272040b9"}
FILES = (base.ORIGINAL_FILES - {base.MANIFEST_NAME, base.RESOLVED_NAME}) | {MANIFEST, RESOLVED}

def sums(folder):
    files = sorted(p for p in folder.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt")
    (folder / "SHA256SUMS.txt").write_text("".join(f"{base.sha256(p)}  {p.name}\n" for p in files))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--kernel-only", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--build-run-id", required=True)
    args = parser.parse_args()
    original = base.check_original_sums(args.input, FILES)
    manifest = json.loads((args.input / MANIFEST).read_text())
    for key, pin in PINS.items():
        base.require(manifest.get(key) == pin, "release421 manifest pin mismatch: " + key)
    base.require(manifest.get("target") ==
                 "android12-5.10.209-2024-05 / KernelSU 40994 / UAPI 5 / SUSFS 2.3.0",
                 "release421 manifest target mismatch")
    base.require(manifest.get("resolved_toolchain_manifest_sha256") == base.sha256(args.input / RESOLVED),
                 "resolved source manifest hash differs")
    config = manifest.get("build_config", {})
    base.require(config.get("release_4_2_1") is True and config.get("use_kpm") is False and
                 config.get("make_release") is False, "unexpected release421 build profile")
    result = json.loads((args.input / "build-result.json").read_text())
    base.require(result.get("total") == 1 and result.get("success") == 1 and result.get("failed") == 0,
                 "build-result counts are not one success")
    base.require(len(result.get("results", [])) == 1 and result["results"][0].get("success") is True,
                 "build-result lacks a successful target")
    image, archive = base.check_archive(args.input)
    base.require(not args.kernel_only.exists() and not args.evidence.exists(), "output directory exists")
    args.kernel_only.mkdir(parents=True)
    args.evidence.mkdir(parents=True)
    for name in (MANIFEST, RESOLVED, "kernel.config", "gki_defconfig", "build-result.json", "SHA256SUMS.txt"):
        target = "original-SHA256SUMS.txt" if name == "SHA256SUMS.txt" else name
        shutil.copy2(args.input / name, args.evidence / target)
    try:
        functions, metadata = base.elf_proof(args.input / "vmlinux", image,
            args.evidence / "symbol-diagnostic.json", base.FUNCTIONS + ("do_manager",))
        base.disassemble(args.input / "vmlinux", functions, args.evidence / "aarch64-functions.disasm.txt")
        (args.evidence / "unverified-code-proof.json").write_text(json.dumps(
            {"linked_functions": functions, "elf_address_metadata": metadata,
             "identity_validated": False}, indent=2) + "\n")
        base.require(metadata.get("copy_to_user_address") is not None, "_copy_to_user symbol missing")
        identity = verify_get_info_identity(image, functions[0], metadata)
    except Exception:
        sums(args.evidence)
        raise
    proof = {"source_run_id": args.build_run_id, "original_sha256sums_verified": True,
             "original_files": original, "manifest_pins_verified": PINS, **archive,
             "linked_functions_match_packaged_image": functions, "elf_address_metadata": metadata,
             "get_info_identity": identity,
             "scope": "Artifact/config/source identity and linked code; no device boot/root acceptance."}
    (args.evidence / "binary-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    (args.evidence / "unverified-code-proof.json").unlink()
    shutil.copy2(args.input / base.ZIP_NAME, args.kernel_only / base.ZIP_NAME)
    base.require(base.sha256(args.kernel_only / base.ZIP_NAME) == original[base.ZIP_NAME], "exported ZIP differs")
    sums(args.evidence)
    sums(args.kernel_only)
    print(json.dumps({"archive_sha256": archive["archive_sha256"],
                      "image_sha256": archive["image_sha256"],
                      "functions": [f["symbol"] for f in functions]}, indent=2))

if __name__ == "__main__":
    main()
