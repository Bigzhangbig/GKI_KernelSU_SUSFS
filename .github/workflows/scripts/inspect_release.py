"""Verify the audited Release artifact and export compact linked-code evidence."""
import argparse
import json
from pathlib import Path
import shutil

import artifact_checks as base
from release_target import load_target_file, verify_release_snapshot
from kernel_binary_identity import verify_get_info_identity

MANIFEST = base.MANIFEST_NAME
RESOLVED = base.RESOLVED_NAME

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
    target = load_target_file(args.input / "release-target.json")
    verify_release_snapshot(target)
    original = base.check_original_sums(args.input, base.original_files(target))
    base.check_manifest(args.input, target)
    image, archive = base.check_archive(args.input, target)
    base.require(not args.kernel_only.exists() and not args.evidence.exists(), "output directory exists")
    args.kernel_only.mkdir(parents=True)
    args.evidence.mkdir(parents=True)
    for name in (MANIFEST, RESOLVED, "release-target.json", "kernel.config", "gki_defconfig", "build-result.json", "SHA256SUMS.txt"):
        destination = "original-SHA256SUMS.txt" if name == "SHA256SUMS.txt" else name
        shutil.copy2(args.input / name, args.evidence / destination)
    try:
        functions, metadata = base.elf_proof(args.input / "vmlinux", image,
            args.evidence / "symbol-diagnostic.json", base.FUNCTIONS)
        base.disassemble(args.input / "vmlinux", functions, args.evidence / "aarch64-functions.disasm.txt")
        (args.evidence / "unverified-code-proof.json").write_text(json.dumps(
            {"linked_functions": functions, "elf_address_metadata": metadata,
             "identity_validated": False}, indent=2) + "\n")
        base.require(metadata.get("copy_to_user_address") is not None, "_copy_to_user symbol missing")
        identity = verify_get_info_identity(
            image, functions[0], metadata, expected_version=target.version,
            expected_uapi=target.uapi, expected_features=target.features,
            expected_full_version=target.full_version)
    except Exception:
        sums(args.evidence)
        raise
    proof = {"source_run_id": args.build_run_id, "original_sha256sums_verified": True,
             "original_files": original, "manifest_pins_verified": target.pins, **archive,
             "linked_functions_match_packaged_image": functions, "elf_address_metadata": metadata,
             "get_info_identity": identity,
             "scope": "Artifact/config/source identity and linked code; no device boot/root acceptance."}
    (args.evidence / "binary-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    (args.evidence / "unverified-code-proof.json").unlink()
    shutil.copy2(args.input / target.archive_name, args.kernel_only / target.archive_name)
    base.require(base.sha256(args.kernel_only / target.archive_name) == original[target.archive_name], "exported ZIP differs")
    sums(args.evidence)
    sums(args.kernel_only)
    print(json.dumps({"archive_sha256": archive["archive_sha256"],
                      "image_sha256": archive["image_sha256"],
                      "functions": [f["symbol"] for f in functions]}, indent=2))

if __name__ == "__main__":
    main()
