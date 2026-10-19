"""Revalidate the unchanged build after repairing its post-build checker.

The original build and ELF checks succeeded, but the first identity checker
selected the last of several identically named _copy_to_user symbols. This
recovery uses authenticated artifacts and their original ELF disassembly; it
does not claim to rerun missing vmlinux/System.map checks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

import inspect_40971_5_artifacts as base
import inspect_release421_artifacts as target
from kernel_binary_identity import verify_get_info_identity

REPO = "Bigzhangbig/GKI_KernelSU_SUSFS"
SOURCE_RUN = 39184992228
SOURCE_HEAD = "7b8e6a33a7a7ee2beca9abe0ebee083664de26b1"
SOURCE_WORKFLOW = 388903719

def api(path):
    result = subprocess.run(["gh", "api", f"repos/{REPO}/{path}"],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout)

def capture_source(out):
    run = api(f"actions/runs/{SOURCE_RUN}")
    base.require(run["id"] == SOURCE_RUN and run["repository"]["full_name"] == REPO and run["head_sha"] == SOURCE_HEAD,
                 "unexpected source repository/head")
    base.require(run["workflow_id"] == SOURCE_WORKFLOW and run["event"] == "workflow_dispatch" and
                 run["path"] == ".github/workflows/kernel-release421.yml", "unexpected source workflow")
    base.require(run["run_attempt"] == 1 and run["status"] == "completed" and
                 run["conclusion"] == "failure", "unexpected source run state/attempt")
    jobs = api(f"actions/runs/{SOURCE_RUN}/attempts/1/jobs?per_page=100")
    base.require(jobs["total_count"] == 1 and len(jobs["jobs"]) == 1, "unexpected source job count")
    steps = {s["name"]: s["conclusion"] for s in jobs["jobs"][0]["steps"]}
    for name in ("Verify pinned build integration", "Build pinned release 4.2.1 GKI",
                 "Collect original kernel and exact build evidence"):
        base.require(steps.get(name) == "success", "source build prerequisite did not succeed: " + name)
    failed = {name for name, result in steps.items() if result == "failure"}
    base.require(failed == {"Verify packaged Image and export compact evidence"},
                 "source run failed outside the repairable inspection step")
    artifacts = api(f"actions/runs/{SOURCE_RUN}/artifacts?per_page=100")
    expected = {"evidence-release421", "unverified-release421-inspection-input"}
    indexed = {a["name"]: a for a in artifacts["artifacts"]}
    base.require(artifacts["total_count"] == 2 and set(indexed) == expected, "unexpected source artifacts")
    for artifact in indexed.values():
        base.require(not artifact["expired"] and artifact.get("digest", "").startswith("sha256:") and
                     artifact["workflow_run"]["id"] == SOURCE_RUN and
                     artifact["workflow_run"]["head_sha"] == SOURCE_HEAD, "invalid source artifact provenance")
    out.mkdir(parents=True)
    for name, value in (("source-run.json", run), ("source-jobs.json", jobs), ("source-artifacts.json", artifacts)):
        (out / name).write_text(json.dumps(value, indent=2) + "\n")
    print("Source build/head/workflow/attempt and successful compile/source checks verified")

def verify_small(folder):
    sums = {}
    for line in (folder / "SHA256SUMS.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})\s+([^/\s]+)", line)
        base.require(match is not None, "invalid original evidence checksum")
        digest, name = match.groups()
        base.require(name not in sums and base.sha256(folder / name) == digest,
                     "original evidence checksum mismatch: " + name)
        sums[name] = digest
    base.require(set(sums) == {p.name for p in folder.iterdir() if p.is_file()} - {"SHA256SUMS.txt"},
                 "original evidence file set differs")
    return sums

def restore_copy_symbols(image, functions, metadata, disassembly):
    # Match the actual instruction bytes as well as the ELF-disassembler label.
    fn = functions[0]
    begin, size = int(fn["address"], 16), fn["size"]
    code = bytes.fromhex(fn["hex"])
    rows = {}
    copies = set()
    for line in disassembly.splitlines():
        match = re.match(r"^\s*([0-9a-f]{16}):\s+([0-9a-f]{8})\s+(.*)$", line)
        if not match:
            continue
        address, word, instruction = int(match[1], 16), int(match[2], 16), match[3]
        if not begin <= address < begin + size:
            continue
        base.require(address not in rows and struct.pack("<I", word) == code[address - begin:address - begin + 4],
                     "ELF disassembly bytes differ from bound GET_INFO bytes")
        rows[address] = word
        label = re.fullmatch(r"bl\s+([0-9a-f]{16})\s+<_copy_to_user(?:\$[0-9a-f]{32})?>", instruction.strip())
        if label:
            base.require(word & 0xfc000000 == 0x94000000, "labelled copy is not a BL instruction")
            immediate = word & 0x3ffffff
            if immediate & (1 << 25):
                immediate -= 1 << 26
            target_address = (address + immediate * 4) & ((1 << 64) - 1)
            base.require(target_address == int(label[1], 16), "copy BL address differs from ELF label")
            copies.add(target_address)
    base.require(set(rows) == set(range(begin, begin + size, 4)) and copies,
                 "incomplete ELF disassembly/copy target evidence")
    for fn in functions:
        offset = int(fn["image_offset"], 16)
        raw = bytes.fromhex(fn["hex"])
        base.require(offset == int(fn["address"], 16) - int(metadata["text_base"], 16) and
                     image[offset:offset + fn["size"]] == raw and
                     hashlib.sha256(raw).hexdigest() == fn["sha256"], "linked function does not match Image")
    corrected = {**metadata, "copy_to_user_addresses": [hex(a) for a in sorted(copies)]}
    return corrected

def recheck(source, raw_dir, provenance, evidence, kernel, inspection_run):
    small = verify_small(source)
    original = {}
    for line in (source / "original-SHA256SUMS.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})\s+(?:\./)?([^/\s]+)", line)
        base.require(match is not None and match[2] not in original, "invalid original build checksum")
        original[match[2]] = match[1]
    base.require(set(original) == target.FILES, "original build file set differs")
    archive = raw_dir / base.ZIP_NAME
    base.require(base.sha256(archive) == original[base.ZIP_NAME], "raw original ZIP hash differs")
    for name in target.FILES - {base.ZIP_NAME, "vmlinux", "System.map"}:
        base.require(base.sha256(source / name) == original[name], "original file hash differs: " + name)
    manifest = json.loads((source / target.MANIFEST).read_text())
    for key, value in target.PINS.items():
        base.require(manifest[key] == value, "original source pin differs: " + key)
    base.require(manifest["target"] == "android12-5.10.209-2024-05 / KernelSU 40994 / UAPI 5 / SUSFS 2.3.0",
                 "original manifest target differs")
    base.require(manifest["build_config"]["release_4_2_1"] is True and
                 manifest["build_config"]["use_kpm"] is False and manifest["build_config"]["make_release"] is False,
                 "original profile differs")
    base.require(manifest["resolved_toolchain_manifest_sha256"] == base.sha256(source / target.RESOLVED),
                 "resolved manifest hash differs")
    result = json.loads((source / "build-result.json").read_text())
    base.require(result.get("total") == 1 and result.get("success") == 1 and result.get("failed") == 0 and
                 len(result["results"]) == 1 and result["results"][0]["success"] is True,
                 "original source build result differs")
    # Reuse the original ZIP/config/certificate checker in a temporary view.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="release421-original-") as tmp:
        view = Path(tmp)
        shutil.copy2(archive, view / base.ZIP_NAME)
        shutil.copy2(source / "kernel.config", view / "kernel.config")
        image, archive_proof = base.check_archive(view)
    partial = json.loads((source / "unverified-code-proof.json").read_text())
    functions, old_metadata = partial["linked_functions"], partial["elf_address_metadata"]
    base.require([base.function_target(f["symbol"], base.FUNCTIONS + ("do_manager",)) for f in functions] ==
                 list(base.FUNCTIONS + ("do_manager",)), "unexpected linked functions")
    metadata = restore_copy_symbols(image, functions, old_metadata,
                                    (source / "aarch64-functions.disasm.txt").read_text())
    identity = verify_get_info_identity(image, functions[0], metadata)
    base.require(not evidence.exists() and not kernel.exists(), "reinspection output already exists")
    evidence.mkdir(parents=True)
    kernel.mkdir(parents=True)
    for name in (target.MANIFEST, target.RESOLVED, "kernel.config", "gki_defconfig", "build-result.json",
                 "original-SHA256SUMS.txt", "aarch64-functions.disasm.txt"):
        shutil.copy2(source / name, evidence / name)
    for item in provenance.iterdir():
        if item.is_file():
            shutil.copy2(item, evidence / item.name)
    proof = {"source_run_id": str(SOURCE_RUN), "source_build_head": SOURCE_HEAD,
             "inspection_run_id": str(inspection_run), "reinspection_head":
             subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip(),
             "original_identity_check_failed": "duplicate copy symbol selection; repaired using bound ELF disassembly",
             "original_evidence_checksums_verified": small, "original_files": original,
             "original_large_file_hashes_retained_not_recomputed": {n: original[n] for n in ("vmlinux", "System.map")},
             "source_artifacts_recorded": [
                 {"id": a["id"], "name": a["name"], "digest": a["digest"]}
                 for a in json.loads((provenance / "source-artifacts.json").read_text())["artifacts"]],
             "source_transport": "Trusted Actions download by fixed run/name plus original file hashes; API archive digests recorded, not independently recomputed.",
             "manifest_pins_verified": target.PINS, **archive_proof,
             "linked_functions_match_packaged_image": functions, "elf_address_metadata": metadata,
             "original_copy_to_user_address": old_metadata.get("copy_to_user_address"), "get_info_identity": identity,
             "scope": "Unchanged compiled Image revalidated with authenticated original ELF evidence; no device runtime acceptance."}
    (evidence / "binary-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    shutil.copy2(archive, kernel / base.ZIP_NAME)
    target.sums(evidence)
    target.sums(kernel)
    print(json.dumps({"archive_sha256": proof["archive_sha256"], "image_sha256": proof["image_sha256"],
                      "version": identity["version"], "uapi": identity["uapi_version"]}, indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-source", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--inspection-run-id")
    args = parser.parse_args()
    if args.capture_source:
        capture_source(args.capture_source)
        return
    base.require(all((args.source, args.raw, args.provenance, args.evidence, args.kernel, args.inspection_run_id)),
                 "missing reinspection inputs")
    capture_source(args.provenance)  # Always refresh the authenticated source metadata.
    recheck(args.source, args.raw, args.provenance, args.evidence, args.kernel, args.inspection_run_id)

if __name__ == "__main__":
    main()
