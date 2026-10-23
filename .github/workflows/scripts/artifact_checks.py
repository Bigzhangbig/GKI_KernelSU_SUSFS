"""Shared Release artifact, config and linked ELF checks."""

import gzip
import hashlib
import json
import re
import struct
import subprocess
import zipfile
from pathlib import Path


MANIFEST_NAME = "release-manifest.json"
RESOLVED_NAME = "release-resolved-manifest.xml"
FUNCTIONS = ("do_get_info", "do_get_info_legacy", "do_report_event", "do_extension", "do_lookup_symbols")


def original_files(target):
    return {target.archive_name, MANIFEST_NAME, RESOLVED_NAME, "build-result.json",
            "gki_defconfig", "kernel.config", "vmlinux", "System.map", "release-target.json"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_original_sums(source: Path, original_files: set[str]) -> dict[str, str]:
    sums = {}
    for line in (source / "SHA256SUMS.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})\s+\*?(?:\./)?([^/\s]+)", line)
        require(match is not None, f"invalid original SHA256SUMS line: {line!r}")
        digest, name = match.groups()
        require(name not in sums, f"duplicate original checksum: {name}")
        sums[name] = digest
    require(set(sums) == original_files, f"original checksum set differs: {set(sums) ^ original_files}")
    actual = {p.name for p in source.iterdir() if p.is_file()} - {"SHA256SUMS.txt"}
    require(actual == original_files, f"downloaded file set differs: {actual ^ original_files}")
    for name, expected in sums.items():
        require(sha256(source / name) == expected, f"original SHA256 mismatch: {name}")
    return sums


def check_manifest(source: Path, target) -> dict:
    manifest = json.loads((source / MANIFEST_NAME).read_text())
    for key, pin in target.pins.items():
        require(manifest.get(key) == pin, "Release manifest pin mismatch: " + key)
    require(manifest.get("target") ==
                 f"{target.archive_name.removesuffix('-AnyKernel3.zip')} / KernelSU {target.version} / UAPI {target.uapi} / SUSFS {target.susfs_version}",
                 "Release manifest target mismatch")
    require(manifest.get("resolved_toolchain_manifest_sha256") == sha256(source / RESOLVED_NAME),
                 "resolved source manifest hash differs")
    require(manifest.get("release_tag") == target.tag and
                 manifest.get("release_commit") == target.release_commit, "official Release identity differs")
    for key, expected in {
            "manager_version": target.manager_version, "backend_tag": target.backend_tag,
            "backend_version": target.version, "backend_source_commit": target.kernelsu_commit,
            "source_fingerprint": target.source_fingerprint, "full_version": target.full_version,
            "official_manager_apk_sha256": target.apk_sha256,
            "official_manager_certificate_sha256": target.manager_certificate_sha256}.items():
        require(manifest.get(key) == expected, "Release manifest identity mismatch: " + key)
    config = manifest.get("build_config", {})
    require(config.get("release") is True and config.get("use_kpm") is False and
                 config.get("make_release") is False, "unexpected Release build profile")
    result = json.loads((source / "build-result.json").read_text())
    require(result.get("total") == 1 and result.get("success") == 1 and result.get("failed") == 0,
                 "build-result counts are not one success")
    require(len(result.get("results", [])) == 1 and result["results"][0].get("success") is True,
                 "build-result lacks a successful target")
    return manifest


def check_archive(source: Path, target) -> tuple[bytes, dict]:
    archive = source / target.archive_name
    with zipfile.ZipFile(archive) as zipped:
        require(zipped.testzip() is None, "ZIP CRC failed")
        require({"Image", "anykernel.sh"} <= set(zipped.namelist()), "AnyKernel ZIP is incomplete")
        image = zipped.read("Image")
    require(image[0x38:0x3c] == b"ARMd", "packaged Image is not ARM64")
    start = image.find(b"IKCFG_ST")
    require(start >= 0, "embedded IKCONFIG start missing")
    start += len(b"IKCFG_ST")
    end = image.find(b"IKCFG_ED", start)
    require(end > start, "embedded IKCONFIG end missing")
    config = gzip.decompress(image[start:end]).decode()
    require(config == (source / "kernel.config").read_text(), "Image config differs from kernel.config")
    lines = set(config.splitlines())
    for key in ("CONFIG_KSU", "CONFIG_KSU_SUSFS", "CONFIG_KSU_SUSFS_SUS_PATH",
                "CONFIG_KSU_SUSFS_SUS_MOUNT", "CONFIG_KSU_SUSFS_SUS_MAP",
                "CONFIG_KSU_SUSFS_SPOOF_UNAME", "CONFIG_KSU_SUSFS_OPEN_REDIRECT"):
        require(f"{key}=y" in lines, f"{key} is not enabled")
    for key in ("CONFIG_KPM", "CONFIG_KSU_DEBUG"):
        require(f"# {key} is not set" in lines, f"{key} is enabled or missing")
    require(target.manager_certificate_sha256.encode() in image, "official certificate digest missing from Image")
    susfs_version = "v" + target.susfs_version
    require(susfs_version.encode() in image, "SuSFS version string missing from Image")
    android, kernel, sublevel, _ = target.kernel_tuple
    release_prefix = f"Linux version {kernel}.{sublevel}-{android}".encode()
    release = re.search(re.escape(release_prefix) + rb"[^\x00\n]*", image)
    require(release is not None, "unexpected Linux release string")
    return image, {"archive_sha256": sha256(archive), "image_sha256": hashlib.sha256(image).hexdigest(),
                   "image_bytes": len(image), "linux_release": release.group().decode(),
                   "embedded_config_matches": True, "official_certificate_present": True,
                   "susfs_version_string": susfs_version}


def hex_number(value: int) -> str:
    return f"0x{value:x}"


def function_target(name: str, function_names: tuple[str, ...] = FUNCTIONS) -> str | None:
    for target in function_names:
        if name == target or re.fullmatch(re.escape(target) + r"\$[0-9a-f]{32}", name):
            return target
    return None


def elf_proof(path: Path, image: bytes, diagnostic_path: Path | None = None,
              function_names: tuple[str, ...] = FUNCTIONS) -> tuple[list[dict], dict]:
    elf = path.read_bytes()
    require(elf[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", elf, 18)[0] == 183,
            "vmlinux is not little-endian AArch64 ELF64")
    phoff, shoff = struct.unpack_from("<QQ", elf, 32)
    phentsize, phcount = struct.unpack_from("<HH", elf, 54)
    shentsize, shcount, shstrndx = struct.unpack_from("<HHH", elf, 58)
    require(0 < shcount < 65535 and shentsize >= 64 and shstrndx < shcount,
            "invalid ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", elf, shoff + i * shentsize)
                for i in range(shcount)]
    shstrings = sections[shstrndx]
    shnames = elf[shstrings[4]:shstrings[4] + shstrings[5]]

    def name_from(table: bytes, offset: int) -> str:
        end = table.find(b"\0", offset)
        require(end >= 0, "unterminated ELF string")
        return table[offset:end].decode(errors="replace")

    named_sections = {}
    for section in sections:
        name = name_from(shnames, section[0])
        if name in (".text", ".rodata"):
            named_sections[name] = {"address": hex_number(section[3]),
                                    "file_offset": hex_number(section[4]), "size": section[5]}
    require(".text" in named_sections and ".rodata" in named_sections,
            "ELF text/rodata sections missing")
    loads = []
    for i in range(phcount):
        p_type, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", elf, phoff + i * phentsize)
        if p_type == 1:
            loads.append({"virtual_address": hex_number(vaddr), "physical_address": hex_number(paddr),
                          "file_offset": hex_number(offset), "file_bytes": filesz,
                          "memory_bytes": memsz, "flags": flags, "alignment": align})
    require(loads, "ELF LOAD segments missing")
    found = {}
    text_base = None
    copy_to_user_addresses = set()
    symbol_tables = []
    candidates = []
    for table in sections:
        if table[1] != 2:  # SHT_SYMTAB
            continue
        require(table[9] >= 24 and table[6] < shcount, "invalid ELF symbol table")
        stats = {"entry_count": table[5] // table[9], "entry_size": table[9],
                 "file_offset": hex_number(table[4]), "type_counts": {}, "named_count": 0}
        symbol_tables.append(stats)
        string_section = sections[table[6]]
        names = elf[string_section[4]:string_section[4] + string_section[5]]
        for offset in range(table[4], table[4] + table[5], table[9]):
            nameoff, info, _, section_index, address, size = struct.unpack_from("<IBBHQQ", elf, offset)
            name = name_from(names, nameoff)
            kind = info & 0x0f
            stats["type_counts"][str(kind)] = stats["type_counts"].get(str(kind), 0) + 1
            stats["named_count"] += bool(name)
            if name == "_text":
                text_base = address
            if kind == 2 and (name == "_copy_to_user" or
                              re.fullmatch(r"_copy_to_user\$[0-9a-f]{32}", name)):
                copy_to_user_addresses.add(address)
            lower = name.lower()
            if ("get_info" in lower or "report_event" in lower or
                    ("ksu" in lower and "ioctl" in lower) or
                    "anon_ksu" in lower or "supercall" in lower):
                section_name = (name_from(shnames, sections[section_index][0])
                                if section_index < shcount else f"special:{section_index}")
                candidates.append({"name": name, "type": kind, "binding": info >> 4,
                                   "size": size, "shndx": section_index,
                                   "section_name": section_name, "address": hex_number(address)})
            target = function_target(name, function_names)
            if not target or kind != 2 or size <= 32 or section_index >= shcount:
                continue
            section = sections[section_index]
            fileoff = section[4] + address - section[3]
            require(0 <= fileoff and fileoff + size <= len(elf), f"{name} outside ELF section")
            code = elf[fileoff:fileoff + size]
            image_offset = image.find(code)
            require(image_offset >= 0, f"{name} linked bytes absent from packaged Image")
            proof = {"symbol": name, "address": hex_number(address), "size": size,
                     "elf_file_offset": hex_number(fileoff), "image_offset": hex_number(image_offset),
                     "sha256": hashlib.sha256(code).hexdigest(), "hex": code.hex()}
            if target not in found or (name == target and found[target]["symbol"] != target):
                found[target] = proof
    missing = set(function_names) - set(found)
    if missing and diagnostic_path is not None:
        diagnostic = {"missing_required_symbols": sorted(missing),
                      "required_rule": "STT_FUNC, exact name or exact $ plus 32 lowercase hex suffix; size > 32; bytes in Image",
                      "symtab_count": len(symbol_tables), "symtabs": symbol_tables,
                      "candidate_count": len(candidates), "candidate_symbols": candidates,
                      "elf_sections": {"count": shcount, **named_sections},
                      "text_base_symbol": hex_number(text_base) if text_base is not None else None}
        diagnostic_path.write_text(json.dumps(diagnostic, indent=2) + "\n")
        print(json.dumps({"missing_required_symbols": sorted(missing),
                          "symtabs": symbol_tables, "candidate_count": len(candidates),
                          "first_candidates": candidates[:120]}, indent=2), flush=True)
    require(not missing, f"missing linked function symbols: {missing}")
    require(text_base is not None, "_text ELF symbol missing")
    metadata = {"text_base": hex_number(text_base), "sections": named_sections,
                "load_segments": loads,
                "copy_to_user_address": hex_number(min(copy_to_user_addresses)) if copy_to_user_addresses else None,
                "copy_to_user_addresses": [hex_number(a) for a in sorted(copy_to_user_addresses)],
                "note": "rodata addresses and ELF file offsets retained for PC-relative constant-pool analysis"}
    return [found[name] for name in function_names], metadata


def disassemble(vmlinux: Path, functions: list[dict], output: Path) -> None:
    parts = []
    for function in functions:
        start = int(function["address"], 16)
        end = start + function["size"]
        result = subprocess.run(["aarch64-linux-gnu-objdump", "-d", f"--start-address={start}",
                                 f"--stop-address={end}", str(vmlinux)],
                                capture_output=True, text=True, check=True)
        require(re.search(r"^\s*[0-9a-f]+:\s+[0-9a-f]", result.stdout, re.M) is not None,
                f"no AArch64 disassembly for {function['symbol']}")
        parts.append(f"# {function['symbol']} {function['address']} size={function['size']}\n"
                     + result.stdout)
    output.write_text("\n".join(parts))
