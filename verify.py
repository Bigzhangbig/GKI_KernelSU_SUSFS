#!/usr/bin/env python3
"""Verify the ARM64 GKI build and export its release artifacts."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zlib


EXPECTED_CONFIG = {
    "ARM64": "y",
    "IKCONFIG": "y",
    "ZSMALLOC": "y",
    "ZRAM": "y",
    "ZRAM_WRITEBACK": "y",
    "ZRAM_DEF_COMP_LZ4KD": "y",
    "ZRAM_DEF_COMP": '"lz4kd"',
    "CRYPTO_LZ4KD": "y",
}
REQUIRED_FUNCTIONS = (
    "zram_init",
    "zram_submit_bio",
    "lz4kd_compress_crypto",
    "lz4kd_decompress_crypto",
)
# ThinLTO can promote a local function using a hash suffix. A CFI jump-table
# symbol alone is not the function body and must not satisfy this check.
PROMOTED_SUFFIX = re.compile(r"(?:\$[0-9a-f]{32}|\.llvm\.[0-9]+)$")
EXCLUDED_ADDONS = re.compile(r"(?:^|_)(?:kernelsu|ksu|susfs)(?:_|$)", re.I)
CONFIG_LINE = re.compile(rb"^CONFIG_([A-Z0-9_]+)=(.+)$", re.M)
LINUX_BANNER = re.compile(rb"Linux version (5\.10\.209(?:[-+][^\s]*)?) ")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify_image_config(image, build_config):
    check(len(image) >= 64 and image[56:60] == b"ARM\x64",
          "missing ARM64 Image boot-header magic at offset 0x38")
    # Match the beginning of the gzip member so a bare marker is not mistaken
    # for the data. Check the end marker immediately after that member.
    marker = b"IKCFG_ST"
    start = image.find(marker + b"\x1f\x8b\x08")
    check(start >= 0, "no IKCONFIG gzip member in the ARM64 Image")
    decoder = zlib.decompressobj(wbits=31)
    config = decoder.decompress(memoryview(image)[start + len(marker):], 4 * 1024 * 1024)
    check(decoder.eof and decoder.unused_data.startswith(b"IKCFG_ED"),
          "invalid IKCONFIG gzip member or end marker")
    check(config == build_config, "Image IKCONFIG differs from out/.config")

    settings = {}
    for match in CONFIG_LINE.finditer(config):
        key, value = (part.decode("ascii") for part in match.groups())
        check(key not in settings, f"duplicate CONFIG_{key} assignment")
        settings[key] = value
    for key, expected in EXPECTED_CONFIG.items():
        check(settings.get(key) == expected, f"expected CONFIG_{key}={expected}")
    for key in settings:
        check(not EXCLUDED_ADDONS.search(key), f"unexpected add-on assignment CONFIG_{key}")
    return config


def read_required_symbols(data, source):
    functions = {}
    for line in data.splitlines():
        address, symbol_type, name = line.split(maxsplit=2)
        name = name.decode("ascii")
        check(not EXCLUDED_ADDONS.search(name), f"unexpected add-on symbol {name} in {source}")
        base_name = PROMOTED_SUFFIX.sub("", name)
        if symbol_type in (b"T", b"t") and base_name in REQUIRED_FUNCTIONS:
            functions.setdefault(base_name, set()).add((int(address, 16), name))
    for name in REQUIRED_FUNCTIONS:
        check(name in functions, f"missing text symbol {name} in {source}")
    return functions


def kernel_tool(workdir, name):
    override = os.environ.get(name.upper())
    if override:
        return override
    # Resolve the two pinned toolchain locations in build.sh.
    for directory in ("toolchain", "clang-git/clang-r416183b"):
        candidate = workdir / directory / "bin" / f"llvm-{name}"
        if candidate.is_file():
            return str(candidate.resolve())
    return f"aarch64-linux-gnu-{name}"


def verify_elf(workdir, elf, image, required_symbols):
    with elf.open("rb") as file:
        header = file.read(20)
    check(header[:7] == b"\x7fELF\x02\x01\x01" and header[16:18] in (b"\x02\x00", b"\x03\x00")
          and header[18:20] == b"\xb7\x00", "vmlinux is not a little-endian ELF64 AArch64 kernel")

    objcopy = kernel_tool(workdir, "objcopy")
    nm = kernel_tool(workdir, "nm")
    with tempfile.TemporaryDirectory() as tempdir:
        rebuilt = Path(tempdir) / "Image"
        # Match the Image export in arch/arm64/boot/Makefile for this kernel.
        subprocess.run(
            [objcopy, "-O", "binary", "-R", ".note", "-R", ".note.gnu.build-id",
             "-R", ".comment", "-S", str(elf), str(rebuilt)],
            check=True,
        )
        check(rebuilt.read_bytes() == image, "Image bytes differ from the vmlinux load image")

    elf_symbols = subprocess.check_output([nm, "-n", "--defined-only", str(elf)])
    check(read_required_symbols(elf_symbols, "vmlinux") == required_symbols,
          "required System.map text symbol addresses differ from vmlinux")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_workdir", type=Path, help="directory containing out/")
    parser.add_argument("artifact_dir", type=Path, help="output directory for verified artifacts")
    args = parser.parse_args()

    out = args.build_workdir / "out"
    image = (out / "arch/arm64/boot/Image").read_bytes()
    config = verify_image_config(image, (out / ".config").read_bytes())
    system_map = (out / "System.map").read_bytes()
    required_symbols = read_required_symbols(system_map, "System.map")
    verify_elf(args.build_workdir, out / "vmlinux", image, required_symbols)
    banner = LINUX_BANNER.search(image)
    check(banner is not None, "Image has no Linux 5.10.209 version banner")

    report = [
        f"Kernel release: {banner[1].decode('ascii')}",
        f"ARM64 boot-header magic: present (offset 0x38, Image size {len(image)} bytes)",
        "ARM64 Image matches the load image reconstructed from the AArch64 vmlinux.",
        "Image IKCONFIG gzip data exactly matches the build .config.",
        *[f"CONFIG_{key}={value}" for key, value in EXPECTED_CONFIG.items()],
        "Required System.map text symbols match vmlinux:",
        *[f"  {address:016x} {name}" for base_name in REQUIRED_FUNCTIONS
          for address, name in sorted(required_symbols[base_name])],
        "No KernelSU, KSU or SUSFS identifiers found in assigned configuration options "
        "or defined ELF symbols.",
        "Scope: static build verification. Device boot and swap behavior are untested.",
        "",
    ]
    artifacts = {
        "Image": image,
        "kernel.config": config,
        "System.map": system_map,
        "verification.txt": "\n".join(report).encode(),
    }
    checksums = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in artifacts.items()
    )
    artifacts["SHA256SUMS"] = checksums.encode()
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    for name, content in artifacts.items():
        (args.artifact_dir / name).write_bytes(content)
    print(f"Verified and exported {len(artifacts)} artifacts to {args.artifact_dir}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, zlib.error) as error:
        sys.exit(f"Verification failed: {error}")
