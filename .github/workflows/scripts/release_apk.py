"""Inspect a signed official manager without running Android code or SDK parsers.

Only apksigner is external. Unknown AXML/ELF/code layouts fail closed: update the
parser after reviewing a new format instead of guessing an API version.
"""
import hashlib
import io
import os
from pathlib import Path
import re
import struct
import subprocess
import zipfile
import zlib

MAX_APK_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
ANDROID_NS = "http://schemas.android.com/apk/res/android"
MANAGER_SYMBOL = "Java_com_sukisu_ultra_Natives_getManagerUAPIVersion"
NONE = 0xffffffff


def _slice(data, offset, size, label):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"Truncated or out-of-bounds {label}")
    return data[offset:offset + size]


def _unpack(fmt, data, offset, label):
    return struct.unpack(fmt, _slice(data, offset, struct.calcsize(fmt), label))


def _string_pool(chunk, header_size):
    if header_size < 28:
        raise ValueError("Unsupported manifest string-pool header")
    count, styles, flags, start, styles_start = _unpack("<IIIII", chunk, 8, "string-pool header")
    table_end = header_size + 4 * (count + styles)
    if count > 100000 or table_end > len(chunk) or start < table_end or start > len(chunk):
        raise ValueError("Invalid manifest string-pool offsets")
    if flags & ~0x101:
        raise ValueError("Unsupported manifest string-pool flags")
    limit = styles_start if styles_start else len(chunk)
    if limit < start or limit > len(chunk):
        raise ValueError("Invalid manifest string-pool data boundary")
    data = chunk[start:limit]

    def length(offset, utf8):
        if utf8:
            first = _slice(data, offset, 1, "UTF-8 string length")[0]
            if first & 0x80:
                return ((first & 0x7f) << 8) | _slice(data, offset + 1, 1, "UTF-8 length")[0], offset + 2
            return first, offset + 1
        first, = _unpack("<H", data, offset, "UTF-16 string length")
        if first & 0x8000:
            second, = _unpack("<H", data, offset + 2, "UTF-16 length")
            return ((first & 0x7fff) << 16) | second, offset + 4
        return first, offset + 2

    result = []
    for i in range(count):
        offset, = _unpack("<I", chunk, header_size + i * 4, "string offset")
        units, pos = length(offset, bool(flags & 0x100))
        if flags & 0x100:
            size, pos = length(pos, True)
            raw = _slice(data, pos, size, "UTF-8 manifest string")
            if _slice(data, pos + size, 1, "string terminator") != b"\0":
                raise ValueError("Unterminated manifest string")
            encoding = "utf-8"
        else:
            size = units * 2
            raw = _slice(data, pos, size, "UTF-16 manifest string")
            if _slice(data, pos + size, 2, "string terminator") != b"\0\0":
                raise ValueError("Unterminated manifest string")
            encoding = "utf-16le"
        try:
            value = raw.decode(encoding)
        except UnicodeError as exc:
            raise ValueError("Invalid manifest string encoding") from exc
        if len(value.encode("utf-16le")) // 2 != units or "\0" in value:
            raise ValueError("Invalid manifest string length")
        result.append(value)
    return result


def parse_binary_manifest(data):
    """Return the package and version attributes from Android binary XML."""
    typ, header, total = _unpack("<HHI", data, 0, "binary manifest header")
    if typ != 3 or header != 8 or total != len(data):
        raise ValueError("Unsupported or malformed binary AndroidManifest.xml")
    strings, attrs, pos, elements, stack = None, None, header, 0, []

    def string(index):
        if strings is None or index >= len(strings):
            raise ValueError("Invalid manifest string index")
        return strings[index]

    while pos < total:
        kind, size_header, size = _unpack("<HHI", data, pos, "manifest chunk")
        if size_header < 8 or size < size_header:
            raise ValueError("Invalid manifest chunk size")
        chunk = _slice(data, pos, size, "manifest chunk")
        if kind == 1:
            if strings is not None or elements:
                raise ValueError("Multiple or misplaced manifest string pools")
            strings = _string_pool(chunk, size_header)
        elif kind == 0x102:
            if size_header != 16:
                raise ValueError("Unsupported manifest element header")
            ns, name, attr_start, attr_size, count, _, _, _ = _unpack("<IIHHHHHH", chunk, 16, "manifest element")
            element = string(name)
            if elements == 0 and (element != "manifest" or ns != NONE):
                raise ValueError("AndroidManifest root must be manifest")
            if elements and not stack:
                raise ValueError("Multiple manifest root elements")
            elements += 1
            if ns != NONE:
                string(ns)
            if attr_start < 20 or attr_size != 20:
                raise ValueError("Unsupported manifest attributes")
            _slice(chunk, 16 + attr_start, count * attr_size, "manifest attributes")
            collected = {}
            for i in range(count):
                namespace, key, raw, val_size, res0, val_type, value = _unpack(
                    "<IIIHBBI", chunk, 16 + attr_start + i * attr_size, "manifest attribute")
                if val_size != 8 or res0 != 0:
                    raise ValueError("Invalid manifest typed value")
                key = (None if namespace == NONE else string(namespace), string(key))
                if key in collected:
                    raise ValueError("Duplicate manifest attribute")
                if raw != NONE:
                    string(raw)
                if val_type == 3:
                    string(value)
                collected[key] = (val_type, value)
            if element == "manifest":
                if attrs is not None:
                    raise ValueError("Duplicate manifest element")
                attrs = collected
            stack.append((ns, name))
        elif kind == 0x103:
            if size_header != 16 or size != 24 or not stack:
                raise ValueError("Invalid manifest end element")
            if _unpack("<II", chunk, 16, "manifest end element") != stack.pop():
                raise ValueError("Unbalanced manifest elements")
        elif kind in (0x100, 0x101):
            if size_header != 16 or size != 24:
                raise ValueError("Invalid manifest namespace metadata")
            prefix, uri = _unpack("<II", chunk, 16, "manifest namespace")
            if prefix != NONE:
                string(prefix)
            string(uri)
        elif kind == 0x180:
            if strings is None or size_header != 8 or (size - 8) % 4 or (size - 8) // 4 > len(strings):
                raise ValueError("Invalid manifest resource map")
        elif kind == 0x104:
            if size_header != 16 or size != 28 or not stack:
                raise ValueError("Unsupported manifest text metadata")
            string(_unpack("<I", chunk, 16, "manifest text")[0])
        else:
            raise ValueError("Unsupported manifest chunk type: " + hex(kind))
        pos += size
    if attrs is None or stack:
        raise ValueError("Missing or unclosed manifest root")

    def text(key):
        value_type, value = attrs.get(key, (None, None))
        if value_type != 3:
            raise ValueError("Missing or unsupported manifest attribute: " + key[1])
        return string(value)

    package = text((None, "package"))
    version_name = text((ANDROID_NS, "versionName"))
    value_type, version_code = attrs.get((ANDROID_NS, "versionCode"), (None, None))
    if value_type not in (0x10, 0x11) or not 0 < version_code <= 0x7fffffff:
        raise ValueError("Missing or unsupported manifest versionCode")
    if (ANDROID_NS, "versionCodeMajor") in attrs and attrs[(ANDROID_NS, "versionCodeMajor")] != (0x10, 0):
        raise ValueError("Unsupported manifest versionCodeMajor")
    if not package or not version_name:
        raise ValueError("Empty manager package or versionName")
    return {"package": package, "version_name": version_name, "version_code": version_code}


def parse_manager_uapi(data):
    """Read a constant-return ARM64 JNI function; never execute the library."""
    if _slice(data, 0, 7, "ELF identity") != b"\x7fELF\x02\x01\x01":
        raise ValueError("Manager JNI must be a little-endian ELF64 library")
    typ, machine, version = _unpack("<HHI", data, 16, "ELF header")
    shoff, = _unpack("<Q", data, 40, "ELF section offset")
    ehsize, = _unpack("<H", data, 52, "ELF header size")
    entry_size, count, names_index = _unpack("<HHH", data, 58, "ELF section header")
    if (typ != 3 or machine != 183 or version != 1 or ehsize != 64 or entry_size != 64 or
            not 1 <= count <= 8192 or not 0 < names_index < count):
        raise ValueError("Unsupported ARM64 ELF section metadata")
    _slice(data, shoff, count * entry_size, "ELF section table")
    sections = [_unpack("<IIQQQQIIQQ", data, shoff + i * entry_size, "ELF section")
                for i in range(count)]

    def section_bytes(section):
        return _slice(data, section[4], section[5], "ELF section data")

    def cstring(table, index):
        if index >= len(table):
            raise ValueError("Invalid ELF string offset")
        end = table.find(b"\0", index, min(len(table), index + 4096))
        if end < 0:
            raise ValueError("Unterminated ELF symbol or section name")
        return table[index:end]

    if sections[names_index][1] != 3:
        raise ValueError("Invalid ELF section-name table")
    names = section_bytes(sections[names_index])
    dynsyms = [s for s in sections if cstring(names, s[0]) == b".dynsym"]
    if len(dynsyms) != 1:
        raise ValueError("Manager JNI requires one .dynsym section")
    symbols = dynsyms[0]
    if (symbols[1] != 11 or symbols[9] != 24 or symbols[5] % 24 or
            symbols[5] // 24 > 100000 or not 0 < symbols[6] < count):
        raise ValueError("Invalid ELF dynamic symbol table")
    strtab = sections[symbols[6]]
    if strtab[1] != 3:
        raise ValueError("Invalid ELF dynamic symbol string table")
    strings, table, matches = section_bytes(strtab), section_bytes(symbols), []
    for offset in range(0, len(table), 24):
        symbol = _unpack("<IBBHQQ", table, offset, "ELF symbol")
        if cstring(strings, symbol[0]) == MANAGER_SYMBOL.encode("ascii"):
            matches.append(symbol)
    if len(matches) != 1:
        raise ValueError("Missing or ambiguous manager UAPI JNI symbol")
    _, info, other, section_index, address, size = matches[0]
    if info & 15 != 2 or info >> 4 not in (1, 2) or other & 3 or not 0 < section_index < count:
        raise ValueError("Unsupported manager UAPI JNI symbol metadata")
    section = sections[section_index]
    if (section[1] != 1 or not section[2] & 4 or size not in (8, 12) or
            address < section[3] or address % 4):
        raise ValueError("Unsupported manager UAPI JNI code section or size")
    code = _slice(section_bytes(section), address - section[3], size, "manager UAPI code")
    words = list(struct.unpack("<" + "I" * (len(code) // 4), code))
    if words[0] == 0xd503245f:  # BTI c, a reviewed ARM64 function-entry hint.
        words.pop(0)
    if len(words) != 2 or words[0] & 0xffe0001f != 0x52800000 or words[1] != 0xd65f03c0:
        raise ValueError("Unsupported manager UAPI instructions; expected MOV w0,#imm and RET")
    uapi = (words[0] >> 5) & 0xffff
    if not uapi:
        raise ValueError("Invalid zero manager UAPI version")
    return uapi


def _verify_signature(path, apksigner):
    command = str(apksigner or os.environ.get("APKSIGNER") or "apksigner")
    try:
        result = subprocess.run([command, "verify", "--verbose", "--print-certs", str(path)],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("apksigner is required and must complete successfully: " + str(exc)) from exc
    if result.returncode:
        raise ValueError(f"APK signature verification failed (apksigner exit {result.returncode})")
    # This builtin backend recognizes APK v2 signing blocks. A v1-only APK can
    # verify successfully in apksigner yet remain untrusted by the kernel.
    if not re.search(r"^Verified using v2 scheme \(APK Signature Scheme v2\): true\s*$",
                     result.stdout, re.M):
        raise ValueError("APK signature verification requires a verified v2 signing block")
    counts = re.findall(r"^Number of signers:\s*(\d+)\s*$", result.stdout, re.M)
    # SDK37 labels its single v2 signer 'V2 Signer'; older/Linux versions use
    # 'Signer #1'. Require exactly one signer and one unambiguous certificate.
    certs = re.findall(r"^(?:Signer #1|V[234](?:\.\d+)? Signer):? certificate SHA-256 digest:\s*([0-9a-fA-F]{64})\s*$",
                       result.stdout, re.M)
    if counts != ["1"] or not certs or len({c.lower() for c in certs}) != 1:
        raise ValueError("apksigner did not report one unambiguous signer certificate")
    if re.search(r"^Signer #(?!1\b)\d+", result.stdout, re.M):
        raise ValueError("Multiple APK signers are unsupported")
    return certs[0].lower()


def inspect_release_apk(path, apksigner=None):
    """Verify APK signature, then return package/version/UAPI/certificate/hash.

    This inspects the artifact; callers must additionally compare the certificate,
    asset digest and interface with their admitted release compatibility profile.
    """
    path = Path(path)
    try:
        if not 0 < path.stat().st_size <= MAX_APK_BYTES:
            raise ValueError("APK file exceeds the supported size limit")
        data = path.read_bytes()
        if not 0 < len(data) <= MAX_APK_BYTES:
            raise ValueError("APK changed size or exceeds the supported size limit")
        certificate = _verify_signature(path, apksigner)
        if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(data).digest():
            raise ValueError("APK changed during signature verification")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            names = [i.filename for i in infos]
            if len(infos) > 10000 or len(names) != len(set(names)):
                raise ValueError("APK has excessive or duplicate ZIP entries")
            if sum(i.file_size for i in infos) > MAX_EXPANDED_BYTES:
                raise ValueError("APK exceeds the expanded size limit")
            def read(name, maximum):
                try:
                    info = archive.getinfo(name)
                except KeyError as exc:
                    raise ValueError("Missing APK member: " + name) from exc
                if (not 0 < info.file_size <= maximum or info.flag_bits & 1 or
                        info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    raise ValueError("Unsupported APK member size or encryption: " + name)
                return archive.read(info)
            manifest = parse_binary_manifest(read("AndroidManifest.xml", 4 * 1024 * 1024))
            if manifest["package"] != "com.sukisu.ultra":
                raise ValueError("Unexpected manager APK package: " + manifest["package"])
            uapi = parse_manager_uapi(read("lib/arm64-v8a/libkernelsu.so", 16 * 1024 * 1024))
        return dict(manifest, uapi=uapi, certificate_sha256=certificate,
                    sha256=hashlib.sha256(data).hexdigest())
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as exc:
        raise ValueError("Cannot inspect release APK: " + str(exc)) from exc
