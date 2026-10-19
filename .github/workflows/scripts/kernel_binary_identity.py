"""Fail-closed static data-flow check of the packaged AArch64 GET_INFO handler.

This is deliberately a small decoder, not a general disassembler or kernel
emulator. It follows constants and stack writes up to the 16-byte copy ABI,
joining both sides of conditional branches to a fixed point. Unrecognized
instructions fail; BRK is a terminal trap and cannot count as a proven copy.
"""
from dataclasses import dataclass
import hashlib
import re
import struct

_MASK64 = (1 << 64) - 1


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


@dataclass(frozen=True)
class _Stack:
    offset: int


def _plus(value, delta):
    if isinstance(value, _Stack):
        return _Stack(value.offset + delta)
    return (value + delta) & _MASK64 if isinstance(value, int) else None


class _State:
    def __init__(self):
        self.regs = [None] * 32
        self.regs[31] = _Stack(0)
        self.origins = [()] * 32
        self.vectors = [None] * 32
        self.vector_origins = [()] * 32
        self.stack = {}

    def clone(self):
        other = _State()
        other.regs = self.regs.copy()
        other.origins = self.origins.copy()
        other.vectors = self.vectors.copy()
        other.vector_origins = self.vector_origins.copy()
        other.stack = self.stack.copy()
        return other

    def read(self, reg, sp=False):
        return self.regs[reg] if reg != 31 or sp else 0

    def write(self, reg, value, origin=(), width=64, sp=False):
        if reg == 31 and not sp:
            return
        if width == 32:
            value = value & 0xffffffff if isinstance(value, int) else None
        self.regs[reg] = value
        self.origins[reg] = tuple(sorted(set(origin))) if value is not None else ()

    def join(self, other):
        """Least precise state covering both inputs; differing constants become unknown."""
        result = self.clone()
        for values, origins in (("regs", "origins"), ("vectors", "vector_origins")):
            left_values, right_values = getattr(self, values), getattr(other, values)
            left_origins, right_origins = getattr(self, origins), getattr(other, origins)
            merged_values, merged_origins = [], []
            for left, right, left_src, right_src in zip(left_values, right_values, left_origins, right_origins):
                value = left if left == right else None
                merged_values.append(value)
                merged_origins.append(tuple(sorted(set(left_src + right_src))) if value is not None else ())
            setattr(result, values, merged_values)
            setattr(result, origins, merged_origins)
        for location in self.stack.keys() | other.stack.keys():
            left, left_src = self.stack.get(location, (None, ()))
            right, right_src = other.stack.get(location, (None, ()))
            result.stack[location] = (left if left == right else None,
                                      tuple(sorted(set(left_src + right_src))))
        return result

    def same(self, other):
        return self.__dict__ == other.__dict__


def verify_get_info_identity(image: bytes, function: dict, metadata: dict,
                             expected_version=40994, expected_uapi=5,
                             expected_features=7,
                             expected_full_version="v4.2.1-ee35e654@builtin") -> dict:
    """Prove the handler's returned constants from Image bytes, or raise ValueError.

    ``function`` and ``metadata`` use the existing ELF inspector's dictionaries.
    The function byte/hash/address binding is independently checked again here.
    ``records`` retain the copy-call instructions and per-byte initialization
    provenance; runtime manager flags may be unknown, but identity fields cannot.
    """
    base, address = _number(metadata["text_base"]), _number(function["address"])
    offset, size = _number(function["image_offset"]), _number(function["size"])
    _require(re.fullmatch(r"do_get_info(?:\$[0-9a-f]{32})?", function["symbol"]),
             "identity function is not the exact GET_INFO handler")
    _require(offset == address - base, "GET_INFO virtual address/Image offset mismatch")
    code = bytes.fromhex(function["hex"])
    _require(len(code) == size and size % 4 == 0 and 0 < size <= 4096,
             "GET_INFO function size/alignment is unsupported")
    _require(0 <= offset <= len(image) - size and image[offset:offset + size] == code,
             "GET_INFO function bytes do not match packaged Image")
    digest = hashlib.sha256(code).hexdigest()
    _require(digest == function["sha256"], "GET_INFO function bytes hash mismatch")
    # Plural ELF symbol candidates are authoritative when present. A stale
    # single-value compatibility field must not broaden that allow-set.
    if "copy_to_user_addresses" in metadata:
        candidates = metadata["copy_to_user_addresses"]
        _require(isinstance(candidates, (list, tuple, set)) and bool(candidates),
                 "GET_INFO copy_to_user address metadata is required and must be a nonempty collection")
        copy_addresses = {_number(candidate) for candidate in candidates}
    else:
        _require("copy_to_user_address" in metadata, "GET_INFO copy_to_user address metadata is required")
        copy_addresses = {_number(metadata["copy_to_user_address"])}
    _require(all(0 <= candidate <= _MASK64 for candidate in copy_addresses), "invalid GET_INFO copy address")
    section = metadata["sections"][".rodata"]
    ro_start, ro_end = _number(section["address"]), _number(section["address"]) + _number(section["size"])
    _require(base <= ro_start < ro_end <= base + len(image), "rodata lies outside packaged Image")
    reads = {}
    records = []

    def load(state, location, width, pc):
        if isinstance(location, _Stack):
            parts = [state.stack.get(location.offset + i, (None, ())) for i in range(width)]
            origins = tuple(sorted(set(origin for _, entries in parts for origin in entries)))
            raw = bytes(value for value, _ in parts) if all(value is not None for value, _ in parts) else None
            return raw, origins
        if isinstance(location, int) and ro_start <= location < ro_end:
            _require(location + width <= ro_end, "GET_INFO constant crosses rodata bounds")
            imageoff = location - base
            raw = image[imageoff:imageoff + width]
            _require(len(raw) == width, "truncated GET_INFO rodata constant")
            key = (imageoff, width)
            reads[key] = {"address": hex(location), "image_offset": hex(imageoff),
                          "bytes_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest(),
                          "load_instruction_image_offset": hex(offset + pc)}
            return raw, (("rodata", imageoff, width),)
        return None, ()

    def store(state, location, value, width, origins, pc):
        _require(isinstance(location, _Stack),
                 f"unsupported non-stack store before GET_INFO copy at {hex(offset + pc)}")
        raw = (value.to_bytes(width, "little") if isinstance(value, int) else value)
        _require(raw is None or isinstance(raw, bytes) and len(raw) == width, "unsupported GET_INFO store width")
        for i in range(width):
            state.stack[location.offset + i] = (raw[i] if raw is not None else None,
                                               tuple(sorted(set(origins + (("instruction", offset + pc, 4),)))))

    def check_record(state, pc, target):
        start = state.read(1).offset
        parts = [state.stack.get(start + i, (None, ())) for i in range(16)]
        fields = []
        for i, name in ((0, "version"), (8, "features"), (12, "uapi_version")):
            _require(all(byte is not None for byte, _ in parts[i:i + 4]),
                     f"GET_INFO {name} is not a proven constant in the copied record")
            fields.append(int.from_bytes(bytes(byte for byte, _ in parts[i:i + 4]), "little"))
        actual_version, actual_features, actual_uapi = fields
        _require(actual_version == expected_version,
                 f"GET_INFO version mismatch: {actual_version} != {expected_version}")
        _require(actual_uapi == expected_uapi,
                 f"GET_INFO uapi_version mismatch: {actual_uapi} != {expected_uapi}")
        _require(actual_features == expected_features,
                 f"GET_INFO features mismatch: {actual_features} != {expected_features}")
        _require(all(origins for _, origins in parts[:4]), "GET_INFO version initialization lacks provenance")
        _require(target in copy_addresses, "GET_INFO copy call target mismatch")
        flags = parts[4:8]
        records.append({
            "copy_call_image_offset": hex(offset + pc), "copy_call_target": hex(target),
            "stack_offset": start, "bytes_hex": "".join(f"{b:02x}" if b is not None else "??" for b, _ in parts),
            "flags": int.from_bytes(bytes(b for b, _ in flags), "little") if all(b is not None for b, _ in flags) else None,
            "byte_origins": [[{"kind": kind, "image_offset": hex(where), "size": length}
                              for kind, where, length in origins] for _, origins in parts],
        })

    pending = [(0, _State(), 0)]
    explored = 0
    states = {}
    traps = set()
    while pending:
        pc, state, steps = pending.pop()
        while True:
            explored += 1
            steps += 1
            _require(explored <= 4096 and steps <= 512, "unsupported GET_INFO loop/path complexity")
            _require(pc % 4 == 0 and 0 <= pc < size, "unsupported GET_INFO branch outside handler before copy")
            prior = states.get(pc)
            if prior is not None:
                state = prior.join(state)
                if state.same(prior):
                    break  # This edge is already covered by the fixed-point input.
            states[pc] = state.clone()
            word = struct.unpack_from("<I", code, pc)[0]
            rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
            origin = (("instruction", offset + pc, 4),)
            next_pc = pc + 4
            # Architectural hints, including pointer-auth and BTI prologue markers.
            if word in (0xd503233f, 0xd50323bf, 0xd503201f, 0xd503245f, 0xd503249f):
                pass
            elif word & 0x9f000000 in (0x90000000, 0x10000000):  # ADRP / ADR
                immediate = _signed(((word >> 5) & 0x7ffff) << 2 | (word >> 29) & 3, 21)
                value = (((address + pc) & ~0xfff) + immediate * 4096 if word & 0x80000000
                         else address + pc + immediate) & _MASK64
                state.write(rd, value, origin)
            elif word & 0x1f000000 == 0x11000000:  # ADD/SUB immediate, including SP aliases
                immediate = ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)
                if word & (1 << 30):
                    immediate = -immediate
                value = _plus(state.read(rn, sp=True), immediate)
                state.write(rd, value, state.origins[rn] + origin,
                            64 if word & (1 << 31) else 32, sp=not bool(word & (1 << 29)))
            elif word & 0x1f800000 == 0x12800000:  # MOVN/MOVZ/MOVK wide immediate
                width = 64 if word & (1 << 31) else 32
                shift, immediate, opcode = ((word >> 21) & 3) * 16, (word >> 5) & 0xffff, (word >> 29) & 3
                _require(shift < width and opcode in (0, 2, 3), "unsupported move-wide encoding")
                if opcode == 2:
                    value = immediate << shift
                    provenance = origin
                elif opcode == 0:
                    value = (~(immediate << shift)) & ((1 << width) - 1)
                    provenance = origin
                else:
                    old = state.read(rd)
                    value = (old & ~(0xffff << shift) | immediate << shift) if isinstance(old, int) else None
                    provenance = state.origins[rd] + origin
                state.write(rd, value, provenance, width)
            elif word & 0x7fe0ffe0 == 0x2a0003e0:  # MOV register (ORR with zero)
                state.write(rd, state.read(rm), state.origins[rm] + origin, 64 if word >> 31 else 32)
            elif word & 0xfff00000 == 0xd5300000:  # MRS system state, not a constant
                state.write(rd, None)
            elif word & 0x3a000000 == 0x28000000 and not word & (1 << 26):  # scalar LDP/STP
                opc, mode = word >> 30, (word >> 23) & 3
                _require(opc in (0, 2) and mode in (1, 2, 3), "unsupported scalar pair encoding")
                width = 8 if opc == 2 else 4
                delta = _signed((word >> 15) & 0x7f, 7) * width
                base_value = state.read(rn, sp=True)
                location = _plus(base_value, delta if mode != 1 else 0)
                other = (word >> 10) & 31
                if word & (1 << 22):
                    # Decode the complete pair before either destination can alias its base.
                    pair, sources = load(state, location, width * 2, pc)
                    for i, reg in enumerate((rd, other)):
                        raw = pair[i * width:(i + 1) * width] if pair is not None else None
                        state.write(reg, int.from_bytes(raw, "little") if raw is not None else None,
                                    sources + origin, width * 8)
                else:
                    for reg, loc in ((rd, location), (other, _plus(location, width))):
                        store(state, loc, state.read(reg), width, state.origins[reg], pc)
                if mode in (1, 3):
                    state.write(rn, _plus(base_value, delta), sp=True)
            elif word & 0xffc00000 in (0x3dc00000, 0x3d800000, 0xfd400000, 0xfd000000):  # LDR/STR Q or D
                width = 8 if word & 0x80000000 else 16
                location = _plus(state.read(rn, sp=True), ((word >> 10) & 0xfff) * width)
                if word & (1 << 22):
                    raw, sources = load(state, location, width, pc)
                    state.vectors[rd], state.vector_origins[rd] = raw, sources + origin
                else:
                    store(state, location, state.vectors[rd], width, state.vector_origins[rd], pc)
            elif word & 0x3ffffc00 == 0x08dffc00:  # LDAR[B/H/W/X], acquire-only scalar load
                width = 1 << (word >> 30)
                raw, sources = load(state, state.read(rn, sp=True), width, pc)
                state.write(rd, int.from_bytes(raw, "little") if raw is not None else None,
                            sources + origin, 64 if width == 8 else 32)
            elif word & 0x3b000000 == 0x39000000 and not word & (1 << 26):  # scalar LDR/STR unsigned
                width, opcode = 1 << (word >> 30), (word >> 22) & 3
                _require(opcode in (0, 1), "unsupported signed scalar load")
                location = _plus(state.read(rn, sp=True), ((word >> 10) & 0xfff) * width)
                if opcode:
                    raw, sources = load(state, location, width, pc)
                    state.write(rd, int.from_bytes(raw, "little") if raw is not None else None,
                                sources + origin, width * 8)
                else:
                    value = state.read(rd)
                    if isinstance(value, int):
                        value &= (1 << (width * 8)) - 1
                    store(state, location, value, width, state.origins[rd], pc)
            elif word & 0x3b200000 == 0x38000000 and not word & (1 << 26):  # unscaled/pre/post scalar
                width, mode, opcode = 1 << (word >> 30), (word >> 10) & 3, (word >> 22) & 3
                _require(mode in (0, 1, 3) and opcode in (0, 1), "unsupported unscaled scalar encoding")
                delta = _signed((word >> 12) & 0x1ff, 9)
                base_value = state.read(rn, sp=True)
                location = _plus(base_value, 0 if mode == 1 else delta)
                if opcode:
                    raw, sources = load(state, location, width, pc)
                    state.write(rd, int.from_bytes(raw, "little") if raw is not None else None, sources + origin)
                elif rn == 18 and rd == 30 and width == 8 and mode == 1 and delta == 8:
                    pass  # clang shadow-call-stack LR save cannot alias the ordinary SP frame.
                else:
                    value = state.read(rd)
                    if isinstance(value, int):
                        value &= (1 << (width * 8)) - 1
                    store(state, location, value, width, state.origins[rd], pc)
                if mode in (1, 3):
                    state.write(rn, _plus(base_value, delta), sp=True)
            elif word & 0x7c000000 == 0x14000000:  # B / BL
                target_pc = pc + _signed(word & 0x3ffffff, 26) * 4
                if word & (1 << 31):
                    target = (address + target_pc) & _MASK64
                    if isinstance(state.read(1), _Stack) and state.read(2) == 16:
                        check_record(state, pc, target)
                        break
                    _require(not any(isinstance(state.read(reg), _Stack) for reg in range(8)),
                             "unsupported external call receives GET_INFO stack frame before proven copy")
                    # A normal manager authorization call returns runtime state and follows AAPCS64.
                    for reg in range(19):
                        state.write(reg, None)
                    # AAPCS64 preserves only the low 64 bits of V8..V15;
                    # V0..V7 and V16..V31 are caller-clobbered. Conservatively
                    # discard every vector constant rather than retain a Q value
                    # across a call from a partially preserved register.
                    state.vectors = [None] * 32
                    state.vector_origins = [()] * 32
                else:
                    next_pc = target_pc
            elif word & 0xff000010 == 0x54000000:  # B.cond
                target_pc = pc + _signed((word >> 5) & 0x7ffff, 19) * 4
                pending.append((target_pc, state.clone(), steps))
            elif word & 0x7e000000 in (0x34000000, 0x36000000):  # CBZ/CBNZ, TBZ/TBNZ
                bits, shift = (19, 5) if word & 0x7e000000 == 0x34000000 else (14, 5)
                target_pc = pc + _signed((word >> shift) & ((1 << bits) - 1), bits) * 4
                pending.append((target_pc, state.clone(), steps))
            elif word & 0xffe0001f == 0xd4200000:  # BRK is a terminal trap, never a successful copy
                traps.add(offset + pc)
                break
            elif (word & 0x1f800000 in (0x13000000, 0x12000000) or
                  word & 0x1f000000 in (0x0b000000, 0x0a000000, 0x1b000000) or
                  word & 0x1fe00000 == 0x1a800000):
                # Known pure register arithmetic/bitfields/select: invalidate its result.
                # This intentionally does not guess runtime UID/authorization calculations.
                state.write(rd, None)
            else:
                raise ValueError(f"unsupported GET_INFO instruction {word:08x} at Image {hex(offset + pc)}")
            pc = next_pc
    _require(records, "GET_INFO has no proven 16-byte record copy")
    full = expected_full_version.encode("ascii") + b"\0"
    full_offset = image.find(full)
    _require(full_offset >= 0, f"pinned full version string absent: {expected_full_version}")
    return {"version": expected_version, "features": expected_features, "uapi_version": expected_uapi,
            "function_symbol": function["symbol"], "function_address": hex(address),
            "function_image_offset": hex(offset), "function_size": size, "function_sha256": digest,
            "rodata_reads": list(reads.values()), "records": records,
            "copy_to_user_addresses": [hex(candidate) for candidate in sorted(copy_addresses)],
            "trap_terminal_image_offsets": [hex(where) for where in sorted(traps)],
            "full_version": {"value": expected_full_version, "image_offset": hex(full_offset), "bytes_hex": full.hex()},
            "method": "AArch64 constant/stack fixed-point data-flow to 16-byte copy ABI; all reachable copy records checked"}
