#!/usr/bin/env python3
"""Parser and disassembler for the pre-release Android DEX version 012 format."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import struct
import sys
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from typing import Iterator, Sequence


DEX_MAGIC = b"dex\n012\0"
DEX_HEADER_SIZE = 124
NO_INDEX = 0xFFFFFFFF
CATCH_ALL = -1


class DexError(ValueError):
    pass


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _ranges(*items: int | range) -> list[int]:
    result: list[int] = []
    for item in items:
        result.extend(item if isinstance(item, range) else [item])
    return result


OP_NAMES = """
nop
move
move/from16
move/16
move-wide
move-wide/from16
move-wide/16
move-object
move-object/from16
move-object/16
move-result
move-result-wide
move-result-object
move-exception
return-void
return
return-wide
return-object
const/4
const/16
const
const-wide/16
const-wide/32
const-wide
const-string
const-class
const/special
const-wide/special
monitor-enter
monitor-exit
check-cast
instance-of
array-length
new-instance
new-array
new-array-boolean
new-array-byte
new-array-char
new-array-short
new-array-int
new-array-long
new-array-float
new-array-double
filled-new-array
filled-new-array/range
UNUSED
cmpl-float
cmpg-float
cmpl-double
cmpg-double
cmp-long
throw
goto
goto/24
packed-switch
sparse-switch
if-eq
if-ne
if-lt
if-ge
if-gt
if-le
if-eqz
if-nez
if-ltz
if-gez
if-gtz
if-lez
aget
aget-wide
aget-object
aget-boolean
aget-byte
aget-char
aget-short
aput
aput-wide
aput-object
aput-boolean
aput-byte
aput-char
aput-short
iget
iget-wide
iget-object
iget-boolean
iget-byte
iget-char
iget-short
iput
iput-wide
iput-object
iput-boolean
iput-byte
iput-char
iput-short
sget
sget-wide
sget-object
sget-boolean
sget-byte
sget-char
sget-short
sput
sput-wide
sput-object
sput-boolean
sput-byte
sput-char
sput-short
invoke-virtual
invoke-super
invoke-direct
invoke-static
invoke-interface
UNUSED
invoke-virtual/range
invoke-super/range
invoke-direct/range
invoke-static/range
invoke-interface/range
UNUSED
UNUSED
neg-int
not-int
neg-long
not-long
neg-float
neg-double
int-to-long
int-to-float
int-to-double
long-to-int
long-to-float
long-to-double
float-to-int
float-to-long
float-to-double
double-to-int
double-to-long
double-to-float
int-to-byte
int-to-char
int-to-short
add-int
sub-int
mul-int
div-int
rem-int
and-int
or-int
xor-int
shl-int
shr-int
ushr-int
add-long
sub-long
mul-long
div-long
rem-long
and-long
or-long
xor-long
shl-long
shr-long
ushr-long
add-float
sub-float
mul-float
div-float
rem-float
add-double
sub-double
mul-double
div-double
rem-double
add-int/2addr
sub-int/2addr
mul-int/2addr
div-int/2addr
rem-int/2addr
and-int/2addr
or-int/2addr
xor-int/2addr
shl-int/2addr
shr-int/2addr
ushr-int/2addr
add-long/2addr
sub-long/2addr
mul-long/2addr
div-long/2addr
rem-long/2addr
and-long/2addr
or-long/2addr
xor-long/2addr
shl-long/2addr
shr-long/2addr
ushr-long/2addr
add-float/2addr
sub-float/2addr
mul-float/2addr
div-float/2addr
rem-float/2addr
add-double/2addr
sub-double/2addr
mul-double/2addr
div-double/2addr
rem-double/2addr
add-int/lit16
rsub-int
mul-int/lit16
div-int/lit16
rem-int/lit16
and-int/lit16
or-int/lit16
xor-int/lit16
add-int/lit8
rsub-int/lit8
mul-int/lit8
div-int/lit8
rem-int/lit8
and-int/lit8
or-int/lit8
xor-int/lit8
shl-int/lit8
shr-int/lit8
ushr-int/lit8
UNUSED
UNUSED
UNUSED
UNUSED
UNUSED
UNUSED
UNUSED
UNUSED
UNUSED
UNUSED
UNUSED
+execute-inline
UNUSED
+invoke-direct-empty
UNUSED
+iget-quick
+iget-wide-quick
+iget-object-quick
+iput-quick
+iput-wide-quick
+iput-object-quick
+invoke-virtual-quick
+invoke-virtual-quick/range
+invoke-super-quick
+invoke-super-quick/range
UNUSED
UNUSED
UNUSED
UNUSED
""".strip().splitlines()

if len(OP_NAMES) != 256:
    raise RuntimeError(f"internal opcode table has {len(OP_NAMES)} entries")


FORMATS = [0] * 256


def _set_format(fmt: int, opcodes: Sequence[int]) -> None:
    for opcode in opcodes:
        FORMATS[opcode] = fmt


_set_format(1, [0x00, 0x0E])
_set_format(2, _ranges(0x01, 0x04, 0x07, 0x20, range(0x23, 0x2B),
                       range(0x7B, 0x90), range(0xB0, 0xD0)))
_set_format(3, [0x12])
_set_format(4, [0x1A, 0x1B])
_set_format(5, _ranges(range(0x0A, 0x0E), range(0x0F, 0x12), 0x1C, 0x1D, 0x33))
_set_format(6, [0x34])
_set_format(7, [0x35])
_set_format(8, [0x02, 0x05, 0x08])
_set_format(9, _ranges(0x36, 0x37, range(0x3E, 0x44)))
_set_format(10, [0x13, 0x15])
_set_format(11, _ranges(0x18, 0x19, 0x1E, 0x21, range(0x60, 0x6E)))
_set_format(12, _ranges(range(0x2E, 0x33), range(0x44, 0x52), range(0x90, 0xB0)))
_set_format(13, list(range(0xD8, 0xE3)))
_set_format(14, list(range(0x38, 0x3E)))
_set_format(15, list(range(0xD0, 0xD8)))
_set_format(16, _ranges(0x1F, 0x22, range(0x52, 0x60)))
_set_format(17, list(range(0xF2, 0xF8)))
_set_format(18, [0x03, 0x06, 0x09])
_set_format(19, [0x14, 0x16])
_set_format(20, _ranges(0x2B, range(0x6E, 0x73), 0xF0))
_set_format(21, [0xF8, 0xFA])
_set_format(23, _ranges(0x2C, range(0x74, 0x79)))
_set_format(24, [0xF9, 0xFB])
_set_format(26, [0xEE])
_set_format(27, [0x17])

FORMAT_WIDTHS = {
    1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1,
    7: 2, 8: 2, 9: 2, 10: 2, 11: 2, 12: 2, 13: 2,
    14: 2, 15: 2, 16: 2, 17: -2,
    18: 3, 19: 3, 20: 3, 21: -3, 23: 3, 24: -3,
    26: -3, 27: 5,
}


@dataclasses.dataclass(frozen=True)
class Header:
    magic: bytes
    checksum: int
    signature: bytes
    file_size: int
    header_size: int
    link_size: int
    link_off: int
    string_ids_size: int
    string_ids_off: int
    string_objects_size: int
    type_ids_size: int
    type_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    word_data_size: int
    word_data_off: int
    codes_size: int
    codes_off: int
    string_data_size: int
    string_data_off: int
    debug_data_size: int
    debug_data_off: int


@dataclasses.dataclass(frozen=True)
class FieldId:
    class_idx: int
    name_idx: int
    type_descriptor_idx: int


@dataclasses.dataclass(frozen=True)
class MethodId:
    class_idx: int
    name_idx: int
    descriptor_idx: int


@dataclasses.dataclass(frozen=True)
class ClassDef:
    class_idx: int
    access_flags: int
    superclass_idx: int
    interfaces_off: int
    static_fields_off: int
    instance_fields_off: int
    direct_methods_off: int
    virtual_methods_off: int
    annotations_off: int


@dataclasses.dataclass(frozen=True)
class DexMethod:
    method_idx: int
    access_flags: int
    thrown_exceptions_off: int
    code_off: int


@dataclasses.dataclass(frozen=True)
class Code:
    registers_size: int
    ins_size: int
    outs_size: int
    padding: int
    source_file_idx: int
    insns_off: int
    exceptions_off: int
    debug_info_off: int


@dataclasses.dataclass(frozen=True)
class Instruction:
    pc: int
    file_offset: int
    width: int
    opcode: int | None
    name: str
    operands: str
    raw: tuple[int, ...]


class Dex012:
    def __init__(self, data: bytes, source: str = "<memory>"):
        self.data = data
        self.source = source
        if len(data) < DEX_HEADER_SIZE:
            raise DexError(f"{source}: too short to be DEX 012")
        values = struct.unpack_from("<8sI20s23I", data, 0)
        self.header = Header(*values)
        if self.header.magic != DEX_MAGIC:
            raise DexError(f"{source}: unsupported magic {self.header.magic!r}")
        if self.header.header_size != DEX_HEADER_SIZE:
            raise DexError(
                f"{source}: header_size={self.header.header_size}, expected {DEX_HEADER_SIZE}"
            )
        if self.header.file_size > len(data):
            raise DexError(
                f"{source}: stored size {self.header.file_size} exceeds input size {len(data)}"
            )
        self._check_fixed_section("string_ids", self.header.string_ids_off,
                                  self.header.string_ids_size, 8)
        self._check_fixed_section("type_ids", self.header.type_ids_off,
                                  self.header.type_ids_size, 4)
        self._check_fixed_section("field_ids", self.header.field_ids_off,
                                  self.header.field_ids_size, 12)
        self._check_fixed_section("method_ids", self.header.method_ids_off,
                                  self.header.method_ids_size, 12)
        self._check_fixed_section("class_defs", self.header.class_defs_off,
                                  self.header.class_defs_size, 36)

    @classmethod
    def from_path(cls, path: str | Path) -> "Dex012":
        path = Path(path)
        raw = path.read_bytes()
        if raw.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(path) as archive:
                try:
                    raw = archive.read("classes.dex")
                except KeyError as exc:
                    raise DexError(f"{path}: archive has no classes.dex") from exc
            source = f"{path}!classes.dex"
        else:
            source = str(path)
        return cls(raw, source)

    def _check(self, off: int, size: int, what: str) -> None:
        end = off + size
        if off < 0 or size < 0 or end < off or end > self.header.file_size:
            raise DexError(
                f"{self.source}: {what} range 0x{off:x}..0x{end:x} is outside file"
            )

    def _check_fixed_section(self, name: str, off: int, count: int, width: int) -> None:
        if count == 0:
            return
        self._check(off, count * width, name)

    def u16(self, off: int) -> int:
        self._check(off, 2, "u16")
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off: int) -> int:
        self._check(off, 4, "u32")
        return struct.unpack_from("<I", self.data, off)[0]

    def s32(self, off: int) -> int:
        self._check(off, 4, "s32")
        return struct.unpack_from("<i", self.data, off)[0]

    def u64(self, off: int) -> int:
        self._check(off, 8, "u64")
        return struct.unpack_from("<Q", self.data, off)[0]

    def string_id(self, idx: int) -> tuple[int, int]:
        if not 0 <= idx < self.header.string_ids_size:
            raise DexError(f"string index {idx} out of range")
        return struct.unpack_from("<II", self.data, self.header.string_ids_off + idx * 8)

    def string(self, idx: int) -> str:
        off, utf16_length = self.string_id(idx)
        self._check(off, 1, "string_data")
        end = self.data.find(b"\0", off, self.header.file_size)
        if end < 0:
            raise DexError(f"unterminated string at 0x{off:x}")
        value = self._decode_mutf8(self.data[off:end])
        if len(value.encode("utf-16-le", "surrogatepass")) // 2 != utf16_length:
            # Preserve usable output for malformed files; validation reports this separately.
            pass
        return value

    @staticmethod
    def _decode_mutf8(raw: bytes) -> str:
        units: list[int] = []
        i = 0
        while i < len(raw):
            b0 = raw[i]
            if b0 < 0x80:
                units.append(b0)
                i += 1
            elif b0 & 0xE0 == 0xC0 and i + 1 < len(raw):
                units.append(((b0 & 0x1F) << 6) | (raw[i + 1] & 0x3F))
                i += 2
            elif b0 & 0xF0 == 0xE0 and i + 2 < len(raw):
                units.append(
                    ((b0 & 0x0F) << 12)
                    | ((raw[i + 1] & 0x3F) << 6)
                    | (raw[i + 2] & 0x3F)
                )
                i += 3
            else:
                units.append(0xFFFD)
                i += 1
        encoded = b"".join(struct.pack("<H", unit) for unit in units)
        return encoded.decode("utf-16-le", "replace")

    def type_id(self, idx: int) -> int:
        if not 0 <= idx < self.header.type_ids_size:
            raise DexError(f"type index {idx} out of range")
        return self.u32(self.header.type_ids_off + idx * 4)

    def type_descriptor(self, idx: int) -> str:
        return self.string(self.type_id(idx))

    def field_id(self, idx: int) -> FieldId:
        if not 0 <= idx < self.header.field_ids_size:
            raise DexError(f"field index {idx} out of range")
        return FieldId(*struct.unpack_from(
            "<III", self.data, self.header.field_ids_off + idx * 12
        ))

    def method_id(self, idx: int) -> MethodId:
        if not 0 <= idx < self.header.method_ids_size:
            raise DexError(f"method index {idx} out of range")
        return MethodId(*struct.unpack_from(
            "<III", self.data, self.header.method_ids_off + idx * 12
        ))

    def class_def(self, idx: int) -> ClassDef:
        if not 0 <= idx < self.header.class_defs_size:
            raise DexError(f"class index {idx} out of range")
        return ClassDef(*struct.unpack_from(
            "<9I", self.data, self.header.class_defs_off + idx * 36
        ))

    def type_list(self, off: int) -> list[int]:
        if off == 0:
            return []
        size = self.u32(off)
        self._check(off + 4, size * 4, "type_list")
        return list(struct.unpack_from(f"<{size}I", self.data, off + 4)) if size else []

    def static_fields(self, off: int) -> Iterator[tuple[int, int, int]]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 8 + size * 16, "static_field_list")
        for i in range(size):
            pos = off + 8 + i * 16
            yield self.u32(pos), self.u32(pos + 4), self.u64(pos + 8)

    def instance_fields(self, off: int) -> Iterator[tuple[int, int]]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 4 + size * 8, "instance_field_list")
        for i in range(size):
            pos = off + 4 + i * 8
            yield self.u32(pos), self.u32(pos + 4)

    def methods(self, off: int) -> Iterator[DexMethod]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 4 + size * 16, "method_list")
        for i in range(size):
            yield DexMethod(*struct.unpack_from("<4I", self.data, off + 4 + i * 16))

    def code(self, off: int) -> Code | None:
        if off == 0:
            return None
        self._check(off, 24, "code")
        return Code(*struct.unpack_from("<4H4I", self.data, off))

    def catches(self, off: int) -> Iterator[tuple[int, int, int, int]]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 4 + size * 16, "catch_list")
        for i in range(size):
            yield struct.unpack_from("<IIIi", self.data, off + 4 + i * 16)

    def field_label(self, idx: int) -> str:
        field = self.field_id(idx)
        return (
            f"{self.type_descriptor(field.class_idx)}."
            f"{self.string(field.name_idx)}:{self.string(field.type_descriptor_idx)}"
        )

    def method_label(self, idx: int) -> str:
        method = self.method_id(idx)
        return (
            f"{self.type_descriptor(method.class_idx)}."
            f"{self.string(method.name_idx)}:{self.string(method.descriptor_idx)}"
        )

    def instruction_units(self, code: Code) -> list[int]:
        size = self.u32(code.insns_off)
        self._check(code.insns_off + 4, size * 2, "instructions")
        return list(struct.unpack_from(f"<{size}H", self.data, code.insns_off + 4))

    def instructions(self, code: Code) -> Iterator[Instruction]:
        units = self.instruction_units(code)
        pc = 0
        while pc < len(units):
            word = units[pc]
            file_offset = code.insns_off + 4 + pc * 2
            if word == 0x0100:
                if pc + 4 > len(units):
                    raise DexError(f"truncated packed-switch payload at code unit 0x{pc:x}")
                size = units[pc + 1]
                # DEX 012 predates the modern 32-bit switch targets.  Its
                # packed payload is:
                #   u2 signature, u2 size, s4 first_key, s2 targets[size]
                width = 4 + size
                if pc + width > len(units):
                    raise DexError(f"truncated packed-switch payload at code unit 0x{pc:x}")
                first_key = _signed(units[pc + 2] | (units[pc + 3] << 16), 32)
                targets = [_signed(value, 16) for value in units[pc + 4:pc + width]]
                operands = (
                    f"size={size}, first_key={first_key}, "
                    f"targets={targets}"
                )
                yield Instruction(pc, file_offset, width, None, "packed-switch-data",
                                  operands, tuple(units[pc:pc + width]))
                pc += width
                continue
            if word == 0x0200:
                if pc + 2 > len(units):
                    raise DexError(f"truncated sparse-switch payload at code unit 0x{pc:x}")
                size = units[pc + 1]
                # Sparse payloads contain size 32-bit keys followed by size
                # signed 16-bit targets.
                width = 2 + size * 3
                if pc + width > len(units):
                    raise DexError(f"truncated sparse-switch payload at code unit 0x{pc:x}")
                keys = [
                    _signed(units[pc + 2 + i * 2] | (units[pc + 3 + i * 2] << 16), 32)
                    for i in range(size)
                ]
                target_start = pc + 2 + size * 2
                targets = [
                    _signed(value, 16)
                    for value in units[target_start:target_start + size]
                ]
                yield Instruction(pc, file_offset, width, None, "sparse-switch-data",
                                  f"size={size}, keys={keys}, targets={targets}",
                                  tuple(units[pc:pc + width]))
                pc += width
                continue

            opcode = word & 0xFF
            fmt = FORMATS[opcode]
            signed_width = FORMAT_WIDTHS.get(fmt, 0)
            width = abs(signed_width)
            if width == 0:
                raise DexError(
                    f"unknown/unused opcode 0x{opcode:02x} at code unit 0x{pc:x}"
                )
            if pc + width > len(units):
                raise DexError(
                    f"truncated {OP_NAMES[opcode]} at code unit 0x{pc:x}"
                )
            raw = tuple(units[pc:pc + width])
            decoded = self._decode_operands(fmt, raw)
            operands = self._format_operands(opcode, decoded, pc)
            yield Instruction(pc, file_offset, width, opcode, OP_NAMES[opcode],
                              operands, raw)
            pc += width

    @staticmethod
    def _decode_operands(fmt: int, raw: tuple[int, ...]) -> dict[str, object]:
        word = raw[0]
        if fmt == 1:
            return {}
        if fmt == 2:
            return {"A": (word >> 8) & 0xF, "B": (word >> 12) & 0xF}
        if fmt == 3:
            return {"A": (word >> 8) & 0xF, "B": _signed(word >> 12, 4)}
        if fmt == 4:
            return {"A": (word >> 8) & 0xF, "B": (word >> 12) & 0xF}
        if fmt == 5:
            return {"A": word >> 8}
        if fmt == 6:
            return {"A": _signed(word >> 8, 8)}
        if fmt == 7:
            return {"A": _signed(((word >> 8) << 16) | raw[1], 24)}
        if fmt in (8, 11):
            return {"A": word >> 8, "B": raw[1]}
        if fmt in (9, 10):
            return {"A": word >> 8, "B": _signed(raw[1], 16)}
        if fmt == 12:
            return {"A": word >> 8, "B": raw[1] & 0xFF, "C": raw[1] >> 8}
        if fmt == 13:
            return {
                "A": word >> 8,
                "B": raw[1] & 0xFF,
                "C": _signed(raw[1] >> 8, 8),
            }
        if fmt in (14, 15):
            return {
                "A": (word >> 8) & 0xF,
                "B": (word >> 12) & 0xF,
                "C": _signed(raw[1], 16),
            }
        if fmt in (16, 17):
            return {
                "A": (word >> 8) & 0xF,
                "B": (word >> 12) & 0xF,
                "C": raw[1],
            }
        if fmt == 18:
            return {"A": raw[1], "B": raw[2]}
        if fmt == 19:
            return {"A": word >> 8, "B": _signed(raw[1] | (raw[2] << 16), 32)}
        if fmt in (20, 21, 26):
            count = word >> 8
            if count > 4:
                raise DexError(f"invalid argument count {count} in invoke format")
            packed = raw[2]
            args = [(packed >> (4 * i)) & 0xF for i in range(count)]
            return {"A": count, "B": raw[1], "args": args}
        if fmt in (23, 24):
            return {"A": word >> 8, "B": raw[1], "C": raw[2]}
        if fmt == 27:
            value = raw[1] | (raw[2] << 16) | (raw[3] << 32) | (raw[4] << 48)
            return {"A": word >> 8, "B": value}
        raise DexError(f"unsupported internal instruction format {fmt}")

    def _format_operands(self, opcode: int, d: dict[str, object], pc: int) -> str:
        a = int(d.get("A", 0))
        b = int(d.get("B", 0))
        c = int(d.get("C", 0))
        if opcode in (0x00, 0x0E):
            return ""
        if opcode in _ranges(range(0x01, 0x0A), 0x20, range(0x23, 0x2B),
                             range(0x7B, 0x90), range(0xB0, 0xD0)):
            return f"v{a}, v{b}"
        if opcode in _ranges(range(0x0A, 0x0E), range(0x0F, 0x12), 0x1C, 0x1D, 0x33):
            return f"v{a}"
        if opcode in (0x12, 0x13, 0x14):
            return f"v{a}, #int {b} // 0x{b & 0xffffffff:x}"
        if opcode in (0x15, 0x16):
            return f"v{a}, #long {b}"
        if opcode == 0x17:
            return f"v{a}, #long 0x{b:016x}"
        if opcode == 0x18:
            return f"v{a}, {json.dumps(self.string(b))} // string@{b:04x}"
        if opcode == 0x19:
            return f"v{a}, {self.type_descriptor(b)} // type@{b:04x}"
        if opcode in (0x1A, 0x1B):
            return f"v{a}, #special {b}"
        if opcode == 0x1E:
            return f"v{a}, {self.type_descriptor(b)} // type@{b:04x}"
        if opcode == 0x1F:
            return f"v{a}, v{b}, {self.type_descriptor(c)} // type@{c:04x}"
        if opcode == 0x21:
            return f"v{a}, {self.type_descriptor(b)} // type@{b:04x}"
        if opcode == 0x22:
            return f"v{a}, v{b}, {self.type_descriptor(c)} // type@{c:04x}"
        if opcode in range(0x2E, 0x33) or opcode in range(0x44, 0x52) or opcode in range(0x90, 0xB0):
            return f"v{a}, v{b}, v{c}"
        if opcode in (0x34, 0x35):
            return f"{pc + a:04x} // {a:+d}"
        if opcode in (0x36, 0x37):
            return f"v{a}, {pc + b:04x} // {b:+d}"
        if opcode in range(0x38, 0x3E):
            return f"v{a}, v{b}, {pc + c:04x} // {c:+d}"
        if opcode in range(0x3E, 0x44):
            return f"v{a}, {pc + b:04x} // {b:+d}"
        if opcode in range(0x52, 0x60):
            return f"v{a}, v{b}, {self.field_label(c)} // field@{c:04x}"
        if opcode in range(0x60, 0x6E):
            return f"v{a}, {self.field_label(b)} // field@{b:04x}"
        if opcode in range(0xD0, 0xE3):
            return f"v{a}, v{b}, #{c}"
        if opcode in _ranges(0x2B, range(0x6E, 0x73), 0xF0, 0xEE, 0xF8, 0xFA):
            args = ", ".join(f"v{x}" for x in d.get("args", []))
            if opcode == 0xEE:
                ref = f"inline@{b:04x}"
            elif opcode in (0xF8, 0xFA):
                ref = f"vtable@{b:04x}"
            else:
                ref = self.type_descriptor(b) if opcode == 0x2B else self.method_label(b)
            return f"{{{args}}}, {ref}"
        if opcode in _ranges(0x2C, range(0x74, 0x79), 0xF9, 0xFB):
            end = c + a - 1
            regs = "{}" if a == 0 else f"{{v{c} .. v{end}}}"
            if opcode == 0x2C:
                ref = self.type_descriptor(b)
            elif opcode in (0xF9, 0xFB):
                ref = f"vtable@{b:04x}"
            else:
                ref = self.method_label(b)
            return f"{regs}, {ref}"
        if opcode in range(0xF2, 0xF8):
            return f"v{a}, v{b}, [obj+0x{c:04x}]"
        return ", ".join(f"{key}={value}" for key, value in d.items())

    def validate(self) -> dict[str, object]:
        opcode_counts: Counter[str] = Counter()
        instruction_count = 0
        payload_count = 0
        code_count = 0
        method_count = 0
        branch_target_count = 0
        string_mismatches = 0

        for idx in range(self.header.string_ids_size):
            off, expected = self.string_id(idx)
            value = self.string(idx)
            actual = len(value.encode("utf-16-le", "surrogatepass")) // 2
            if actual != expected:
                string_mismatches += 1
            self._check(off, 1, "string_data")

        for class_idx in range(self.header.class_defs_size):
            class_def = self.class_def(class_idx)
            self.type_descriptor(class_def.class_idx)
            if class_def.superclass_idx != NO_INDEX:
                self.type_descriptor(class_def.superclass_idx)
            for type_idx in self.type_list(class_def.interfaces_off):
                self.type_descriptor(type_idx)
            for field_idx, _access_flags, _value in self.static_fields(
                class_def.static_fields_off
            ):
                self.field_label(field_idx)
            for field_idx, _access_flags in self.instance_fields(
                class_def.instance_fields_off
            ):
                self.field_label(field_idx)
            for list_off in (class_def.direct_methods_off, class_def.virtual_methods_off):
                for method in self.methods(list_off):
                    method_count += 1
                    self.method_label(method.method_idx)
                    for type_idx in self.type_list(method.thrown_exceptions_off):
                        self.type_descriptor(type_idx)
                    code = self.code(method.code_off)
                    if code is None:
                        continue
                    code_count += 1
                    if code.source_file_idx != 0xFFFFFFFF:
                        self.string(code.source_file_idx)
                    for start, end, handler, type_idx in self.catches(code.exceptions_off):
                        if end < start:
                            raise DexError("catch range ends before it starts")
                        if type_idx != CATCH_ALL:
                            self.type_descriptor(type_idx)
                        if handler >= self.u32(code.insns_off):
                            raise DexError("catch handler lies outside instruction stream")
                    instructions = list(self.instructions(code))
                    instructions_by_pc = {insn.pc: insn for insn in instructions}
                    for insn in instructions:
                        instruction_count += 1
                        if insn.opcode is None:
                            payload_count += 1
                        else:
                            opcode_counts[insn.name] += 1
                            decoded = self._decode_operands(
                                FORMATS[insn.opcode], insn.raw
                            )
                            targets: list[int] = []
                            if insn.opcode in (0x34, 0x35):
                                targets.append(insn.pc + int(decoded["A"]))
                            elif insn.opcode in range(0x38, 0x3E):
                                targets.append(insn.pc + int(decoded["C"]))
                            elif insn.opcode in range(0x3E, 0x44):
                                targets.append(insn.pc + int(decoded["B"]))
                            elif insn.opcode in (0x36, 0x37):
                                payload_pc = insn.pc + int(decoded["B"])
                                payload = instructions_by_pc.get(payload_pc)
                                expected_name = (
                                    "packed-switch-data"
                                    if insn.opcode == 0x36 else "sparse-switch-data"
                                )
                                if payload is None or payload.name != expected_name:
                                    raise DexError(
                                        f"{insn.name} at code unit 0x{insn.pc:x} "
                                        f"does not point to {expected_name}"
                                    )
                                targets.append(payload_pc)
                                size = payload.raw[1]
                                target_start = (
                                    4 if insn.opcode == 0x36 else 2 + size * 2
                                )
                                targets.extend(
                                    insn.pc + _signed(value, 16)
                                    for value in payload.raw[
                                        target_start:target_start + size
                                    ]
                                )
                            branch_target_count += len(targets)
                            for target in targets:
                                if target not in instructions_by_pc:
                                    raise DexError(
                                        f"branch from code unit 0x{insn.pc:x} "
                                        f"targets non-instruction boundary 0x{target:x}"
                                    )

        return {
            "source": self.source,
            "classes": self.header.class_defs_size,
            "methods": method_count,
            "code_items": code_count,
            "instructions_and_payloads": instruction_count,
            "payloads": payload_count,
            "branch_targets": branch_target_count,
            "string_length_mismatches": string_mismatches,
            "opcode_counts": dict(sorted(opcode_counts.items())),
        }

    def dump_header(self) -> str:
        h = self.header
        rows = [
            ("magic", repr(h.magic)),
            ("checksum", f"0x{h.checksum:08x}"),
            ("signature", h.signature.hex()),
            ("file_size", f"{h.file_size} (0x{h.file_size:x})"),
            ("header_size", f"{h.header_size}"),
            ("link", f"{h.link_size} @ 0x{h.link_off:x}"),
            ("string_ids", f"{h.string_ids_size} @ 0x{h.string_ids_off:x}"),
            ("string_objects", str(h.string_objects_size)),
            ("type_ids", f"{h.type_ids_size} @ 0x{h.type_ids_off:x}"),
            ("field_ids", f"{h.field_ids_size} @ 0x{h.field_ids_off:x}"),
            ("method_ids", f"{h.method_ids_size} @ 0x{h.method_ids_off:x}"),
            ("class_defs", f"{h.class_defs_size} @ 0x{h.class_defs_off:x}"),
            ("word_data", f"{h.word_data_size} @ 0x{h.word_data_off:x}"),
            ("codes", f"{h.codes_size} @ 0x{h.codes_off:x}"),
            ("string_data", f"{h.string_data_size} @ 0x{h.string_data_off:x}"),
            ("debug_data", f"{h.debug_data_size} @ 0x{h.debug_data_off:x}"),
        ]
        width = max(len(name) for name, _ in rows)
        return "\n".join(f"{name:<{width}} : {value}" for name, value in rows)

    def dump_classes(self, disassemble: bool = False, class_filter: str | None = None) -> str:
        output: list[str] = []
        for class_number in range(self.header.class_defs_size):
            class_def = self.class_def(class_number)
            descriptor = self.type_descriptor(class_def.class_idx)
            if class_filter and class_filter not in descriptor:
                continue
            superclass = (
                self.type_descriptor(class_def.superclass_idx)
                if class_def.superclass_idx != NO_INDEX else "(none)"
            )
            output.extend([
                f"Class #{class_number}: {descriptor}",
                f"  access       : 0x{class_def.access_flags:08x}",
                f"  superclass   : {superclass}",
                f"  interfaces   : {', '.join(self.type_descriptor(i) for i in self.type_list(class_def.interfaces_off)) or '(none)'}",
            ])
            for title, fields in (
                ("static fields", self.static_fields(class_def.static_fields_off)),
                ("instance fields", self.instance_fields(class_def.instance_fields_off)),
            ):
                output.append(f"  {title}:")
                any_fields = False
                for field in fields:
                    any_fields = True
                    idx, access = field[0], field[1]
                    suffix = f" value=0x{field[2]:016x}" if len(field) == 3 else ""
                    output.append(
                        f"    {self.field_label(idx)} access=0x{access:08x}{suffix}"
                    )
                if not any_fields:
                    output.append("    (none)")
            for title, off in (
                ("direct methods", class_def.direct_methods_off),
                ("virtual methods", class_def.virtual_methods_off),
            ):
                output.append(f"  {title}:")
                any_methods = False
                for method in self.methods(off):
                    any_methods = True
                    output.append(
                        f"    {self.method_label(method.method_idx)} "
                        f"access=0x{method.access_flags:08x}"
                    )
                    code = self.code(method.code_off)
                    if code is None:
                        continue
                    output.append(
                        f"      registers={code.registers_size} ins={code.ins_size} "
                        f"outs={code.outs_size} source_idx={code.source_file_idx}"
                    )
                    if disassemble:
                        for insn in self.instructions(code):
                            raw = " ".join(f"{word:04x}" for word in insn.raw)
                            text = f"{insn.name} {insn.operands}".rstrip()
                            output.append(
                                f"      {insn.file_offset:06x}: {raw:<24} "
                                f"|{insn.pc:04x}: {text}"
                            )
                if not any_methods:
                    output.append("    (none)")
            output.append("")
        return "\n".join(output)

    def checksum_status(self) -> tuple[bool, bool]:
        actual_checksum = zlib.adler32(self.data[12:self.header.file_size]) & 0xFFFFFFFF
        actual_signature = hashlib.sha1(self.data[32:self.header.file_size]).digest()
        return actual_checksum == self.header.checksum, actual_signature == self.header.signature


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse and disassemble Android pre-release DEX 012 files"
    )
    parser.add_argument("input", help="raw .dex file or APK/JAR containing classes.dex")
    parser.add_argument("-H", "--header", action="store_true", help="display the DEX header")
    parser.add_argument("-d", "--disassemble", action="store_true",
                        help="display class contents and disassemble method code")
    parser.add_argument("-c", "--classes", action="store_true",
                        help="display class, field, and method metadata")
    parser.add_argument("--class-filter", help="only display classes containing this text")
    parser.add_argument("--validate", action="store_true",
                        help="walk all structures and instruction streams")
    parser.add_argument("--json", action="store_true", help="emit validation data as JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    try:
        dex = Dex012.from_path(args.input)
        sections: list[str] = []
        if args.header or not (args.classes or args.disassemble or args.validate):
            sections.append(dex.dump_header())
            checksum_ok, signature_ok = dex.checksum_status()
            sections.append(
                f"checksum_valid : {str(checksum_ok).lower()}\n"
                f"signature_valid: {str(signature_ok).lower()}"
            )
        if args.classes or args.disassemble:
            sections.append(dex.dump_classes(args.disassemble, args.class_filter))
        if args.validate:
            result = dex.validate()
            sections.append(json.dumps(result, indent=2 if args.json else None))
        print("\n\n".join(sections))
        return 0
    except (DexError, OSError, zipfile.BadZipFile) as exc:
        print(f"dex012: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
