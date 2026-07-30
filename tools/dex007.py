#!/usr/bin/env python3
"""Parser, validator, disassembler, and Smali exporter for DEX version 007."""

from __future__ import annotations

import argparse
import dataclasses
import json
import struct
import sys
import zipfile
from pathlib import Path
from typing import Iterator, Sequence

from dex012 import (
    CATCH_ALL,
    FORMAT_WIDTHS,
    FORMATS,
    NO_INDEX,
    OP_NAMES,
    Dex012,
    DexError,
    FieldId,
    Instruction,
    MethodId,
    _signed,
)


DEX_MAGIC = b"dex\n007\0"
DEX_HEADER_SIZE = 92


@dataclasses.dataclass(frozen=True)
class Header007:
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
    class_ids_size: int
    class_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int


@dataclasses.dataclass(frozen=True)
class ClassDef007:
    class_idx: int
    access_flags: int
    superclass_idx: int
    interfaces_off: int
    static_fields_off: int
    instance_fields_off: int
    direct_methods_off: int
    virtual_methods_off: int

    @property
    def annotations_off(self) -> int:
        return 0


@dataclasses.dataclass(frozen=True)
class DexMethod007:
    method_idx: int
    access_flags: int
    code_off: int

    @property
    def thrown_exceptions_off(self) -> int:
        return 0


@dataclasses.dataclass(frozen=True)
class Code007:
    registers_size: int
    ins_size: int
    outs_size: int
    padding: int
    source_file_idx: int
    insns_off: int
    exceptions_off: int
    positions_off: int
    locals_off: int

    @property
    def debug_info_off(self) -> int:
        # DEX 007 stores position and local tables separately.
        return 0


# DEX 007's physical opcode numbers were recovered from dvmInterpretStd's
# 256-entry dispatch table. Values here are DEX 012 logical opcodes, whose
# instruction encodings and names are shared by the two early formats.
PHYSICAL_TO_LOGICAL: list[int | None] = [None] * 256


def _map(physical: int, logical: int) -> None:
    PHYSICAL_TO_LOGICAL[physical] = logical


for _opcode in range(0x00, 0x2D):
    _map(_opcode, _opcode)
for _physical in range(0x2D, 0x72):
    _map(_physical, _physical + 1)
for _physical in range(0x72, 0x77):
    _map(_physical, _physical + 2)       # invoke-*/range
for _physical in range(0x7B, 0xE3):
    _map(_physical, _physical)           # unary, binary, and literal ops
for _physical in range(0xF2, 0xFC):
    _map(_physical, _physical)           # quick field and invoke ops


class Dex007(Dex012):
    def __init__(self, data: bytes, source: str = "<memory>"):
        self.data = data
        self.source = source
        if len(data) < DEX_HEADER_SIZE:
            raise DexError(f"{source}: too short to be DEX 007")
        self.header = Header007(*struct.unpack_from("<8sI20s15I", data, 0))
        if self.header.magic != DEX_MAGIC:
            raise DexError(f"{source}: unsupported magic {self.header.magic!r}")
        if self.header.header_size != DEX_HEADER_SIZE:
            raise DexError(
                f"{source}: header_size={self.header.header_size}, "
                f"expected {DEX_HEADER_SIZE}"
            )
        if self.header.file_size > len(data):
            raise DexError(
                f"{source}: stored size {self.header.file_size} "
                f"exceeds input size {len(data)}"
            )
        self._check_fixed_section(
            "string_ids", self.header.string_ids_off,
            self.header.string_ids_size, 8
        )
        self._check_fixed_section(
            "class_ids", self.header.class_ids_off,
            self.header.class_ids_size, 4
        )
        self._check_fixed_section(
            "field_ids", self.header.field_ids_off,
            self.header.field_ids_size, 12
        )
        self._check_fixed_section(
            "method_ids", self.header.method_ids_off,
            self.header.method_ids_size, 12
        )
        self._check_fixed_section(
            "class_defs", self.header.class_defs_off,
            self.header.class_defs_size, 32
        )

    def class_id(self, idx: int) -> int:
        if not 0 <= idx < self.header.class_ids_size:
            raise DexError(f"class index {idx} out of range")
        return self.u32(self.header.class_ids_off + idx * 4)

    @staticmethod
    def _class_descriptor(name: str) -> str:
        if name.startswith("[") or (name.startswith("L") and name.endswith(";")):
            return name
        if len(name) == 1 and name in "VZBSCIJFD":
            return name
        return f"L{name};"

    def type_id(self, idx: int) -> int:
        return self.class_id(idx)

    def type_descriptor(self, idx: int) -> str:
        return self._class_descriptor(self.string(self.class_id(idx)))

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

    def class_def(self, idx: int) -> ClassDef007:
        if not 0 <= idx < self.header.class_defs_size:
            raise DexError(f"class definition index {idx} out of range")
        values = list(struct.unpack_from(
            "<8I", self.data, self.header.class_defs_off + idx * 32
        ))
        # DEX 007 uses zero, not 0xffffffff, as the no-superclass sentinel.
        if values[2] == 0:
            values[2] = NO_INDEX
        return ClassDef007(*values)

    def static_fields(self, off: int) -> Iterator[tuple[int, int, int]]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 4 + size * 16, "static_field_list")
        for i in range(size):
            pos = off + 4 + i * 16
            yield self.u32(pos), self.u32(pos + 4), self.u64(pos + 8)

    def methods(self, off: int) -> Iterator[DexMethod007]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 4 + size * 12, "method_list")
        for i in range(size):
            yield DexMethod007(*struct.unpack_from(
                "<3I", self.data, off + 4 + i * 12
            ))

    def code(self, off: int) -> Code007 | None:
        if off == 0:
            return None
        self._check(off, 28, "code")
        return Code007(*struct.unpack_from("<4H5I", self.data, off))

    def positions(self, off: int) -> Iterator[tuple[int, int]]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 4 + size * 6, "position_list")
        for i in range(size):
            pos = off + 4 + i * 6
            yield self.u32(pos), self.u16(pos + 4)

    def locals(self, off: int) -> Iterator[tuple[int, int, int, int, int]]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 4 + size * 20, "local_list")
        for i in range(size):
            yield struct.unpack_from("<5I", self.data, off + 4 + i * 20)

    def instructions(self, code: Code007) -> Iterator[Instruction]:
        units = self.instruction_units(code)
        pc = 0
        while pc < len(units):
            word = units[pc]
            file_offset = code.insns_off + 4 + pc * 2
            if word == 0x0100:
                if pc + 4 > len(units):
                    raise DexError(
                        f"truncated packed-switch payload at code unit 0x{pc:x}"
                    )
                size = units[pc + 1]
                width = 4 + size
                if pc + width > len(units):
                    raise DexError(
                        f"truncated packed-switch payload at code unit 0x{pc:x}"
                    )
                first_key = _signed(
                    units[pc + 2] | (units[pc + 3] << 16), 32
                )
                targets = [
                    _signed(value, 16) for value in units[pc + 4:pc + width]
                ]
                yield Instruction(
                    pc, file_offset, width, None, "packed-switch-data",
                    f"size={size}, first_key={first_key}, targets={targets}",
                    tuple(units[pc:pc + width])
                )
                pc += width
                continue
            if word == 0x0200:
                if pc + 2 > len(units):
                    raise DexError(
                        f"truncated sparse-switch payload at code unit 0x{pc:x}"
                    )
                size = units[pc + 1]
                width = 2 + size * 3
                if pc + width > len(units):
                    raise DexError(
                        f"truncated sparse-switch payload at code unit 0x{pc:x}"
                    )
                keys = [
                    _signed(
                        units[pc + 2 + i * 2]
                        | (units[pc + 3 + i * 2] << 16), 32
                    )
                    for i in range(size)
                ]
                target_start = pc + 2 + size * 2
                targets = [
                    _signed(value, 16)
                    for value in units[target_start:target_start + size]
                ]
                yield Instruction(
                    pc, file_offset, width, None, "sparse-switch-data",
                    f"size={size}, keys={keys}, targets={targets}",
                    tuple(units[pc:pc + width])
                )
                pc += width
                continue

            physical = word & 0xFF
            logical = PHYSICAL_TO_LOGICAL[physical]
            if logical is None:
                raise DexError(
                    f"unknown/unused DEX 007 opcode 0x{physical:02x} "
                    f"at code unit 0x{pc:x}"
                )
            fmt = FORMATS[logical]
            width = abs(FORMAT_WIDTHS.get(fmt, 0))
            if width == 0:
                raise DexError(
                    f"unsupported DEX 007 opcode 0x{physical:02x} "
                    f"at code unit 0x{pc:x}"
                )
            if pc + width > len(units):
                raise DexError(
                    f"truncated {OP_NAMES[logical]} at code unit 0x{pc:x}"
                )
            raw = tuple(units[pc:pc + width])
            decoded = self._decode_operands(fmt, raw)
            operands = self._format_operands(logical, decoded, pc)
            yield Instruction(
                pc, file_offset, width, logical, OP_NAMES[logical], operands, raw
            )
            pc += width

    def _smali_instruction(self, insn: Instruction) -> str:
        return super()._smali_instruction(insn).replace("DEX012", "DEX007")

    def smali_class(self, class_number: int) -> str:
        return (
            super().smali_class(class_number)
            .replace("DEX 012", "DEX 007")
            .replace("dex012.py", "dex007.py")
        )

    def validate(self) -> dict[str, object]:
        result = super().validate()
        positions = 0
        locals_count = 0
        for class_number in range(self.header.class_defs_size):
            class_def = self.class_def(class_number)
            for list_off in (
                class_def.direct_methods_off, class_def.virtual_methods_off
            ):
                for method in self.methods(list_off):
                    code = self.code(method.code_off)
                    if code is None:
                        continue
                    insns_size = self.u32(code.insns_off)
                    for address, _line in self.positions(code.positions_off):
                        if address >= insns_size:
                            raise DexError(
                                f"position address 0x{address:x} lies outside code"
                            )
                        positions += 1
                    for start, end, name_idx, descriptor_idx, register in self.locals(
                        code.locals_off
                    ):
                        if end < start or end > insns_size:
                            raise DexError("invalid local-variable address range")
                        if register >= code.registers_size:
                            raise DexError("local-variable register is out of range")
                        self.string(name_idx)
                        self.string(descriptor_idx)
                        locals_count += 1
        result["positions"] = positions
        result["locals"] = locals_count
        return result

    def dump_header(self) -> str:
        h = self.header
        rows = [
            ("magic", repr(h.magic)),
            ("checksum", f"0x{h.checksum:08x}"),
            ("signature", h.signature.hex()),
            ("file_size", f"{h.file_size} (0x{h.file_size:x})"),
            ("header_size", str(h.header_size)),
            ("link", f"{h.link_size} @ 0x{h.link_off:x}"),
            ("string_ids", f"{h.string_ids_size} @ 0x{h.string_ids_off:x}"),
            ("string_objects", str(h.string_objects_size)),
            ("class_ids", f"{h.class_ids_size} @ 0x{h.class_ids_off:x}"),
            ("field_ids", f"{h.field_ids_size} @ 0x{h.field_ids_off:x}"),
            ("method_ids", f"{h.method_ids_size} @ 0x{h.method_ids_off:x}"),
            ("class_defs", f"{h.class_defs_size} @ 0x{h.class_defs_off:x}"),
        ]
        width = max(len(name) for name, _value in rows)
        return "\n".join(f"{name:<{width}} : {value}" for name, value in rows)

    def dump_classes(
        self, disassemble: bool = False, class_filter: str | None = None
    ) -> str:
        text = super().dump_classes(disassemble, class_filter)
        if not disassemble:
            return text
        debug_rows: list[str] = ["", "DEX 007 debug tables:"]
        for class_number in range(self.header.class_defs_size):
            class_def = self.class_def(class_number)
            descriptor = self.type_descriptor(class_def.class_idx)
            if class_filter and class_filter not in descriptor:
                continue
            for list_off in (
                class_def.direct_methods_off, class_def.virtual_methods_off
            ):
                for method in self.methods(list_off):
                    code = self.code(method.code_off)
                    if code is None or not (code.positions_off or code.locals_off):
                        continue
                    debug_rows.append(f"  {self.method_label(method.method_idx)}")
                    for address, line in self.positions(code.positions_off):
                        debug_rows.append(f"    position pc=0x{address:x} line={line}")
                    for start, end, name_idx, type_idx, register in self.locals(
                        code.locals_off
                    ):
                        debug_rows.append(
                            f"    local v{register} [0x{start:x},0x{end:x}) "
                            f"{self.string(name_idx)}:{self.string(type_idx)}"
                        )
        return text + "\n" + "\n".join(debug_rows)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse and disassemble Android pre-release DEX 007 files"
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
    parser.add_argument("--smali-out", metavar="DIR",
                        help="write one Smali file per class under DIR")
    parser.add_argument("--force", action="store_true",
                        help="allow --smali-out to replace existing class files")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    try:
        dex = Dex007.from_path(args.input)
        sections: list[str] = []
        if args.header or not (
            args.classes or args.disassemble or args.validate or args.smali_out
        ):
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
        if args.smali_out:
            written = dex.write_smali(
                args.smali_out, class_filter=args.class_filter, force=args.force
            )
            sections.append(
                f"wrote {len(written)} Smali files to {Path(args.smali_out).resolve()}"
            )
        print("\n\n".join(sections))
        return 0
    except (DexError, OSError, zipfile.BadZipFile) as exc:
        print(f"dex007: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
