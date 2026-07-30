#!/usr/bin/env python3
"""Parser, validator, disassembler, and Smali exporter for DEX version 009."""

from __future__ import annotations

import argparse
import json
import struct
import sys
import zipfile
from pathlib import Path
from typing import Iterator, Sequence

from dex007 import (
    DEX_HEADER_SIZE,
    PHYSICAL_TO_LOGICAL,
    Dex007,
    Header007,
)
from dex012 import DexError, DexMethod, Instruction


DEX_MAGIC = b"dex\n009\0"

# DEX 009 retains the DEX 007 physical opcode map and adds the optimized
# execute-inline and invoke-direct-empty instructions later seen in DEX 012.
PHYSICAL_TO_LOGICAL_009 = PHYSICAL_TO_LOGICAL.copy()
PHYSICAL_TO_LOGICAL_009[0xEE] = 0xEE
PHYSICAL_TO_LOGICAL_009[0xF0] = 0xF0


class Dex009(Dex007):
    opcode_map = PHYSICAL_TO_LOGICAL_009
    format_name = "DEX 009"

    def __init__(self, data: bytes, source: str = "<memory>"):
        self.data = data
        self.source = source
        if len(data) < DEX_HEADER_SIZE:
            raise DexError(f"{source}: too short to be DEX 009")
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

    def static_fields(self, off: int) -> Iterator[tuple[int, int, int]]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 8 + size * 16, "static_field_list")
        for i in range(size):
            pos = off + 8 + i * 16
            yield self.u32(pos), self.u32(pos + 4), self.u64(pos + 8)

    def methods(self, off: int) -> Iterator[DexMethod]:
        if off == 0:
            return
        size = self.u32(off)
        self._check(off, 4 + size * 16, "method_list")
        for i in range(size):
            yield DexMethod(*struct.unpack_from(
                "<4I", self.data, off + 4 + i * 16
            ))

    def _smali_instruction(self, insn: Instruction) -> str:
        return super()._smali_instruction(insn).replace("DEX007", "DEX009")

    def smali_class(self, class_number: int) -> str:
        return (
            super().smali_class(class_number)
            .replace("DEX 007", "DEX 009")
            .replace("dex007.py", "dex009.py")
        )

    def dump_classes(
        self, disassemble: bool = False, class_filter: str | None = None
    ) -> str:
        return (
            super().dump_classes(disassemble, class_filter)
            .replace("DEX 007", "DEX 009")
        )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse and disassemble Android pre-release DEX 009 files"
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
        dex = Dex009.from_path(args.input)
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
        print(f"dex009: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
