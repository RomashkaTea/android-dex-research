#!/usr/bin/env python3
"""Assemble Smali source into the pre-release Android DEX 007 format."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path
from typing import Sequence

from dex007 import (
    DEX_HEADER_SIZE,
    DEX_MAGIC,
    PHYSICAL_TO_LOGICAL,
    Dex007,
)
from dex012 import CATCH_ALL, NO_INDEX, DexError
from smali012 import (
    Dex012Assembler,
    EncodedClass,
    EncodedMethod,
    SmaliClass,
    SmaliError,
    SmaliField,
    SmaliMethod,
    SmaliParser,
    WordData,
    encode_mutf8,
    parse_descriptor_types,
    parse_method_descriptor,
)


LOGICAL_TO_PHYSICAL_007 = {
    logical: physical
    for physical, logical in enumerate(PHYSICAL_TO_LOGICAL)
    if logical is not None
}


def _class_name(descriptor: str) -> str:
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1]
    return descriptor


class EarlyDexAssembler(Dex012Assembler):
    """Shared encoder for the class-ID-based DEX 007/009 formats."""

    dex_magic = DEX_MAGIC
    dex_class = Dex007
    version = "007"
    logical_to_physical = LOGICAL_TO_PHYSICAL_007
    static_field_padding = False
    supports_throws = False

    def __init__(self, classes: Sequence[SmaliClass]):
        super().__init__(classes)
        # Index zero is the superclass null sentinel. Keep it unreferenced so
        # every real superclass can be represented safely.
        self.add_string("")
        self.add_string("__dex__/NoSuperclass")
        self.types.add("L__dex__/NoSuperclass;")

    def add_type(self, descriptor: str) -> int:
        parsed = parse_descriptor_types(descriptor)
        if len(parsed) != 1 or parsed[0] == "V":
            raise SmaliError(f"invalid class descriptor {descriptor!r}")
        self.add_string(_class_name(descriptor))
        return self.types.add(descriptor)

    def add_field(self, ref: tuple[str, str, str]) -> int:
        owner, name, descriptor = ref
        self.add_type(owner)
        parsed = parse_descriptor_types(descriptor)
        if len(parsed) != 1 or parsed[0] == "V":
            raise SmaliError(f"invalid field descriptor {descriptor!r}")
        self.add_string(name)
        self.add_string(descriptor)
        return self.fields.add(ref)

    def add_method(self, ref: tuple[str, str, str]) -> int:
        owner, name, descriptor = ref
        self.add_type(owner)
        parse_method_descriptor(descriptor)
        self.add_string(name)
        self.add_string(descriptor)
        return self.methods.add(ref)

    def assemble(self, validate: bool = True) -> bytes:
        self.collect_symbols()
        encoded_classes: list[EncodedClass] = []
        for cls in self.classes:
            encoded = EncodedClass(cls)
            for method in cls.methods:
                if method.has_code:
                    encoded.methods.append(self._encode_method(method))
            encoded_classes.append(encoded)
        data = self._build_file(encoded_classes)
        if validate:
            self.dex_class(data, "<assembled>").validate()
        return data

    @staticmethod
    def _pack_logical_format(
        opcode: int, a: int, b: int, c: int, args: Sequence[int]
    ) -> list[int]:
        return Dex012Assembler._pack_format(opcode, a, b, c, args)

    def _pack_format(
        self, opcode: int, a: int, b: int, c: int, args: Sequence[int]
    ) -> list[int]:
        try:
            physical = self.logical_to_physical[opcode]
        except KeyError as exc:
            raise SmaliError(
                f"instruction opcode 0x{opcode:02x} is unavailable in DEX {self.version}"
            ) from exc
        units = self._pack_logical_format(opcode, a, b, c, args)
        units[0] = (units[0] & 0xFF00) | physical
        return units

    def _static_field_payload(
        self, cls: SmaliClass, fields: Sequence[SmaliField]
    ) -> bytes:
        payload = bytearray(
            struct.pack("<II", len(fields), 0)
            if self.static_field_padding else struct.pack("<I", len(fields))
        )
        for field in fields:
            payload.extend(
                struct.pack(
                    "<IIQ",
                    self.fields[(cls.descriptor, field.name, field.descriptor)],
                    field.access_flags,
                    self._static_value(field),
                )
            )
        return bytes(payload)

    def _build_file(self, encoded_classes: Sequence[EncodedClass]) -> bytes:
        header_size = DEX_HEADER_SIZE
        string_ids_off = header_size
        class_ids_off = string_ids_off + len(self.strings) * 8
        field_ids_off = class_ids_off + len(self.types) * 4
        method_ids_off = field_ids_off + len(self.fields) * 12
        class_defs_off = method_ids_off + len(self.methods) * 12
        word_data_off = class_defs_off + len(encoded_classes) * 32

        word = WordData()
        method_by_object: dict[int, EncodedMethod] = {
            id(encoded.method): encoded
            for encoded_class in encoded_classes
            for encoded in encoded_class.methods
        }
        throws_by_object: dict[int, int] = {}
        code_headers: list[EncodedMethod] = []

        for encoded_class in encoded_classes:
            cls = encoded_class.cls
            if cls.interfaces:
                payload = struct.pack(
                    f"<I{len(cls.interfaces)}I",
                    len(cls.interfaces),
                    *(self.types[value] for value in cls.interfaces),
                )
                encoded_class.interfaces_relative = word.add(payload)

            static_fields = [
                field for field in cls.fields if field.access_flags & 0x0008
            ]
            instance_fields = [
                field for field in cls.fields if not field.access_flags & 0x0008
            ]
            if static_fields:
                encoded_class.static_fields_relative = word.add(
                    self._static_field_payload(cls, static_fields)
                )
            if instance_fields:
                payload = bytearray(struct.pack("<I", len(instance_fields)))
                for field in instance_fields:
                    payload.extend(
                        struct.pack(
                            "<II",
                            self.fields[
                                (cls.descriptor, field.name, field.descriptor)
                            ],
                            field.access_flags,
                        )
                    )
                encoded_class.instance_fields_relative = word.add(bytes(payload))

            for method in cls.methods:
                if method.throws:
                    if not self.supports_throws:
                        raise SmaliError(
                            f"{method.name}: DEX {self.version} cannot encode "
                            "declared thrown exceptions"
                        )
                    payload = struct.pack(
                        f"<I{len(method.throws)}I",
                        len(method.throws),
                        *(self.types[value] for value in method.throws),
                    )
                    throws_by_object[id(method)] = word.add(payload)

                encoded = method_by_object.get(id(method))
                if encoded is None:
                    continue
                if encoded.catches:
                    payload = bytearray(struct.pack("<I", len(encoded.catches)))
                    for start, end, handler, descriptor in encoded.catches:
                        catch_type = (
                            CATCH_ALL
                            if descriptor is None else self.types[descriptor]
                        )
                        payload.extend(
                            struct.pack("<IIIi", start, end, handler, catch_type)
                        )
                    encoded.catches_relative = word.add(bytes(payload))
                encoded.code_relative = word.reserve(28)
                code_headers.append(encoded)

            direct = [method for method in cls.methods if self._is_direct(method)]
            virtual = [
                method for method in cls.methods if not self._is_direct(method)
            ]
            encoded_class.direct_methods_relative = self._add_early_method_list(
                word, cls, direct, method_by_object, throws_by_object,
                word_data_off,
            )
            encoded_class.virtual_methods_relative = self._add_early_method_list(
                word, cls, virtual, method_by_object, throws_by_object,
                word_data_off,
            )

        codes = bytearray()
        for encoded in code_headers:
            while len(codes) % 4:
                codes.append(0)
            encoded.code_blob_relative = len(codes)
            codes.extend(struct.pack("<I", len(encoded.units)))
            codes.extend(struct.pack(f"<{len(encoded.units)}H", *encoded.units))
            while len(codes) % 4:
                codes.append(0)

        codes_off = word_data_off + len(word.data)
        for encoded in code_headers:
            source = encoded.method.source_file
            source_idx = NO_INDEX if source is None else self.strings[source]
            word.patch(
                encoded.code_relative,
                struct.pack(
                    "<4H5I",
                    encoded.method.registers,
                    encoded.ins_size,
                    encoded.outs_size,
                    0,
                    source_idx,
                    codes_off + encoded.code_blob_relative,
                    (
                        word_data_off + encoded.catches_relative
                        if encoded.catches else 0
                    ),
                    0,
                    0,
                ),
            )

        string_data_off = codes_off + len(codes)
        string_data = bytearray()
        string_offsets: list[tuple[int, int]] = []
        for value in self.strings.values:
            encoded = encode_mutf8(value)
            utf16_length = (
                len(value.encode("utf-16-le", "surrogatepass")) // 2
            )
            string_offsets.append(
                (string_data_off + len(string_data), utf16_length)
            )
            string_data.extend(encoded)

        string_ids = b"".join(
            struct.pack("<II", offset, length)
            for offset, length in string_offsets
        )
        class_ids = b"".join(
            struct.pack("<I", self.strings[_class_name(descriptor)])
            for descriptor in self.types.values
        )
        field_ids = b"".join(
            struct.pack(
                "<III",
                self.types[owner],
                self.strings[name],
                self.strings[descriptor],
            )
            for owner, name, descriptor in self.fields.values
        )
        method_ids = b"".join(
            struct.pack(
                "<III",
                self.types[owner],
                self.strings[name],
                self.strings[descriptor],
            )
            for owner, name, descriptor in self.methods.values
        )

        class_defs = bytearray()
        for encoded_class in encoded_classes:
            cls = encoded_class.cls
            superclass_idx = (
                0
                if not cls.superclass
                or (
                    cls.descriptor == "Ljava/lang/Object;"
                    and cls.superclass == cls.descriptor
                )
                else self.types[cls.superclass]
            )
            class_defs.extend(
                struct.pack(
                    "<8I",
                    self.types[cls.descriptor],
                    cls.access_flags,
                    superclass_idx,
                    self._absolute(
                        encoded_class.interfaces_relative, word_data_off
                    ),
                    self._absolute(
                        encoded_class.static_fields_relative, word_data_off
                    ),
                    self._absolute(
                        encoded_class.instance_fields_relative, word_data_off
                    ),
                    self._absolute(
                        encoded_class.direct_methods_relative, word_data_off
                    ),
                    self._absolute(
                        encoded_class.virtual_methods_relative, word_data_off
                    ),
                )
            )

        body = (
            string_ids
            + class_ids
            + field_ids
            + method_ids
            + bytes(class_defs)
            + bytes(word.data)
            + bytes(codes)
            + bytes(string_data)
        )
        file_size = header_size + len(body)
        header = struct.pack(
            "<8sI20s15I",
            self.dex_magic,
            0,
            bytes(20),
            file_size,
            header_size,
            0,
            0,
            len(self.strings),
            string_ids_off if len(self.strings) else 0,
            len(self.string_objects),
            len(self.types),
            class_ids_off if len(self.types) else 0,
            len(self.fields),
            field_ids_off if len(self.fields) else 0,
            len(self.methods),
            method_ids_off if len(self.methods) else 0,
            len(encoded_classes),
            class_defs_off if encoded_classes else 0,
        )
        data = bytearray(header + body)
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into(
            "<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF
        )
        return bytes(data)

    def _add_early_method_list(
        self,
        word: WordData,
        cls: SmaliClass,
        methods: Sequence[SmaliMethod],
        encoded_by_object: dict[int, EncodedMethod],
        throws_by_object: dict[int, int],
        word_data_off: int,
    ) -> int:
        if not methods:
            return 0
        payload = bytearray(struct.pack("<I", len(methods)))
        for method in methods:
            encoded = encoded_by_object.get(id(method))
            method_idx = self.methods[
                (cls.descriptor, method.name, method.descriptor)
            ]
            code_off = (
                word_data_off + encoded.code_relative
                if encoded is not None else 0
            )
            if self.supports_throws:
                throws_off = (
                    word_data_off + throws_by_object[id(method)]
                    if id(method) in throws_by_object else 0
                )
                payload.extend(
                    struct.pack(
                        "<4I",
                        method_idx,
                        method.access_flags,
                        throws_off,
                        code_off,
                    )
                )
            else:
                payload.extend(
                    struct.pack(
                        "<3I", method_idx, method.access_flags, code_off
                    )
                )
        return word.add(bytes(payload))


class Dex007Assembler(EarlyDexAssembler):
    """Two-pass assembler for the Smali subset emitted by dex007.py."""


def build_arg_parser(version: str = "007") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Assemble Smali sources into pre-release DEX version {version}."
    )
    parser.add_argument("input", help="Smali file or directory")
    parser.add_argument("-o", "--output", required=True, help="output DEX path")
    parser.add_argument(
        "-f", "--force", action="store_true", help="replace an existing output"
    )
    parser.add_argument(
        "--no-validate", action="store_true",
        help="skip parsing and validating the assembled DEX"
    )
    return parser


def assembler_main(
    assembler_class: type[EarlyDexAssembler],
    version: str,
    argv: Sequence[str] | None = None,
) -> int:
    args = build_arg_parser(version).parse_args(argv)
    output = Path(args.output)
    if output.exists() and not args.force:
        print(
            f"error: {output} already exists; use --force to replace it",
            file=sys.stderr,
        )
        return 2
    try:
        classes = SmaliParser().parse_path(args.input)
        assembler = assembler_class(classes)
        data = assembler.assemble(validate=not args.no_validate)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
    except (OSError, SmaliError, DexError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"Wrote {output} ({len(data)} bytes, {len(classes)} classes, "
        f"{len(assembler.methods)} method IDs)"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return assembler_main(Dex007Assembler, "007", argv)


if __name__ == "__main__":
    raise SystemExit(main())
