#!/usr/bin/env python3
"""Assemble Smali source into the pre-release Android DEX 012 format."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import re
import struct
import sys
import zlib
from pathlib import Path
from typing import Generic, Iterable, Sequence, TypeVar

from dex012 import (
    ACCESS_FLAGS,
    CATCH_ALL,
    DEX_HEADER_SIZE,
    DEX_MAGIC,
    FORMATS,
    FORMAT_WIDTHS,
    NO_INDEX,
    OP_NAMES,
    SPECIAL_DOUBLE_BITS,
    SPECIAL_FLOAT_BITS,
    Dex012,
    DexError,
)


class SmaliError(DexError):
    pass


T = TypeVar("T")


class IndexPool(Generic[T]):
    def __init__(self) -> None:
        self.values: list[T] = []
        self.indices: dict[T, int] = {}

    def add(self, value: T) -> int:
        index = self.indices.get(value)
        if index is None:
            index = len(self.values)
            self.values.append(value)
            self.indices[value] = index
        return index

    def __getitem__(self, value: T) -> int:
        try:
            return self.indices[value]
        except KeyError as exc:
            raise SmaliError(f"internal symbol was not collected: {value!r}") from exc

    def __len__(self) -> int:
        return len(self.values)


ACCESS_BY_NAME = {
    kind: {name: bit for bit, name in entries}
    for kind, entries in ACCESS_FLAGS.items()
}

OPCODE_BY_NAME = {
    name.lstrip("+"): opcode
    for opcode, name in enumerate(OP_NAMES)
    if name != "UNUSED"
}

PRIMITIVE_ARRAY_OPCODES = {
    "[Z": 0x23,
    "[B": 0x24,
    "[C": 0x25,
    "[S": 0x26,
    "[I": 0x27,
    "[J": 0x28,
    "[F": 0x29,
    "[D": 0x2A,
}

FIELD_REF_RE = re.compile(
    r"^(?P<owner>\S+)->(?P<name>[^:\s]+):(?P<type>\S+)$"
)
METHOD_REF_RE = re.compile(
    r"^(?P<owner>\S+)->(?P<name>[^\s(]+)(?P<desc>\([^)]*\).+)$"
)
REGISTER_RE = re.compile(r"^(?P<kind>[vp])(?P<number>\d+)$")
LABEL_RE = re.compile(r"^:[A-Za-z0-9_.$-]+$")


@dataclasses.dataclass
class AsmInstruction:
    mnemonic: str
    operands: str
    source: str


@dataclasses.dataclass
class PackedSwitch:
    first_key: int
    targets: list[str]
    source: str


@dataclasses.dataclass
class SparseSwitch:
    entries: list[tuple[int, str]]
    source: str


@dataclasses.dataclass
class EndMarker:
    source: str


AsmOperation = AsmInstruction | PackedSwitch | SparseSwitch | EndMarker


@dataclasses.dataclass
class AsmItem:
    labels: list[str]
    operation: AsmOperation


@dataclasses.dataclass
class SmaliCatch:
    type_descriptor: str | None
    start: str
    end: str
    handler: str


@dataclasses.dataclass
class SmaliField:
    name: str
    descriptor: str
    access_flags: int
    value_text: str | None


@dataclasses.dataclass
class SmaliMethod:
    name: str
    descriptor: str
    access_flags: int
    registers: int | None = None
    items: list[AsmItem] = dataclasses.field(default_factory=list)
    catches: list[SmaliCatch] = dataclasses.field(default_factory=list)
    throws: list[str] = dataclasses.field(default_factory=list)
    source_file: str | None = None

    @property
    def is_static(self) -> bool:
        return bool(self.access_flags & 0x0008)

    @property
    def has_code(self) -> bool:
        return self.registers is not None


@dataclasses.dataclass
class SmaliClass:
    descriptor: str
    access_flags: int
    superclass: str = "Ljava/lang/Object;"
    interfaces: list[str] = dataclasses.field(default_factory=list)
    source_file: str | None = None
    fields: list[SmaliField] = dataclasses.field(default_factory=list)
    methods: list[SmaliMethod] = dataclasses.field(default_factory=list)
    source_path: Path | None = None


@dataclasses.dataclass
class EncodedMethod:
    method: SmaliMethod
    units: list[int]
    label_pcs: dict[str, int]
    catches: list[tuple[int, int, int, str | None]]
    ins_size: int
    outs_size: int
    code_blob_relative: int = 0
    code_relative: int = 0
    catches_relative: int = 0


@dataclasses.dataclass
class EncodedClass:
    cls: SmaliClass
    static_fields_relative: int = 0
    instance_fields_relative: int = 0
    interfaces_relative: int = 0
    direct_methods_relative: int = 0
    virtual_methods_relative: int = 0
    methods: list[EncodedMethod] = dataclasses.field(default_factory=list)


def parse_access(words: Iterable[str], kind: str, source: str) -> int:
    result = 0
    for word in words:
        try:
            result |= ACCESS_BY_NAME[kind][word]
        except KeyError as exc:
            raise SmaliError(f"{source}: unsupported {kind} access flag {word!r}") from exc
    return result


def strip_comment(line: str) -> str:
    quoted = False
    escaped = False
    for i, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "#" and not quoted:
            return line[:i].rstrip()
    return line.rstrip()


def split_operands(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    braces = 0
    quoted = False
    escaped = False
    for i, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted:
            if char == "{":
                braces += 1
            elif char == "}":
                braces -= 1
            elif char == "," and braces == 0:
                parts.append(text[start:i].strip())
                start = i + 1
    if text[start:].strip():
        parts.append(text[start:].strip())
    return parts


def parse_int(text: str) -> int:
    value = text.strip()
    if value.endswith(("L", "l")):
        value = value[:-1]
    try:
        return int(value, 0)
    except ValueError as exc:
        raise SmaliError(f"invalid integral literal {text!r}") from exc


def parse_descriptor_types(descriptor: str) -> list[str]:
    result: list[str] = []
    i = 0
    while i < len(descriptor):
        start = i
        while i < len(descriptor) and descriptor[i] == "[":
            i += 1
        if i >= len(descriptor):
            raise SmaliError(f"truncated type descriptor {descriptor!r}")
        if descriptor[i] == "L":
            end = descriptor.find(";", i)
            if end < 0:
                raise SmaliError(f"unterminated object descriptor {descriptor!r}")
            i = end + 1
        elif descriptor[i] in "VZBSCIJFD":
            i += 1
        else:
            raise SmaliError(f"invalid type descriptor {descriptor!r}")
        result.append(descriptor[start:i])
    return result


def parse_method_descriptor(descriptor: str) -> tuple[list[str], str]:
    if not descriptor.startswith("("):
        raise SmaliError(f"invalid method descriptor {descriptor!r}")
    close = descriptor.find(")")
    if close < 0:
        raise SmaliError(f"invalid method descriptor {descriptor!r}")
    parameters = parse_descriptor_types(descriptor[1:close])
    returns = parse_descriptor_types(descriptor[close + 1:])
    if len(returns) != 1:
        raise SmaliError(f"invalid method return descriptor {descriptor!r}")
    return parameters, returns[0]


def parameter_word_count(descriptor: str, is_static: bool) -> int:
    parameters, _return_type = parse_method_descriptor(descriptor)
    return (0 if is_static else 1) + sum(
        2 if parameter in ("J", "D") else 1 for parameter in parameters
    )


def parse_register(token: str, method: SmaliMethod) -> int:
    match = REGISTER_RE.match(token.strip())
    if not match:
        raise SmaliError(f"invalid register {token!r}")
    number = int(match.group("number"))
    if match.group("kind") == "v":
        register = number
    else:
        if method.registers is None:
            raise SmaliError("parameter register used in a method without code")
        register = method.registers - parameter_word_count(
            method.descriptor, method.is_static
        ) + number
    if method.registers is not None and not 0 <= register < method.registers:
        raise SmaliError(
            f"register {token} resolves to v{register}, outside .registers {method.registers}"
        )
    return register


def parse_field_ref(text: str) -> tuple[str, str, str]:
    match = FIELD_REF_RE.match(text.strip())
    if not match:
        raise SmaliError(f"invalid field reference {text!r}")
    return match.group("owner"), match.group("name"), match.group("type")


def parse_method_ref(text: str) -> tuple[str, str, str]:
    match = METHOD_REF_RE.match(text.strip())
    if not match:
        raise SmaliError(f"invalid method reference {text!r}")
    return match.group("owner"), match.group("name"), match.group("desc")


def parse_register_list(text: str, method: SmaliMethod) -> list[int]:
    value = text.strip()
    if not value.startswith("{") or not value.endswith("}"):
        raise SmaliError(f"invalid register list {text!r}")
    inner = value[1:-1].strip()
    if not inner:
        return []
    if ".." in inner:
        start_text, end_text = (part.strip() for part in inner.split("..", 1))
        start = parse_register(start_text, method)
        end = parse_register(end_text, method)
        if end < start:
            raise SmaliError(f"descending register range {text!r}")
        return list(range(start, end + 1))
    return [parse_register(part.strip(), method) for part in inner.split(",")]


class SmaliParser:
    def parse_path(self, path: str | Path) -> list[SmaliClass]:
        path = Path(path)
        files = [path] if path.is_file() else sorted(path.rglob("*.smali"))
        if not files:
            raise SmaliError(f"{path}: no .smali files found")
        classes = [self.parse_file(file) for file in files]
        descriptors = [cls.descriptor for cls in classes]
        if len(set(descriptors)) != len(descriptors):
            raise SmaliError("duplicate class descriptor in Smali input")
        return classes

    def parse_file(self, path: Path) -> SmaliClass:
        lines = path.read_text(encoding="utf-8").splitlines()
        cls: SmaliClass | None = None
        method: SmaliMethod | None = None
        pending_labels: list[str] = []
        annotation: str | None = None
        throws_values = False
        i = 0
        while i < len(lines):
            line_number = i + 1
            source = f"{path}:{line_number}"
            raw = lines[i]
            text = strip_comment(raw).strip()
            i += 1
            if not text:
                continue

            if annotation is not None:
                if text == ".end annotation":
                    annotation = None
                    throws_values = False
                elif annotation == "throws":
                    if text.startswith("value") and "{" in text:
                        throws_values = True
                    elif throws_values and text == "}":
                        throws_values = False
                    elif throws_values:
                        descriptor = text.rstrip(",").strip()
                        if descriptor:
                            method.throws.append(descriptor)
                continue

            if text.startswith(".class "):
                if cls is not None:
                    raise SmaliError(f"{source}: multiple .class directives")
                words = text.split()
                descriptor = words[-1]
                cls = SmaliClass(
                    descriptor=descriptor,
                    access_flags=parse_access(words[1:-1], "class", source),
                    source_path=path,
                )
                continue
            if cls is None:
                raise SmaliError(f"{source}: directive before .class")

            if method is None:
                if text.startswith(".super "):
                    cls.superclass = text.split(None, 1)[1]
                elif text.startswith(".implements "):
                    cls.interfaces.append(text.split(None, 1)[1])
                elif text.startswith(".source "):
                    cls.source_file = json.loads(text.split(None, 1)[1])
                elif text.startswith(".field "):
                    cls.fields.append(self._parse_field(text, source))
                elif text.startswith(".method "):
                    method = self._parse_method(text, source)
                    method.source_file = cls.source_file
                    cls.methods.append(method)
                elif text.startswith(".annotation "):
                    annotation = "ignored"
                elif text.startswith("."):
                    raise SmaliError(f"{source}: unsupported class directive {text!r}")
                continue

            if text == ".end method":
                if pending_labels:
                    method.items.append(
                        AsmItem(pending_labels, EndMarker(source))
                    )
                    pending_labels = []
                method = None
                continue
            if text.startswith(".registers "):
                method.registers = int(text.split()[1], 0)
                continue
            if text.startswith(".locals "):
                locals_count = int(text.split()[1], 0)
                method.registers = locals_count + parameter_word_count(
                    method.descriptor, method.is_static
                )
                continue
            if text.startswith(".annotation "):
                annotation = (
                    "throws"
                    if "Ldalvik/annotation/Throws;" in text else "ignored"
                )
                continue
            if text.startswith(".catchall "):
                method.catches.append(self._parse_catch(text, source, catch_all=True))
                continue
            if text.startswith(".catch "):
                method.catches.append(self._parse_catch(text, source, catch_all=False))
                continue
            if LABEL_RE.match(text):
                pending_labels.append(text)
                continue
            if text.startswith(".packed-switch "):
                first_key = parse_int(text.split(None, 1)[1])
                targets: list[str] = []
                while i < len(lines):
                    entry_source = f"{path}:{i + 1}"
                    entry = strip_comment(lines[i]).strip()
                    i += 1
                    if not entry:
                        continue
                    if entry == ".end packed-switch":
                        break
                    if not LABEL_RE.match(entry):
                        raise SmaliError(
                            f"{entry_source}: invalid packed-switch target {entry!r}"
                        )
                    targets.append(entry)
                else:
                    raise SmaliError(f"{source}: unterminated packed-switch")
                method.items.append(
                    AsmItem(pending_labels, PackedSwitch(first_key, targets, source))
                )
                pending_labels = []
                continue
            if text == ".sparse-switch":
                entries: list[tuple[int, str]] = []
                while i < len(lines):
                    entry_source = f"{path}:{i + 1}"
                    entry = strip_comment(lines[i]).strip()
                    i += 1
                    if not entry:
                        continue
                    if entry == ".end sparse-switch":
                        break
                    match = re.match(r"^(\S+)\s*->\s*(:\S+)$", entry)
                    if not match:
                        raise SmaliError(
                            f"{entry_source}: invalid sparse-switch entry {entry!r}"
                        )
                    entries.append((parse_int(match.group(1)), match.group(2)))
                else:
                    raise SmaliError(f"{source}: unterminated sparse-switch")
                method.items.append(
                    AsmItem(pending_labels, SparseSwitch(entries, source))
                )
                pending_labels = []
                continue
            if text.startswith("."):
                # Debug directives are accepted but intentionally omitted.
                if text.split()[0] in {
                    ".line", ".local", ".end", ".restart", ".prologue",
                    ".epilogue", ".param",
                }:
                    continue
                raise SmaliError(f"{source}: unsupported method directive {text!r}")

            mnemonic, _, operands = text.partition(" ")
            method.items.append(
                AsmItem(
                    pending_labels,
                    AsmInstruction(mnemonic, operands.strip(), source),
                )
            )
            pending_labels = []

        if cls is None:
            raise SmaliError(f"{path}: missing .class directive")
        if method is not None:
            raise SmaliError(f"{path}: unterminated method {method.name}")
        return cls

    @staticmethod
    def _parse_field(text: str, source: str) -> SmaliField:
        body = text[len(".field "):]
        left, separator, value_text = body.partition("=")
        words = left.strip().split()
        if not words or ":" not in words[-1]:
            raise SmaliError(f"{source}: invalid field declaration {text!r}")
        member = words[-1]
        name, descriptor = member.split(":", 1)
        return SmaliField(
            name=name,
            descriptor=descriptor,
            access_flags=parse_access(words[:-1], "field", source),
            value_text=value_text.strip() if separator else None,
        )

    @staticmethod
    def _parse_method(text: str, source: str) -> SmaliMethod:
        words = text[len(".method "):].split()
        if not words:
            raise SmaliError(f"{source}: empty method declaration")
        signature = words[-1]
        open_paren = signature.find("(")
        if open_paren <= 0:
            raise SmaliError(f"{source}: invalid method signature {signature!r}")
        name = signature[:open_paren]
        descriptor = signature[open_paren:]
        parse_method_descriptor(descriptor)
        return SmaliMethod(
            name=name,
            descriptor=descriptor,
            access_flags=parse_access(words[:-1], "method", source),
        )

    @staticmethod
    def _parse_catch(text: str, source: str, catch_all: bool) -> SmaliCatch:
        if catch_all:
            match = re.match(
                r"^\.catchall\s+\{(:\S+)\s+\.\.\s+(:\S+)\}\s+(:\S+)$", text
            )
            type_descriptor = None
        else:
            match = re.match(
                r"^\.catch\s+(\S+)\s+\{(:\S+)\s+\.\.\s+(:\S+)\}\s+(:\S+)$",
                text,
            )
            type_descriptor = match.group(1) if match else None
        if not match:
            raise SmaliError(f"{source}: invalid catch directive {text!r}")
        base = 1 if catch_all else 2
        return SmaliCatch(
            type_descriptor,
            match.group(base),
            match.group(base + 1),
            match.group(base + 2),
        )


def require_range(value: int, low: int, high: int, what: str) -> int:
    if not low <= value <= high:
        raise SmaliError(f"{what} {value} is outside {low}..{high}")
    return value


def encode_mutf8(value: str) -> bytes:
    units = value.encode("utf-16-le", "surrogatepass")
    result = bytearray()
    for i in range(0, len(units), 2):
        unit = units[i] | (units[i + 1] << 8)
        if 0x0001 <= unit <= 0x007F:
            result.append(unit)
        elif unit <= 0x07FF:
            result.extend((0xC0 | (unit >> 6), 0x80 | (unit & 0x3F)))
        else:
            result.extend(
                (
                    0xE0 | (unit >> 12),
                    0x80 | ((unit >> 6) & 0x3F),
                    0x80 | (unit & 0x3F),
                )
            )
    result.append(0)
    return bytes(result)


def parse_float_bits(text: str, double: bool) -> int:
    value_text = text.strip()
    if value_text.endswith(("f", "F")):
        value_text = value_text[:-1]
    if value_text == "NaN":
        value = math.nan
    elif value_text in ("Infinity", "+Infinity"):
        value = math.inf
    elif value_text == "-Infinity":
        value = -math.inf
    else:
        value = float(value_text)
    if double:
        return struct.unpack("<Q", struct.pack("<d", value))[0]
    return struct.unpack("<I", struct.pack("<f", value))[0]


class WordData:
    def __init__(self) -> None:
        # Offset zero is the format's null pointer, so keep the first word unused.
        self.data = bytearray(4)

    def add(self, payload: bytes, alignment: int = 4) -> int:
        while len(self.data) % alignment:
            self.data.append(0)
        relative = len(self.data)
        self.data.extend(payload)
        return relative

    def reserve(self, size: int, alignment: int = 4) -> int:
        return self.add(bytes(size), alignment)

    def patch(self, relative: int, payload: bytes) -> None:
        self.data[relative:relative + len(payload)] = payload


class Dex012Assembler:
    """Two-pass assembler for the Smali subset emitted by dex012.py."""

    def __init__(self, classes: Sequence[SmaliClass]):
        self.classes = list(classes)
        self.strings: IndexPool[str] = IndexPool()
        self.types: IndexPool[str] = IndexPool()
        self.fields: IndexPool[tuple[str, str, str]] = IndexPool()
        self.methods: IndexPool[tuple[str, str, str]] = IndexPool()
        self.string_objects: set[str] = set()

    def add_string(self, value: str) -> int:
        return self.strings.add(value)

    def add_type(self, descriptor: str) -> int:
        parse_descriptor_types(descriptor)
        self.add_string(descriptor)
        return self.types.add(descriptor)

    def add_field(self, ref: tuple[str, str, str]) -> int:
        owner, name, descriptor = ref
        self.add_type(owner)
        self.add_type(descriptor)
        self.add_string(name)
        return self.fields.add(ref)

    def add_method(self, ref: tuple[str, str, str]) -> int:
        owner, name, descriptor = ref
        self.add_type(owner)
        parameters, return_type = parse_method_descriptor(descriptor)
        for parameter in parameters:
            self.add_type(parameter)
        self.add_type(return_type)
        self.add_string(name)
        self.add_string(descriptor)
        return self.methods.add(ref)

    def collect_symbols(self) -> None:
        for cls in self.classes:
            self.add_type(cls.descriptor)
            if cls.superclass:
                self.add_type(cls.superclass)
            for interface in cls.interfaces:
                self.add_type(interface)
            if cls.source_file is not None:
                self.add_string(cls.source_file)
            for field in cls.fields:
                self.add_field((cls.descriptor, field.name, field.descriptor))
                if (
                    field.descriptor == "Ljava/lang/String;"
                    and field.value_text is not None
                    and field.value_text != "null"
                ):
                    value = json.loads(field.value_text)
                    self.add_string(value)
                    self.string_objects.add(value)
            for method in cls.methods:
                self.add_method((cls.descriptor, method.name, method.descriptor))
                if method.source_file is not None:
                    self.add_string(method.source_file)
                for thrown in method.throws:
                    self.add_type(thrown)
                for catch in method.catches:
                    if catch.type_descriptor is not None:
                        self.add_type(catch.type_descriptor)
                for item in method.items:
                    if isinstance(item.operation, AsmInstruction):
                        self._collect_instruction(item.operation)

    def _collect_instruction(self, instruction: AsmInstruction) -> None:
        opcode = self._select_opcode(instruction)
        operands = split_operands(instruction.operands)
        if opcode == 0x18:
            if len(operands) != 2:
                raise SmaliError(f"{instruction.source}: malformed const-string")
            value = json.loads(operands[1])
            self.add_string(value)
            self.string_objects.add(value)
        elif opcode in (0x19, 0x1E, 0x21):
            self.add_type(operands[-1])
        elif opcode in (0x1F, 0x22):
            self.add_type(operands[-1])
        elif opcode in range(0x52, 0x6E):
            self.add_field(parse_field_ref(operands[-1]))
        elif opcode in (0x2B, 0x2C):
            self.add_type(operands[-1])
        elif opcode in list(range(0x6E, 0x73)) + list(range(0x74, 0x79)):
            self.add_method(parse_method_ref(operands[-1]))

    @staticmethod
    def _select_opcode(instruction: AsmInstruction) -> int:
        name = instruction.mnemonic.lstrip("+")
        if name in ("goto/16", "goto/32"):
            return 0x35
        if name == "goto":
            return 0x34
        if name == "new-array":
            operands = split_operands(instruction.operands)
            if len(operands) == 3 and operands[2] in PRIMITIVE_ARRAY_OPCODES:
                return PRIMITIVE_ARRAY_OPCODES[operands[2]]
        try:
            return OPCODE_BY_NAME[name]
        except KeyError as exc:
            raise SmaliError(
                f"{instruction.source}: unsupported instruction {instruction.mnemonic!r}"
            ) from exc

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
            Dex012(data, "<assembled>").validate()
        return data

    def _layout_method(
        self, method: SmaliMethod
    ) -> tuple[dict[str, int], dict[int, int], dict[int, int], int]:
        widened: set[int] = set()
        while True:
            labels: dict[str, int] = {}
            pcs: dict[int, int] = {}
            pads: dict[int, int] = {}
            pc = 0
            for item_index, item in enumerate(method.items):
                is_payload = isinstance(
                    item.operation, (PackedSwitch, SparseSwitch)
                )
                pad = 1 if is_payload and pc & 1 else 0
                pads[item_index] = pad
                pc += pad
                for label in item.labels:
                    if label in labels:
                        raise SmaliError(f"duplicate label {label} in {method.name}")
                    labels[label] = pc
                pcs[item_index] = pc
                operation = item.operation
                if isinstance(operation, AsmInstruction):
                    opcode = self._select_opcode(operation)
                    if item_index in widened:
                        opcode = 0x35
                    pc += abs(FORMAT_WIDTHS[FORMATS[opcode]])
                elif isinstance(operation, PackedSwitch):
                    pc += 4 + len(operation.targets)
                elif isinstance(operation, SparseSwitch):
                    pc += 2 + len(operation.entries) * 3
            changed = False
            for item_index, item in enumerate(method.items):
                if not isinstance(item.operation, AsmInstruction):
                    continue
                opcode = self._select_opcode(item.operation)
                if opcode != 0x34 or item_index in widened:
                    continue
                operands = split_operands(item.operation.operands)
                if len(operands) != 1 or operands[0] not in labels:
                    raise SmaliError(
                        f"{item.operation.source}: goto requires a known label"
                    )
                delta = labels[operands[0]] - pcs[item_index]
                if not -128 <= delta <= 127:
                    widened.add(item_index)
                    changed = True
            if not changed:
                return labels, pcs, pads, pc

    def _encode_method(self, method: SmaliMethod) -> EncodedMethod:
        if method.registers is None:
            raise SmaliError(f"{method.name}: missing .registers or .locals")
        require_range(method.registers, 0, 0xFFFF, "register count")
        labels, pcs, pads, total_units = self._layout_method(method)
        switch_bases: dict[str, int] = {}
        outs_size = 0
        for index, item in enumerate(method.items):
            operation = item.operation
            if not isinstance(operation, AsmInstruction):
                continue
            opcode = self._select_opcode(operation)
            operands = split_operands(operation.operands)
            if opcode in (0x36, 0x37):
                label = operands[-1]
                if label in switch_bases and switch_bases[label] != pcs[index]:
                    raise SmaliError(f"{operation.source}: shared switch payload")
                switch_bases[label] = pcs[index]
            if opcode in (
                0x2B, 0x2C, *range(0x6E, 0x73), *range(0x74, 0x79),
                0xEE, 0xF0, 0xF8, 0xF9, 0xFA, 0xFB,
            ):
                regs = parse_register_list(operands[0], method)
                outs_size = max(outs_size, len(regs))
        require_range(outs_size, 0, 0xFFFF, "outgoing argument count")

        units: list[int] = []
        for index, item in enumerate(method.items):
            units.extend([0] * pads[index])
            operation = item.operation
            pc = pcs[index]
            if isinstance(operation, AsmInstruction):
                opcode = self._select_opcode(operation)
                if opcode == 0x34:
                    target = split_operands(operation.operands)[0]
                    if not -128 <= labels[target] - pc <= 127:
                        opcode = 0x35
                units.extend(
                    self._encode_instruction(operation, opcode, method, pc, labels)
                )
            elif isinstance(operation, PackedSwitch):
                base = self._switch_base(item, switch_bases)
                require_range(len(operation.targets), 0, 0xFFFF, "switch size")
                first = operation.first_key & 0xFFFFFFFF
                encoded_targets = [
                    require_range(labels[target] - base, -0x8000, 0x7FFF,
                                  "DEX 012 switch target")
                    & 0xFFFF
                    for target in operation.targets
                ]
                units.extend(
                    [0x0100, len(operation.targets), first & 0xFFFF, first >> 16]
                    + encoded_targets
                )
            elif isinstance(operation, SparseSwitch):
                base = self._switch_base(item, switch_bases)
                require_range(len(operation.entries), 0, 0xFFFF, "switch size")
                keys: list[int] = []
                targets: list[int] = []
                for key, target in operation.entries:
                    key &= 0xFFFFFFFF
                    keys.extend((key & 0xFFFF, key >> 16))
                    targets.append(
                        require_range(labels[target] - base, -0x8000, 0x7FFF,
                                      "DEX 012 switch target")
                        & 0xFFFF
                    )
                units.extend([0x0200, len(operation.entries)] + keys + targets)
        if len(units) != total_units:
            raise SmaliError(f"internal layout mismatch in {method.name}")

        catches: list[tuple[int, int, int, str | None]] = []
        for catch in method.catches:
            try:
                start, end, handler = (
                    labels[catch.start], labels[catch.end], labels[catch.handler]
                )
            except KeyError as exc:
                raise SmaliError(
                    f"{method.name}: unknown catch label {exc.args[0]}"
                ) from exc
            require_range(start, 0, total_units, "catch start")
            require_range(end, start, total_units, "catch end")
            require_range(handler, 0, total_units - 1, "catch handler")
            # DEX 012 stores absolute start/end code-unit PCs, not a length.
            catches.append((start, end, handler, catch.type_descriptor))
        return EncodedMethod(
            method, units, labels, catches,
            parameter_word_count(method.descriptor, method.is_static), outs_size
        )

    @staticmethod
    def _switch_base(item: AsmItem, switch_bases: dict[str, int]) -> int:
        matches = [switch_bases[label] for label in item.labels if label in switch_bases]
        if len(set(matches)) != 1:
            raise SmaliError(
                f"{item.operation.source}: switch payload must have one referring switch"
            )
        return matches[0]

    def _encode_instruction(
        self,
        instruction: AsmInstruction,
        opcode: int,
        method: SmaliMethod,
        pc: int,
        labels: dict[str, int],
    ) -> list[int]:
        ops = split_operands(instruction.operands)
        source = instruction.source

        def reg(index: int) -> int:
            try:
                return parse_register(ops[index], method)
            except IndexError as exc:
                raise SmaliError(f"{source}: missing register operand") from exc

        a = b = c = 0
        args: list[int] = []
        if opcode in (0x00, 0x0E):
            pass
        elif opcode in range(0x23, 0x2B):
            a, b = reg(0), reg(1)
        elif opcode in (
            *range(0x01, 0x0A), 0x20, *range(0x7B, 0x90),
            *range(0xB0, 0xD0),
        ):
            a, b = reg(0), reg(1)
        elif opcode in (
            *range(0x0A, 0x0E), *range(0x0F, 0x12), 0x1C, 0x1D, 0x33
        ):
            a = reg(0)
        elif opcode in (0x12, 0x13, 0x14):
            a, b = reg(0), parse_int(ops[1])
        elif opcode in (0x15, 0x16, 0x17):
            a, b = reg(0), parse_int(ops[1])
        elif opcode == 0x18:
            a, b = reg(0), self.strings[json.loads(ops[1])]
        elif opcode == 0x19:
            a, b = reg(0), self.types[ops[1]]
        elif opcode == 0x1A:
            a = reg(0)
            b = SPECIAL_FLOAT_BITS.index(parse_int(ops[1]) & 0xFFFFFFFF)
        elif opcode == 0x1B:
            a = reg(0)
            b = SPECIAL_DOUBLE_BITS.index(
                parse_int(ops[1]) & 0xFFFFFFFFFFFFFFFF
            )
        elif opcode == 0x1E:
            a, b = reg(0), self.types[ops[1]]
        elif opcode == 0x1F:
            a, b, c = reg(0), reg(1), self.types[ops[2]]
        elif opcode == 0x21:
            a, b = reg(0), self.types[ops[1]]
        elif opcode == 0x22:
            a, b, c = reg(0), reg(1), self.types[ops[2]]
        elif opcode in (
            *range(0x2E, 0x33), *range(0x44, 0x52), *range(0x90, 0xB0)
        ):
            a, b, c = reg(0), reg(1), reg(2)
        elif opcode in (0x34, 0x35):
            a = self._branch_delta(ops[0], pc, labels, source)
        elif opcode in (0x36, 0x37):
            a = reg(0)
            b = self._branch_delta(ops[1], pc, labels, source)
        elif opcode in range(0x38, 0x3E):
            a, b = reg(0), reg(1)
            c = self._branch_delta(ops[2], pc, labels, source)
        elif opcode in range(0x3E, 0x44):
            a = reg(0)
            b = self._branch_delta(ops[1], pc, labels, source)
        elif opcode in range(0x52, 0x60):
            a, b = reg(0), reg(1)
            c = self.fields[parse_field_ref(ops[2])]
        elif opcode in range(0x60, 0x6E):
            a = reg(0)
            b = self.fields[parse_field_ref(ops[1])]
        elif opcode in range(0xD0, 0xE3):
            a, b, c = reg(0), reg(1), parse_int(ops[2])
        elif opcode in (
            0x2B, *range(0x6E, 0x73), 0xEE, 0xF0, 0xF8, 0xFA
        ):
            args = parse_register_list(ops[0], method)
            if opcode == 0x2B:
                b = self.types[ops[1]]
            elif opcode in range(0x6E, 0x73):
                b = self.methods[parse_method_ref(ops[1])]
            else:
                b = self._parse_slot_reference(ops[1])
            a = len(args)
        elif opcode in (
            0x2C, *range(0x74, 0x79), 0xF9, 0xFB
        ):
            args = parse_register_list(ops[0], method)
            if opcode == 0x2C:
                b = self.types[ops[1]]
            elif opcode in range(0x74, 0x79):
                b = self.methods[parse_method_ref(ops[1])]
            else:
                b = self._parse_slot_reference(ops[1])
            a = len(args)
            c = args[0] if args else 0
        elif opcode in range(0xF2, 0xF8):
            a, b = reg(0), reg(1)
            c = self._parse_slot_reference(ops[2])
        else:
            raise SmaliError(f"{source}: instruction encoder missing opcode 0x{opcode:02x}")
        try:
            return self._pack_format(opcode, a, b, c, args)
        except SmaliError as exc:
            raise SmaliError(f"{source}: {exc}") from exc

    @staticmethod
    def _branch_delta(label: str, pc: int, labels: dict[str, int], source: str) -> int:
        try:
            return labels[label] - pc
        except KeyError as exc:
            raise SmaliError(f"{source}: unknown branch label {label}") from exc

    @staticmethod
    def _parse_slot_reference(text: str) -> int:
        value = text.strip()
        if "@" not in value:
            raise SmaliError(f"invalid optimized reference {text!r}")
        return parse_int(value.rsplit("@", 1)[1].strip("[]"))

    @staticmethod
    def _pack_format(
        opcode: int, a: int, b: int, c: int, args: Sequence[int]
    ) -> list[int]:
        fmt = FORMATS[opcode]
        if fmt == 1:
            return [opcode]
        if fmt == 2:
            require_range(a, 0, 15, "register A")
            require_range(b, 0, 15, "register B")
            return [opcode | (a << 8) | (b << 12)]
        if fmt == 3:
            require_range(a, 0, 15, "register A")
            require_range(b, -8, 7, "literal")
            return [opcode | (a << 8) | ((b & 15) << 12)]
        if fmt == 4:
            require_range(a, 0, 15, "register A")
            require_range(b, 0, 15, "special literal index")
            return [opcode | (a << 8) | (b << 12)]
        if fmt == 5:
            require_range(a, 0, 255, "register A")
            return [opcode | (a << 8)]
        if fmt == 6:
            require_range(a, -128, 127, "branch offset")
            return [opcode | ((a & 0xFF) << 8)]
        if fmt == 7:
            require_range(a, -0x800000, 0x7FFFFF, "branch offset")
            return [opcode | (((a >> 16) & 0xFF) << 8), a & 0xFFFF]
        if fmt in (8, 11):
            require_range(a, 0, 255, "register A")
            require_range(b, 0, 0xFFFF, "index/register B")
            return [opcode | (a << 8), b]
        if fmt in (9, 10):
            require_range(a, 0, 255, "register A")
            require_range(b, -0x8000, 0x7FFF, "signed operand B")
            return [opcode | (a << 8), b & 0xFFFF]
        if fmt == 12:
            require_range(a, 0, 255, "register A")
            require_range(b, 0, 255, "register B")
            require_range(c, 0, 255, "register C")
            return [opcode | (a << 8), b | (c << 8)]
        if fmt == 13:
            require_range(a, 0, 255, "register A")
            require_range(b, 0, 255, "register B")
            require_range(c, -128, 127, "literal C")
            return [opcode | (a << 8), b | ((c & 0xFF) << 8)]
        if fmt in (14, 15):
            require_range(a, 0, 15, "register A")
            require_range(b, 0, 15, "register B")
            require_range(c, -0x8000, 0x7FFF, "signed operand C")
            return [opcode | (a << 8) | (b << 12), c & 0xFFFF]
        if fmt in (16, 17):
            require_range(a, 0, 15, "register A")
            require_range(b, 0, 15, "register B")
            require_range(c, 0, 0xFFFF, "index/offset C")
            return [opcode | (a << 8) | (b << 12), c]
        if fmt == 18:
            require_range(a, 0, 0xFFFF, "register A")
            require_range(b, 0, 0xFFFF, "register B")
            return [opcode, a, b]
        if fmt == 19:
            require_range(a, 0, 255, "register A")
            require_range(b, -0x80000000, 0xFFFFFFFF, "literal B")
            b &= 0xFFFFFFFF
            return [opcode | (a << 8), b & 0xFFFF, b >> 16]
        if fmt in (20, 21, 26):
            require_range(a, 0, 4, "argument count")
            require_range(b, 0, 0xFFFF, "reference index")
            packed = 0
            for index, register in enumerate(args):
                require_range(register, 0, 15, "argument register")
                packed |= register << (index * 4)
            return [opcode | (a << 8), b, packed]
        if fmt in (23, 24):
            require_range(a, 0, 255, "argument count")
            require_range(b, 0, 0xFFFF, "reference index")
            require_range(c, 0, 0xFFFF, "first argument register")
            if args and args != list(range(c, c + len(args))):
                raise SmaliError("range invoke registers must be contiguous")
            return [opcode | (a << 8), b, c]
        if fmt == 27:
            require_range(a, 0, 255, "register A")
            require_range(b, -0x8000000000000000, 0xFFFFFFFFFFFFFFFF, "literal B")
            b &= 0xFFFFFFFFFFFFFFFF
            return [
                opcode | (a << 8),
                b & 0xFFFF,
                (b >> 16) & 0xFFFF,
                (b >> 32) & 0xFFFF,
                b >> 48,
            ]
        raise SmaliError(f"unsupported DEX 012 instruction format {fmt}")

    def _static_value(self, field: SmaliField) -> int:
        text = field.value_text
        descriptor = field.descriptor
        if descriptor == "Ljava/lang/String;":
            if text is None or text == "null":
                return 0xFFFFFFFFFFFFFFFF
            return self.strings[json.loads(text)]
        if descriptor.startswith(("L", "[")):
            if text not in (None, "null"):
                raise SmaliError(
                    f"non-null static object initializer for {field.name}"
                )
            return 0xFFFFFFFFFFFFFFFF
        if text is None:
            return 0
        if descriptor == "Z":
            if text in ("true", "1"):
                return 1
            if text in ("false", "0"):
                return 0
            raise SmaliError(f"invalid boolean initializer {text!r}")
        if descriptor == "F":
            return parse_float_bits(text, False)
        if descriptor == "D":
            return parse_float_bits(text, True)
        return parse_int(text) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _is_direct(method: SmaliMethod) -> bool:
        return (
            method.name in ("<init>", "<clinit>")
            or bool(method.access_flags & (0x0002 | 0x0008 | 0x10000))
        )

    def _build_file(self, encoded_classes: Sequence[EncodedClass]) -> bytes:
        header_size = DEX_HEADER_SIZE
        string_ids_off = header_size
        type_ids_off = string_ids_off + len(self.strings) * 8
        field_ids_off = type_ids_off + len(self.types) * 4
        method_ids_off = field_ids_off + len(self.fields) * 12
        class_defs_off = method_ids_off + len(self.methods) * 12
        word_data_off = class_defs_off + len(encoded_classes) * 36

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
            static_fields = [field for field in cls.fields if field.access_flags & 8]
            instance_fields = [field for field in cls.fields if not field.access_flags & 8]
            if static_fields:
                payload = bytearray(struct.pack("<II", len(static_fields), 0))
                for field in static_fields:
                    payload.extend(
                        struct.pack(
                            "<IIQ",
                            self.fields[(cls.descriptor, field.name, field.descriptor)],
                            field.access_flags,
                            self._static_value(field),
                        )
                    )
                encoded_class.static_fields_relative = word.add(bytes(payload))
            if instance_fields:
                payload = bytearray(struct.pack("<I", len(instance_fields)))
                for field in instance_fields:
                    payload.extend(
                        struct.pack(
                            "<II",
                            self.fields[(cls.descriptor, field.name, field.descriptor)],
                            field.access_flags,
                        )
                    )
                encoded_class.instance_fields_relative = word.add(bytes(payload))

            for method in cls.methods:
                if method.throws:
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
                    for start, count, handler, descriptor in encoded.catches:
                        catch_type = (
                            CATCH_ALL if descriptor is None else self.types[descriptor]
                        )
                        payload.extend(
                            struct.pack("<IIIi", start, count, handler, catch_type)
                        )
                    encoded.catches_relative = word.add(bytes(payload))
                encoded.code_relative = word.reserve(24)
                code_headers.append(encoded)

            direct = [method for method in cls.methods if self._is_direct(method)]
            virtual = [method for method in cls.methods if not self._is_direct(method)]
            encoded_class.direct_methods_relative = self._add_method_list(
                word, cls, direct, method_by_object, throws_by_object,
                word_data_off
            )
            encoded_class.virtual_methods_relative = self._add_method_list(
                word, cls, virtual, method_by_object, throws_by_object,
                word_data_off
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
                    "<4H4I",
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
                ),
            )

        string_data_off = codes_off + len(codes)
        string_data = bytearray()
        string_offsets: list[tuple[int, int]] = []
        for value in self.strings.values:
            encoded = encode_mutf8(value)
            utf16_length = len(value.encode("utf-16-le", "surrogatepass")) // 2
            string_offsets.append((string_data_off + len(string_data), utf16_length))
            string_data.extend(encoded)

        string_ids = b"".join(
            struct.pack("<II", offset, length)
            for offset, length in string_offsets
        )
        type_ids = b"".join(
            struct.pack("<I", self.strings[value]) for value in self.types.values
        )
        field_ids = b"".join(
            struct.pack(
                "<III", self.types[owner], self.strings[name],
                self.strings[descriptor]
            )
            for owner, name, descriptor in self.fields.values
        )
        method_ids = b"".join(
            struct.pack(
                "<III", self.types[owner], self.strings[name],
                self.strings[descriptor]
            )
            for owner, name, descriptor in self.methods.values
        )
        class_defs = bytearray()
        for encoded_class in encoded_classes:
            cls = encoded_class.cls
            superclass_idx = (
                NO_INDEX
                if not cls.superclass
                or (
                    cls.descriptor == "Ljava/lang/Object;"
                    and cls.superclass == cls.descriptor
                )
                else self.types[cls.superclass]
            )
            class_defs.extend(
                struct.pack(
                    "<9I",
                    self.types[cls.descriptor],
                    cls.access_flags,
                    superclass_idx,
                    self._absolute(encoded_class.interfaces_relative, word_data_off),
                    self._absolute(encoded_class.static_fields_relative, word_data_off),
                    self._absolute(encoded_class.instance_fields_relative, word_data_off),
                    self._absolute(encoded_class.direct_methods_relative, word_data_off),
                    self._absolute(encoded_class.virtual_methods_relative, word_data_off),
                    0,
                )
            )
        body = (
            string_ids + type_ids + field_ids + method_ids + bytes(class_defs)
            + bytes(word.data) + bytes(codes) + bytes(string_data)
        )
        file_size = header_size + len(body)
        header = struct.pack(
            "<8sI20s23I",
            DEX_MAGIC,
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
            type_ids_off if len(self.types) else 0,
            len(self.fields),
            field_ids_off if len(self.fields) else 0,
            len(self.methods),
            method_ids_off if len(self.methods) else 0,
            len(encoded_classes),
            class_defs_off if encoded_classes else 0,
            len(word.data),
            word_data_off if word.data else 0,
            len(codes),
            codes_off if codes else 0,
            len(string_data),
            string_data_off if string_data else 0,
            0,
            0,
        )
        data = bytearray(header + body)
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
        return bytes(data)

    def _add_method_list(
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
            payload.extend(
                struct.pack(
                    "<4I",
                    self.methods[(cls.descriptor, method.name, method.descriptor)],
                    method.access_flags,
                    (
                        word_data_off + throws_by_object[id(method)]
                        if id(method) in throws_by_object else 0
                    ),
                    (
                        word_data_off + encoded.code_relative
                        if encoded is not None else 0
                    ),
                )
            )
        return word.add(bytes(payload))

    @staticmethod
    def _absolute(relative: int, base: int) -> int:
        return base + relative if relative else 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Assemble Smali sources into pre-release DEX version 012."
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


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    output = Path(args.output)
    if output.exists() and not args.force:
        print(f"error: {output} already exists; use --force to replace it",
              file=sys.stderr)
        return 2
    try:
        classes = SmaliParser().parse_path(args.input)
        assembler = Dex012Assembler(classes)
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


if __name__ == "__main__":
    raise SystemExit(main())
