#!/usr/bin/env python3

import hashlib
import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from dex009 import (  # noqa: E402
    DEX_HEADER_SIZE,
    DEX_MAGIC,
    PHYSICAL_TO_LOGICAL_009,
    Dex009,
)
from smali009 import Dex009Assembler  # noqa: E402
from smali012 import SmaliParser  # noqa: E402


CORPUS_ENV = os.environ.get("DEX009_CORPUS")
CORPUS_ROOT = Path(CORPUS_ENV).resolve() if CORPUS_ENV else None
HAS_CORPUS = bool(
    CORPUS_ROOT
    and (CORPUS_ROOT / "app" / "Calculator.apk").is_file()
    and (CORPUS_ROOT / "javalib" / "core.jar").is_file()
)


class Dex009Tests(unittest.TestCase):
    def test_empty_dex(self) -> None:
        fields = [DEX_HEADER_SIZE, DEX_HEADER_SIZE] + [0] * 13
        data = bytearray(struct.pack(
            "<8sI20s15I", DEX_MAGIC, 0, bytes(20), *fields
        ))
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)

        dex = Dex009(bytes(data), "synthetic-empty.dex")
        self.assertEqual(dex.checksum_status(), (True, True))
        self.assertEqual(dex.validate()["classes"], 0)

    def test_interpreter_opcode_map(self) -> None:
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0x2C], 0x2C)
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0x2D], 0x2E)
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0x72], 0x74)
        self.assertIsNone(PHYSICAL_TO_LOGICAL_009[0x77])
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0x7B], 0x7B)
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0xE2], 0xE2)
        self.assertIsNone(PHYSICAL_TO_LOGICAL_009[0xE3])
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0xEE], 0xEE)
        self.assertIsNone(PHYSICAL_TO_LOGICAL_009[0xEF])
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0xF0], 0xF0)
        self.assertIsNone(PHYSICAL_TO_LOGICAL_009[0xF1])
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0xF2], 0xF2)
        self.assertEqual(PHYSICAL_TO_LOGICAL_009[0xFB], 0xFB)

    def test_smali_assembler_synthetic(self) -> None:
        source = """\
.class public Lexample/Assembler009;
.super Ljava/lang/Object;
.source "Assembler009.java"

.field public static message:Ljava/lang/String; = "hello"

.method public constructor <init>()V
    .registers 1
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static optimized()V
    .registers 1
    execute-inline {v0}, inline@0x1
    return-void
.end method

.method public abstract risky()V
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation
.end method
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Assembler009.smali"
            path.write_text(source, encoding="utf-8")
            data = Dex009Assembler(SmaliParser().parse_path(path)).assemble()

        dex = Dex009(data, "synthetic-assembled-009.dex")
        result = dex.validate()
        self.assertEqual(dex.header.magic, DEX_MAGIC)
        self.assertEqual(dex.checksum_status(), (True, True))
        self.assertEqual(result["classes"], 1)
        self.assertEqual(result["methods"], 3)
        self.assertEqual(result["opcode_counts"]["+execute-inline"], 1)

        class_def = dex.class_def(0)
        methods = [
            method
            for off in (
                class_def.direct_methods_off, class_def.virtual_methods_off
            )
            for method in dex.methods(off)
        ]
        risky = next(
            method for method in methods
            if ".risky:" in dex.method_label(method.method_idx)
        )
        self.assertEqual(
            [
                dex.type_descriptor(index)
                for index in dex.type_list(risky.thrown_exceptions_off)
            ],
            ["Ljava/io/IOException;"],
        )
        optimized = next(
            method for method in methods
            if ".optimized:" in dex.method_label(method.method_idx)
        )
        execute = next(
            insn
            for insn in dex.instructions(dex.code(optimized.code_off))
            if insn.name == "+execute-inline"
        )
        self.assertEqual(execute.raw[0] & 0xFF, 0xEE)

    @unittest.skipUnless(HAS_CORPUS, "set DEX009_CORPUS to htc-29386.0.9.0.0")
    def test_calculator_integrity_and_debug_tables(self) -> None:
        dex = Dex009.from_path(CORPUS_ROOT / "app" / "Calculator.apk")
        result = dex.validate()
        self.assertEqual(dex.header.magic, DEX_MAGIC)
        self.assertEqual(dex.header.header_size, DEX_HEADER_SIZE)
        self.assertEqual(dex.checksum_status(), (True, True))
        self.assertEqual(result["classes"], 12)
        self.assertEqual(result["methods"], 73)
        self.assertEqual(result["code_items"], 73)
        self.assertEqual(result["instructions_and_payloads"], 4471)
        self.assertEqual(result["payloads"], 11)
        self.assertEqual(result["positions"], 1025)
        self.assertEqual(result["locals"], 221)

    @unittest.skipUnless(HAS_CORPUS, "set DEX009_CORPUS to htc-29386.0.9.0.0")
    def test_thrown_exception_lists(self) -> None:
        dex = Dex009.from_path(CORPUS_ROOT / "javalib" / "core.jar")
        lists = []
        for class_number in range(dex.header.class_defs_size):
            class_def = dex.class_def(class_number)
            for list_off in (
                class_def.direct_methods_off, class_def.virtual_methods_off
            ):
                lists.extend(
                    dex.type_list(method.thrown_exceptions_off)
                    for method in dex.methods(list_off)
                    if method.thrown_exceptions_off
                )
        self.assertEqual(len(lists), 3289)
        self.assertEqual(sum(map(len, lists)), 3869)

        text = dex.smali_class(1)
        self.assertIn(".class Landroid/app/TouchDexLoader;", text)
        self.assertIn(".annotation system Ldalvik/annotation/Throws;", text)
        self.assertIn("Ljava/lang/ClassNotFoundException;", text)

    @unittest.skipUnless(HAS_CORPUS, "set DEX009_CORPUS to htc-29386.0.9.0.0")
    def test_calculator_smali_export(self) -> None:
        original = Dex009.from_path(CORPUS_ROOT / "app" / "Calculator.apk")
        with tempfile.TemporaryDirectory() as output:
            paths = original.write_smali(output)
            calculator = next(
                path for path in paths
                if path.as_posix().endswith("/calculator/Calculator.smali")
            )
            text = calculator.read_text(encoding="utf-8")
            self.assertIn("# Generated from Android DEX 009 by dex009.py", text)
            self.assertIn(
                ".class Lcom/google/android/calculator/Calculator;", text
            )
            self.assertIn(".packed-switch", text)
            self.assertIn(".sparse-switch", text)

            rebuilt = Dex009(
                Dex009Assembler(SmaliParser().parse_path(output)).assemble(),
                "DEX009-Smali-roundtrip.dex",
            )
        rebuilt_result = rebuilt.validate()
        original_result = original.validate()
        for key in (
            "classes",
            "methods",
            "code_items",
            "instructions_and_payloads",
            "payloads",
            "branch_targets",
        ):
            self.assertEqual(rebuilt_result[key], original_result[key])

    @unittest.skipUnless(HAS_CORPUS, "set DEX009_CORPUS to htc-29386.0.9.0.0")
    def test_complete_build_corpus(self) -> None:
        paths = (
            sorted((CORPUS_ROOT / "app").glob("*.apk"))
            + sorted((CORPUS_ROOT / "javalib").glob("*.jar"))
            + sorted((CORPUS_ROOT / "javalib").glob("*.apk"))
        )
        totals = {
            "classes": 0,
            "methods": 0,
            "code_items": 0,
            "instructions_and_payloads": 0,
            "payloads": 0,
            "positions": 0,
            "locals": 0,
        }
        dex_paths = 0
        for path in paths:
            try:
                dex = Dex009.from_path(path)
            except ValueError as exc:
                if "archive has no classes.dex" in str(exc):
                    continue
                raise
            self.assertEqual(dex.checksum_status(), (True, True), path.name)
            result = dex.validate()
            dex_paths += 1
            for key in totals:
                totals[key] += result[key]

        self.assertEqual(len(paths), 50)
        self.assertEqual(dex_paths, 49)
        self.assertEqual(
            totals,
            {
                "classes": 7636,
                "methods": 54183,
                "code_items": 48461,
                "instructions_and_payloads": 1622847,
                "payloads": 945,
                "positions": 290406,
                "locals": 142225,
            },
        )


if __name__ == "__main__":
    unittest.main()
