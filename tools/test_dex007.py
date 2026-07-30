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

from dex007 import (  # noqa: E402
    DEX_HEADER_SIZE,
    DEX_MAGIC,
    PHYSICAL_TO_LOGICAL,
    Dex007,
)
from dex012 import Dex012  # noqa: E402
from smali012 import Dex012Assembler, SmaliParser  # noqa: E402


CORPUS_ENV = os.environ.get("DEX007_CORPUS")
CORPUS_ROOT = Path(CORPUS_ENV).resolve() if CORPUS_ENV else None
HAS_CORPUS = bool(
    CORPUS_ROOT
    and (CORPUS_ROOT / "app" / "Calculator.apk").is_file()
    and (CORPUS_ROOT / "javalib" / "core.jar").is_file()
)


class Dex007Tests(unittest.TestCase):
    def test_empty_dex(self) -> None:
        fields = [DEX_HEADER_SIZE, DEX_HEADER_SIZE] + [0] * 13
        data = bytearray(struct.pack(
            "<8sI20s15I", DEX_MAGIC, 0, bytes(20), *fields
        ))
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)

        dex = Dex007(bytes(data), "synthetic-empty.dex")
        self.assertEqual(dex.checksum_status(), (True, True))
        self.assertEqual(dex.validate()["classes"], 0)

    def test_modified_utf8_and_class_names(self) -> None:
        self.assertEqual(Dex007._decode_mutf8(b"A\xc0\x80\xc3\xa9"), "A\0é")
        self.assertEqual(Dex007._class_descriptor("java/lang/Object"),
                         "Ljava/lang/Object;")
        self.assertEqual(Dex007._class_descriptor("[I"), "[I")

    def test_interpreter_opcode_map_boundaries(self) -> None:
        self.assertEqual(PHYSICAL_TO_LOGICAL[0x22], 0x22)
        self.assertEqual(PHYSICAL_TO_LOGICAL[0x2C], 0x2C)
        self.assertEqual(PHYSICAL_TO_LOGICAL[0x2D], 0x2E)
        self.assertEqual(PHYSICAL_TO_LOGICAL[0x71], 0x72)
        self.assertEqual(PHYSICAL_TO_LOGICAL[0x72], 0x74)
        self.assertEqual(PHYSICAL_TO_LOGICAL[0x76], 0x78)
        self.assertIsNone(PHYSICAL_TO_LOGICAL[0x77])
        self.assertEqual(PHYSICAL_TO_LOGICAL[0x7B], 0x7B)
        self.assertEqual(PHYSICAL_TO_LOGICAL[0xE2], 0xE2)
        self.assertIsNone(PHYSICAL_TO_LOGICAL[0xE3])
        self.assertEqual(PHYSICAL_TO_LOGICAL[0xF2], 0xF2)
        self.assertEqual(PHYSICAL_TO_LOGICAL[0xFB], 0xFB)
        self.assertIsNone(PHYSICAL_TO_LOGICAL[0xFC])

    @unittest.skipUnless(HAS_CORPUS, "set DEX007_CORPUS to build 20645")
    def test_calculator_integrity_and_debug_tables(self) -> None:
        dex = Dex007.from_path(CORPUS_ROOT / "app" / "Calculator.apk")
        result = dex.validate()
        self.assertEqual(dex.header.magic, DEX_MAGIC)
        self.assertEqual(dex.header.header_size, DEX_HEADER_SIZE)
        self.assertEqual(dex.checksum_status(), (True, True))
        self.assertEqual(result["classes"], 11)
        self.assertEqual(result["code_items"], 72)
        self.assertEqual(result["instructions_and_payloads"], 4569)
        self.assertEqual(result["payloads"], 11)
        self.assertEqual(result["positions"], 1049)
        self.assertEqual(result["locals"], 217)

    @unittest.skipUnless(HAS_CORPUS, "set DEX007_CORPUS to build 20645")
    def test_calculator_smali_export(self) -> None:
        original = Dex007.from_path(CORPUS_ROOT / "app" / "Calculator.apk")
        with tempfile.TemporaryDirectory() as output:
            paths = original.write_smali(output)
            calculator = next(
                path for path in paths
                if path.as_posix().endswith("/calculator/Calculator.smali")
            )
            text = calculator.read_text(encoding="utf-8")
            self.assertIn("# Generated from Android DEX 007 by dex007.py", text)
            self.assertIn(
                ".class Lcom/google/android/calculator/Calculator;", text
            )
            self.assertIn(".packed-switch", text)
            self.assertIn(".sparse-switch", text)

            rebuilt = Dex012(
                Dex012Assembler(SmaliParser().parse_path(output)).assemble(),
                "DEX007-Smali-logical-roundtrip.dex",
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

    @unittest.skipUnless(HAS_CORPUS, "set DEX007_CORPUS to build 20645")
    def test_complete_build_20645_corpus(self) -> None:
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
                dex = Dex007.from_path(path)
            except ValueError as exc:
                if "archive has no classes.dex" in str(exc):
                    continue
                raise
            self.assertEqual(dex.checksum_status(), (True, True), path.name)
            result = dex.validate()
            dex_paths += 1
            for key in totals:
                totals[key] += result[key]

        self.assertEqual(len(paths), 52)
        self.assertEqual(dex_paths, 51)
        self.assertEqual(
            totals,
            {
                "classes": 4905,
                "methods": 34965,
                "code_items": 31167,
                "instructions_and_payloads": 960047,
                "payloads": 600,
                "positions": 166626,
                "locals": 82293,
            },
        )


if __name__ == "__main__":
    unittest.main()
