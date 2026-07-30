#!/usr/bin/env python3

import hashlib
import os
import re
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from dex012 import DEX_HEADER_SIZE, DEX_MAGIC, NO_INDEX, Dex012  # noqa: E402

CORPUS_ENV = os.environ.get("DEX012_CORPUS")
CORPUS_ROOT = Path(CORPUS_ENV).resolve() if CORPUS_ENV else None
HAS_CORPUS = bool(
    CORPUS_ROOT
    and (CORPUS_ROOT / "app" / "Calculator.apk").is_file()
    and (CORPUS_ROOT / "framework" / "core.jar").is_file()
)


class Dex012Tests(unittest.TestCase):
    def test_empty_dex(self) -> None:
        fields = [DEX_HEADER_SIZE, DEX_HEADER_SIZE] + [0] * 21
        data = bytearray(struct.pack(
            "<8sI20s23I", DEX_MAGIC, 0, bytes(20), *fields
        ))
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)

        dex = Dex012(bytes(data), "synthetic-empty.dex")
        self.assertEqual(dex.checksum_status(), (True, True))
        self.assertEqual(dex.validate()["classes"], 0)

    def test_modified_utf8(self) -> None:
        self.assertEqual(Dex012._decode_mutf8(b"A\xc0\x80\xc3\xa9"), "A\0é")

    @unittest.skipUnless(HAS_CORPUS, "set DEX012_CORPUS to the Android system root")
    def test_small_archive_header_and_integrity(self) -> None:
        dex = Dex012.from_path(CORPUS_ROOT / "app" / "GTalkSettings.apk")
        self.assertEqual(dex.header.magic, DEX_MAGIC)
        self.assertEqual(dex.header.header_size, DEX_HEADER_SIZE)
        self.assertEqual(dex.header.file_size, 1649)
        self.assertEqual(dex.checksum_status(), (True, True))

    @unittest.skipUnless(HAS_CORPUS, "set DEX012_CORPUS to the Android system root")
    def test_switch_payloads_and_control_flow(self) -> None:
        result = Dex012.from_path(CORPUS_ROOT / "app" / "Calculator.apk").validate()
        self.assertEqual(result["classes"], 25)
        self.assertEqual(result["code_items"], 205)
        self.assertEqual(result["payloads"], 19)
        self.assertGreater(result["branch_targets"], 0)
        self.assertEqual(result["string_length_mismatches"], 0)

    @unittest.skipUnless(HAS_CORPUS, "set DEX012_CORPUS to the Android system root")
    def test_smali_export(self) -> None:
        dex = Dex012.from_path(CORPUS_ROOT / "app" / "Calculator.apk")
        with tempfile.TemporaryDirectory() as output:
            paths = dex.write_smali(output, class_filter="/Calculator;")
            self.assertEqual(len(paths), 1)
            text = paths[0].read_text(encoding="utf-8")

            self.assertIn(
                ".class Lcom/google/android/calculator/Calculator;", text
            )
            self.assertIn(".super Landroid/app/Activity;", text)
            self.assertIn(".method public constructor <init>()V", text)
            self.assertIn(
                "invoke-direct {v1}, Landroid/app/Activity;-><init>()V", text
            )
            self.assertIn(".packed-switch", text)
            self.assertIn(".sparse-switch", text)
            self.assertIn(".catch Ljava/lang/Exception;", text)
            self.assertIn("# DEX012 const-wide/special =", text)
            self.assertNotRegex(text, r"(?m)^\\s*const-wide/special\\b")

            references = set(re.findall(r":L[0-9a-f]{4,}\\b", text))
            definitions = set(
                re.findall(r"^\\s*(:L[0-9a-f]{4,})$", text, re.MULTILINE)
            )
            self.assertFalse(references - definitions)

            with self.assertRaises(FileExistsError):
                dex.write_smali(output, class_filter="/Calculator;")
            self.assertEqual(
                len(dex.write_smali(output, class_filter="/Calculator;", force=True)),
                1,
            )

    @unittest.skipUnless(HAS_CORPUS, "set DEX012_CORPUS to the Android system root")
    def test_no_superclass_sentinel(self) -> None:
        dex = Dex012.from_path(CORPUS_ROOT / "framework" / "core.jar")
        object_defs = [
            dex.class_def(i)
            for i in range(dex.header.class_defs_size)
            if dex.type_descriptor(dex.class_def(i).class_idx) == "Ljava/lang/Object;"
        ]
        self.assertEqual(len(object_defs), 1)
        self.assertEqual(object_defs[0].superclass_idx, NO_INDEX)

    @unittest.skipUnless(HAS_CORPUS, "set DEX012_CORPUS to the Android system root")
    def test_complete_system_corpus(self) -> None:
        paths = (
            sorted((CORPUS_ROOT / "app").glob("*.apk"))
            + sorted((CORPUS_ROOT / "framework").glob("*.jar"))
        )
        totals = {
            "classes": 0,
            "methods": 0,
            "code_items": 0,
            "instructions_and_payloads": 0,
            "payloads": 0,
        }
        for path in paths:
            result = Dex012.from_path(path).validate()
            for key in totals:
                totals[key] += result[key]

        self.assertEqual(len(paths), 41)
        self.assertEqual(
            totals,
            {
                "classes": 8392,
                "methods": 61584,
                "code_items": 53910,
                "instructions_and_payloads": 1180222,
                "payloads": 904,
            },
        )


if __name__ == "__main__":
    unittest.main()
