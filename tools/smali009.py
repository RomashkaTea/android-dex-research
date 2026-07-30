#!/usr/bin/env python3
"""Assemble Smali source into the pre-release Android DEX 009 format."""

from __future__ import annotations

from typing import Sequence

from dex009 import DEX_MAGIC, PHYSICAL_TO_LOGICAL_009, Dex009
from smali007 import EarlyDexAssembler, assembler_main


LOGICAL_TO_PHYSICAL_009 = {
    logical: physical
    for physical, logical in enumerate(PHYSICAL_TO_LOGICAL_009)
    if logical is not None
}


class Dex009Assembler(EarlyDexAssembler):
    """Two-pass assembler for the Smali subset emitted by dex009.py."""

    dex_magic = DEX_MAGIC
    dex_class = Dex009
    version = "009"
    logical_to_physical = LOGICAL_TO_PHYSICAL_009
    static_field_padding = True
    supports_throws = True


def main(argv: Sequence[str] | None = None) -> int:
    return assembler_main(Dex009Assembler, "009", argv)


if __name__ == "__main__":
    raise SystemExit(main())
