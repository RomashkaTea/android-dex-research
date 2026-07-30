# Early Android DEX research

This repository contains working tools and reverse-engineering notes for two
pre-release Dalvik executable formats:

- `tools/dex007.py` parses, validates, disassembles, and exports Smali from
  Android build 20645's `dex\n007\0` files. See
  [`tools/DEX007.md`](tools/DEX007.md).
- `tools/dex012.py` parses, validates, disassembles, and exports Smali from
  the later Sooner build's `dex\n012\0` files.
- `tools/smali012.py` assembles the supported Smali subset into DEX 012.

The DEX 007 implementation has been validated against all 51 DEX-bearing
APK/JAR files in build 20645: 4,905 classes, 31,167 code items, and 960,047
decoded instructions and payloads.

## Android DEX 012 format notes

These notes describe the pre-release `dex\n012\0` files in this Android 1.0
Sooner system image. They were reconstructed from `lib/libdvm.so`, checked
against `bin/dexdump`, and validated against every `classes.dex` in `app/` and
`framework/`.

All integers are little-endian. Offsets are absolute file offsets unless noted
otherwise.

## Files worth reverse engineering

- `lib/libdvm.so` is authoritative. It contains the DEX parser, class/method
  loader, instruction decoder, opcode metadata, interpreter, switch handling,
  exception lookup, and optimizer-facing structures.
- `bin/dexdump` is the reference presentation layer. Its opcode-name table is
  useful for reproducing the original mnemonics and its output is useful for
  comparison testing.
- `bin/dexopt` and `bin/dalvikvm` are thin clients of `libdvm.so`. They help
  establish call flow and optimized-file behavior, but do not define the raw
  DEX layout.
- The APK/JAR corpus supplies real format fixtures and catches assumptions that
  are invisible in one binary, such as `0xffffffff` index sentinels and both
  switch payload encodings.

## Header

The header is 124 bytes:

```c
struct DexHeader012 {
    uint8_t  magic[8];           // "dex\n012\0"
    uint32_t checksum;           // Adler-32 of bytes [12, fileSize)
    uint8_t  signature[20];      // SHA-1 of bytes [32, fileSize)
    uint32_t fileSize;
    uint32_t headerSize;         // 124
    uint32_t linkSize;
    uint32_t linkOff;
    uint32_t stringIdsSize;
    uint32_t stringIdsOff;
    uint32_t stringObjectsSize;
    uint32_t typeIdsSize;
    uint32_t typeIdsOff;
    uint32_t fieldIdsSize;
    uint32_t fieldIdsOff;
    uint32_t methodIdsSize;
    uint32_t methodIdsOff;
    uint32_t classDefsSize;
    uint32_t classDefsOff;
    uint32_t wordDataSize;
    uint32_t wordDataOff;
    uint32_t codesSize;
    uint32_t codesOff;
    uint32_t stringDataSize;
    uint32_t stringDataOff;
    uint32_t debugDataSize;
    uint32_t debugDataOff;
};
```

## Identifier and class tables

```c
struct DexStringId012 { uint32_t stringDataOff, utf16Length; };
struct DexTypeId012   { uint32_t descriptorIdx; };
struct DexFieldId012  { uint32_t classIdx, nameIdx, typeDescriptorIdx; };
struct DexMethodId012 { uint32_t classIdx, nameIdx, descriptorIdx; };

struct DexClassDef012 {
    uint32_t classIdx;
    uint32_t accessFlags;
    uint32_t superclassIdx;      // 0xffffffff means no superclass
    uint32_t interfacesOff;
    uint32_t staticFieldsOff;
    uint32_t instanceFieldsOff;
    uint32_t directMethodsOff;
    uint32_t virtualMethodsOff;
    uint32_t annotationsOff;
};
```

String data is directly NUL-terminated modified UTF-8. Unlike later DEX
versions, no ULEB128 length precedes the bytes; the UTF-16 length is in the
eight-byte string-id entry.

Variable tables:

```c
struct DexTypeList012 {
    uint32_t size;
    uint32_t typeIdx[size];
};

struct DexInstanceFieldList012 {
    uint32_t size;
    struct { uint32_t fieldIdx, accessFlags; } entries[size];
};

struct DexStaticFieldList012 {
    uint32_t size;
    uint32_t padding;
    struct {
        uint32_t fieldIdx, accessFlags;
        uint64_t constantValue;
    } entries[size];
};

struct DexMethodList012 {
    uint32_t size;
    struct {
        uint32_t methodIdx, accessFlags, thrownExceptionsOff, codeOff;
    } entries[size];
};
```

`thrownExceptionsOff` addresses a `DexTypeList012`.

## Code and exceptions

```c
struct DexCode012 {
    uint16_t registersSize, insSize, outsSize, padding;
    uint32_t sourceFileIdx;
    uint32_t insnsOff;
    uint32_t exceptionsOff;
    uint32_t debugInfoOff;
};

struct DexInsnList012 {
    uint32_t insnsSize;          // number of 16-bit code units
    uint16_t insns[insnsSize];
};

struct DexCatchList012 {
    uint32_t size;
    struct {
        uint32_t startAddr, endAddr, handlerAddr;
        int32_t typeIdx;         // -1 means catch-all
    } entries[size];
};
```

Exception and branch addresses are measured in 16-bit code units.

## Instructions

The opcode is the low byte of the first code unit. DEX 012 uses a distinct
opcode map and must not be decoded with a modern DEX table. Important
differences include:

- `const/special` and `const-wide/special` at `0x1a` and `0x1b`;
- primitive-specific `new-array-*` opcodes at `0x23` through `0x2a`;
- packed and sparse switch opcodes at `0x36` and `0x37`;
- four-register non-range invoke encoding;
- optimized opcodes such as `+execute-inline`, quick fields, and quick invokes
  in the `0xee` through `0xfb` region.

Switch payloads have the familiar `0x0100` and `0x0200` signatures, but their
targets are signed **16-bit** offsets relative to the switch instruction:

```c
struct PackedSwitchData012 {
    uint16_t signature;          // 0x0100
    uint16_t size;
    int32_t firstKey;
    int16_t targets[size];
};

struct SparseSwitchData012 {
    uint16_t signature;          // 0x0200
    uint16_t size;
    int32_t keys[size];
    int16_t targets[size];
};
```

## Using the disassembler

```sh
python3 tools/dex012.py -H app/Calculator.apk
python3 tools/dex012.py -d --class-filter 'Calculator;' app/Calculator.apk
python3 tools/dex012.py --smali-out out/smali app/Calculator.apk
python3 tools/smali012.py out/smali -o out/classes.dex
python3 tools/dex012.py --validate --json framework/core.jar
python3 -m unittest tools/test_dex012.py
DEX012_CORPUS=/path/to/android/system python3 -m unittest tools/test_dex012.py
```

The tool accepts a raw DEX file or an APK/JAR containing `classes.dex`.
Validation walks every referenced table and instruction stream, checks string
lengths, catch handlers, switch payload types, and all branch boundaries. The
small synthetic tests run everywhere; setting `DEX012_CORPUS` enables the
full-system regression suite without checking proprietary binaries into this
repository.

## Smali-to-DEX 012 assembly

`tools/smali012.py` assembles a Smali file or directory into a raw DEX 012
file. It builds all identifier and class tables, separates direct and virtual
methods, lays out code and exception data, resolves labels and switch payloads,
and writes the DEX SHA-1 signature and Adler-32 checksum. The generated file is
parsed and fully validated before it is written:

```sh
python3 tools/dex012.py app/Calculator.apk --smali-out out/smali
python3 tools/smali012.py out/smali -o out/classes.dex
python3 tools/dex012.py out/classes.dex --validate
```

Existing output files are protected unless `--force` is supplied.
`--no-validate` is available for investigating malformed output.

The assembler accepts the complete instruction and metadata subset emitted by
the companion disassembler, including DEX 012 packed/sparse switches, absolute
exception ranges, primitive array opcodes, special constants, and optimized
quick/inline instructions. Debug streams and general annotation values are
currently omitted because the disassembler preserves them only as comments.

Round-trip testing covers all 41 APK/JAR files in the Sooner system image:
8,392 classes, 53,910 code items, and 1,180,222 decoded instructions and
payloads.

## DEX-to-Smali export

`--smali-out DIR` writes one source file per class using the descriptor as its
directory path. Existing files are protected by default; pass `--force` to
replace them. `--class-filter TEXT` can limit the export.

The exporter emits class, superclass, interface, source, field, method,
register, exception, branch, packed-switch, and sparse-switch directives. It
also converts DEX 012's primitive-specific `new-array-*` instructions and
`const/special` tables into ordinary Smali instructions. Unoptimized
Calculator output has been assembled successfully with Smali 3.0.9.

DEX 012 annotations and debug streams are not decoded yet, so their offsets are
preserved as comments. Optimized quick/inline opcodes are emitted in odex-style
Smali form and may require an assembler mode that permits optimized
instructions.
