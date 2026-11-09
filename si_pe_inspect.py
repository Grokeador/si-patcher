#!/usr/bin/env python3
"""
SI-Patcher (by SI NEWS) — Zero-dependency Windows PE (.exe/.dll) Inspector,
NOP-Safe Byte Patch Validator, Wildcard AOB Builder, and C++ ASI Mod Generator.
100% Python 3 standard library (struct, re, json).
"""
from __future__ import annotations
import argparse
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List


def parse_hex_bytes(hex_str: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", hex_str or "")
    if not cleaned or len(cleaned) % 2 != 0:
        raise ValueError(f"Invalid hex byte string: {hex_str!r}")
    return bytes.fromhex(cleaned)


def format_hex_bytes(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def validate_and_pad_patch(orig_hex: str, new_hex: str) -> Dict[str, Any]:
    """
    Ensures replacement instruction bytes fit inside original instruction length.
    Pads trailing bytes with 0x90 (NOP) if shorter; raises ValueError if longer.
    """
    orig_b = parse_hex_bytes(orig_hex)
    new_b = parse_hex_bytes(new_hex)
    if len(new_b) > len(orig_b):
        raise ValueError(
            f"Patch too long ({len(new_b)} bytes > original {len(orig_b)} bytes). "
            "Allocate a Code Cave jump instead of overwriting adjacent instructions."
        )
    nop_count = len(orig_b) - len(new_b)
    padded_b = new_b + (b"\x90" * nop_count)
    return {
        "originalHex": format_hex_bytes(orig_b),
        "originalLen": len(orig_b),
        "newLen": len(new_b),
        "nopPaddingCount": nop_count,
        "paddedHex": format_hex_bytes(padded_b),
        "cByteLiteral": "".join(f"\\x{b:02X}" for b in padded_b),
    }


def generate_wildcard_aob(hex_str: str) -> str:
    """
    Masks 4-byte RIP-relative displacement fields following common x86/x64 opcodes
    (e.g. 48 8B 05 [disp32], E8 [disp32], E9 [disp32], 0F 84 [disp32]) with '?' wildcards.
    """
    raw = parse_hex_bytes(hex_str)
    tokens = [f"{b:02X}" for b in raw]
    i = 0
    n = len(tokens)
    while i < n:
        b0 = raw[i]
        # CALL rel32 (E8) or JMP rel32 (E9)
        if b0 in (0xE8, 0xE9) and i + 4 < n:
            for k in range(1, 5):
                tokens[i + k] = "??"
            i += 5
            continue
        # Conditional near jumps 0F 80..0F 8F
        if b0 == 0x0F and i + 5 < n and 0x80 <= raw[i + 1] <= 0x8F:
            for k in range(2, 6):
                tokens[i + k] = "??"
            i += 6
            continue
        # RIP-relative ModR/M (Mod=00, R/M=101 -> byte & 0xC7 == 0x05) after common mov/lea/cmp
        if b0 in (0x8B, 0x89, 0x8D, 0x3B, 0x39) and i + 5 < n and (raw[i + 1] & 0xC7) == 0x05:
            for k in range(2, 6):
                tokens[i + k] = "??"
            i += 6
            continue
        i += 1
    return " ".join(tokens)


def parse_pe_headers(data: bytes) -> Dict[str, Any]:
    """Lightweight stdlib parser for Windows PE32 / PE32+ headers."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Not a valid DOS/PE binary (missing MZ header).")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature.")

    machine, num_sections, _, _, _, opt_hdr_size, _ = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    arch = "x64" if machine == 0x8664 else ("x86" if machine == 0x014C else f"0x{machine:04X}")

    opt_offset = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_pe64 = (magic == 0x20B)
    entry_rva = struct.unpack_from("<I", data, opt_offset + 16)[0]
    if is_pe64:
        image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
        dll_chars = struct.unpack_from("<H", data, opt_offset + 70)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
        dll_chars = struct.unpack_from("<H", data, opt_offset + 70)[0]

    aslr_enabled = bool(dll_chars & 0x0040)
    sec_table_off = opt_offset + opt_hdr_size
    sections: List[Dict[str, Any]] = []
    for idx in range(num_sections):
        off = sec_table_off + idx * 40
        if off + 40 > len(data):
            break
        raw_name = data[off:off + 8].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        vsize, vrva, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append({
            "name": raw_name,
            "virtualRVA": f"0x{vrva:X}",
            "virtualSize": vsize,
            "rawSize": rsize,
        })

    return {
        "architecture": arch,
        "peFormat": "PE32+" if is_pe64 else "PE32",
        "imageBase": f"0x{image_base:X}",
        "entryPointRVA": f"0x{entry_rva:X}",
        "aslrEnabled": aslr_enabled,
        "sections": sections,
    }


def generate_asi_cpp(rva_hex: str, orig_hex: str, new_hex: str) -> str:
    patch_info = validate_and_pad_patch(orig_hex, new_hex)
    rva_int = int(rva_hex, 16) if str(rva_hex).lower().startswith("0x") else int(rva_hex)
    return f"""// Auto-generated by SI-Patcher (https://github.com/Grokeador/si-patcher)
// Compile as x64/x86 DLL and rename extension to .asi
#include <windows.h>
#include <cstdint>

static const uintptr_t PATCH_RVA = 0x{rva_int:X};
static const size_t PATCH_LEN = {patch_info['originalLen']};
static const uint8_t PATCH_BYTES[PATCH_LEN] = {{ {", ".join("0x" + b for b in patch_info['paddedHex'].split())} }};

DWORD WINAPI ApplySiPatchThread(LPVOID) {{
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    uint8_t* target = reinterpret_cast<uint8_t*>(base + PATCH_RVA);
    DWORD oldProtect = 0;
    if (VirtualProtect(target, PATCH_LEN, PAGE_EXECUTE_READWRITE, &oldProtect)) {{
        memcpy(target, PATCH_BYTES, PATCH_LEN);
        VirtualProtect(target, PATCH_LEN, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), target, PATCH_LEN);
    }}
    return 0;
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {{
    if (reason == DLL_PROCESS_ATTACH) {{
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, ApplySiPatchThread, nullptr, 0, nullptr);
    }}
    return TRUE;
}}
"""


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SI-Patcher PE & ASI Toolkit (by SI NEWS)")
    parser.add_argument("--inspect", type=str, help="Inspect a Windows .exe or .dll file")
    parser.add_argument("--pad-patch", action="store_true", help="Validate & NOP-pad instruction bytes")
    parser.add_argument("--orig", type=str, default="", help="Original instruction hex bytes")
    parser.add_argument("--new", type=str, default="", help="New instruction hex bytes")
    parser.add_argument("--aob", type=str, help="Generate wildcard AOB pattern from hex bytes")
    parser.add_argument("--gen-asi", action="store_true", help="Generate C++ ASI memory patch plugin")
    parser.add_argument("--rva", type=str, default="0x1000", help="Target Relative Virtual Address (RVA)")
    parser.add_argument("--out", type=str, help="Output file path")
    args = parser.parse_args(argv)

    if args.inspect:
        data = Path(args.inspect).read_bytes()
        info = parse_pe_headers(data)
        print(json.dumps(info, indent=2))
        return 0

    if args.pad_patch:
        res = validate_and_pad_patch(args.orig, args.new)
        print(json.dumps(res, indent=2))
        return 0

    if args.aob:
        print(generate_wildcard_aob(args.aob))
        return 0

    if args.gen_asi:
        cpp = generate_asi_cpp(args.rva, args.orig, args.new)
        if args.out:
            Path(args.out).write_text(cpp, encoding="utf-8")
        else:
            print(cpp)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
