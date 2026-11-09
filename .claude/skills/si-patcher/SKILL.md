---
name: si-patcher
description: Reverse engineer Windows PE (.exe/.dll) binaries with x64dbg MCP + si_pe_inspect.py, validate NOP-padded byte patches, and generate C++ ASI memory mods.
---

# SI-Patcher Skill (Windows PE + x64dbg MCP Router)

## Rules
1. **Never Corrupt the Disk EXE**: Prefer generating a runtime C++ ASI plugin (`--gen-asi`) or backing up the binary first.
2. **Always Use RVA (`Address - ModuleBase`)**: Windows ASLR shifts hardcoded addresses on every reboot. Always record offsets as `ModuleBase + RVA`.
3. **Strict Byte-Length Check**: Never overwrite an $N$-byte instruction with $>N$ bytes in place. Run `python si_pe_inspect.py --pad-patch` to verify length and auto-pad trailing `0x90` (`NOP`) bytes.

## The 5-Step Loop

### Step 1 — Fast Static PE Recon
Run:
```sh
python si_pe_inspect.py --inspect target.exe
```
Check architecture (`x86` vs `x64`), `imageBase`, `aslrEnabled`, section RVAs, and candidate strings (`FPS`, `FOV`, `Aspect`, `Debug`).

### Step 2 — Dynamic Trace in x64dbg MCP
Attach `x64dbg` (for `x64`) or `x32dbg` (for `x86`), set a hardware execution breakpoint on the candidate XREF address, and inspect live registers (`RAX`, `RCX`, `XMM0`).

### Step 3 — Validate & NOP-Pad the Patch Bytes
Run:
```sh
python si_pe_inspect.py --pad-patch --orig "<original_hex>" --new "<replacement_hex>"
```

### Step 4 — Build an Update-Proof Wildcard AOB Signature
Run:
```sh
python si_pe_inspect.py --aob "<instruction_window_hex>"
```

### Step 5 — Generate the C++ ASI Memory Hook
Run:
```sh
python si_pe_inspect.py --gen-asi --rva 0x<HEX_RVA> --orig "<orig_hex>" --new "<padded_hex>" --out mod_patch.cpp
```
