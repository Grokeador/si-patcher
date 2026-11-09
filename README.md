# SI-Patcher: Windows PE (.exe/.dll) AI Reverse Engineering & Auto-ASI Mod Generator

**Created by [SI NEWS](https://www.youtube.com/channel/UC4m6veQiZdc_pAfxKQluRgA) • Companion repo for *"x64dbg MCP and Claude Desktop: Reverse Engineer and Patch Any Windows EXE Free"*.**

`si-patcher` is a Windows-ready Claude skill and zero-dependency Python 3 PE binary toolkit (`si_pe_inspect.py`) that bridges **[SIREA](https://github.com/Grokeador/sirea)** (static recon) and **[x64dbg MCP](https://github.com/Wasdubby/x64dbg-mcp)** (live dynamic debugging).

Instead of corrupting game or app executables on disk with wrong byte lengths or broken ASLR addresses, `si-patcher`:
1. **Inspects any Windows PE (`.exe`/`.dll`) in 1 call** (`PE32` x86 vs `PE32+` x64, ImageBase, ASLR flag, `.text`/`.rdata` RVA ranges, and targeted string offsets for `FPS`, `FOV`, `AspectRatio`, `Debug`).
2. **Pads instruction patches safely (`--pad-patch`)**: Ensures your replacement bytes match the exact instruction length of the original assembly (automatically padding trailing `0x90` `NOP` bytes and rejecting oversize patches that require a code cave).
3. **Builds wildcard AOB signatures (`--aob`)**: Masks RIP-relative displacement bytes (`??`) so your patch survives future game updates.
4. **Generates a clean C++ ASI Memory Hook (`--gen-asi`)**: Outputs a ready-to-compile `dllmain.cpp` ASI plugin that patches RAM at runtime (`VirtualProtect` + `ModuleBase + RVA`) without touching the original `.exe` on disk.

---

## Quick Start (Windows 10/11 — PowerShell)

```powershell
git clone https://github.com/Grokeador/si-patcher
cd si-patcher
python -m unittest discover -s tests -v
```

### 1. Inspect a Windows `.exe` or `.dll`
```powershell
python si_pe_inspect.py --inspect C:\Games\MyGame\Game.exe
```

### 2. Validate & NOP-Pad an Instruction Patch
```powershell
python si_pe_inspect.py --pad-patch --orig "B8 1E 00 00 00" --new "B8 78 00 00 00"
```

### 3. Generate a C++ ASI Runtime Mod (Zero `.exe` Modification)
```powershell
python si_pe_inspect.py --gen-asi --rva 0x2A4F18 --orig "B8 1E 00 00 00" --new "B8 78 00 00 00" --out fps_unlock_asi.cpp
```

### 4. Install the Skill for Claude Code / Claude Desktop
```powershell
npx skills add Grokeador/si-patcher -a claude-code -y
```

## License
MIT — Built by [SI NEWS](https://www.youtube.com/channel/UC4m6veQiZdc_pAfxKQluRgA). Use only on software/games you own for modding, interoperability, or security lab testing.
