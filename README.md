# BloatwareGuard v1.8.0-mvp

## What It Does

Removes Windows bloatware across **7 prevention layers** in both **Python** and **C#** implementations.

### Layers

|| Layer | Python | C# | Non-Admin |
||---|---|---|---|
|| 1. AppxPackage removal | ✅ | ✅ | Regular→✓, SystemApp→skip |
|| 2. ProvisionedPackage removal | ✅ | ✅ | Requires admin |
|| 3. Consumer Experiences | ✅ | ✅ | HKCU write |
|| 4. Cloud Content | ✅ | ✅ | HKCU write |
|| 5. Device Metadata | ✅ | ✅ | HKLM (admin) |
|| 6. OEM Scheduled Tasks | ✅ | ✅ | ✅ Disable works |
|| 7. Re-install Monitor | ✅ | ✅ | ✅ Service mode |

---

## Quick Start

### Self-Contained C# EXE (Recommended)

No .NET runtime installation needed — the C# binary includes the full .NET 8 runtime in a single 11.3MB file.

```bash
# Build
dotnet publish src/BloatwareGuard.csproj -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=false \
  -p:PublishTrimmed=true -o src/bin/Release/net8.0-windows/win-x64/

# Run (requires Administrator — UAC manifest requests admin)
src\bin\Release\net8.0-windows\win-x64\BloatwareGuard.exe dry-run
```

### Python (Primary - works without admin)

```bash
# Dry-run (no admin needed — SystemApp detection + skip)
python bloatware_guard.py --dry-run

# Full removal (requires admin)
python bloatware_guard.py --execute
```

---

## Key Design Decisions

### SystemApp Detection

SystemApps (e.g., `Microsoft.XboxGameCallableUI`) **cannot be removed per-user** — Windows returns `HRESULT 0x80073CFA`. Detection method:

- PowerShell `Get-AppxPackage` returns **null `InstallPath`** for SystemApps
- C#: `InstallPath == null` check with `string?` nullable annotation
- Python: 3-tuple `(PackageFamilyName, DisplayName, InstallPath)` with None check
- These are **skipped gracefully** with `[requires admin]` tag, not a failure

### ProvisionedPackage Dry-Run Logging

Both implementations log `[requires admin]` for ProvisionedPackage entries during dry-run, with a `removed` counter showing what WOULD be removed.

### ProvisionedPackage Removal

Requires admin (`DISM /Online /Remove-ProvisionedPackage`). Non-admin path logs `[requires admin]` and continues.

### Whitelist

Always preserves: `WindowsStore`, `Calculator`, `Notepad`, `Microsoft.VCLibs`, `Microsoft.VCWeb`.

---

## Files

|| File | Description |
||---|---||
|| `bloatware_guard.py` | Python implementation (primary) |
|| `src/Program.cs` | C#/.NET 8 implementation |
|| `src/BloatwareGuard.csproj` | C# project (self-contained win-x64) |
|| `config.json` | Blacklist + whitelist config |
|| `deploy_verify.bat` | Admin deployment + verification script |
|| `check_pkgs.ps1` | PowerShell package checker |
|| `verify_scan.ps1` | Post-reboot verification script |

---

## Build & Test

```bash
# Python
python -c "import py_compile; py_compile.compile('bloatware_guard.py', doraise=True)"

# C# (self-contained single-file)
dotnet publish src/BloatwareGuard.csproj -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=false \
  -p:PublishTrimmed=true -o src/bin/Release/net8.0-windows/win-x64/
```

## Version

```bash
python bloatware_guard.py --version   # BloatwareGuard v1.8.0-mvp
BloatwareGuard.exe --version          # BloatwareGuard v1.8.0-mvp
```

---

## Environment Requirements

| Check | Requirement |
|---|---|
| OS | Windows 11 |
| C# EXE | **No .NET runtime needed** (self-contained, 11.3MB single file) |
| Python | Python 3.10+ |
| Admin rights | Required for Layers 2-5 (DISM, HKLM, ProvisionedPackage removal) |
| Non-admin | Layers 1, 6, 7 work (AppxPackage skip, OEM task disable, re-install monitor) |

**Out of scope**: Windows kernel boundary removal (DISM /Online, HKLM) in non-admin mode — architecturally impossible.
