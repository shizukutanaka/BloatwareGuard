# BloatwareGuard v1.10.0-mvp

## What It Does

Removes Windows bloatware across **14 prevention layers** in both **Python** and **C#** implementations.
Per-user settings are written to **every loaded user hive + the Default profile template**, so they
also apply correctly when the tool runs as a SYSTEM service and for users created later.

### Layers

|| Layer | Python | C# | Non-Admin |
||---|---|---|---|
|| 1. AppxPackage removal (all users when admin) | ✅ | ✅ | Regular→✓, SystemApp→skip |
|| 2. ProvisionedPackage removal | ✅ | ✅ | Requires admin |
|| 3. Consumer Experiences | ✅ | ✅ | HKLM (admin) |
|| 4. Cloud Content | ✅ | ✅ | HKLM (admin) |
|| 5. Device Metadata | ✅ | ✅ | HKLM (admin) |
|| 6. OEM Scheduled Tasks | ✅ | ✅ | ✅ Disable works |
|| 7. Re-install Monitor | ✅ | ✅ | ✅ Service mode |
|| 8. Copilot off (policy, all hives) | ✅ | ✅ | Own hive only |
|| 9. Recall / Windows AI off (policy + feature removal) | ✅ | ✅ | Own hive only |
|| 10. Search suggestions / Bing off (all hives) | ✅ | ✅ | Own hive only |
|| 11. Widgets board off (policy + taskbar button) | ✅ | ✅ | HKLM needs admin |
|| 12. Telemetry off (DiagTrack svc, ad ID, feedback nags, activity history) | ✅ | ✅ | HKLM needs admin |
|| 13. GameDVR / Game Bar capture off | ✅ | ✅ | HKLM needs admin |
|| 14. Delivery Optimization P2P sharing off | ✅ | ✅ | HKLM needs admin |

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

### Python (reference implementation — works without admin)

The C# single-file EXE is the canonical implementation (self-contained runtime, SCM-native service). The Python script is kept as a readable reference and for non-admin dry-run diagnosis; both share the same `config.json` schema.

```bash
# Dry-run (no admin needed — SystemApp detection + skip)
python bloatware_guard.py --dry-run

# Full removal (requires admin)
python bloatware_guard.py --scan

# Restore staged packages (from the removal ledger)
python bloatware_guard.py --restore
BloatwareGuard.exe restore
```

## Service Mode (background monitoring)

```bash
# Run in foreground with monitor loop enabled (console mode = live scan loop)
python bloatware_guard.py --service
BloatwareGuard.exe                    # no args = console monitor mode (performs real scans)

# Same, but forced dry-run (monitor-only, changes nothing)
python bloatware_guard.py --service-dry-run
BloatwareGuard.exe --service-dry-run

# Install as a Windows service
BloatwareGuard.exe install        # C# — direct SCM registration
python bloatware_guard.py --install   # requires NSSM (nssm.exe on PATH or beside the script);
                                      # plain pythonw.exe is NOT SCM-aware and fails with error 1053.
                                      # Fallback: prints a ready-to-run schtasks command.
BloatwareGuard.exe uninstall
```

## Removal Ledger & Restore

Every successful removal is appended to `removed-packages.jsonl` under
`BackupDirectory` (default `C:\ProgramData\BloatwareGuard\Backups`).
`restore` re-registers staged AppxPackages via their manifest;
provisioned packages cannot be restored from the image and are reported
for manual reinstall via the Microsoft Store.

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
|| `verify_scan.ps1` | Post-reboot verification script |
|| `verify_scan_sys.ps1` | System-context verification script |

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
python bloatware_guard.py --version   # BloatwareGuard v1.10.0-mvp
BloatwareGuard.exe --version          # BloatwareGuard v1.10.0-mvp
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
