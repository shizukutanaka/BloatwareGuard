# BloatwareGuard v1.8.0-dev

## What It Does

Removes Windows bloatware across **7 prevention layers** in both **Python** and **C#** implementations.

### Layers

| Layer | Python | C# | Non-Admin |
|---|---|---|---|
| 1. AppxPackage removal | ✅ | ✅ | Regular→✓, SystemApp→skip |
| 2. ProvisionedPackage removal | ✅ | ✅ | Requires admin |
| 3. Consumer Experiences | ✅ | ✅ | HKCU write |
| 4. Cloud Content | ✅ | ✅ | HKCU write |
| 5. Device Metadata | ✅ | ✅ | HKLM (admin) |
| 6. OEM Scheduled Tasks | ✅ | ✅ | ✅ Disable works |
| 7. Re-install Monitor | ✅ | ✅ | ✅ Service mode |

---

## Quick Start

### Non-Admin (dry-run)

```bash
# Python
python bloatware_guard.py --dry-run

# C# (.NET 8 required)
dotnet run src/BloatwareGuard.csproj -- --dry-run
```

### Admin Deployment

```bash
# 1. Build C# version
dotnet build src/BloatwareGuard.csproj -c Release

# 2. Run as Administrator
.\src\bin\Release\net8.0-windows\BloatwareGuard.exe --admin-scan

# 3. Reboot, wait 30 minutes, then verify
.\src\bin\Release\net8.0-windows\BloatwareGuard.exe --verify
```

---

## Key Design Decisions

### SystemApp Detection

SystemApps (e.g., `Microsoft.XboxGameCallableUI`) **cannot be removed per-user** — Windows returns `HRESULT 0x80073CFA`. Detection method:

- PowerShell `Get-AppxPackage` returns **null `InstallPath`** for SystemApps
- These are **skipped gracefully** with a warning, not a failure

### ProvisionedPackage Removal

Requires admin (`DISM /Online /Remove-ProvisionedPackage`). Non-admin path logs `[requires admin]` and continues.

### Whitelist

Always preserves: `WindowsStore`, `Calculator`, `Notepad`, `Microsoft.VCLibs`, `Microsoft.VCWeb`.

---

## Files

| File | Description |
|---|---|
| `bloatware_guard.py` | Python implementation (primary) |
| `src/Program.cs` | C#/.NET 8 implementation |
| `src/BloatwareGuard.csproj` | C# project file |
| `config.json` | Blacklist + whitelist config |
| `deploy_verify.bat` | Admin deployment script |
| `check_pkgs.ps1` | PowerShell package checker |
| `verify_scan.ps1` | Post-reboot verification script |

---

## Build & Test

```bash
# Python
python -c "import py_compile; py_compile.compile('bloatware_guard.py', doraise=True)"

# C#
dotnet build src/BloatwareGuard.csproj -c Release
```

## Version

```bash
python bloatware_guard.py --version   # Python
BloatwareGuard.exe --version          # C#
```