# BloatwareGuard v1.8.0-mvp

## What It Does

Removes Windows bloatware across **23 prevention layers** in both **Python** and **C#** implementations.

### Layers

|| Layer | Python | C# | Non-Admin |
||---|---|---|---|
|| 1. AppxPackage removal (-AllUsers when elevated) | ✅ | ✅ | Regular→✓, SystemApp→skip |
|| 2. ProvisionedPackage removal | ✅ | ✅ | Requires admin |
|| 3. Consumer Experiences | ✅ | ✅ | HKCU write |
|| 4. Cloud Content | ✅ | ✅ | HKCU write |
|| 5. Device Metadata | ✅ | ✅ | HKLM (admin) |
|| 6. OEM Scheduled Tasks (TaskPath+TaskName match) | ✅ | ✅ | ✅ Disable works |
|| 7. Re-install Monitor | ✅ | ✅ | ✅ Service mode |
|| 8. Deprovisioned markers (blocks feature-update reinstalls) | ✅ | ✅ | HKLM (admin) |
|| 9. 25H2 `RemoveDefaultStorePackages` policy (new profiles) | ✅ | ✅ | HKLM (admin) |
|| 10. Content-delivery hardening across all user hives + Default | ✅ | ✅ | Current user only |
|| 11. AI features: Copilot, Recall, Click to Do | ✅ | ✅ | HKLM (admin) |
|| 12. Widgets / News-and-Interests board | ✅ | ✅ | HKLM (admin) |
|| 13. Start-search web suggestions (Bing) | ✅ | ✅ | HKLM+HKCU |
|| 14. Telemetry/CEIP scheduled tasks (exact paths) | ✅ | ✅ | Admin |
| 15. Telemetry/privacy policies (telemetry level, activity feed, ad ID, tailored experiences, per-hive tracking) | ✅ | ✅ | HKLM+hives (admin) |
| 16. Edge annoyance policies (sidebar, startup boost, Spotlight, shopping) | ✅ | ✅ | HKLM (admin) |
| 17. Win32/MSI/EXE bloatware uninstall (silent uninstallers only) | ✅ | ✅ | Admin |
| 18. OEM/vendor service stop+disable | ✅ | ✅ | Admin |
| 19. Startup (Run/RunOnce) bloat cleanup across all hives | ✅ | ✅ | Current user |
|| 20. Game Bar GameDVR capture off (policy + per-hive) | ✅ | ✅ | HKLM (admin) |
|| 21. Telemetry-domain hosts block (26 domains, reversible) | ✅ | ✅ | Admin |
|| 22. winget silent-uninstall sweep | ✅ | ✅ | Admin (skips w/o winget) |
|| 23. Deprecated capability removal (WordPad, Steps Recorder) | ✅ | ✅ | Admin |

Layers 20–23 close the loop. `DisableGameDvr` stops Game Bar background
capture via `AllowGameDVR=0` (HKLM policy) plus per-hive `AppCaptureEnabled`/
`GameDVR_Enabled`. `BlockTelemetryEndpoints` null-routes **26 pure-telemetry
domains** through a marked hosts-file block — the Spybot Anti-Beacon technique;
the list is conservative (no Windows Update / Store / activation endpoints) and
**toggling the flag off removes the block**, so it's fully reversible.
`WingetSweep` runs `winget list` + `winget uninstall --silent
--disable-interactivity` for matches the Uninstall-hive sweep can't reach
silently, skipping cleanly when App Installer is absent.
`RemoveDeprecatedCapabilities` removes Windows capabilities Microsoft itself
deprecated (WordPad, Steps Recorder).

Layer 17 sweeps the `Uninstall` registry hives (HKLM 64- and 32-bit views plus
every loaded user hive) for `DisplayName` values matching the blacklist plus a
built-in OEM/vendor list. It only executes **silent** uninstall paths —
`QuietUninstallString`, MSI product codes rewritten to `msiexec /x {GUID} /qn
/norestart`, or an `UninstallString` already carrying `/S`, `/silent`, `/qn`,
etc. Entries with only an interactive uninstaller are logged as "manual" so the
scan can never hang on a UI prompt.

Layer 18 stops and disables Windows **services** matching the same OEM/vendor
list (trial nagware, updaters). Layer 19 deletes `Run`/`RunOnce` values matching
blacklist/vendor patterns under HKLM (both bitness views) and every loaded user
hive — the autostart side of OEM bloat that Appx removal never touches.

Layer 15 is the broad privacy policy set — `AllowTelemetry=0`, activity-feed /
Timeline upload off, cross-device clipboard off, advertising ID off, location
scripting off, Delivery Optimization P2P upload off (`DODownloadMode=0`), the
OOBE privacy screen skipped, WER extra data off, and the Start-menu
"Recommended" section hidden — plus per-hive values that can't be policy-managed
(tailored experiences, ink/typing personalization, `Start_TrackProgs`, SIUF
cadence, Explorer sync-provider ads, typing insights). Layer 16 hardens Edge via
official `HKLM\SOFTWARE\Policies\Microsoft\Edge` policies — sidebar, Startup
Boost, Spotlight recommendations, personalization reporting, shopping
assistant, New-Tab feed (the browser stays whitelisted; only the noise is cut).

Layer 9 uses the official Windows 11 25H2 Group Policy *"Remove Default Microsoft
Store packages from the system"* — for each blacklisted package family found on
the system it writes `HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\<PackageFamilyName>`
with `RemovePackage=1`, so Windows itself removes those apps at first sign-in of
new user profiles. Inert on builds older than 25H2.

Layer 8 creates empty keys under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\<PackageFamilyName>`
— the documented marker Windows checks before re-provisioning apps during a
feature update.

Layer 10 exists because the service runs as SYSTEM: HKCU writes would land in
SYSTEM's own hive. The tool instead applies the ContentDeliveryManager killswitch
set, `ShowCopilotButton`, `Start_IrisRecommendations`, `DisableSearchBoxSuggestions`,
and `TurnOffWindowsCopilot` to every loaded `HKU\S-1-5-21-*` hive and loads the
`C:\Users\Default\NTUSER.DAT` template so future profiles inherit them.

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

Requires admin (`Remove-AppxProvisionedPackage -Online`). Non-admin path logs `[requires admin]` and continues.
The provisioned query returns `PackageName` **and** the derived `PackageFamilyName`
(`DisplayName_PublisherId`) in one pass — the family name feeds layers 8 and 9.

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
