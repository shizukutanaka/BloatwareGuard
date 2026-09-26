# Changelog

All notable changes to BloatwareGuard. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] — v1.8.0-mvp hardening

### Added — debloat round 3 (Win32 coverage + privacy policies)
- **5 more prevention toggles** (all default-on):
  - `RemoveWin32Bloatware` — sweeps the `Uninstall` registry hives (HKLM 64-/32-bit + every loaded user hive) for `DisplayName` matching Blacklist ∪ a built-in OEM/vendor list, and uninstalls them. **Silent-paths only**: `QuietUninstallString`, MSI codes rewritten to `msiexec /x {GUID} /qn /norestart`, or UninstallStrings already carrying a silent flag — interactive uninstallers are logged and skipped so a UI prompt can never hang the scan.
  - `DisableOemServices` — `Get-Service` sweep for vendor names (McAfee/Norton/Dell/HP/Lenovo/ASUS/Acer/Razer/ExpressVPN/CyberLink/…), `sc stop` + `start= disabled`.
  - `CleanStartupEntries` — deletes `Run`/`RunOnce` values matching bloat/vendor patterns across HKLM (both bitness views) and all loaded user hives.
  - `DisableTelemetryPolicies` — documented Group Policies: `AllowTelemetry=0`, feedback notifications off, activity-feed/Timeline upload off, advertising ID off, cross-device clipboard sync off, location scripting off; plus per-hive values (tailored experiences, ink/typing personalization, app-launch tracking `Start_TrackProgs`, SIUF feedback cadence).
  - `HardenEdgePolicies` — `HKLM\SOFTWARE\Policies\Microsoft\Edge`: sidebar off, startup boost off, Spotlight experiences/recommendations off, personalization reporting off, shopping assistant off.
- Self-tests: Python 14 checks (+Win32 silent-uninstall classifier, vendor-pattern sanity, policy-table validation), C# 10 checks.

### Added — debloat round 2 (researched vs. Win11Debloat / WindowsDecrapifier / MS Learn)
- **7 new prevention toggles** (all default-on, config `Prevention.*`):
  - `MarkDeprovisioned` — writes `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\<PackageFamilyName>` for every blacklisted family; the documented marker Windows checks before re-provisioning removed apps during feature updates.
  - `RemoveDefaultStorePackages` — Windows 11 25H2 official Group Policy ("Remove Default Microsoft Store packages from the system"): writes `HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\<family>` `RemovePackage=1` so the OS itself strips those apps at first sign-in of new user profiles. Inert on older builds.
  - `HardenContentDelivery` — the full 18-value ContentDeliveryManager killswitch set (Win11Debloat's `Disable_Windows_Suggestions.reg`) + `ShowCopilotButton`/`Start_IrisRecommendations`, applied to **every loaded `HKU\S-1-5-21-*` hive and the Default profile template** — previously HKCU writes from the SYSTEM service went to SYSTEM's own hive and protected nobody.
  - `DisableAiFeatures` — `TurnOffWindowsCopilot=1`, `DisableAIDataAnalysis=1` (Recall), `AllowRecallEnablement=0`, `DisableClickToDo=1` (HKLM + per-hive Copilot policy).
  - `DisableWidgets` — `AllowNewsAndInterests=0` (Policy + PolicyManager default).
  - `DisableSearchSuggestions` — `DisableSearchBoxSuggestions=1` (HKLM + per-hive) kills Bing/web results in Start-menu search.
  - `DisableTelemetryTasks` — disables 16 known Microsoft telemetry/CEIP scheduled tasks by exact path (CompatAppraiser, ProgramDataUpdater, CEIP Consolidator/KernelCeip/UsbCeip, Siuf DmClient, Maps tasks, …).
- **Blacklist additions** (5): `Microsoft.OutlookForWindows` (new Outlook auto-provisioned since Mail & Calendar deprecation), `microsoft.windowscommunicationsapps` (dead Mail & Calendar remnants), `Microsoft.BingSearch`, `Microsoft.Windows.Ai.Copilot.Provider`, `Disney.`.
- Self-tests: Python 8→11 checks (framework/dedupe filtering, provisioned name+family derivation, telemetry list sanity, CDM set, whitelist parity), C# 6→8 (new flags registered & default-on, new methods wired).

### Fixed
- **CEIP scheduled tasks were never matched**: the OEM scan only matched `TaskName` — CEIP tasks like `Consolidator` live under `...\Customer Experience Improvement Program\` TaskPath. The query now matches TaskPath too; the (now redundant) CEIP name patterns moved out of the OEM list since `DisableTelemetryTasks` owns them by exact path.
- **Python could remove framework packages**: `IsFramework` was never queried — Python now filters frameworks like C# does.
- **Provisioned removal spawned an extra PowerShell lookup per package**: the query now returns `PackageName` directly (also yields `PackageFamilyName` via `DisplayName_PublisherId` for the marker/policy layers).
- **Python generated-default `Whitelist` had 4 entries vs. C#/shipped 8** — aligned.
- Python removal now uses `Remove-AppxPackage -AllUsers` when elevated (per-user fallback); both implementations enumerate `Get-AppxPackage -AllUsers` when admin so other users' installs are seen (results deduped).
- PowerShell command injection-safety: blacklist patterns are `''`-escaped before embedding; package queries get bounded `WaitForExit` (180s) instead of unbounded waits.
- **EXE startup crash (critical)**: `PublishTrimmed` removed reflection-based JSON serialization, crashing every command at startup. Replaced with source-generated `GuardJsonContext`.
- **Config toggles ignored**: `RemoveProvisionedPackages`/`ReinstallMonitor` were nested inside `RemoveAppxPackages` — independent toggles now work (C# + Python).
- **Reinstall monitor false positives**: baseline was seeded with *current* packages, so non-admin runs spammed fake "reinstalled" alerts; baseline now seeds from the removal ledger.
- **Inert `--service`**: `python --service` silently forced DryRun, making an installed service permanently inert. Added explicit `--service-dry-run`; `--service` now runs live.
- **Python service could never start**: `sc create` on `pythonw.exe` (not SCM-aware, error 1053). Now requires NSSM or prints a ready-to-run `schtasks` fallback.
- **Empty blacklist/blank entries matched EVERYTHING**: `-match ''` / empty-substring matches removed all Appx packages. Empty patterns now short-circuit.
- **Microsoft system tasks protection dead code**: `MicrosoftSystemPrefixes` had double backslashes (unmatchable) and was never consulted — now enforced with skipped-count logging.
- **Service-mode dry-run mutated system**: startup prevention (registry/tasks) now gated behind `!DryRun` in both implementations.
- **Unknown CLI args ran a real scan**: unrecognized args fell through to console mode (destructive). Now prints usage and exits 1.
- **`--self-test` always exited 0**: failures were invisible to CI (C# now returns the real result; Python already did).
- **BOM crash**: `load_config` now reads UTF-8 with BOM tolerance (Notepad-saved configs).
- **Generated `config.json` lacked `Whitelist`**: first-run configs had zero protection; defaults now include the shipped whitelist.
- **Diverged defaults**: C# `CreateDefault` blacklist was missing 14 shipped entries (Edge, Copilot, Teams, Clipchamp, etc.) — now identical.
- **`verify_scan_sys.ps1` hardcoded `C:\Users\HP`** — now resolves via `$PSScriptRoot`.
- **CI never ran**: `branches: [main]` vs actual `master`, plus stale test signatures — fixed; lint/test-scan/build-csharp now run on every push and PR.
- **`windows-11-admin.yml` ran a real `scan`** on the self-hosted runner every push — replaced with read-only `list-installed`.

### Performance
- Scan resolves PackageFullName in **one** PowerShell call instead of one per package (`get_package_full_names()` batch map; C# returns full names from the initial query).
- Reinstall monitor batch-resolves reinstalled packages (was one PowerShell spawn per package).
- `GuardLogger` no longer re-reads + re-parses `config.json` on every log line.

### Docs
- README: service mode commands, NSSM requirement, removal ledger/restore.
- DESIGN.md: `dry-run` and `--service-dry-run` commands.
- `help` output now lists `--version` and `--self-test`.
