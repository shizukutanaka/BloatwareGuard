# Changelog

All notable changes to BloatwareGuard. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] — v1.11.0-mvp: OneDrive / Chat / Edge / capabilities

### Added
- **4 new prevention layers**:
  - `DisableOneDrive` (**opt-in, default `false`**) — `DisableFileSyncNGSC=1` policy +
    hides the OneDrive pin in Explorer (`CLSID\{018D5C66-…}` `System.IsPinnedToNameSpaceTree=0`,
    all hives). Off by default because it affects active file sync.
  - `DisableChatTaskbar` — hides the Teams Chat taskbar button (`TaskbarMn=0`,
    `HideSCAMeetNow=1` legacy policy, all hives).
  - `DisableEdgeBloat` — Edge policies `HubsSidebarEnabled=0`, `StartupBoostEnabled=0`,
    `AllowPrelaunch=0`, `HideFirstRunExperience=1`.
  - `RemoveOptionalCapabilities` — `Remove-WindowsCapability` for deprecated capabilities:
    `Browser.InternetExplorer`, `App.StepsRecorder`, `Microsoft.Windows.WordPad`
    (conservative list; admin only; skipped when absent).

## [Unreleased] — v1.10.0-mvp: privacy & telemetry hardening

### Added
- **3 new prevention layers** (`Prevention` config flags, default on; key sets mirror
  Win11Debloat `Disable_Telemetry.reg` / `Disable_DVR.reg` / `Disable_Delivery_Optimization.reg`):
  - `DisableTelemetry` — `AllowTelemetry=0`; **DiagTrack** ("Connected User Experiences and
    Telemetry") service stopped + disabled; per-hive: advertising ID, tailored experiences,
    online speech recognition, inking/typing collection (`TIPC`, `InputPersonalization`,
    `HarvestContacts`), feedback frequency (`Siuf\Rules`), `Start_TrackProgs`; HKLM:
    `PublishUserActivities`/`UploadUserActivities=0`, Edge `PersonalizationReportingEnabled=0`,
    `DiagnosticData=0`
  - `DisableGameDvr` — `AllowGameDVR=0` policy + per-hive `GameDVR_Enabled=0`,
    `AppCaptureEnabled=0` (kills Game Bar's background recording buffer)
  - `DisableDeliveryOptimization` — `DODownloadMode=0` policy + per-hive `DownloadMode=0`,
    including the `S-1-5-20` (NETWORK SERVICE) hive the DO service actually reads
- **Layer 9 (`DisableRecall`) extended** — also sets `DisableClickToDo=1` (24H2 "Click to Do"
  AI actions, HKLM + hives) and demotes `WSAIFabricSvc` (AI fabric service) to demand-start.
- **Layer 10 (`DisableSearchSuggestions`) extended** — machine-wide `AllowCortana=0` +
  `CortanaConsent=0` policy (`SOFTWARE\Policies\Microsoft\Windows\Windows Search`).

## [Unreleased] — v1.9.0-mvp: Windows 11 24H2 coverage

### Added
- **Per-user settings now write to every user hive** — loaded `HKEY_USERS\<SID>` profiles + the
  Default-profile template (`C:\Users\Default\NTUSER.DAT`, mounted via `reg load`) + HKCU. Running as
  a SYSTEM service previously wrote HKCU → the *SYSTEM* hive, so suggestion/ad settings never reached
  real users. New profiles created later also inherit them.
- **4 new prevention layers** (`Prevention` config flags, default on):
  - `DisableCopilot` — `TurnOffWindowsCopilot=1` policy (HKLM + all user hives)
  - `DisableRecall` — `WindowsAI` policies `DisableAIDataAnalysis=1`, `TurnOffSavingSnapshots=1`,
    `AllowRecallEnablement=0` + best-effort `Disable-WindowsOptionalFeature Recall` (24H2 Copilot+ PCs)
  - `DisableSearchSuggestions` — `DisableSearchBoxSuggestions=1`, `BingSearchEnabled=0`,
    `CortanaConsent=0` (all hives) — removes Bing web results + suggestions from Start/Search
  - `DisableWidgets` — `AllowNewsAndInterests=0` + `EnableFeeds=0` policies, `TaskbarDa=0` per user
- **`BlockProvisioning` expanded** to the full consumer-suggestion surface (mirrors Win11Debloat
  `Disable_Windows_Suggestions.reg`): all `SubscribedContent-*` keys (incl. Settings suggestions
  338393/353694/353696/353698, lock-screen 338387), `Start_IrisRecommendations` (Start ads),
  `ShowSyncProviderNotifications` (Explorer ads), `ScoobeSystemSettingEnabled` ("finish setup" nag),
  `EnableAccountNotifications`, `Windows.SystemToast.Suggested`, `Mobility\OptedIn`,
  lock-screen `RotatingLockScreen*`.
- **Blacklist: 17 new entries for Windows 11 23H2/24H2-era packages** (key set cross-checked against
  Win11Debloat defaults): `MSTeams` (new Teams — old `MicrosoftTeams` entry did not match),
  `Microsoft.OutlookForWindows` (preinstalled since 23H2), `Microsoft.WindowsCommunicationsApps`
  (Mail/Calendar, discontinued), `MicrosoftCorporationII.MicrosoftFamily`, `...QuickAssist`,
  `Microsoft.BingSearch`, `Microsoft.MicrosoftStickyNotes`, `Microsoft.Edge.GameAssist`,
  `Disney`, `Amazon.com.Amazon`, `AmazonVideo.PrimeVideo`, `LinkedIn`, `Flipboard`,
  `Asphalt8Airborne`, `CyberLinkMediaSuite`, `EclipseManager`; `KING.COM.CandyCrush` widened to
  `KING.COM.` (all King.com promo games).
- **C# service install**: idempotent reinstall (stop+delete existing), service description, and
  `sc failure` restart-on-crash policy (60s/60s/5min).

### Fixed
- **`Microsoft.DevHome` was a dead blacklist entry** — real package is `Microsoft.Windows.DevHome`
  (substring match can't bridge `Windows.`); corrected, which also catches
  `Microsoft.Windows.DevHomeGitHubExtension`.
- **Package enumeration only saw the current user** — `Get-AppxPackage` now runs with `-AllUsers`
  when elevated (fallback to current-user scope otherwise, dedupe by PackageFullName), matching the
  removal path that already used `-AllUsers`.
- **Python lacked the framework-package guard** — `IsFramework` packages (dependency DLLs) are now
  skipped like C#.
- **Python provisioned removal did a second PowerShell lookup per package** — `PackageName` is now
  selected up-front and passed to `Remove-AppxProvisionedPackage` directly (parity with C#).
- **Python removal never tried `-AllUsers`** — admin runs now remove for all users first, falling
  back to per-user (parity with C#).
- **Python-generated `config.json` shipped a 4-entry whitelist** — now the full 8-entry shipped
  whitelist (ShellExperienceHost, Cortana, SecHealthUI, Apprep.ChxApp included).
- `GuardLogger` probed `EventLog.SourceExists` (registry hit) on **every** log line — now once.

## [Unreleased] — v1.8.0-mvp hardening

### Fixed
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
