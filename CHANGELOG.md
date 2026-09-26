# Changelog

All notable changes to BloatwareGuard. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] — v1.32.0-mvp: reinstall monitor covers Win32

### Changed
- `ReinstallMonitor` now watches the Win32 channel too: each scan diffs
  `GetBlacklistedPrograms`/`get_blacklisted_win32` display names and
  re-runs `RemoveProgram`/`remove_win32_program` on new entries. Before
  this, only Appx/provisioned re-installs were caught — but OEM
  updaters re-push the Win32 preinstalls (the primary bloat channel).

## [Unreleased] — v1.31.0-mvp: telemetry tasks — census/family-safety/net-trace

### Changed
- `DisableTelemetryTasks` extended (25 → 29): Device Census `Device` /
  `Device User` (hardware+app inventory upload), `FamilySafetyMonitor`,
  and `NetTrace\GatherNetworkInfo`.

## [Unreleased] — v1.30.0-mvp: telemetry tasks — RetailDemo/Flighting/feedback

### Changed
- `DisableTelemetryTasks` extended (20 → 25): RetailDemo cleanup task,
  three Insider flighting `FeatureConfig` data-collection tasks, and the
  Windows Insider feedback app-usage client. schtasks still ignores
  missing paths, so Office/Insider-less images are unaffected.

## [Unreleased] — v1.29.0-mvp: RemoteRegistry / device-metadata channel

### Changed
- `DisableMiscBloatServices` now **disables** `RemoteRegistry` outright
  (SMB remote-registry attack surface; demand-start would still leave it
  reachable). The other 11 services stay demand-start.
- `BlockOemDriverUpdates` also sets
  `Device Metadata\PreventDeviceMetadataFromNetwork=1` — closes the
  channel OEMs use to silently deliver companion apps/icons alongside
  drivers.
- `BackupRegistry` export set extended (34 keys).

## [Unreleased] — v1.28.0-mvp: no phantom service keys

### Fixed
- Service demotion (`DisableEdgeUpdateBloat`, `DisableXboxServices`,
  `DisableMiscBloatServices`, WSAIFabricSvc in `DisableRecall`) used
  `CreateSubKey`/`CreateKeyEx`, which **created** `Services\<name>` keys
  for vendor services absent from the machine (e.g. `NvTelemetryContainer`
  on non-NVIDIA hardware). All now go through an open-only `DemoteService`
  / `demote_service` helper — missing services are skipped, not created.

## [Unreleased] — v1.27.0-mvp: shared-experiences consent off

### Changed
- `DisableTelemetry` also zeros the Connected Devices Platform consent
  policies (`CdpSessionUserAuthzPolicy`, `RomeSdkChannelUserAuthzPolicy`)
  across every user hive — "Share across devices" / cross-device
  experiences off even though `CDPSvc` is already demand-start.

## [Unreleased] — v1.26.0-mvp: push-install / settings-sync surfaces

### Changed
- `DisableMiscBloatServices` extended: `PushToInstall` (Store push-install
  channel — a known silent-app-delivery vector), `SEMgrSvc` (NFC/SE
  payments manager), `PhoneSvc` (Phone Link). Total: 11 services →
  demand-start.
- `DisableTelemetry` also sets `SettingSync\DisableSettingSync=2`
  (settings roaming to Microsoft accounts off).
- `BackupRegistry` export set extended (33 keys).

## [Unreleased] — v1.25.0-mvp: ad-ID / Find My Device policies

### Changed
- `DisableAppPermissions` also sets HKLM policies
  `AdvertisingInfo\DisabledByGroupPolicy=1` (per-hive ad-ID writes survive
  profile churn only loosely; this is the machine-level guarantee) and
  `FindMyDevice\AllowFindMyDevice=0`.
- `BackupRegistry` export set extended (32 keys).

## [Unreleased] — v1.24.0-mvp: vendor telemetry services / speech models

### Changed
- `DisableMiscBloatServices` extended: `CDPSvc` (Nearby Sharing),
  `NvTelemetryContainer` (NVIDIA driver telemetry), `esrv_svc` /
  `ESRV_SVC_QUEENCREEK` (Intel driver telemetry — absent on machines
  without those vendors). Total: 8 services → demand-start.
- `DisableTelemetry` also sets `Speech_OneCore\ModelDownloadAllowed=0`
  (voice-model download pipeline off).
- `BackupRegistry` export set extended (30 keys).

## [Unreleased] — v1.23.0-mvp: Start recommendations / diagnostic caps

### Added
- **`HideStartRecommendations`** — `Explorer` policy
  `HideRecommendedSection=1` (22H2+): removes Start's "Recommended"
  section, which surfaces promoted apps rather than your own files.

### Changed
- `DisableTelemetry` also caps diagnostic collection
  (`LimitDiagnosticLogCollection`, `LimitDumpCollection`,
  `LimitEnhancedDiagnosticDataWindowsAnalytics`) and sets MRT
  `DontReportInfectionInformation=1`.
- `BackupRegistry` export set extended (29 keys).

## [Unreleased] — v1.22.0-mvp: AutoPlay off / WU forced-reboot prevention

### Added
- **`DisableAutoplay`** — `NoDriveTypeAutoRun=255` + `NoAutorun=1` at HKLM
  and every user hive: removable-media auto-execute off.
- **`NoForcedReboot`** — `WindowsUpdate\AU` `NoAutoRebootWithLoggedOnUsers=1`
  + `AlwaysAutoRebootAtScheduledTime=0`: no more forced restarts while a
  user is logged on.

## [Unreleased] — v1.21.0-mvp: Desktop Spotlight / blacklist additions

### Added
- **`DisableSpotlight`** — Desktop Spotlight off (`DesktopSpotlight\Settings
  Enabled=0` + `Wallpapers\BackgroundType=0`, all user hives). The wallpaper
  surface is also a content-delivery channel for promos.
- **Blacklist +6**: `Booking`, `PicsArt`, `Twitter`, `Evernote`,
  `ExpressVPN`, `Nordcurrent` — recurring OEM/bundled preinstall names
  (config.json ×2 + code defaults). Blacklist now 68 patterns.

## [Unreleased] — v1.20.0-mvp: misc services / SpyNet / Edge surfaces

### Added
- **`DisableMiscBloatServices`** — `dmwappushservice` (WAP push/MDM channel),
  `MapsBroker`, `WMPNetworkSvc`, `diagnosticshub.standardcollector.service`
  demoted to demand-start.

### Changed
- `DisableTelemetry` also sets Defender SpyNet `SpynetReporting=0` +
  `SubmitSamplesConsent=0` (no sample uploads) and
  `AllowExperimentation=0` (Microsoft A/B feature flighting off).
- `DisableEdgeBloat` extended: shopping assistant, content
  recommendations, navigation-error web service, alternate error pages,
  user feedback — all off.
- `BackupRegistry` export set extended to the new keys (26 total).

## [Unreleased] — v1.19.0-mvp: cloud clipboard / Remote Assistance / Insider block

### Added
- **`DisableCloudClipboard`** — `AllowCrossDeviceClipboard=0` policy plus
  `EnableClipboardHistory=0` per-hive. Clipboard content stops syncing to
  Microsoft's cloud (local history stays usable).
- **`DisableRemoteAssistance`** — `fAllowToGetHelp=0`, `fAllowFullControl=0`:
  inbound Remote Assistance offers refused.
- **`BlockInsiderPreview`** — `PreviewBuilds\AllowBuildPreview=0` +
  `HideInsiderPage=1`. Preview builds ship heavier telemetry and
  instability; enrollment is now blocked.

### Changed
- `DisableTelemetryTasks` list extended with the Office CEIP set
  (OfficeTelemetryAgent*/Heartbeat/Feature Updates — 7 tasks, ignored when
  Office is absent). Total: 20 tasks.

## [Unreleased] — v1.18.0-mvp: WPBT block / Reserved Storage release

### Added
- **`BlockOemWpbtExecution`** — `DisableWpbtExecution=1`. The Windows Platform
  Binary Table lets OEMs inject executables into the boot chain via firmware
  (the ASUS Live Update abuse vector) — a documented OEM bloatware
  persistence channel, now ignored by Windows.
- **`DisableReservedStorage`** — `ReserveManager` `ShippedWithReserves=0`,
  `MiscPolicyInfo=2`, `PassedPolicy=0`. Releases the ~7GB Windows sets aside
  for updates; updates then use free disk space as they did pre-1903 —
  helps small-disk devices.

## [Unreleased] — v1.17.0-mvp: registry backup / opt-in Print Spooler

### Added
- **`BackupRegistry`** — before any layer writes, every HKLM key this tool
  touches is `reg export`-ed to `%ProgramData%\BloatwareGuard\backup\`
  (once per process). All policy changes are now one double-click away
  from being reverted.
- **`DisablePrintSpooler`** (**opt-in, default `false`**) — stops + disables
  the Spooler service. Kills the PrintNightmare attack surface on machines
  that never print; off by default since it breaks printing.

## [Unreleased] — v1.16.0-mvp: Xbox services / AutoLogger / capability set

### Added
- **`DisableXboxServices`** — `XblAuthManager`, `XblGameSave`, `XboxNetApiSvc`,
  `XboxGipSvc` demoted to demand-start (`Start=3`). They run permanently on
  machines that never touch Xbox sign-in; demand-start keeps Game Bar and
  Xbox features usable when invoked.

### Changed
- `RemoveOptionalCapabilities` list extended: `XPS.Viewer`, `Print.Fax.Scan`,
  `App.WirelessDisplay.Connect` join IE mode / Steps Recorder / WordPad.
- `DisableTelemetry` also sets the `AutoLogger-Diagtrack-Listener` ETW trace
  to `Start=0` (boot-time telemetry feed, same knob O&O ShutUp10 toggles)
  and disables the Ink Workspace suggestion surface
  (`AllowWindowsInkWorkspace=0`).

## [Unreleased] — v1.15.0-mvp: app permissions / cloud search / RetailDemo

### Added
- **`DisableAppPermissions`** — force-deny (policy value 2) a conservative
  `SOFTWARE\Policies\Microsoft\Windows\AppPrivacy` set of 16 capabilities:
  background-run, account info, call history, contacts, email, messaging,
  motion, notifications, phone, radios, tasks, trusted devices, sync-with-
  devices, diagnostic info, voice activation (incl. above-lock). Camera,
  microphone and location are deliberately left alone — Teams/Weather and
  similar apps legitimately need them.

### Changed
- `DisableSearchSuggestions` now also clears the dynamic search box and AAD/MSA
  cloud search (`SearchSettings\IsDynamicSearchBoxEnabled`,
  `IsAADCloudSearchEnabled`, `IsMSACloudSearchEnabled` — all hives).
- `DisableTelemetry` also stops + disables the `RetailDemo` service.

## [Unreleased] — v1.14.0-mvp: Edge update / WU-OEM channel / RunOnce

### Added
- **2 new prevention layers**:
  - `DisableEdgeUpdateBloat` — `edgeupdate`, `edgeupdatem`,
    `MicrosoftEdgeElevationService` demoted to demand-start (`Start=3`) and the
    three Edge update scheduled tasks disabled. Demand-start keeps manual Edge
    updates working while removing the always-on updater/elevation surface.
  - `BlockOemDriverUpdates` — `ExcludeWUDriversInQualityUpdate=1`: Windows Update
    is a documented OEM bloatware re-delivery channel; drivers now come from the
    vendor only.

### Changed
- `DisableStartupBloat` now also scans `RunOnce` keys (HKLM + every hive) and
  writes the marker under `StartupApproved\RunOnce`.
- `DisableTelemetry` also sets `EnableActivityFeed=0` (HKLM System policy).

## [Unreleased] — v1.13.0-mvp: telemetry tasks / startup bloat / WER

### Added
- **3 new prevention layers**:
  - `DisableTelemetryTasks` — `schtasks /DISABLE` on a fixed list of 13 Microsoft
    data-collection tasks: Compatibility Appraiser (CompatTelRunner — notorious
    CPU/IO hog), CEIP Consolidator/UsbCeip/KernelCeipTask, Autochk Proxy,
    ProgramDataUpdater, PcaPatchDbTask, StartupAppTask, DiskDiagnostic
    DataCollector, Siuf DmClient ×2, Maps Update/Toast. Exact names, not patterns —
    nothing else is touched.
  - `DisableStartupBloat` — enumerates `Run` keys (HKLM 64-bit + WOW6432Node +
    every user hive + Default template) for entries whose name/command matches
    the blacklist or a built-in OEM list (Skype, McAfee, Norton, SupportAssist…),
    then writes the `StartupApproved\Run` **0x03 disabled marker** — the same
    mechanism Task Manager's Startup tab uses, so entries stay listed and can be
    re-enabled (nothing is deleted). OneDrive is deliberately absent from the
    built-in list — its layer stays opt-in.
  - `DisableErrorReporting` — WER `Disabled=1` + `DontSendAdditionalData=1`
    (HKLM + policy key) and per-hive `Disabled`/`DontShowUI`/`LoggingDisabled`.

## [Unreleased] — v1.12.0-mvp: Win32 bloatware + restore point

### Added
- **2 new prevention layers**:
  - `RemoveWin32Programs` — closes the biggest coverage gap: most OEM preinstalls
    (McAfee, Norton, vendor trials) are **Win32 programs, not Appx packages**, so the
    Appx-only pipeline never reached them. Enumerates the `Uninstall` registry keys
    (HKLM 64-bit + WOW6432Node + HKCU + every loaded `S-1-5-21-*` hive), matches
    `DisplayName` against the same blacklist/whitelist, then uninstalls via the
    vendor-supplied `QuietUninstallString` or `msiexec /x {guid} /qn /norestart`.
    Programs with no silent uninstaller are logged for manual removal — vendor
    switches are never guessed. Results recorded in the removal ledger (`kind: win32`).
  - `CreateRestorePoint` — `Enable-ComputerRestore` + `Checkpoint-Computer
    -RestorePointType MODIFY_SETTINGS` before the first destructive step of every
    live scan. Windows self-throttles checkpoints to ~1/24h; failure is non-fatal.

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
