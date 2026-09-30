# Changelog

All notable changes to BloatwareGuard. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] — v1.60.1-mvp: Edge policy expansion

### Added
- noid-privacy AntiAI diff (25H2 WindowsCopilot ADMX): DisableRecall
  +AllowRecallExport=0 +app/URI deny-lists (browsers/terminals/
  password managers/RDP; account/login/mail/payment URIs);
  DisableCopilot +agent framework kills (Agent connectors/workspaces
  force-deny, consent duration/policy minimum) +LetAppsAccessGenerativeAI
  force-deny +DisableRecallDataProviders (per-user); DisableEdgeBloat
  +6 Copilot-in-Edge surface kills.
- VDOT (Virtual-Desktop-Optimization-Tool) diff: blacklist
  +Microsoft.USNationalParks (theme-pack stub, 186->187); misc
  services +BcastDVRUserService/autotimesvc/SmsRouter/icssvc
  (GameDVR broadcast template, cellular time, SMS router, ICS —
  demand-start keeps invocation). Skipped: VSS/defrag/RmSvc/
  MessagingService (functional; restore points need VSS),
  LanManWorkstation SMB tuning (perf).
- ReviOS privacy/misc diff: DisableTelemetry +machine-side input
  kills (Input\Settings InsightsEnabled/EnableHwkbTextPrediction,
  Input\TIPC Enabled) + WiFi Sense family (WcmSvc PaidWifi/
  WiFiSenseOpen/AutoConnectAllowedOEM, PolicyManager default\WiFi
  hotspot reporting/auto-connect). Backup keys 93->97.
- ReviOS search.yml diff: DisableSearchSuggestions +AAD Cortana
  kills (AllowCortanaInAAD/PathOOBE) + WinRT activation neuter for
  WinStore.Tasks.WindowsSearchTask (Store-driven search task).
- ReviOS appx diff: blacklist +Flipgrid (Flip education stub,
  185->186 across all four sites).
- ReviOS updates.yml: DisableWindowsUpdateBloat +SYSTEM\Setup\
  UpgradeNotification UpgradeAvailable=0 (feature-upgrade offer nag off).
  Backup keys 92->93.
- ReviOS privacy.yml: DisableErrorReporting +PCHealth\HelpSvc
  Headlines/MicrosoftKBSearch=0 (online-help fetch channels off).
  Backup keys 91->92.
- ReviOS playbook diff (telemetry.yml/ceip.yml): DisableTelemetry +5 —
  Wow6432Node AllowTelemetry mirror, PolicyManager default-provider
  node, CPSS DevicePolicy/Store overrides (survive CSP re-sync),
  DisableEnterpriseAuthProxy (authenticated-proxy telemetry),
  IE SQM DisableCustomerImprovementProgram. Backup keys 87->91.
- tiny11Coremaker diff: telemetry tasks +Chkdsk\Proxy (event-driven
  disk diagnostic collector, 93->94). Defender service kills / task-file
  deletions / component stripping skipped (security boundary + offline-
  image technique, not applicable to live policy enforcement).
- tiny11builder diff: blacklist +AppUp.IntelManagementandSecurityStatus
  (Intel IMSS OEM support stub, 184->185); DisableChatTaskbar now also
  writes the HKLM 'Windows Chat' ChatIcon=3 policy — the taskbar toggle
  alone only hides the icon, the policy kills the Chat integration
  (backup key added, 86->87).
- Per-layer fault isolation also inside apply_registry_prevention:
  all 33 inline `if prev.get(...)` layer blocks now run under try/except
  (cs ApplyAll was already per-method isolated in the previous commit).
- Per-layer fault isolation: each prevention layer invocation now runs
  in its own try/catch (34 sites in ApplyAll + task/winget/capability/
  registry calls in scan+service+RunOnce; 9 sites py). Previously one
  layer raising an exception aborted every later layer that cycle —
  now it logs and continues (a persistent fault no longer starves
  the rest of the pipeline between scan intervals).
- --restore now covers winget removals: kind="winget" ledger entries
  reinstall via `winget install -e --id` (id-charset checked,
  300s-bounded, no-op without winget) instead of reporting manual.
- Capability removal now restorable: RemoveOptionalCapabilities records
  each removed capability name to the removal ledger (was previously
  unrecorded — invisible to --restore), and --restore reinstalls them
  via Add-WindowsCapability (safe-name checked, 180s-bounded).
- BackupRegistry now covers service config too: every
  Services\<name> key for the demoted/disabled services (misc list +
  _EXTRA_BACKUP_SERVICES for the 13 named demotes/disables) is
  exported so original Start values survive. T12 asserts named
  demote/disable calls stay covered — it immediately caught that
  wercplsupport was demoted in Program.cs but absent from the cs
  misc list (parity gap — now demoted+backed up on both).
- BackupRegistry now covers per-user writes: _USER_BACKUP_KEY_PATHS
  (51 paths — every path written through the per-user hive writers)
  exported under each loaded interactive SID + HKCU alongside the
  HKLM set. Previously the .reg safety net covered machine-scope keys
  only, leaving the bulk of the user-facing knobs (CDM, search,
  suggestions, Copilot surfaces) unrevertable via export. T12 now
  asserts both scopes stay covered going forward.
- T12 fix: py-side extraction now tolerates multi-line
  set_registry_*( "HKLM", ... ) calls — the same blind spot that hid
  the 2 misses it had just caught.
- Self-test T12: HKLM write-path backup coverage — every literal-path
  registry write is asserted covered by _BACKUP_KEY_PATHS (both impls),
  turning the manual audit that found the gap into a permanent gate.
  It immediately caught 2 more misses (TextInput + Bluetooth PolicyManager
  from the hellzerg diff) — added (84->86).
- Backup coverage fix: 15 HKLM write paths were not in
  _BACKUP_KEY_PATHS, so `restore` could not revert them — CBS
  deprovision marker, DiagTrack EventTranscriptKey, Explorer
  (Edge-shortcut suppression), SmartGlass, DeviceHealthAttestation,
  PCHealth WER, Speech, DNSClient, DeviceInstall settings, Messaging,
  WDI GUID, WindowsNotepad, Diagnostics Performance, Lsa,
  LanmanServer. All now exported before first write (69->84).
- bloatbox (W4RH4WK extended hosts) diff: telemetry hosts 116->137 —
  nsatc/akadns CDN aliases (vortex cy2, OneSettings db5, social
  services i1), insider/flighting ring endpoints
  (insiderservice.trafficmanager/insiderppe/flightingserviceweurope),
  Google/Twitter ad-analytics nets (adservice.google.{com,de},
  googleads/pagead46/stats doubleclick, googlesyndication,
  google-analytics, ads-twitter), statsfe1.ws. Skipped: NCSI probes,
  login.live/Skype/Hotmail/XboxLive/Store/WU/Defender-cloud/OCSP/
  corporate-STS/Edge+Akamai+MSN CDNs, WNS push, live tiles (functional
  or auth-bearing). Blacklist 178->184 — publisher namespaces:
  A278AB0D. (absorbs MarchofEmpires entry), 9E2F88E3. (Twitter),
  613EBCEA. (Polarr), 89006A2E. (Autodesk), D52A8D61. (FarmVille),
  DB6EA5DB. (CyberLink), NORDCURRENT. (CookingFever family).
- hellzerg/Optimizer diff: `AllowCloudSearch`=0 (Windows Search cloud
  master), SettingSync per-category kills (app-setting + credential sync,
  both overrides), `AllowLinguisticDataCollection`=0 (TextInput),
  `AllowAdvertising`=0 (Bluetooth device advertising),
  `Edge3PSerpTelemetryEnabled`=0. Skipped: Defender/SmartScreen/AV
  boundary, TPM/upgrade bypasses, Chrome/Firefox/VS vendor policies,
  ~140 UI/perf/lockdown prefs.
- Raphire/Win11Debloat appx diff: blacklist 176->178 —
  `LGElectronics.` namespace (LG OEM stubs) + `COOKINGFEVER` stub game.
  Everything else already covered by existing needles (AD2F1837./
  DellInc./KING.COM./Disney/LinkedIn/PicsArt/CyberLink/4DF9E0F8./Facebook.)
  or functional/whitelisted (Camera/Paint/OneNote/Zune/Xbox/Widgets hosts/
  OneDrive/Copilot provisioned ids/Edge).
- Raphire/Win11Debloat diff: Edge policies `CopilotCDPPageContext`,
  `NewTabPageBingChatEnabled`, `NewTabPageContentEnabled`,
  `TabServicesEnabled`, `DefaultBrowserSettingsCampaignEnabled` =0 and
  `NewTabPageHideDefaultTopSites`=1; per-user `Start_AccountNotifications`=0
  (Start account promo toasts). Skipped: Brave/vendor policies, ~120
  explorer/taskbar/snap/theme/context-menu UI prefs, BitLocker
  auto-encryption toggle (security boundary).
- Disassembler Win10-Initial-Setup-Script diff: Ink Workspace
  `AllowSuggestedAppsInWindowsInkWorkspace=0` (belt for the existing
  AllowWindowsInkWorkspace=0), `DisableEdgeDesktopShortcutCreation=1`
  (update-time Edge shortcut suppression, DisableEdgeUpdateBloat), WMP
  per-user metadata-retrieval trio (windowsmedia.com lookups off).
  Skipped: Defender/UAC/audit/security toggles, ~120 UI/power/UX prefs.
- Telemetry hosts 109->116: ad/feedback ingestion from
  DisableWinTracking's domain diff — DoubleClick ad serving/CDN
  (ad.doubleclick.net, s0/static.2mdn.net), MS ads (b.ads2.msads.net),
  compat-exchange endpoint, search/Windows feedback endpoints.
  Skipped: NCSI (active-probing), Skype/Hotmail/MSN content, Edge/WU
  CDNs, DNS infrastructure (functional).
- Win32 uninstall scan: per-subkey `winreg` handles now released via
  `with` instead of relying on GC finalizers between iterations.
- Dispose the `BingChat` subkey handle opened inline in DisableCopilot —
  the only registry key opened without `using` in the codebase.
- C# PowerShell invocations now pass `-NonInteractive` (11 sites) —
  py `run_powershell` always had it; a prompting cmdlet could hang the
  C# scan until the process timeout killed it.
- T9 now also pins the hosts-block begin/end markers to the C#
  copy — mismatched markers would duplicate the telemetry block.
- T6 now asserts all 46 prevention keys exist in Program.cs —
  a py-only toggle would otherwise skip silently on the C# build.
- T9 now asserts root `config.json` == `src/config.json` — the C#
  build ships the src copy, which had drifted unnoticed before.
- T11 now asserts both directions: cs-only names (e.g. a value name
  written in Program.cs but never in py) fail the gate; C# line
  comments are stripped before extraction so quoted words in
  comments are not mistaken for writes.
- `verify_scan.ps1`: appx before/after snapshot used `-contains` for
  exact-name equality that could never match real package names — probes
  for YourPhone/MicrosoftTeams/Zune were dead. Now substring `-like`
  matching across all probe names.
- C# service ops: install/stop/delete waited with 60/30s timeouts
  (stop now completes before delete fires), `sc query` output read
  bounded instead of an unbounded synchronous `ReadToEnd`.
- Service install/uninstall/status shell-outs now go through `run_cmd`
  (30s timeout) instead of bare `subprocess.run` — a hung SCM or missing
  NSSM can no longer stall the admin CLI paths.
- `T11` self-test: registry value-name parity (py → cs). Every value
  name the Python impl writes (call args, loop variables, (name, value)
  tuple loops) must appear in Program.cs — drift between the mirrored
  payloads now fails the gate instead of shipping silently.
- Atlas-OS playbook diff — 165-value audit, adopted the in-scope
  privacy/hardening set across existing layers:
  - `DisableTelemetry`: LLMNR off (`EnableMulticast`), anonymous
    SAM/null-session enumeration off (`RestrictAnonymous`,
    `RestrictAnonymousSAM`, `RestrictNullSessAccess`), WDI
    `ScenarioExecutionEnabled`, `RSoPLogging`, DiagTrack
    `EnableEventTranscript`/`MiniTraceSlotEnabled`,
    `DisableDiagnosticTracing`, Device Health Attestation,
    speech-model auto-download, cloud message sync, SettingSync
    extras, per-user CDM master switches + `NoInstrumentation` +
    input `InsightsEnabled`/`SyncPolicy`.
  - `DisableErrorReporting`: PCHealth `DoReport`, CBS
    `DisableWerReporting`, device-install WER spill sends.
  - `DisableSpotlight`: per-user Spotlight policy +
    welcome-experience/action-center/settings kills.
  - `DisableSearchSuggestions`: `EnableDynamicContentInWSB`.
  - `DisableMiscBloatServices`: NetBIOS-over-TCP/IP (`NetBT`) demoted —
    legacy LAN name protocol matching the LLMNR kill.
  - Skipped: UAC secure-desktop off (weakens security), MS-account
    block, kernel/page/MMCSS perf tweaks, ~100 Explorer/UX
    preference values, crash-dump disables, Office/vendor telemetry.
- `DisableTelemetry` .NET hardening (simeononsecurity
  Windows-Optimize-Harden-Debloat): `SchUseStrongCrypto` = 1 and
  `AllowStrongNameBypass` = 0 under both 64/32-bit .NET v4
  Framework roots — forces strong TLS for .NET apps and closes
  the strong-name verification bypass.
- `DisableEdgeUpdateBloat` EdgeUpdate shortcut suppression (Sophia
  Script `PreventEdgeShortcutCreation`): `CreateDesktopShortcut{GUID}`
  = 0 for all four channel product GUIDs — the installer previously
  re-dropped a desktop Edge shortcut on every update.
- `DisableEdgeBloat` +18 policy disables (privacy.sexy
  SetEdgePolicyViaRegistry diff): `BingAdsSuppression`,
  `DiscoverPageContextEnabled`, `EdgeDiscoverEnabled`,
  `EdgeEnhanceImagesEnabled`, `MetricsReportingEnabled`,
  `RelatedMatchesCloudServiceEnabled`, `SendSiteInfoToImproveServices`
  (deprecated but still read), `ShowMicrosoftRewards`,
  `SignInCtaOnNtpEnabled`, `SpotlightExperiencesAndRecommendationsEnabled`,
  `StandaloneHubsSidebarEnabled`, `AllowGamesMenu`, `InAppSupportEnabled`,
  `ShowAcrobatSubscriptionButton`, `WebWidgetIsEnabledOnStartup`,
  `SearchbarAllowed`/`SearchbarIsEnabledOnStartup`, and
  `ExperimentationAndConfigurationServiceControl` (ECS experiments).
  Deliberately skipped: the whole SmartScreen family (protection
  boundary), `FamilySafetySettingsEnabled` (functional), autofill
  toggles (convenience, not telemetry), cookie/tracking policies
  (browsing-behavior changes), NTP cosmetic settings.

## [Released] — v1.59.2-mvp: deploy/docstaleness + exe metadata

### Fixed
- `deploy_verify.bat` was three versions stale (v1.56.0 header), hardcoded a
  build-dependent binary size, and referenced obsolete "layers 2-6" wording —
  version strings, size claim, and layer phrasing brought current.
- `BloatwareGuard.exe` had no PE version metadata (right-click → Details
  showed nothing, and tools like winget/SCCM can't inventory the install) —
  csproj now carries `Version`/`InformationalVersion`.
- README repeated the hardcoded binary size — genericized like the bat.

## [Unreleased] — v1.59.1-mvp: WindowsSpyBlocker hosts diff + diagnostics task

### Added
- Telemetry hosts 69→109 (WindowsSpyBlocker data/hosts/spy.txt diff): pure-
  telemetry pipes (vortex/settings sandbox + PPE envs, glbdns2 aliases, oca/
  umwatsonc/remoteapp pipes, activity test endpoint, residual Cortana, Edge
  offers, legacy IE web service, GameDVR asset CDN) + ad-delivery endpoints
  feeding MSN/Edge/widget surfaces (adnxs/adnexus, msn ads/rad variants,
  msads, serving-sys, flashtalking, atdmt set, adtech.de, footprintpredict).
  Skipped: *.wns.windows.com (~100 per-region push servers — breaks push
  notifications), trafficmanager.net/akadns.net CNAME aliases (only resolved
  inside the DNS chain, never queried literally), llnw/v0cdn CDN edges,
  Teredo ipv6.microsoft.com, and WU/signon-capable live.com/Office pipes.
- Telemetry tasks +1: `\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem`
  (Winhance diff — diagnostic ETW collection task).
- Blacklist 171→176 (RemoveWindowsAI $aipackages + winutil WPFTweaksWindowsAI
  diff): the Copilot+ AI client packages none of the Store-app lists cover —
  `MicrosoftWindows.Client.CoreAI` (AI platform hosting Recall/ClickToDo
  runtime), `MicrosoftWindows.Client.AIX` (AI experience shell),
  `MicrosoftWindows.Client.CoPilot` (Copilot client — distinct package from
  `Microsoft.Copilot`), `Microsoft.Windows.Ai.Copilot.Provider`, `aimgr`
  (AI Manager). Skipped: `MicrosoftWindows.Client.CBS`/`.Core`/`.Photon`
  (inbox shell components), `MicrosoftWindows.*.Voiess/Speion/Livtop/Filons`
  (Copilot+ voice/vision components — wildcard-only references, package
  names unverified), `Microsoft.AIFabric.CBS` (explorer dependency per
  RemoveWindowsAI itself; WSAIFabricSvc is already demand-started),
  `Microsoft.Ink.Handwriting` (functional input pack).
- Blacklist 156→171 (xd-AntiSpy DebloaterPlugin.json diff): OEM promo/
  collection stubs (`HPJumpStart`, `ASUSGiftBox`, `AcerCollection`,
  `DellDigitalDelivery`, `DellSupportAssist`) + third-party promo
  preinstalls (`GAMELOFTSA`, `KhanAcademy`, `AsanaInc.Asana`, `Luminar`,
  `DropboxInc.Dropbox`, `TripAdvisor`, `Uber`, `WildTangent`, `SaferVPN`,
  `SymantecCorporation`). Vendor-product needles, not bare vendor names —
  the existing commented-out `HPInc.`/`DellInc.Dell`/`Lenovo.`/`ASUS`
  prefixes stay opt-in. Skipped: `Apple`/`Adobe`/`Corel`/`Google`/`Amazon`
  (legit-app publishers), single-word game names (`Farm`/`Heroes`/`Gears`/
  `Tsum`/`Tetris` — substring-collision risk vs. non-promo packages),
  Office apps + Calculator/Camera (functional), `BioEnrollment` (Windows
  Hello biometrics), `Microsoft.Feedback` (Feedback Hub already covered),
  classic UI toggles.
- hellzerg/Optimizer diff (privacy tweaks): +`SubscribedContent-88000326Enabled`
  CDM id (Edge/app promotions), `DisableWebSearch=1` policy under
  `DisableSearchSuggestions` (web results in Start — one level deeper than
  the existing Bing/suggestion switches), and `SmartGlass UserAuthPolicy=0`
  under `DisableXboxServices` (deny Xbox companion-app connections).
  Skipped: `EnableWebContentEvaluation=0` (SmartScreen for app web content —
  security path), `MaxTelemetryAllowed` (undocumented value), `SafeSearchMode`
  (already covered), XPS print feature + Fax printer removal (functional),
  VS Telemetry (dev tool), language/attachment/zone-map settings (out of
  scope or security).
- `DisableEdgeBloat` +3 values (xd-AntiSpy diff): `ImportOnEachLaunch=0`
  (Edge re-imports foreign browser data on every launch),
  `DefaultBrowserSettingEnabled=0` (set-default nag),
  `NewTabPageQuickLinksEnabled=0` (NTP sponsored quick links). Skipped:
  `BrowserSignin`/`GamerModeEnabled` (functional features),
  `NewTabPageHideDefaultTopSites` (UI preference + inverted semantics in
  source), location ConsentStore (deliberately untouched),
  `GlobalUserDisabled` background apps (kills all background apps),
  OOBE `DisablePrivacyExperience` (functional OOBE change), UI toggles
  (TaskbarDa/Al, ShowTaskViewButton, classic context menu, verbose logon).

### Fixed
- Python `get_blacklisted_packages` deduped `-AllUsers` rows by family —
  when two versions of the same family coexisted (inbox update pending),
  only the first was removed while C# removed all versions. Dedupe now keys
  on PackageFullName like C# (family fallback for empty full_name).
- `--restore` interpolated the ledger's `name` into a PowerShell string
  unvalidated — a malformed/hand-edited ledger entry could break quoting.
  Both impls now skip entries outside the package-name charset
  (`_safe_pkg_name` / `AppxManager.IsPackageNameSafe`, widened to internal).
- `ScanIntervalSeconds` was unvalidated: `0`/negative values would spin the
  service loop (`time.sleep(0)` busy-loop in Python, `Task.Delay` range
  exception in C#) and non-numeric values crashed the Python loop. Both
  impls now clamp to a 60s floor with a warning (non-numeric falls back to
  the 300s default).
- `--uninstall`/`uninstall` left the tool-owned hosts block behind forever —
  a deleted tool permanently null-routing 109 telemetry/ad domains with no
  removal path. Uninstall now strips the marked block before returning
  (both impls). Registry policies and deprovision/startup markers
  intentionally persist: they are the hardening itself, not service state,
  and reversing them would re-enable what the tool was installed to kill.
- `CreateRestorePoint` hardcoded `-Drive 'C:\'` for `Enable-ComputerRestore`
  — on systems whose OS volume isn't C: (multi-boot, relocated installs)
  it enabled System Restore on the wrong drive. Both impls now pass
  `$env:SystemDrive`.
- `verify_scan.ps1` printed the appx diff backwards: `SideIndicator "=>"`
  lists packages that *appeared* after the scan, not removed ones —
  corrected to `"<="`.
- DESIGN.md layer table was missing the `DisableModernStandbyNetworking`
  opt-in row — all 46 prevention layers now documented.
- Logging resilience (product-completeness audit): Python `setup_logging`
  ran `mkdir` outside the try, so an unwritable LogFilePath crashed before
  any console output instead of falling back to console-only — mkdir moved
  inside and the catch broadened to OSError. C# `GuardLogger.Write` used
  `File.AppendAllText` without creating the parent dir, so file logging
  silently did nothing until some other component created it — now creates
  the directory on write (caught, non-fatal either way).

## [Unreleased] — v1.58.0-mvp: 32-bit autostart coverage + blacklist expansion

### Added
- `BackupRegistry` coverage completion (36→68 keys): self-audit diffed every
  HKLM path the tool writes against `_BACKUP_KEY_PATHS` and found ~30
  policy-key gaps — the docstring promises "every HKLM key this tool
  touches" is exported for double-click restore. Added the missing write
  paths (DataCollection, WindowsUpdate Orchestrator/UX, PushToInstall,
  TabletPC/Handwriting/EdgeUI, OOBE/Communications, FeatureManagement
  overrides, et al.) so `--uninstall` restore actually covers all writes.
  Deliberately skipped: per-user hive exports — the backup runs under the
  elevated caller so HKCU only captures the admin's own hive, not the
  targets'; exporting every loaded `HKU\S-1-5-21-*` hive for a manual
  restore aid adds complexity out of proportion to its value. HKLM
  machine-scope is the meaningful restore surface.
- Self-test guard registration gap closed: T9 parity + T10 dup-free now
  cover the 11 previously-unregistered shared constants
  (`_ACTIVE_SETUP_PATHS`, `_VELOCITY_AI_IDS`, `_VELOCITY_COPILOT_IDS`,
  `_DEPROVISIONED_PATH`, `_REMOVE_DEFAULT_PKGS_PATH`, `_USER_*` x5)
  and C# T8 gained `ActiveSetupPaths` + `Win32BloatNames`; structured
  (subkey, value) tuple entries are checked per string component.
- 29 blacklist entries (85→114), diffed against Raphire/Win11Debloat's
  default-removal app list: 10 Microsoft apps (`3DBuilder`, six
  discontinued `Bing*` consumer apps, `News`, `PCManager`,
  `Windows.AIHub`) and 19 third-party OEM/promo entries
  (`ACGMediaPlayer`, `ActiproSoftwareLLC`, `AdobePhotoshopExpress`,
  `AutodeskSketchBook`, `CaesarsSlotsFreeCasino`, `DrawboardPDF`,
  `FarmVille2CountryEscape`, `HULUPLUS`, `HiddenCity`, `NYTCrossword`,
  `OneCalendar`, `PhototasticCollage`, `Polarr`, `LiveWallpaper`,
  `SlingTV`, `TuneInRadio`, `WinZipUniversal`, `RoyalRevolt`,
  `iHeartRadio`). Deliberately skipped: `Microsoft.Office.OneNote`
  (exclusion policy), `MicrosoftPowerBIForWindows` (business tool),
  `XP9CXNGPPJ97XX` (WebExperiencePack — breaks Widgets; the toggle
  already covers it), `COOKINGFEVER` (covered by `Nordcurrent`).
- 6 blacklist entries (114→120) from the Recommendation-field pass: OEM
  publisher prefixes `AD2F1837.` (all 21 HP appx bundles), `DellInc.`
  (3 apps), `E046963F.LenovoCompanion`, `LenovoCompanyLimited.
  LenovoVantageService`, plus `Microsoft.M365Companions` (24H2 promo)
  and `Facebook.Instagram` (stable — only the Beta family was listed).
  Skipped: `LGElectronics.LGMonitorApp` (functional monitor utility),
  Paint/Calculator/Camera/Notepad/RemoteDesktop/OneDrive/
  StartExperiencesApp/WidgetsPlatformRuntime (utilities or components,
  not bloat; Calculator/Notepad already whitelisted anyway).
- New opt-in layer `DisableModernStandbyNetworking` (46th toggle, default
  false): ConnectivityInStandby power policy (`AC/DCSettingIndex=0`) —
  severs network during Modern Standby, stopping background sync/telemetry
  while asleep on S0 systems. Source: Win11Debloat DisableModernStandbyNetworking.
- `DisableCloudContent`: added `DisableConsumerAccountStateContent=1`
  (CloudContent policy — hides Microsoft 365 Copilot ads on Settings Home).
- `HideStartRecommendations`: added per-user-hive
  `Start\Companions\Microsoft.YourPhone_8wekyb3d8bbwe\IsEnabled=0` — disables
  the Phone Link companion panel in Start. Skipped as out-of-scope: location
  services (deliberate exclusion), BitLocker auto-encryption (security
  trade-off), Drag Tray/notification/UI-preference tweaks.
- 1 telemetry task (57→58), diffed against Sophia Script + privacy.sexy:
  `\Microsoft\Windows\Application Experience\MareBackup` — gathers Win32
  app data for the Windows Backup app scenario (24H2+).
- `DisableTelemetry`: `AppCompat\DisableInventory=1` (Application
  Compatibility Inventory collector — app inventory telemetry).
  Disassembler0 parity; that script's task/service diffs were already
  covered.
- `DisableTelemetry`: `MaxTelemetryAllowed=1` (policy cap at Security/
  Basic even if AllowTelemetry is re-raised) + per-user-hive
  `Diagnostics\DiagTrack\ShowedToastAtLevel=1` (silences the
  settings-changed toast). Sophia Script parity.
- `DisableTelemetry`: also stops+disables `WerSvc` (Windows Error
  Reporting — crash-dump upload path; QueueReporting task and WER hosts
  were already covered). Matches Sophia Script's ErrorsReporting tweak.
- `DisableTelemetry`: blocks the DiagTrack outbound firewall rules —
  `Get-NetFirewallRule -Group DiagTrack | Set-NetFirewallRule -Enabled
  True -Action Block` (Sophia Script kill-chain). The "Unified Telemetry
  Client Outbound Traffic" rules exist but default to Allow; this makes
  the block survive even if a component re-enables the service.
- 2 service-demote entries (44→46), diffed against winutil's service
  tweak list: `StorSvc` (storage settings) and `CscService` (Offline
  Files — legacy enterprise sync dead on consumer installs). Skipped:
  `SharedAccess` (ICS is already demand-start; disabling breaks mobile
  hotspot). winutil's registry tweaks were verified already covered
  (Activity History upload, WPBT, Notepad AI, CloudContent, DO).
- 12 telemetry-host entries (46→58), diffed against WindowsSpyBlocker's
  spy list: the actual DiagTrack ingest FQDNs `v10/v20.vortex-win.data.
  microsoft.com` (only the CNAME base was blocked before), the Edge ARIA
  pipe `browser.pipe.aria.microsoft.com`, additional WER ingest names on
  `*.events.data.microsoft.com` (`umwatson`, `nw-umwatson`, `kmwatson`,
  `kmwatsonc`), and legacy CEIP/WER endpoints (`df/alpha/ca.telemetry.
  microsoft.com`, `telemetry.microsoft.com`, `watson.live.com`).
  Skipped: sovereign-cloud (`.us`), Azure-service, sandbox, and
  akadns/GLB load-balancer intermediate names.
- Telemetry hosts 58→69 — regional ingest mirrors and sibling pipes from
  WindowsSpyBlocker's "extra" tier (`eu/us-v20.events.data.microsoft.com`,
  `eu/us.vortex-win.data.microsoft.com`, `eu.vortex.data.microsoft.com`,
  `server6/7.pipe.aria.microsoft.com`, `browser.events.data.msn.com`,
  `ic3`/`mobile`/`teams.events.data.microsoft.com`). The rest of that tier
  is deliberately skipped: it null-routes OneDrive, Windows activation,
  SmartScreen and support sites.
- `BlockProvisioning` +3 anchors (tiny11builder diff): policy
  `DisablePushToInstall=1` (third anchor on the push-install channel —
  demoted service + disabled task already existed), `Teams\Disable
  Installation=1` (Teams keeps coming back via Store), and the
  `UScheduler{,_Oobe}\{OutlookUpdate,DevHomeUpdate} workCompleted=1`
  markers so Windows Update treats forced new-Outlook/DevHome pushes as
  delivered. Skipped: MRT `DontOfferThroughWUAU` (declines a security
  tool), `Windows Mail PreventRun` (hard-blocks a functional app),
  install-bypass knobs (LabConfig/BypassNRO), BitLocker opt-out, and
  tiny11's functional removals (Terminal, Paint, OneNote, GetHelp).
- Demote services 47→49 (Atlas services.yml diff): `TrkWks` (Distributed
  Link Tracking — Microsoft 'OK to disable' per IoT/VDI guidance) and
  `wercplsupport` (WER control-panel support, companion to the disabled
  `WerSvc`). Skipped: `UCPD` (protects default-app choice), drivers
  `GpuEnergyDrv`/`NetBT`/`Telemetry` (out of demote scope / risky), and
  Atlas's file-sharing/location/search removals (functional or covered).
- `BlockProvisioning` + `ConfigureChatAutoInstall=0` on
  `HKLM\...\Communications` — the documented Chat/Teams consumer
  auto-install channel (Atlas appx.yml); complements `Teams
  DisableInstallation`.
- Blacklist 140→143 (Sycnex Windows10Debloater diff): dead Microsoft
  products still shipped by images — `Microsoft.Office.Lens` (retired
  Jan 2021), `Microsoft.Office.Todo.List` (folded into Microsoft To Do),
  `Wunderlist` (killed 2020). Skipped: `Microsoft.StorePurchaseApp`
  (Store infra), `Microsoft.PPIProjection` (system component),
  `CanonicalGroupLimited.UbuntuonWindows` (functional WSL distro),
  `Microsoft.RemoteDesktop`/OneNote (utilities), and entries already
  covered by `KING.COM.`/`Microsoft.Zune`/`Microsoft.Xbox` prefixes.
- privacy.sexy corpus diff (934 registry paths / 123 value names — most
  out of scope: WU deferral, SCHANNEL/SMB hardening, DeviceGuard,
  Office-internals, UI prefs). Adopted in-scope adds: per-hive
  `HideNewOutlookToggle=1` + `NewOutlookMigrationUserSetting=0`
  (classic-Outlook migration surface, Office-side sibling of
  `DoNewOutlookAutoMigration`), `CrossDeviceEnabled=0` (cross-device
  consent on Mobility), `SafeSearchMode=0` + `ShowDynamicContent=0`
  (Search highlights/dynamic content), and `DisableCopilot` per-hive
  `AutoOpenCopilotLargeScreens=0` (Copilot auto-open channel).
- Blacklist 143→148 (simeononsecurity Windows-Optimize-Debloat diff):
  `Microsoft.WindowsPhone` (dead companion), `Fitbit.FitbitCoach`,
  `KeeperSecurityInc.Keeper`, `ShazamEntertainmentLtd.Shazam`,
  `XINGAG.XING` (promo preinstalls). Skipped: `PowerBIForWindows`
  (business tool) and `CAF9E577.Plex` (functional app removed by only
  that list). Its other ~90 names are covered by existing prefixes.
- Telemetry tasks 58→61 (zoicware/RemoveWindowsAI task set): Recall
  snapshot tasks `WindowsAI\Recall\InitialConfiguration` +
  `PolicyConfiguration` and `\Microsoft\Office\Office Actions Server`
  (Office AI Actions). `DisableRecall` also now silences the four 25H2
  AI-platform event-log channels (`Microsoft-Windows-AI-ModelContext
  Protocol` + `AI-Platform`, admin + operational).
- Blacklist 148→152 (ReviOS playbook / meetrevision diff):
  `Microsoft.Windows.SecureAssessmentBrowser` (Take-a-Test),
  `Microsoft.Windows.PeopleExperienceHost` (People host backend),
  `MicrosoftCorporationII.MailforSurfaceHub` (Surface Hub mail),
  `OutlookPWA` (New Outlook PWA package name — the existing
  `Microsoft.OutlookForWindows` entry covers the other family name).
  Skipped: Office Excel/PowerPoint/Word appx (functional Office apps),
  `Microsoft.StartExperiencesApp` (Start menu host).
- `_WIN32_BLOAT_NAMES`/`Win32BloatNames` 79→85 — HP serviceware channel
  (Spiceworks HP-debloat canon): Connection Optimizer, Documentation,
  Notifications, Security Update Service, Sure Recover, Sure Run Module.
  `HP Wolf Security` excluded — a real AV product, not trial nagware.
- Telemetry tasks 61→62: `Application Experience\SdbinstMergeDbTask`
  (shim-DB merge on the same AppCompat collection pipeline — privacy.sexy).
  Skipped: UpdateOrchestrator Schedule-Scan/UUS-Failover/UpdateModel
  (servicing infrastructure, not telemetry).
- Demote services 49→51 — ReviOS services.yml diff: `dam` (Desktop
  Activity Moderator), `Telemetry` (Intel driver), `Wecsvc` (Event
  Collector). Skipped: `tcpipreg`/`condrv`/`NetBT`/`GpuEnergyDrv`/`UCPD`
  (network/driver/protected components — ReviOS marks them experimental).
  Also corrected the stale service counts in the applied-log strings
  (44→51) and README (49→51).
- `DisableTelemetry` +4 policy values — ReviOS privacy/telemetry.yml:
  `DisableTelemetryOptInSettingsUx=1` (hides the level picker),
  `AllowCommercialDataPipeline=0`, `AllowDeviceNameInTelemetry=0`,
  `MicrosoftEdgeDataOptIn=0`. Skipped: `DisableEnterpriseAuthProxy`
  (enterprise proxy), CPSS consent-store entries, Wow6432Node policy
  mirror (redirected view of the same key). ReviOS
  deprovisioned-apps.yml is fully covered by the existing blacklist
- `DisableCloudContent` per-user CDM +5 SubscribedContent IDs —
  ReviOS privacy/cdm.yml: 314559/280815/202914/280810/280811
  (OneDrive promotions, SyncProviders ad, Start ads). Skipped:
  Subscriptions/SuggestedApps key deletion (value-off is reversible).
- `DisableErrorReporting` +2 WER consent-policy values (ReviOS
  privacy/wer.yml): `DefaultConsent=0` + `DefaultOverrideBehavior=1`.
- `DisableTelemetry` — ReviOS privacy/app-compat/ceip diffs (~20
  values): WerSvc outbound firewall block (alongside DiagTrack),
  AppCompat `DisableEngine`/`DisableUAR`, CEIP stragglers (App-V,
  Messenger, unattend SQM), EventViewer online links off,
  `DisableHelpSticker`, handwriting error-report/data-sharing off,
  web-printing channels off, Explorer online wizards off
  (HKLM+per-user), Help&Support feedback channel off (per-user),
  EdgeUI `DisableMFUTracking`, NVIDIA `OptInOrOutPreference=0`.
- `DisableXboxServices` — neuter the Xbox GamingAI companion host's
  WinRT activation (ActivationType=0xffffffff + empty Server; ReviOS
  privacy.yml — stops GameAssist).
  Skipped: `SbEnable`/`MSAOptional`/`NoGenTicket` (ambiguous or
  activation-adjacent), XP-era dead targets (MovieMaker, ICW,
  PCHealth, SearchCompanion), DiagTrack/WerSvc firewall *rule
  injection* (registry FirewallRules writes — we block via
  Get/Set-NetFirewallRule instead).
- `DisableTelemetry` — ReviOS updates/ms-store diff: `WindowsStore`
  `AutoDownload=4` + `DisableOSUpgrade=1`, `BlockedOobeUpdaters`
  (OOBE Outlook push), `HideMCTLink`, WMP `DisableAutoUpdate`.
  Skipped: `RestartNotificationsAllowed2`/`UpgradeAvailable`/
  `ShippedWithReserves` (functional update behavior, not promo).
- `BlockProvisioning` — ReviOS notifications.yml: mark second-chance
  OOBE done (`ScoobeCheckCompleted`), tray balloon feature ads off
  (`NoBalloonFeatureAdvertisements`/`NoAutoTrayNotify`, per-user),
  `NoCloudApplicationNotification` (HKLM promo-toast channel).
  Skipped: OOBE page-show/hide set, `UpdateNotificationLevel`, Office
  ClickToRun tuning (functional/UX preferences).
- Blacklist 152→156 — W4RH4WK Debloat-Windows-10 diff:
  `A025C540.Yandex.Music` (RU-region preinstall),
  `Microsoft.WindowsFeedback` (legacy Win10 feedback app),
  `Microsoft.MicrosoftReadingList` (dead), `Microsoft.MSPaint`
  (Paint 3D — deprecated UWP; classic paint.exe unaffected).
  Skipped: `Microsoft.BioEnrollment` (Hello biometric enrollment —
  system component), telemetry IP blocks (firewall IPs rot — we
  block by hostname instead).
  entries + Deprovisioned markers.

- `RemoveWin32Programs`: new `_WIN32_BLOAT_NAMES`/`Win32BloatNames`
  needle list (79 entries) merged into the Win32 DisplayName scan —
  appx publisher prefixes never appear in DisplayName strings, so OEM
  support-ware (`SupportAssist`, `HP Support Assistant`, `MyASUS`,
  `Acer Collection`, `MSI Center`, `Armoury Crate`, `Nahimic`,
  `Killer Intelligence`), PUA optimizers (`IObit`, `Advanced SystemCare`,
  `Driver Booster`/`Easy`/`Tonic`, `SlimWare`, `Outbyte`, `Restoro`,
  `PCRepair`, `TotalAV`, `ScanGuard`…), and the legacy adware/toolbar
  canon (TronScript's programs_to_target_by_name: `Ask Toolbar`,
  `Conduit`, `Wajam`, `Yontoo`, `OpenCandy`, `WildTangent`, `Big Fish`…)
  are now covered. Vendor-bare names deliberately excluded — `HP` is a
  substring of `Touchpad`.
- Blacklist 120→140, diffed against TronScript's Metro app removal list
  (bmrf/tron, 968 user-curated entries — only dead/promo/game-demo
  Microsoft appx adopted; its 3rd-party list nukes user-installed
  utilities like Rufus/QuickLook and stays out): `Microsoft.Advertising.
  JavaScript`/`Xaml` (ad SDK frameworks), `ConnectivityStore` (carrier
  commerce channel), `HelpAndTips`, `HoganThreshold` (OEM factory test),
  `MicrosoftRewards`, `TreasureHunt`/`Jackpot`/`Jigsaw`/`Sudoku`/
  `Mahjong`/`Studios.Wordament` (legacy game promos), `MovieMoments`,
  `SkypeWiFi` (dead), `FeatureOnDemand.InsiderHub`, `ReadingList`,
  `Zune` (subsumes former `ZuneMusic`/`ZuneVideo` entries), `FreshPaint`,
  `MinecraftUWP`, `ForzaHorizon3Demo`/`ForzaMotorsport7Demo`, `BingMaps`.
  Skipped: `BioEnrollment`/`Lucille`/`CBSPreview`/`ContactSupport`
  (system/functional components), `PowerBIForWindows`/`StickyNotes`/
  `Journal`/`DiagnosticDataViewer`/`SurfaceDiagnostics` (utilities),
  language packs, `WorldNationalParks`/`FrenchRiviera` (theme packs).
- `DisableMiscBloatServices` 46→47: `WSAIFabricSvc` (Windows AI Fabric —
  Copilot+ AI API backend; demand-start, Win11Debloat
  DisableAISvcAutoStart / winutil).
- `DisableGameDvr`: `ms-gamebar`/`ms-gamebarservices` protocol hijack —
  `NoOpenWith` + a dead handler command (`%SystemRoot%/System32/
  systray.exe`) kills the "get Game Bar" popup games trigger when the
  app is removed (Win11Debloat Disable_Game_Bar_Integration).
- `BlockProvisioning`: `IsContinuousInnovationOptedIn=0` — opts out of
  "get the latest updates ASAP" continuous-innovation feature drops
  (winutil Disable_Update_ASAP).
- `BlockOemDriverUpdates`: `DisableCoInstallers=1` on
  `SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer` — blocks
  vendor driver co-installers, the channel that seeds OEM companion apps
  alongside driver packages (winutil).
- `BlockProvisioning` per-user suggestions: `DoNewOutlookAutoMigration=0`
  — stops the Mail/Calendar → "new Outlook" forced migration nudge
  (winutil).
- `DisableEdgeBloat`: `MicrosoftEdgeInsiderPromotionEnabled=0`,
  `WalletDonationEnabled=0` (Insider/donation promos) and
  `ConfigureDoNotTrack=1` (winutil Edge set).
- Startup-bloat name list 14→32: promo suites + OEM utilities that
  re-register autostart (`Teams`, `YourPhone`, `PhoneLink`, `Xbox`,
  `EdgeUpdate`, `Armoury`, `Nahimic`), promo-installed third parties
  (`Spotify`, `Opera`, `Adobe`, `iTunes` — markers stay re-enableable),
  and PUA-tier optimizer/driver-updater vendors (`IObit`, `DriverBooster`,
  `DriverEasy`, `SlimWare`, `Outbyte`, `Restoro`, `Wondershare`,
  `PCHealth`).

### Fixed
- Whitelist 8→12: `Microsoft.Xbox.TCUI`, `Microsoft.XboxIdentityProvider`,
  `Microsoft.XboxSpeechToTextOverlay`, `Microsoft.GetHelp` — the broad
  `Microsoft.Xbox`/`Microsoft.GetHelp` blacklist prefixes would otherwise
  remove them; Win11Debloat marks all four unsafe (breaks Store, Photos,
  some games, and the accessibility overlay; GetHelp feeds
  troubleshooters).
- `Policies\Explorer\Run` autostart vector (HKLM + every user hive) —
  entries Task Manager never lists and StartupApproved can't mark;
  bloat matches are deleted with their data logged for manual restore.
- Per-user-hive startup scan covered only the native `Run`/`RunOnce`
  views; 32-bit installers can also register per-user autostart under
  `HKCU\SOFTWARE\WOW6432Node\...\Run`/`RunOnce` (listed by Sysinternals
  Autoruns). Both impls now scan those views in every user hive and mark
  matches with the same StartupApproved 0x03 marker, with the peer-view
  name-collision guard applied symmetrically.

## [1.57.0-mvp] — startup-surface coverage

### Fixed
- Startup-bloat scan missed the 32-bit `RunOnce` view
  (`HKLM\SOFTWARE\WOW6432Node\...\RunOnce`) — 32-bit installers could
  register autostart entries there untouched. Both impls now mark it
  with the same StartupApproved\RunOnce 0x03 marker.
- `_scan` (py) no longer aborts the whole prevention pass when the
  HKLM StartupApproved marker write hits `PermissionError` (non-admin):
  marker creation/write failures are logged and skipped per entry.
- StartupApproved markers are name-keyed and shared across the 64/32-bit
  registry views; both impls now skip stamping a name that a non-bloat
  entry in the peer view also uses (avoids disabling a same-named
  legitimate autostart).

## [Unreleased] — v1.56.0-mvp: service-list dedup + AI-surface hardening

### Added
- `DisableCopilot` extended (both impls): shell eligibility suppression
  (`Shell\Copilot IsCopilotAvailable=0`, `Shell\Copilot\BingChat
  IsUserEligible=0`; HKLM + all user hives), Copilot voice-agent
  activation off (`AgentActivationEnabled=0`), and FeatureManagement
  velocity overrides disabling Copilot nudges/taskbar/systray
  (IDs 1546588812, 203105932, 2381287564, 3389499533, 4027803789 →
  `EnabledState=1`) — same set as zoicware/RemoveWindowsAI.
- `DisableRecall` extended (both impls): 25H2 "Agent in Settings" off
  (`WindowsAI DisableSettingsAgent=1`, HKLM + user hives), per-app AI
  policies — Paint (`DisableImageCreator`/`DisableCocreator`/
  `DisableGenerativeFill`/`DisableGenerativeErase`/
  `DisableRemoveBackground`) and Notepad (`DisableAIFeatures=1`) —
  ClickToDo user preference off, and AI-Actions velocity overrides
  (1853569164/4098520719/929719951 disabled; 1646260367 enabled so the
  Explorer entry hides itself when no action exists).
- `DisableEdgeBloat` extended (both impls): Edge AI surface off —
  `CopilotPageContext`, `EdgeEntraCopilotPageContext`,
  `EdgeHistoryAISearchEnabled`, `ComposeInlineEnabled`,
  `BuiltInAIAPIsEnabled`, `AIGenThemesEnabled`,
  `ShareBrowsingHistoryWithCopilotSearchAllowed` = 0;
  `DevToolsGenAiSettings=2`; `GenAILocalFoundationalModelSettings=1`
  (on-device foundation model off).
- C# CLI `--config PATH` flag (Python parity): loads config from the
  given path instead of the exe-adjacent `config.json`; flag pairs are
  skipped when resolving the command argument.

### Fixed
- Case-variant duplicate `SensrSvc`/`sensrsvc` in the misc-bloat demote
  list (same Windows service; `SensorService` is a distinct service and
  stays). Demote count corrected 45 → 44 in code logs and README (both
  impls).
- `RemoveDefaultStorePackages` PackageList merge was case-sensitive in
  Python while C# merges `OrdinalIgnoreCase` — a family listed under
  different casing could be written twice. Both now dedupe
  case-insensitively, keeping first-seen casing.
- Python Win32 silent-uninstall split the vendor `QuietUninstallString`
  args on whitespace, mangling quoted paths (e.g. `/log "C:\dir x\f"`).
  It now passes the raw command line to CreateProcess, matching the C#
  `FileName`/`Arguments` split.
- Timeout drift (Python vs C#): OEM scheduled-task enumeration now waits
  120s (was 60s vs C# `Proc.Capture(120000)`); every `schtasks /Change`
  call now waits 15s (was the 30s default vs C# `Proc.Wait(15000)`);
  `Remove-AppxProvisionedPackage` now waits 120s (was 60s vs C# 120000 —
  provisioned removal is a servicing op that can exceed a minute); all
  `sc.exe` stop/config and `reg.exe` load/unload/export calls now wait
  15s (was the 30s default vs C# `RunToolSilent`/`RunRegSilent` 15000).
- C# `uninstall` issued only `sc delete` — a running service stays
  marked-for-delete until reboot. Now stops the service first, matching
  the Python `sc stop` → `sc delete` order.
- C# `restore` printed an empty name for ledger entries missing `name`;
  it now falls back to `family` then `?` like the Python restore.
- Python `--install`/`--uninstall` used to exit with an error when not
  elevated; they now re-launch themselves via UAC (`runas`), matching
  the C# self-elevating `install`/`uninstall`.
- C# generated-config `LogFilePath` pointed next to the exe; it now
  defaults to `ProgramData\BloatwareGuard\bloatware-guard.log` like the
  Python side writes.
- C# provisioned-package matching ran the blacklist against `PackageName`
  (whose version/arch/publisher suffixes could over-match); it now
  matches `DisplayName` — the stable product name the blacklist is
  written against — same as Python, while still returning `PackageName`
  for removal.
- `verify_scan.ps1` exported registry snapshots into `C:\temp` without
  creating it (the SYSTEM variant already did); add the same guard.
- Python ran a second `Get-AppxPackage` query per scan just to map
  family → full name; `PackageFullName` is now selected in the same
  enumeration (C# single-query parity), and the reinstall monitor reuses
  that map instead of re-querying.
- C# re-disabled only telemetry tasks on each scan; OEM tasks were
  disabled just once at service start, letting OEM updaters re-enable
  them between scans. `DisableOemTasks` now also runs per scan (Python
  parity).
- C# one-shot `scan`/`dry-run` ran `DisableOemTasks` unconditionally —
  the `DisableOemScheduledTasks` toggle was ignored outside service
  mode. Now gated on the toggle like the scan loop.
- `get_blacklisted_packages` briefly returned 4-tuples, breaking the
  CI verification snippet's 3-field unpack; the public API is back to
  `(family, name, install_path)` while the scan path uses the 4-field
  `_enum_blacklisted_packages` for the single-query full-name map.
- Added missing telemetry task `Microsoft Compatibility Appraiser Exp`
  (newer-build variant of CompatTelRunner — listed by Win11Debloat);
  telemetry-task list now 57, README count updated.

### Changed
- Misc-bloat demote list extracted from inline loop literals into named
  constants (`_MISC_DEMOTE_SERVICES` / `MiscBloatServices`) so it is now
  covered by the T9 cross-check (Python↔C# presence) and the T10/T8
  duplicate guards.
- T10/T8 extended with case-insensitive duplicate detection across all
  shared lists plus `config.Blacklist` — future case-variant dups fail
  the self-test instead of silently shipping.

## [Unreleased] — v1.55.0-mvp: list deduplication + self-test guards

### Fixed
- Duplicate entries in shared lists (both impls): `Microsoft.Microsoft3DViewer`
  appeared twice in the default blacklist (86 → 85, matching `config.json`)
  and the Siuf `DmClient`/`DmClientOnScenarioDownload` task pair was listed
  twice in the telemetry-task list (58 → 56). Dups are harmless at runtime
  but inflate every count in logs/docs.
- Doc counts: telemetry hosts now correctly documented as 46 (README/DESIGN
  said 45 — the v1.54 additions landed without a doc bump).

### Added
- Self-test duplicate guard — Python T10 and C# T8 assert every shared
  data list (tasks, autologgers, hosts, startup names, blacklist,
  system prefixes, backup paths) is duplicate-free, so this class of
  drift fails CI immediately.

## [Unreleased] — v1.54.0-mvp: diagnostic service demotion + post-merge review fixes

### Changed
- `DisableMiscBloatServices` 42→45: added `DPS` (Diagnostic Policy Service),
  `diagsvc` (Diagnostic Execution Service) — both Automatic by default,
  demand-start keeps netsh/PowerShell diagnostics working — and `DcpSvc`
  (Data Collection and Publishing Service, diagnostic ingest feeder).

### Fixed
- Registry backup ordering: one-time and service scans wrote the Deprovisioned
  markers and `RemoveDefaultStorePackages` policy BEFORE `backup_registry_keys`
  ran inside the registry-prevention pass, so exports captured post-change
  values. The backup now runs at scan start (post restore-point); the
  once-per-process guard keeps it single-shot (both impls, review follow-up).
- `ApplyRemoveDefaultStorePackages` rewrote `PackageList` each scan with only
  current matches — families removed in an earlier scan could be re-provisioned
  for new users. Now merges with the existing list (case-insensitive dedup,
  both impls).
- Registry handle leak: `MarkDeprovisioned` opened one key per family per
  interval without disposing — now `using var`/`Close()` (both impls).
- Unbounded log growth: a resident service appended to the log forever —
  now rotates at 1 MB keeping one generation (Python `RotatingFileHandler`,
  C# `.old` rollover).
- `deploy_verify.bat` banner still said v1.8.0 — now v1.54.0-mvp.
- Windows console encoding crash: Python `print()`/logger output containing
  `↔`/`→` (self-test names, "Applied:" lines) raised `UnicodeEncodeError` on
  cp1252/cp932 consoles — caught by CI `test-scan`. Output strings are now
  ASCII-only and `main()` reconfigures stdout/stderr to UTF-8 with
  `errors="replace"` so no character can take the tool down. C# now sets
  `Console.OutputEncoding = UTF8` (mirrors the Python hardening; .NET never
  crashed but rendered `?` mojibake).
- `verify_scan.ps1` invoked a hardcoded `C:\Users\HP\...` script path —
  now `$PSScriptRoot`-relative; `verify_scan_sys.ps1` logged a scan exit
  code that `Start-Process -Wait` never set — now `-PassThru`/`ExitCode`.
- C# `DisableMiscBloatServices` log claimed 42 services (actual: 45).
- `_BACKUP_KEY_PATHS`/`BackupKeyPaths` now include the Deprovisioned and
  RemoveDefaultStorePackages keys; self-test T9 also cross-checks the backup
  path list against Program.cs.
- Telemetry hosts 34→45: added `self.events`/`v10c`/regional `v10`/`v10c`
  ingest variants (same ARIA pipeline), `activity.windows.com` (Timeline —
  ActivityFeedPolicy already off), `api.diagnostics.office.com` — all
  pure-telemetry per hagezi dns-blocklists + MS Learn endpoint docs.

## [Unreleased] — v1.53.0-mvp: stock-app blacklist audit + parity fixes

### Added
- Blacklist +13 dead/deprecated stock apps and promo stubs that the 24H2
  image still ships: 3D Viewer (both ids), Print3D, Whiteboard, Wallet,
  Messaging, OneConnect, CommsPhone, Appconnector, NetworkSpeedTest, Sway,
  Office Hub launcher (`Microsoft.Office.Desktop`), MSTranslatorBeta —
  plus `MicrosoftWindows.CrossDevice`, `Microsoft.ECApp`, `SystweakSoftware`,
  `PricerunnerAB` (82→86 total entries).
- Self-test T9 extended: asserts every Python shared data-list entry
  (telemetry tasks, autologgers, hosts, startup names) exists in Program.cs.
- Telemetry hosts block 26→34 domains: `*.events.data.microsoft.com`
  ingest (v10/v20/Edge/WER), ARIA pipe, survey.watson, diagnostics.support —
  all pure-telemetry endpoints, no functional surface touched.

### Fixed
- C# default blacklist was missing `MicrosoftWindows.Client.WebExperience`
  and `Microsoft.MicrosoftJournal` (Python/config already had them — real
  parity gap: Widgets host package was never removed by the EXE).
- `APP_VERSION` in bloatware_guard.py lagged at 1.43 (drift since v1.44);
  T9 now guards it.
- README/DESIGN counts refreshed (58 telemetry tasks, 13 autologgers,
  42 demoted services); DESIGN table gained the `RemoveProvisionedPackages`
  and `ReinstallMonitor` rows.

## [Unreleased] — v1.52.0-mvp: telemetry-change nag + explorer-search web off

### Changed
- `DisableTelemetry`: `DataCollection\DisableTelemetryOptInChangeNotification`=1 —
  suppresses the "your telemetry setting changed" nag.
- `DisableSearchSuggestions`: HKLM `Explorer\NoSearchInternet`=1 — kills the
  Explorer search pane's web lookup, separate from the Start-search switch.

## [Unreleased] — v1.51.0-mvp: parity audit — Python defaults complete

### Fixed
- `load_config` built-in defaults were missing the five post-merge
  `Prevention.*` keys (`MarkDeprovisioned`, `RemoveDefaultStorePackages`,
  `BlockTelemetryEndpoints`, `WingetSweep`,
  `DisableTelemetryAutologgers`) — a fresh Python install with no
  config.json silently skipped those layers. Defaults now match
  config.json (45 toggles). Cross-impl parity audited: task lists,
  autologger lists, and blacklists are identical.

## [Unreleased] — v1.50.0-mvp: location/sensor stack, SNMP, WWAN demote

### Changed
- `DisableMiscBloatServices`: 33 → 42 demand-start — `lfsvc` (geolocation),
  `SensorService`/`SensrSvc`/`sensrsvc` (sensor monitoring), `SNMPTRAP`
  (dead SNMP traps), `TroubleshootingSvc` (recommended-troubleshooting
  runner — its policy is already off), `WwanSvc`/`WwanAuthSvc` (cellular;
  demand-start keeps LTE functional).

## [Unreleased] — v1.49.0-mvp: CDM master switch, extra content surfaces, Near Share

### Changed
- `BlockProvisioning`: `ContentDeliveryAllowed`=0 — the master
  ContentDeliveryManager kill switch the per-surface list was missing.
- `BlockProvisioning`: `SubscribedContent-338380Enabled` (Settings-app
  content ads) + `SubscribedContent-314563Enabled` (My People
  suggestions) added to the per-hive zeroed set.
- `DisableTelemetry`: `CDP\SettingsPage\NearShareChannelUserAuthzPolicy`=0 —
  Nearby Share consent off, same CDP auth-policy family.

## [Unreleased] — v1.48.0-mvp: AppCompat policies, OOBE skip, broker/WDI tasks

### Changed
- `DisableTelemetry`: `AppCompat\AITEnable`=0 (Application Inventory
  Telemetry — pairs with the already-disabled AitEnableAgent task) and
  `DisablePCA`=1 (Program Compatibility Assistant — pairs with the PcaSvc
  demotion); `OOBE\DisablePrivacyExperience`=1 skips OOBE privacy pages
  whose settings are all denied by policy anyway.
- `DisableTelemetryTasks`: +2 — `BrokerInfrastructure\
  BgTaskRegistrationMaintenanceTask` (Store broker maintenance),
  `WDI\ResolutionHost` (WDI services are already demoted).

## [Unreleased] — v1.47.0-mvp: open-with lookups, online tips, input/IME/perf tasks

### Changed
- `BlockProvisioning`: `NoInternetOpenWith`=1 + `AllowOnlineTips`=0 (HKLM
  Explorer) — Open-With web lookup nag and Settings online tips stopped.
- `DisableTelemetry`: `Maps\AutoDownloadAndUpdateMapData`=0 — offline-map
  data channel off (the MapsBroker service is already demoted).
- `DisableTelemetryTasks`: +6 — `PerfTrack\BackgroundConfigSurveyor` (CEIP
  perf tracking), `IME\SQM data sender`, `Input\LocalUserSyncDataAvailable`,
  `Input\TouchpadSyncDataAvailable`, `Windows Media Sharing\UpdateLibrary`,
  `InstallService\SmartRetry` (Store install-retry hook).

## [Unreleased] — v1.46.0-mvp: service demote sweep 2 + telemetry task additions

### Changed
- `DisableMiscBloatServices`: 24 → 33 demand-start — `WalletService` (dead
  Microsoft Pay), `wisvc` (Windows Insider), `SharedRealitySvc` /
  `perceptionsimulation` / `Spectrum` (Mixed Reality), `AJRouter`
  (deprecated AllJoyn), `SCardSvr` / `ScDeviceEnum` / `CertPropSvc`
  (smart-card triad — Sophia/privacy.sexy demote all three).
- `DisableTelemetryTasks`: +6 — `Application Experience\PcaPatchDbUpdate`,
  `Location\Notifications`, `Location\WindowsActionNotification`,
  `Feedback\Siuf\DmClient`, `Feedback\Siuf\DmClientOnScenarioDownload`,
  `RetailDemo\CleanupContent`.
- `DisableOneDrive` (opt-in): also disables the two `OneDrive Standalone
  Update Task` schedulers alongside the sync policy.

## [Unreleased] — v1.45.0-mvp: Open-With store nags, search location, sync/push tasks

### Changed
- `BlockProvisioning`: HKLM `Explorer\NoUseStoreOpenWith` + `NoNewAppAlert` —
  kills "Look for an app in the Store" and the "new apps can open this file
  type" toast (both are store-promotion surfaces).
- `HideStartRecommendations`: `HideRecentlyAddedApps` policy — the Start
  "Recently added" list is also a promoted-app surface.
- `DisableSearchSuggestions`: `AllowSearchToUseLocation`=0 — location-aware
  search results no longer leak device location to Bing.
- `DisableTelemetryTasks`: +`PushToInstall\LoginCheck` (Store push-install
  login hook — its service is already demoted), `SettingSync\
  BackgroundUploadTask` + `BackupTask` (setting-sync uploads; the policy
  block is already in place).

## [Unreleased] — v1.44.0-mvp: GameBar nags, PcaSvc, review hardening

### Changed
- `DisableGameDvr`: per-hive `GameBar\UseNexusForGameBarEnabled` and
  `ShowStartupPanel` = 0 — kills the Game Bar overlay hook and its
  "press Win+G" startup nag left after DVR is off.
- `DisableSearchSuggestions`: HKLM `Policies\Explorer\DisableSearchBoxSuggestions`
  alongside the per-hive writes — covers hive-creation edge cases.
- `DisableWidgets`: `Feeds\ShellFeedsTaskbarViewMode` = 2 per-hive —
  hides the entire news/interests flyout.
- `DisableTelemetryAutologgers`: 11 → 13 sessions (+`RadioManager`,
  +`SetupPlatformTel` — setup/OS-component telemetry).
- `DisableMiscBloatServices`: 23 → 24 (+`PcaSvc` Program Compatibility
  Assistant telemetry).
- `DisableTelemetryTasks`: +`FamilySafetyRefreshTask` — schedule-side
  complement to the existing FamilySafetyMonitor entry.

### Fixed (review)
- `ProvisionedFamilyName`/`_provisioned_family`: package names containing
  underscores lost their suffix — family now splits the four well-formed
  `version_arch_resourceid_publisher` fields off the RIGHT end.
- `WingetGuard.Sweep`/`winget_sweep`: a blacklisted id that also matched
  the whitelist still reached `winget uninstall` — whitelist now wins.
- Win32 sweep: `HKCU` uninstall entries were executed with our elevated
  token under interactive admin runs (the caller's hive is user-writable).
  HKCU is now report-only like `HKU\<sid>`.
- `BlockTelemetryEndpoints` toggle-off never cleared a previously written
  hosts block — the block manager is now called unconditionally so the
  false path removes entries.
- `Proc.Capture` threw `InvalidOperationException` for callers that only
  redirected stdout — it now forces both stream redirects itself.
- `DEFAULT_BLACKLIST` (Python fallback config) gained
  `MicrosoftWindows.Client.WebExperience` to match config.json.

## [Unreleased] — v1.43.0-mvp: OneSettings, driver search, diagnostics hosts

### Changed
- `DisableTelemetry`: `DisableOneSettingsFileDownloads=1` — blocks the
  periodic OneSettings config download Microsoft uses for recommendations.
- `BlockOemDriverUpdates`: `DriverSearching\SearchOrderConfig=0` — Windows
  Update is never searched for drivers when new hardware is plugged in.
- `DisableCloudContent`: `DisableThirdPartySuggestions=1` (sponsored tiles).
- `DisableEdgeBloat`: `PromotionalTabsEnabled`, `WebWidgetAllowed` off.
- `DisableMiscBloatServices`: 21 → 23 — `WdiSystemHost`/`WdiServiceHost`
  (Diagnostic Service Host pair running WDI diagnostics sessions).

## [Unreleased] — v1.42.0-mvp: service demotion sweep + CEIP/feedback policies

### Changed
- `DisableMiscBloatServices`: 15 → 21 demand-start — `DusmSvc` (data-usage
  metering) and the per-user service templates powering removed apps:
  `CDPUserSvc`, `OneSyncSvc`, `UnistoreSvc`, `UserDataSvc`,
  `PimIndexMaintenanceSvc` (Mail/contacts/My People sync backends).
- `DisableDeliveryOptimization`: `DoSvc` demoted — the service still
  auto-started for CDN fetches even with `DODownloadMode=0`.
- `DisableErrorReporting`: `wercplsupport` (WER control-panel support)
  demoted to demand-start.
- `DisableTelemetry`: `CEIPEnable=0` (SQMClient policy),
  `DoNotShowFeedbackNotifications=1` (feedback nag prompts off), and the
  policy-level `Policies\...\Privacy\TailoredExperiencesWithDiagnosticDataEnabled=0`
  per hive (not just the value key).
- `DisableSearchSuggestions`: `IsDeviceSearchHistoryEnabled=0` per hive.
- `DisableEdgeBloat`: `DropEnabled`, `CryptoWalletEnabled`,
  `EdgeAssetDeliveryServiceEnabled` off (Drop syncs files to OneDrive).
- `DisableTelemetryTasks`: +3 — `PI\Sqm-Tasks`,
  `DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver`,
  `Maintenance\WinSAT`.

## [Unreleased] — v1.41.0-mvp: promo surfaces + dev telemetry + URL leaks

### Changed
- `DisableTelemetry`: added per-hive `HttpAcceptLanguageOptOut=1` (language
  list no longer leaks to websites) and machine-wide env vars
  `POWERSHELL_TELEMETRY_OPTOUT=1` / `DOTNET_CLI_TELEMETRY_OPTOUT=1`.
- `DisableCloudContent`: Settings app "Home" page hidden via
  `SettingsPageVisibility=hide:home` (the Microsoft 365 promo card).
- `DisableCopilot`: taskbar Copilot button off (`ShowCopilotButton=0`, all hives).
- `DisableChatTaskbar`: "My People" button off (`PeopleBand=0`, all hives).
- `DisableEdgeBloat`: URL-leak surfaces off — `SearchSuggestEnabled`,
  `AddressBarMicrosoftSearchInBingProviderEnabled`, `SiteSafetyServicesEnabled`,
  `NetworkPredictionOptions=2`, plus `EdgeCollectionsEnabled`/`EdgeFollowEnabled`.
- `DisableTelemetryTasks`: +4 — `Subscription\EnableLicenseAcquisition` /
  `LicenseAcquisition` (Microsoft 365 upsell channel),
  `Diagnosis\RecommendedTroubleshootingScanner`, `Diagnosis\Scheduled`.
- Blacklist gains `Microsoft.MicrosoftJournal` (Journal app).

## [Unreleased] — v1.40.0-mvp: merge — reprovision persistence + telemetry kill-chain

### Added
- `MarkDeprovisioned` (Layer 40): writes `Deprovisioned\<family>` markers under
  `HKLM\...\Appx\AppxAllUserStore` so feature updates skip re-provisioning
  blacklisted families — runs even when a removal toggle is off.
- `RemoveDefaultStorePackages` (Layer 41): the official Windows 11 25H2
  `RemoveDefaultMicrosoftStorePackages` policy (Enabled=1 + PackageList
  REG_MULTI_SZ) — the OS itself removes listed apps at each new user's
  first sign-in. Unknown ids are ignored on older builds.
- `BlockTelemetryEndpoints` (Layer 42): ~27 pure-telemetry domains null-routed
  via a marked hosts block — fully reversible when toggled off.
- `WingetSweep` (Layer 43): `winget uninstall -e --id <id> --silent
  --disable-interactivity` for blacklist entries that are valid winget ids —
  catches Store apps Appx removal can't see. Skips when winget is absent.
- `DisableTelemetryAutologgers` (Layer 44): Start=0 on 11 boot-time ETW
  trace sessions (Diagtrack-Listener, SQMLogger, WiFiSession, …) — the fifth
  telemetry shutoff (policies / tasks / hosts / services / ETW).
- Active Setup sweep inside `DisableStartupBloat`: deletes
  `Installed Components` stub-installer entries matching the blacklist
  (the per-logon OEM bloatware channel).
- `Windows Error Reporting\QueueReporting` added to the telemetry-task list.

### Fixed
- All process launches now go through `Proc.Wait`/`Proc.Capture`: async
  `ReadToEndAsync` on both streams + `WaitForExit(timeout)` + `Kill(tree)`
  — kills the deadlock a full stderr pipe or a detached grandchild holding
  the pipe EOF used to cause (also fixes `ExitCode` read on live schtasks).
- Provisioned-package family names derive from the `PackageName` tail
  (`_publisherid_` split) — `PublisherId` doesn't exist on provisioned objects.
- `HKU\<user-sid>` uninstall entries are report-only — user-writable strings
  must never be executed as SYSTEM.
- Package names and winget ids are regex-guarded before being interpolated
  into PowerShell/sc/winget command lines.
- Reinstall monitor honors `DryRun` for all three re-removal channels.
- Blacklist gains `MicrosoftWindows.Client.WebExperience` (Widgets host).

## [Unreleased] — v1.39.0-mvp: WSearch/AssignedAccess demoted

### Changed
- `DisableMiscBloatServices` extended (13 → 15 demand-start): `WSearch`
  (the indexer's resident file scan — demand-start keeps search working
  but stops the always-on crawl) and `AssignedAccessManagerSvc` (kiosk
  assigned-access machinery unused outside managed deployments).

## [Unreleased] — v1.38.0-mvp: SysMain/TabletInputService demoted

### Changed
- `DisableMiscBloatServices` extended (11 → 13 demand-start): `SysMain`
  (Superfetch's resident prefetch scanner — dead weight on SSD machines)
  and `TabletInputService` (touch-keyboard surface on non-touch PCs).

## [Unreleased] — v1.37.0-mvp: telemetry tasks — AIT/speech/disk

### Changed
- `DisableTelemetryTasks` extended (29 → 32): `AitEnableAgent`
  (Application Impact Telemetry), `SpeechModelDownloadTask`,
  `DiskFootprint\Diagnostics`.

## [Unreleased] — v1.36.0-mvp: per-hive Spotlight policies

### Changed
- `DisableSpotlight` now also applies the per-hive `CloudContent` policy
  keys — `DisableWindowsSpotlightFeatures`,
  `DisableSpotlightCollectionOnDesktop`, `DisableSoftLanding` — so the
  block holds for every user profile, not just the HKLM side.

## [Unreleased] — v1.35.0-mvp: CDM preinstalled-apps flags off

### Changed
- `BlockProvisioning` CDM zero-list extended: `PreInstalledAppsEnabled`,
  `PreInstalledAppsEverEnabled`, `OemPreInstalledAppsEnabled`,
  `RemediationRequired` — the OEM app-seeding flags that let removed
  bloatware get re-offered after feature updates.

## [Unreleased] — v1.34.0-mvp: Startup-folder bloat disabled

### Changed
- `DisableStartupBloat` now also scans the per-user and common Startup
  folders (`shell:startup`) — they aren't governed by `StartupApproved`.
  Matching shortcuts/files are renamed to `*.bgdisabled` rather than
  deleted, keeping a trivial restore path.

## [Unreleased] — v1.33.0-mvp: Start recent-doc tracking off

### Changed
- `HideStartRecommendations` also sets `Start_TrackDocs=0` in every user
  hive — the Recommended section draws from this tracking, so collection
  stops rather than just hiding its output.

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
