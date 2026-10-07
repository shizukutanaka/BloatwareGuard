# Changelog

All notable changes to BloatwareGuard. Format follows [Keep a Changelog](https://keepachangelog.com/).

- Audit round 161 (Win32 uninstall enumeration — clean):
  HKLM 64/32 (incl. WOW6432Node) + HKCU + loaded S-1-5-21
  hives, identical paths, same filters (DisplayName+UninstallString
  required, SystemComponent=1 skip, whitelist veto BEFORE
  blacklist match, empty-entry guard, Win32BloatNames merged
  into the blacklist at call-time), QuietUninstallString
  captured, user-hive entries flagged report-only, case-fold
  dedupe — all identical.
- Audit round 160 (service registration — py parity fix):
  NSSM-wrapped py service now sets the same SCM-level config
  as the C# service — `sc description` and `sc failure`
  restart-on-failure backoff (60s/60s/5min, reset 86400),
  which were previously NSSM-default only. Install/uninstall
  flow (stop+delete idempotent → create → auto-start) verified
  equivalent; NSSM-vs-SCM-native is the documented mechanism
  split. UAC-decline warn covered (round 109).
- Audit round 159 (--restore path — clean): restore pipeline
  identical end-to-end — same ledger JSONL read + skip-on-
  JSONDecodeError, kind dispatch (appx re-register → winget
  install -e --id --silent --disable-interactivity --accept-* →
  Add-WindowsCapability 180s → provisioned same re-register →
  default vendor/Settings manual), identical _safe_pkg_name/
  IsPackageNameSafe injection guards, manual counter, and
  final restored/manual tally line.
- Audit round 158 (dry-run gate coverage — clean): every
  mutating path verified behind a DryRun gate both sides —
  RunScan's 16 log-would/mutate branch pairs, restore point,
  registry backup, prevention, appx/provisioned/capability/
  win32/winget removal, AND the monitor's 3 re-removal
  channels (provisioned/Appx/Win32: RE-INSTALLED warn →
  DryRun → remove ordering identical). No unguarded mutation.
- Audit round 157 (log surface — clean): severity-by-severity
  extraction (error/warn/info both sides). All behavioural
  branches identical — ScanIntervalSeconds clamps to 60s both,
  admin→user-level removal fallback mirrors, MONITOR
  re-removal covered by 3 channels each (Appx/provisioned/
  Win32). Remaining diffs are message-text shape and helper
  split (cs's per-layer catch Warn vs py's layer-failed /
  try-except) — no uncovered failure path.
- Audit round 156 (timeout values — clean): extracted every
  numeric timeout both sides — py {15,60,120,180,300}s map
  1:1 to cs {15000,...,300000}ms; cs's extra 30000ms sites are
  service stop/delete/query which py covers via run_cmd's
  default timeout=30s. No drift; site-count asymmetry is
  py's per-call kwarg vs cs's centralised Proc.Wait helper.
- Audit round 155 (external-command surface — clean):
  all spawned-tool invocations compared: `sc stop|config` set
  (DiagTrack/RetailDemo/WerSvc/Spooler/RemoteRegistry stop+disable
  pairs), `schtasks /Change /TN /DISABLE`, `winget uninstall|install`
  arg strings (--silent --disable-interactivity --accept-* flags),
  Add-AppxPackage re-register (-DisableDevelopmentMode
  -Register AppxManifest), capability add/remove PS commands,
  restore-point + Checkpoint-Computer — all identical.
  (service-drain uses ping vs sleep — recorded round 101.)
- Audit round 154 (registry-write PATH parity — clean):
  machine-extracted every literal registry path both sides and
  normalized concat-vs-literal parents — zero real diffs:
  PolicyManager WiFi/telemetry defaults, CPSS DevicePolicy/Store,
  SCHANNEL protocol template paths, WinRT ActivatableClassId
  kills, Orchestrator/WinEvt channel templates, ReservedStorage
  power GUID, StartupApproved\Run|RunOnce, Diagnostics\Performance
  — all present both sides (remaining deltas are concat-parent
  vs expanded-literal representation of the same key).
- Audit round 153 (registry-write VALUE parity — clean):
  deeper audit than layer names — extracted every (name, value)
  pair across all write idioms (direct calls, helper wrappers,
  loop tables, tuple unpacks, ~570+ writes). Zero name-set
  diffs, zero value diffs. Verified Recall deny-lists
  (DenyAppList/DenyUriList) byte-identical, CPSS
  DefaultValue/Value pairs, and PolicyManager `value` writes.
- Audit round 152 (RemoveDefaultStorePackages layer
  write-surface — clean): Enabled=1 + DynamicRemovalList
  REG_MULTI_SZ merge + per-family RemovePackage=1 subkeys +
  legacy PackageList migration — identical. Also confirms the
  combined MarkDeprovisioned||RDS gate shape matches both sides.
- Audit round 151 (DisableTelemetryTasks layer write-surface —
  clean): both loop the pinned task-path table → path/name split
  → `schtasks /Change /DISABLE` — identical (mechanism also
  audited round 102).
- Audit round 150 (DisableOemTasks layer write-surface —
  clean): 120s schtasks query, 25-pattern match table, 34
  protected prefixes, /DISABLE at 15s, OEM-binary decode —
  identical.
- Audit round 149 (DisableStartupBloat layer write-surface —
  clean): Run/RunOnce + 32-bit views, per-hive + per-user
  StartupApproved markers, startup-folder sweep, match-blob
  construction — identical. cs inlines the Active-Setup stub
  sweep inside the layer; py keeps it in `disable_active_setup_stubs`
  (audited clean, round 87) — placement diff, same end-state.
- Audit round 148 (BlockProvisioning layer write-surface —
  clean): value-name extraction — zero diffs: silent-install +
  suggestion surfaces across all hives (chat auto-install,
  cross-device, DevHome/Outlook update kills, BITS notification,
  push-to-install, safe-search, phone-link, dynamic content,
  OEM update schedulers) — identical. `NoSystraySystemPromotion`
  placement differs (py under DisableTelemetry / cs under
  BlockProvisioning — both default-on, same end-state).
- Audit round 147 (BlockOemDriverUpdates layer write-surface —
  clean): value-name extraction — zero diffs: ExcludeWUDrivers,
  SearchOrderConfig, device-metadata/drive-search kills,
  SCHANNEL min-key-lengths, insecure-guest/renego denies,
  DisableCoInstallers, NcdAutoSetup, CostedNetworkPolicy —
  identical.
- Audit round 146 (BlockInsiderPreview layer write-surface —
  clean): value-name extraction — zero diffs: flighting/preview-
  build policy kills (ManagePreviewBuildsPolicyValue etc.) —
  identical.
- Audit round 145 (PreventDeviceMetadata layer write-surface —
  clean): value-name extraction — zero diffs:
  PreventDeviceMetadataFromNetwork kill — identical.
- Audit round 144 (DisableCloudContent layer write-surface —
  clean): value-name extraction — zero diffs: Windows Spotlight
  cloud-content policies + CloudContent service demotion —
  identical.
- Audit round 143 (DisableConsumerExperiences layer
  write-surface — clean): value-name extraction — zero diffs:
  consumer-features/auto-app-install policies — identical.
- Audit round 142 (HideStartRecommendations layer
  write-surface — clean): value-name extraction — zero diffs:
  HideRecommendedSection + HideRecentlyAddedApps Explorer
  policies — identical.
- Audit round 141 (NoForcedReboot layer write-surface —
  clean): identical AU policy writes —
  NoAutoRebootWithLoggedOnUsers=1, AlwaysAutoRebootAtScheduledTime=0.
- Audit round 140 (DisableAutoplay layer write-surface —
  clean): value-name extraction — zero diffs: NoDriveTypeAutoRun
  + autorun.inf policy kills — identical.
- Audit round 139 (DisableSpotlight layer write-surface —
  clean): value-name extraction — zero diffs: per-hive Spotlight
  content kills — identical.
- Audit round 138 (DisableMiscBloatServices layer write-surface —
  clean): same service list (91, T-pinned), same RemoteRegistry
  `stop`+`start= disabled` at 15s, same log — identical.
- Audit round 137 (DisableRemoteAssistance layer write-surface —
  clean): value-name extraction — zero diffs: Remote Assistance
  policy kills — identical.
- Audit round 136 (DisableCloudClipboard layer write-surface —
  clean): value-name extraction — zero diffs: cloud-clipboard
  sync/history policies — identical.
- Audit round 135 (DisableReservedStorage layer write-surface —
  clean): value-name extraction — zero diffs: ShippedWithReserves=0
  storage-reservation kill — identical.
- Audit round 134 (BlockOemWpbtExecution layer write-surface —
  clean): value-name extraction — zero diffs: WPBT platform-binary
  execution block — identical.
- Audit round 133 (DisableModernStandbyNetworking layer
  write-surface — clean): value-name extraction — zero diffs:
  ConnectivityInStandby policy, same opt-in `False` default.
- Audit round 132 (DisablePrintSpooler layer write-surface —
  clean): identical `sc stop Spooler` + `sc config Spooler
  start= disabled` at 15s, same opt-in `False` default, same
  log line.
- Audit round 131 (DisableXboxServices layer write-surface —
  clean): value-name extraction — zero diffs: 4 Xbox service
  demotions (XblAuthManager/XblGameSave/XboxNetApiSvc/XboxGipSvc),
  WinRT GamingAI companion-host neuter, SmartGlass=never — all
  identical.
- Audit round 130 (DisableAppPermissions layer write-surface —
  clean): value-name extraction — zero diffs: all 24 LetAppsAccess*
  denies (contacts/calendar/email/messaging/motion/notifications/
  phone/radios/system-AI/tasks/trusted-devices/sync/diag/voice/
  voice-above-lock/generative-AI/gaze/human-presence/graphics-
  capture x2/spatial-perception) + LetAppsRunInBackground —
  identical (cs keeps the name table as a static array above the
  method; py inlines it).
- Audit round 129 (DisableEdgeUpdateBloat layer write-surface —
  clean): value-name extraction — zero diffs: EdgeUpdate service
  demotions, update-disable policies, task scheduler kills, IFEO
  blocks — all identical (py inlines the OEM-driver-update block
  under its own gate inside the same apply fn; cs splits it to a
  separate function — placement diff, same end-state).
- Audit round 128 (DisableErrorReporting layer write-surface —
  clean): value-name extraction — zero diffs: DontShowUI, Disabled,
  consent overrides, WerSvc demotion, send-request/generic-driver
  WER switches, CPL-support suppression, auto-approve dumps,
  report-queue cap — all identical.
- Audit round 127 (DisableEdgeBloat layer write-surface — clean):
  value-name extraction across the largest policy layer (~80 Edge
  policies) — zero diffs: Copilot NTP/address-bar/page-context,
  reading-mode, shopping/wallet/donation, rewards, sidebar/hubs,
  prerender/prediction, telemetry/feature-request/url-diagnostics,
  startup boost/prelaunch, shortcuts, implicit-signin default,
  3P-serp, site-safety, EdgeUpdate suppression, first-run/user-
  feedback — all identical.
- Audit round 126 (DisableChatTaskbar layer write-surface — clean):
  value-name extraction — zero diffs: TaskbarMn icon, Chat policy,
  Teams autostart kill, meet-now hide — all identical.
- Audit round 125 (DisableOneDrive layer write-surface — clean):
  value-name extraction — zero diffs: DisableFileSyncNGSC policy,
  GPO pin/unpin kills, OneDriveSetup process exit + uninstaller
  run, folder redirect restores, and the scheduled-task disables —
  all identical (opt-in layer, same `False` default both sides).
- Audit round 124 (DisableDeliveryOptimization layer write-surface —
  clean): value-name extraction — zero diffs: DODownloadMode,
  DownloadMode policy keys, DoSvc demotion, CDN-bypass and
  P2P-disable switches — all identical.
- Audit round 123 (DisableGameDvr layer write-surface — clean):
  value-name extraction — zero diffs: GameBar FTF/overrides,
  GameDVR policies (AllowGameDVR=0), GameConfig Store settings,
  Broadcast capture off, Game Mode toggle, GameBarFTServer
  deny-list entries, plus per-user GameDVR keys — all identical.
- Audit round 122 (DisableTelemetry layer write-surface — clean):
  value-name extraction — every registry write matches (AllowTelemetry,
  DiagTrack EventTranscriptKey zeroing, advertising ID, tailored
  experiences, speech, ink/type, feedback nag, app-launch tracking,
  activity history, Edge diagnostics). Diffs are placement only: py
  inlines the DiagTrack/WerSvc `sc stop`+`config` kills and telemetry
  task names inside this layer; cs reaches the same end state via its
  DisableTelemetryTasks/misc-service layers. NoSystraySystemPromotion
  sits under DisableConsumerExperiences in cs.
- Audit round 121 (DisableSearchSuggestions layer write-surface —
  clean): value-name extraction across both bodies — zero diffs.
  Cortana policy kills, ConnectedSearchPrivacy=3, location deny,
  search-provider deactivation (ActivationType/Server), SearchBox
  suggestions off (HKLM + user), BingSearchEnabled, cloud-search +
  dynamic box + device history + store suggestions off, background
  apps toggle, Iris recommendations, voice activation, delivery-
  optimization for settings, search history view, global web
  provider — all 20+ writes identical.
- Audit round 120 (DisableWidgets layer write-surface — clean): all 8
  writes identical — AllowNewsAndInterests=0, EnableFeeds=0, the
  counter-intuitive DisableWidgetsBoard/DisableWidgetsOnLockScreen=0
  (NewsAndInterests.admx enabledValue IS 0 — verified the comment is
  right, not a copy-paste bug), TaskbarDa=0,
  ShellFeedsTaskbarViewMode=2, ShellFeedsTaskbarOpenOnHover=0.
- Audit round 119 (DisableCopilot layer write-surface — clean):
  machine-checked value-name extraction across both bodies — every
  policy/preference write matches: TurnOffWindowsCopilot (HKLM+hives),
  shell eligibility (IsCopilotAvailable/IsUserEligible/
  CopilotDisabledReason), context-menu CLSID block, app browsing
  kills, EdgeUpdate Copilot GUIDs, pin overrides, BGA disables,
  velocity RIDs, NVIDIA telemetry, voice-agent + speech + CHS AI
  suggestions, notification/nudge/taskbar/systray overrides, Run-key
  autolaunch, generic/SAM app-permission denies. One structural diff:
  py also writes VoiceActivationEnableAboveLockscreen inside
  DisableCopilot (cs covers it once under DisableSearchSuggestions) —
  idempotent same value/hives, so end state is identical.
- Audit round 118 (DisableRecall layer write-surface — clean): all
  ~30 writes match 1:1 — WindowsAI policy values, model-management
  download kills, export denies, agent consent floors,
  RemoveMicrosoftCopilotApp (HKLM + all user hives), Copilot-keyboard
  telemetry trio, ClickToDo, Notepad/Paint/Photos AI toggles,
  IsRecallAllowed/EnableRecall/ClickToDoEnabled user prefs,
  Disable-WindowsOptionalFeature 'Recall' (120s), WSAIFabricSvc
  demand-start, and the AI event-log channel sweep.
- Audit round 117 (registry-write helper internals — clean): py
  `set_registry_*` (`CreateKeyEx`+`SetValueEx`, exception→False) and
  cs inline `CreateSubKey`+`SetValue` both write the native 64-bit
  view in a 64-bit process (neither pins a Wow64 view, so both miss
  nothing) and both absorb write failures — py silently returns
  False, cs logs Warn per layer; same net effect.
- Audit round 116 (whitelist/blacklist matching internals — clean):
  both sides do case-insensitive *substring* matching (py `in` on
  lowercased names; cs `Contains(OrdinalIgnoreCase)` for whitelist and
  `Regex.Escape`-alternation `-match` for blacklist) with whitelist
  always winning and empty entries guarded — identical semantics, no
  prefix/anchor drift.
- Audit round 115 (provisioned-package enumeration internals — clean):
  same split as the Appx enum — py fetches the full catalog and matches
  `is_target_package` client-side, cs pushes the blacklist down as a
  `-match` alternation then filters whitelist-only; identical literal
  semantics. Both wrap single-object JSON, return [] on query/parse
  failure, and gate removal on non-empty PackageName.
- Audit round 114 (removal-ledger file placement — clean): path
  resolution `BackupDirectory` → `%ProgramData%\BloatwareGuard\Backups`
  fallback and `removed-packages.jsonl` name, append-only +best-effort
  catch, and `yyyy-MM-ddTHH:mm:ss` timestamps identical; py writes a
  sparse dict (only provided keys) vs cs's fixed 4-key object — the
  restore reader tolerates missing keys both ways, so the files are
  mutually readable.
- Audit round 113 (`--list-installed` output parity — clean): row
  format `  family (display) [FRAMEWORK]`, header, and
  `Total: N package(s) installed.` line identical on both sides;
  both enumerate via the same blacklist query (no dedupe needed —
  enum already dedupes).
- Audit round 112 (service-loop exception isolation — clean): each
  scan iteration is wrapped in try/catch → `Scan error` log on both
  sides (py `logger.error` / cs `GuardLogger.Error`), so one failed
  scan never kills the service; `first_scan`/`firstScan` flips only
  on a successful pass identically, and the sleep sits outside the
  guard in both.
- Audit round 111 (atomic-write helper parity — clean): both
  implementations write via a same-directory temp file + rename
  (py `os.replace`, cs `File.Move(overwrite: true)`) — a crash
  mid-write can never leave a truncated config/ledger/hosts file.
- Audit round 110 (config-file I/O parity — clean): missing-config
  default generation + atomic write-back and BOM tolerance
  (py `utf-8-sig`, cs `ReadAllText` BOM-detect) match; corrupt JSON
  intentionally hard-fails on both sides (py `json.loads` raises,
  cs `Deserialize` throws) — loud failure over silent default
  hardening is the design, not a divergence.
- Audit round 109 (cs fix + version/elevation parity): `InstallService`
  and `UninstallService` launched their `Verb="runas"` sc.exe/cmd chains
  unguarded — declining the UAC prompt threw `Win32Exception`
  (ERROR_CANCELLED) and crashed the tool, while py's
  `_relaunch_elevated` reports declined elevation cleanly. Both chains
  now catch `Win32Exception` and warn. Verified version strings
  identical across py `APP_VERSION`, cs output, and csproj PE metadata
  (1.61.3), and the elevation mechanisms semantically equivalent
  (py relaunches itself elevated; cs prompts per-operation via runas).
- Audit round 108 (removal-ledger call-site coverage — clean): every
  removal path records to the ledger on both sides — appx (py's single
  site sits after `remove_appx_package`, which internally tries admin
  `-AllUsers` then per-user = cs's two sites), provisioned, capability,
  win32, winget. Monitor re-removals deliberately do NOT record in
  either implementation — the package was already ledgered at initial
  removal, so a re-record would only duplicate a restore attempt.
- Audit round 107 (cs CLI fix + flag-table parity): the C# entry point
  only accepted bare commands (`dry-run`, `scan`) — every `--`-prefixed
  form except --version/--self-test/--service-dry-run/--config/--help
  was rejected as "Unknown command" while the Python entry point takes
  only `--`-flags, so copy-pasting a documented py invocation into the
  exe failed. All commands now accept both forms (`scan` or `--scan`,
  etc.) and `--service` is accepted as an explicit no-op (py defines it
  unused — default path already runs the service loop). ShowHelp notes
  the dashed forms. --version output and flag semantics verified
  identical across implementations.
- Audit round 106 (Devin Review remediation on merged #45 — 3 fixes):
  monitor no longer watches framework families (py `installed_map`
  and cs `installed` both exclude IsFramework rows — a dependency
  package arriving later can't trigger a re-removal);
  `GetDefaultProfileDat` now falls back to `C:\Users\Default` when
  ProfileList's `Default` value is an empty string, not only on
  null/exception (py `or`-semantics parity); dry-run would-remove
  count in py now gates on the same eligibility the real path uses
  (`full_name and not is_system_app`) so SystemApps no longer
  inflate the reported total — cs kept unconditional because its
  real admin path does attempt SystemApps via `-AllUsers`.
- Audit round 105 (py fix + OEM task-sweep mechanics parity):
  `disable_oem_scheduled_tasks` now warns when the
  Get-ScheduledTask query fails or returns nothing instead of
  silently returning — C# logs the same event as
  "Scheduled task scan error". Mechanism verified identical:
  same Get-ScheduledTask→`-match` query (25 escaped patterns,
  TaskPath `*OEM*`), 120s bound, dict→single wrap, same
  protected-prefix skip via `startswith(prefix+"\")`,
  `schtasks /Change /TN /DISABLE` 15s per task, info/warn per
  result, processed/skipped summary.
- Audit round 104 (reinstall-monitor internals parity — clean):
  the three-channel seen-set semantics verified equivalent —
  empty sets + first-scan baseline so diffs fire only after cycle
  one, provisioned re-removal keyed by DisplayName→PackageName
  map, AppxPackage by family→PackageFullName map, Win32 by
  display name with user-hive entries kept report-only, per-item
  DryRun gates, warn-on-detect / warn-on-fail severities, whole-
  set refresh each cycle, and the same catch→log→sleep loop.
  Cosmetic delta noted: cs uses OrdinalIgnoreCase sets so a
  case-only rename wouldn't alert while py's sets would
  (re-removes once — harmless).
- Audit round 103 (winget sweep internals parity — clean):
  `WingetGuard.Sweep`/`winget_sweep` verified equivalent — same
  ID gate (`^[A-Za-z0-9_.\-]+$` plus a required dot), same
  trim/non-empty guard, same case-insensitive whitelist
  containment that wins over removal, identical uninstall argv
  (`uninstall -e --id <e> --silent --disable-interactivity
  --accept-source-agreements`, 300s), same `winget` ledger kind
  and applied-count summary. The only delta is the already-
  documented probe style (spawned `winget --version` vs PATH
  existence) whose end-state is the same.
- Audit round 102 (task-disable mechanics parity — clean):
  `DisableTelemetryTasks` and `DisableEdgeUpdateBloat` verified
  byte-for-byte equivalent in mechanism — both iterate the same
  explicit task paths through `schtasks /Change /TN "<path>"
  /DISABLE` with a 15s bound, info-on-success / warn-on-failure,
  and an applied-count summary. EdgeUpdate layer identical too:
  same 3 demoted services, same 3 updater task names, same 4
  channel-GUID shortcut suppressions plus
  `DisableEdgeDesktopShortcutCreation`.
- Audit round 101 (service status probe parity — clean):
  `ShowStatus`/`--status` verified equivalent — both run
  `sc query BloatwareGuard` and print stdout verbatim, same 30s
  bound (cs adds a 5s output-drain grace after kill; py hard-caps
  at subprocess timeout — identical for an instant query,
  differing only in the never-hit timeout path's display text).
- Audit round 100 (package-query degrade parity — clean):
  `GetBlacklistedPackages`/`_enum_blacklisted_packages` degrade
  paths verified equivalent — cs tries `-AllUsers` and falls back
  to current-user scope on non-admin failure; py checks
  `is_admin()` upfront and never attempts it. Same end-state
  coverage, same dedupe (fullName→family fallback, case-insensitive
  seen set), same whitelist-first substring matching on
  PackageFamilyName (client-side literal `in` vs server-side
  `-match` with Regex.Escape — documented semantics equal),
  same empty-pattern guard.
- Audit round 99 (self-test invariant coverage — clean):
  cross-mapped py T1–T12 against cs T1–T8. Shared invariants pin
  the same contracts (logger T4≈T2, prevention keys/defaults
  T6+T9≈T7, duplicate-free lists T10≈T8); cs-only tests cover
  .NET-specific surfaces with no py analog (arg parsing, assembly
  metadata, SystemApp wiring, trim safety). The strongest gates
  live py-side and read `Program.cs` directly: T11 value-name
  parity and T12 which is fully bidirectional — HKLM writes,
  per-user writes, and demoted/disabled services are each checked
  against both sides' backup lists, so a cross-language drift
  cannot pass both gates. No silent-drift hole found.
- Audit round 98 (config schema + defaults parity — clean):
  machine-verified: all 46 Prevention toggles are consumed at
  `prev.get` call sites whose per-site defaults equal both the
  `load_config` literal and the C# `GuardConfig` initializers —
  including the three opt-in-false layers (DisableOneDrive,
  DisablePrintSpooler, DisableModernStandbyNetworking use
  `, False`). Top-level fields match too: ScanIntervalSeconds=300,
  DryRun=false, BackupDirectory/LogFilePath fallbacks, Blacklist/
  Whitelist default lists, missing-file → write-then-return and
  BOM-tolerant reads on both sides.
- Audit round 97 (restore-path internals parity — clean):
  `RestorePackages`/`run_restore` verified equivalent — same ledger
  path, per-line JSON tolerance, name→family→"?" display fallback,
  all four kind dispatches (appx re-register 60s, winget install
  300s with `--disable-interactivity` + both accept flags,
  capability Add-WindowsCapability 180s, provisioned re-register
  then manual), same safe-name/ID gates before interpolation,
  restored/manual tally. Probe divergence noted: cs executes
  `winget --version` once and caches (catches dead App-Installer
  aliases); py's `shutil.which` only sees PATH presence — a dead
  alias reaches `winget install`, fails, and lands in the same
  manual bucket, so the end-state is identical.
- Audit round 96 (py fix — framework visibility in package enum):
  `_enum_blacklisted_packages` now returns 5-tuples carrying the
  IsFramework flag instead of dropping framework rows silently — the
  C# `GetBlacklistedPackages` contract it was documented to mirror.
  Callers skip framework rows for removal (scan, matched-families,
  monitor skip only in removal contexts — the monitor still watches
  framework families for re-installs, matching C#) and
  `--list-installed` prints them with the `[FRAMEWORK]` tag, same as
  `ListInstalled`. Framework skips in the scan are Warn-severity on
  both sides now. `get_blacklisted_packages` keeps its public
  3-tuple non-framework view for external callers.
- Audit round 95 (Appx removal-path parity — clean):
  the admin→user dual path verified equivalent — py keeps the
  is_admin → `-AllUsers` → user-level fallback inside
  `remove_appx_package`; cs splits it as `RemoveAppxPackage`
  (unconditional `-AllUsers`) with the user-level fallback in
  `RunScan` on failure (caller-side vs callee-side placement —
  same coverage, same 60s bound, same safe-name gate).
  SystemApp per-user skip uses the same InstallPath-empty
  detection at the same stage on both sides, and provisioned
  removal (`Remove-AppxProvisionedPackage -Online -PackageName`,
  120s, stderr warn) matches exactly.
- Audit round 94 (logging substrate parity — clean):
  `setup_logging`/`GuardLogger` verified equivalent — identical
  `[yyyy-MM-dd HH:mm:ss] [LEVEL] msg` line format on both
  console and file, same 1 MB rotation keeping one prior
  generation (`.1` vs `.old` suffix — cosmetic), same
  file-write-failure → console-only fallback, same once-per-
  process source check. cs additionally mirrors into the Windows
  Event Log — a cs-only sink; py's equivalent channel is NSSM's
  service-stdout capture (documented SCM-awareness split).
- Audit round 92/93 (scan orchestration + Win32 parity):
  `run_scan`/`RunScan` stage order verified — restore point →
  backup → appx → provisioned → capabilities → win32 →
  deprovision/store-policy markers → registry prevention → OEM
  + telemetry tasks → ETW/hosts → winget sweep → summary, with
  identical toggles and dry-run gates at every stage. Documented
  sequencing divergences (end-state identical, all layers
  idempotent and re-applied each interval): cs runs the winget
  sweep before the registry block and autologgers/hosts inside
  `ApplyAll`, while py orders registry → tasks → autologgers →
  hosts → winget; cs also double-checks whitelist/framework
  inside the removal loop and counts skipped/failed/systemApps
  separately where py tracks a single matched counter.
- Audit round 92 (Win32 enumeration parity — clean):
  `get_blacklisted_win32`/`GetBlacklistedPrograms` verified
  identical — same 4-way hive walk (HKLM 64 + WOW6432Node +
  HKCU + every loaded `S-1-5-21-*` user hive, the last two
  report-only since user-writable uninstall strings must never
  run under an admin token), same DisplayName+UninstallString
  presence gate, same SystemComponent=1 skip, same
  whitelist-first predicate over blacklist+Win32BloatNames, same
  case-insensitive display dedupe.
- Audit round 91 (Win32 uninstall dispatch parity — clean):
  `remove_win32_program`/`RemoveProgram` verified identical —
  same quote-aware `SplitCommandLine` (quoted path + verbatim
  args → CreateProcess), same QuietUninstallString-first
  preference, same `msiexec` substring trigger feeding the same
  `\{[0-9A-Fa-f\-]{36}\}` GUID regex into
  `msiexec /x {guid} /qn /norestart`, same 300s timeout, same
  manual-removal log instead of guessing vendor switches. py
  passes the vendor line as one verbatim string; cs splits
  FileName/Arguments — equivalent CreateProcess outcome.
- Audit round 90 (restore-point creation parity): py
  `create_restore_point` now runs through `run_powershell`
  instead of a hand-rolled `run_cmd` argv — it was the one
  PowerShell call site missing `-NonInteractive`, so a stray
  prompt could hold the subprocess until the 120s timeout. Same
  command text, same timeout, same Info/Warn outcome as C#
  `CreateRestorePoint`.
- Audit round 89 (deprovision markers + OEM-task sweep parity):
  `MarkDeprovisioned` now degrades per base key — previously both
  `Deprovisioned` and `EndOfLife` opens sat in one try, so a
  failure on either silently lost BOTH marker sets; the Python
  side always tolerated per-base failure. Same paths, same
  per-family subkey creation and count contract. OEM-task sweep
  verified identical: same 120s `Get-ScheduledTask` query
  (TaskPath `-like '*OEM*'` OR TaskName `-match` the shared
  25-pattern set), same protected `\Microsoft\Windows\…` prefix
  skip, same `schtasks /Change /DISABLE` 15s per task. cs's
  `Regex.Escape` on patterns vs py's raw alternation is a no-op —
  the token set carries no regex metachars.
- Audit round 88 (resident-service loop parity — clean):
  the `--service` monitor loop verified identical — same 300s
  default with the same <60s→60s clamp + Warn, same three-channel
  reinstall diff (provisioned DisplayName→PackageName, installed
  family→fullName, Win32 display minus user-hive/report-only),
  same first-scan baseline and seen-rollover, same dry-run gate
  before every re-removal, same no-hot-reload contract (config is
  fixed at startup on both — a mid-loop reload feature was
  previously rejected). py `int()` tolerates a quoted
  ScanIntervalSeconds where cs JSON-deserializes int strictly —
  both clamp the result identically; py's unconditional `time.sleep`
  vs cs cancellable `Task.Delay(stoppingToken)` is the documented
  SCM-awareness split.
- Audit round 87 (Active Setup stub sweep parity — clean):
  `disable_active_setup_stubs`/`DisableActiveSetupStubs` verified
  identical — same two key paths (64-bit + WOW6432Node
  `Installed Components`), same match blob (subkey name +
  default value + LocalizedName + StubPath), same whitelist-first
  bloat predicate over the same needle set (blacklist +
  startup-bloat names), same `DeleteSubKey`/`DeleteKey` removal,
  same per-key error isolation and identical log line.
- Audit round 86 (matching-engine parity — clean):
  blacklist predicate verified equivalent on both sides — py
  `is_target_package` does a client-side case-folded literal
  substring over the full catalog; cs pushes the same literal
  semantics down to PowerShell `-match` via `Regex.Escape`'d
  alternation (case-insensitive by default) on the same field
  (PackageFamilyName installed / DisplayName provisioned).
  Whitelist-first ordering, empty/whitespace entry guards,
  IsFramework skip, fullName→family dedupe key and the
  -AllUsers admin→non-admin fallback all match. Documented perf
  divergence: py downloads the whole catalog each scan and
  filters in-process, cs ships a 236-name alternation and
  filters server-side — same result set.
- Audit round 85 (prevention-layer dispatch parity — clean):
  all 35 toggles verified present and gated on both sides; every
  layer wrapped in its own catch→Warn so one failure can't abort
  the rest. Two documented structural divergences (same
  semantics): (a) py splits dispatch — `apply_registry_prevention`
  covers 33 while autologgers/hosts-block/winget/tasks live in
  `run_scan` so dry-run prints "[DRY-RUN] Would …" per layer, vs
  cs `ApplyAll` dispatching all 35 and skipping the whole call in
  dry-run ("Startup prevention changes skipped"); (b) py's
  `BlockTelemetryEndpoints` call stays unconditional in both —
  required so toggling off removes a previously written hosts
  block. `DisableXboxServices` call order differs (independent
  layers — no cross-dependencies).
- Audit round 84 (restore dispatch parity — clean):
  `run_restore`/`RestorePackages` verified identical — same ledger
  path + JSONL line-tolerant parse, same display fallback
  (name→family→"?"), all four kinds with identical gates,
  commands and timeouts: appx/provisioned re-register
  (`Add-AppxPackage -Register` 60s, safe-name gate first), winget
  (`install -e --id` 300s, ID-regex + presence gate), capability
  (`Add-WindowsCapability` 180s), everything else → manual bucket.
  Same restored/manual accounting and Info/Warn log severity.
- Audit round 83 (registry backup-net parity): C# `BackupKeyPaths`
  synced 122→191 and `UserBackupKeyPaths` 2→91 to match the Python
  lists — the service's `.reg` export safety net was missing
  coverage for ~70 HKLM write paths (SCHANNEL/TLS kills, Wdigest,
  Lsa, Tcpip/6 hardening, DriverSearching, WindowsUpdate, OOBE,
  EdgeUI, WDI, Windows Chat, etc.) and nearly every per-user
  hardening path. Both implementations now snapshot every key the
  tool touches on first apply.
- Audit round 82 (per-user hive enumeration parity — clean):
  `for_each_user_hive`/`ForEachUserHive` verified identical —
  same `S-1-5-21-*` SID filter (excludes .DEFAULT/service
  accounts/*_Classes), same ordering (loaded hives →
  default-profile NTUSER.DAT mounted under the same
  `BloatwareGuard_DefaultProfile` name via `reg load`/`unload`
  at 15s → HKCU fallback), same per-hive error isolation, same
  warn-when-zero-applies contract. `GetDefaultProfileDat` now
  mirrors `_default_profile_dat` (ProfileList read +
  expandvars + exists check, try-scoped read only).
- Audit round 81 (admin/elevation/service-install parity — clean):
  `is_admin`/`_relaunch_elevated` verified aligned with the C#
  elevation model — same `runas` mechanism (ShellExecuteW vs
  `ProcessStartInfo.Verb`), same install/uninstall self-elevation
  gates. Service lifecycle matches: stop→delete→strip hosts block
  on uninstall (registry/deprovision/startup markers intentionally
  persist on both sides). Documented divergences kept: py installs
  via NSSM+pythonw (pythonw isn't SCM-aware — error 1053 without
  a wrapper; the code itself steers users to `BloatwareGuard.exe
  install`), and cs adds `sc failure` restart-on-failure +
  description that has no NSSM equivalent. `--status` uses the
  same `sc query` (cs bounds it at 30s + 5s drain).
- Audit round 80 (process-runner parity):
  `run_powershell`/`run_cmd` now decode console output in the
  machine's actual OEM code page via `GetOEMCP()` instead of
  hardcoded cp932 — C# `Proc.Capture` uses
  `TextInfo.OEMCodePage`, so on non-Japanese Windows (cp437/cp850)
  the Python side mojibake'd non-ASCII output, corrupting package
  display names before matching. cp932 remains the fallback when
  the CP lookup fails. Invocation flags, timeout semantics
  (rc=-1 vs null), tree-kill and both-stream capture were already
  aligned.
- Audit round 79 (reinstall-monitor parity):
  `CheckReinstalls` now diffs provisioned packages on DisplayName —
  Python's `run_scan` monitor keys on DisplayName ("stable across
  versions"), but the C# monitor keyed on PackageName which embeds
  version+arch, so any provisioned-package version bump tripped a
  spurious RE-INSTALLED flag and re-removal attempt. Added
  `GetBlacklistedProvisionedPackagePairs` (DisplayName→PackageName
  pairs); the string-only API delegates to it. The other channels
  (appx family diff via `PackageFullName` lookup, Win32 display
  diff with user-hive report-only skip, dry-run gating, seen-set
  rollover after first scan) were already aligned.
- Audit round 78 (ETW autologger/channel parity — clean):
  `disable_telemetry_autologgers`/`DisableTelemetryAutologgers`
  verified identical — same 18-session list, same open-only
  `Start=0` write, same 3 diagnostic WINEVT channels with
  `Enabled=0`. DisableRecall's wevtutil kills match too (same 4
  AI/MCP channel names, `sl <chan> /e:false`, 15s) plus the
  `Disable-WindowsOptionalFeature -FeatureName 'Recall'` probe at
  120s (py gates it on `is_admin()`; cs runs unconditionally —
  harmless since ErrorAction SilentlyContinue absorbs the
  non-admin failure).
- Audit round 77 (capabilities + persistence-marker parity — clean):
  `remove_optional_capabilities`/`RemoveOptionalCapabilities`
  verified identical — same 6-name pattern, Installed-state filter,
  60s query + 180s remove, safe-name gate, post-remove re-query so
  only actually-gone capabilities reach the ledger. Persistence
  markers aligned: `MarkDeprovisioned` writes the same subkey under
  both Deprovisioned and EndOfLife roots;
  `ApplyRemoveDefaultStorePackages` does the same
  Enabled=1 + DynamicRemovalList merge (prior + legacy PackageList
  migration + new, case-insensitive first-seen dedupe), drops the
  legacy PackageList value, and writes RemovePackage=1 per family
  subkey.
- Audit round 76 (service-demotion parity — clean):
  `demote_service`/`DemoteService` verified identical — open
  (never create) `SYSTEM\CurrentControlSet\Services\<name>`
  writable, `Start=3` demand-start, errors swallowed; py returns
  bool (unused by callers, matching cs void). All demotion call
  sites aligned: MiscBloatServices loop (91), Xbox 4 + GamingAI
  ActivationType + SmartGlass, DoSvc, WSAIFabricSvc,
  wercplsupport, Edge update 3. Outright disables (RemoteRegistry,
  DiagTrack, RetailDemo, WerSvc, Spooler) use the same
  `sc.exe stop`/`config start= disabled` pair at 15s.
- Audit round 75 (telemetry hosts-block parity — clean):
  `set_telemetry_hosts_block`/`SetTelemetryHostsBlock` verified
  fully aligned — same `%SystemRoot%\System32\drivers\etc\hosts`
  resolution, strict UTF-8 decode (skip on undecodable bytes),
  identical `>>> BloatwareGuard telemetry block`/`<<<` markers and
  newline-normalized splice, same three no-op conditions (no
  block+disabled, absent file, content already desired), atomic
  rewrite, 520=520 domain set (no drift — the lone extractor
  artifact was a code comment, not a domain).
- Audit round 74 (startup-bloat layer parity — clean):
  `disable_startup_bloat`/`DisableStartupBloat` verified fully
  aligned — identical 8-way scan matrix (HKLM Run/RunOnce 64+32-bit
  views, four per-user hive combos), same 0x03+11-byte
  StartupApproved marker, same peer-view block (same-named
  non-bloat entry in the paired view suppresses the marker), same
  Explorer\Run policy-key purge with data logging, same
  `.bgdisabled` folder rename in user+common Startup dirs, and the
  Active Setup stub sweep deletes matching subkeys from the same
  two Installed Components paths with the same blob fields
  (name/default/LocalizedName/StubPath). Needle sources
  (blacklist + startup names, whitelist precedence) identical.
- Audit round 73 (scheduled-task + log-severity parity):
  `DisableOemTasks`/`disable_oem_scheduled_tasks` and the telemetry/
  OneDrive/EdgeUpdate task kills verified aligned — same
  Get-ScheduledTask sweep (OEM TaskPath or TaskName match, 120s),
  protected `Microsoft\*` prefix guard, `schtasks /Change /TN ...
  /DISABLE` at 15s, dict→array wrap. Fixed divergence: 32
  RegistryGuard layer-failure catches logged Error while Python
  logs the same non-fatal failures as warnings — all now
  `GuardLogger.Warn` (scan-loop and scan-error catches were
  already correct and untouched).
- Audit round 72 (winget sweep + restore parity — clean):
  `winget_sweep`/`WingetGuard.Sweep` verified fully aligned — same
  presence probe (`shutil.which` vs `--version` probe, 15s), same id
  gate (dot required + `^[A-Za-z0-9_.\-]+$`), whitelist substring
  precedence, identical `uninstall -e --id {e} --silent
  --disable-interactivity --accept-source-agreements` args, 300s
  timeout, ledger kind `winget`. Restore side identical too:
  `install -e --id ... --accept-package-agreements` (cs caches
  availability, py probes per entry — same outcome). Dry-run skips
  the sweep entirely on both sides.
- Audit round 71 (win32 uninstall path + dry-run counter parity):
  `get_blacklisted_win32`/`GetBlacklistedPrograms` verified aligned —
  same three hive scans (HKLM64/HKLM32/HKCU+HKU S-1-5-21 report-only),
  SystemComponent skip, QuietUninstallString preference, msiexec GUID
  `/x {guid} /qn /norestart` fallback, 300s timeout, user-hive strings
  never executed as SYSTEM. Fixed divergence: `run_scan` now counts
  dry-run would-removals in `removed` and reports them as "would
  remove N" in the scan summary, matching `RunScan`'s counter
  semantics (previously py always logged "removed 0" on dry-runs).
- Audit round 70 (appx enumeration parity):
  `GetBlacklistedPackages` dedupe now keys on `fullName or family`
  (family fallback when PackageFullName is empty) — previously every
  full-name-less row collapsed into a single `seen` entry so only
  the first such package was ever queued for removal, diverging
  from `_enum_blacklisted_packages`. Server-side regex filter vs
  client-side substring match verified equivalent (both substring
  semantics on `PackageFamilyName`); `-AllUsers`→fallback scope,
  120s timeout, dict→array wrap, whitelist precedence and
  IsFramework handling all aligned.
- Audit round 69 (removal-ledger parity — clean):
  `record_removal`/`RemovalLedger.Record` write the same JSONL
  schema (`ts` + `kind`/`name`/`family`/`full_name`); Python stores
  sparse dicts while C# always emits all four keys — both readers
  tolerate missing keys so the formats are interchangeable. Restore
  dispatch verified identical: appx/provisioned → staged re-register
  (`Get-AppxPackage -AllUsers` + `Add-AppxPackage -Register`),
  capability → `Add-WindowsCapability` (180s), winget → strict-ID
  `winget install` (300s), unknown kinds → manual bucket; same
  safe-name and winget-ID gates. Both ledgers append-only
  (rotation exists only on the log file, by design).
- Audit round 68 (registry write-kind parity — clean):
  machine-diffed every `set_registry_*` py call vs every
  `RegistryValueKind` cs SetValue by value-name — no DWord/String
  kind drift. `SendTelemetryData` verified as the intended
  DWORD `0` + REG_SZ `"0"` dual-write on both sides (covers
  consumers reading either type); remaining name-level diffs were
  extraction artifacts of variable-path call sites, all confirmed
  present in the counterpart implementation by targeted check.
- Audit round 67 (config load-path parity — semantics aligned):
  both loaders give the user's `config.json` full replace semantics
  for `Blacklist`/`Whitelist` (no merge with defaults) — identical
  contract. Noted divergence (kept intentionally): C#
  `ConfigLoader.Load` returns `CreateDefault()` when the file parses
  to JSON `null`; Python returns `None` which surfaces as a loud
  `AttributeError` — a broken/empty config file should fail noisily
  rather than silently re-run with defaults, so no change made.
  Remaining verified-clean surfaces: startup-bloat names, win32
  removal names, OEM task patterns, protected task prefixes.
- Audit round 66 (user-hive enumeration parity):
  `RegistryGuard.GetDefaultProfileDat` no longer returns null when the
  ProfileList read itself throws — it now degrades to
  `C:\Users\Default` and still validates via `File.Exists`, matching
  `_default_profile_dat`'s semantics. Previously any ProfileList read
  exception skipped the default-profile hive entirely, so new-user
  template hardening silently did not apply on machines where the
  ProfileList query fails.
- Audit round 62 (LeDragoX/Win-Debloat-Tools diff):
  `CurrentVersion\DeviceSetup CostedNetworkPolicy=1` — no
  device-software downloads over metered connections; closes the last
  silent-provision path for OEM companion payloads
  (BlockOemDriverUpdates layer + both backup lists). TextInput/
  EventTranscript/DisableUAR/PresenceWriter already covered;
  ConsentStore, UX prefs, mitigation-tuning skipped.
- Audit round 61 (O&O ShutUp10++ procmon-diff):
  `SOFTWARE\Microsoft\PCHC PreviousUninstall=1` (HKLM + per-user) —
  Windows Update treats PC Health Check as previously uninstalled and
  stops re-pushing the "is your PC ready" app; per-user
  `SQMClient\Windows CEIPEnable=0` — CEIP opt-out now covers the user
  hive too (HKLM service side already killed). Registered in all four
  backup lists. ConsentStore denies + Biometrics/location policies
  skipped — forbidden/kept-by-design.
- Audit round 60 (doc-drift audit): mechanical recount of every shared
  list — tasks py=cs=136 ✓, demoted services py=cs=91 (README said 89 →
  fixed), blacklist py=cs=config.json=src/config.json=236 ✓,
  telemetry hosts py=cs=520 ✓, whitelist py=cs=config=12 ✓,
  capabilities=6 ✓, DESIGN task count 134→136 fixed. No code changes.
- Audit round 59 (gordonbay/Windows-On-Reins diff): `NcdAutoSetup\Private
  AutoSetup=0` — UPnP/WSD network-device auto-install off: detected
  printers/media renderers no longer silently provision drivers +
  companion apps (BlockOemDriverUpdates layer + both backup lists).
  NetbiosOptions=2 skipped — NetBT driver + lmhosts already demoted;
  WDigest/CredentialsDelegation already covered; Defender/firewall/
  update kills, storage-disables, prefetch/hibernation prefs, and
  history-wipes rejected by policy.
- Audit round 58 (Disassembler0 diff): `UpdateOrchestrator\MusNotification`
  + `MusNotification_Ux` tasks disabled (134→136) — kills the
  "finish setting up your device"/restart-nag toasts; update
  orchestration tasks (Schedule Scan, USO_UxBroker) untouched.
  IFEO `Debugger` kill from same source skipped (task-disable is
  reversible; IFEO breaks any future exe update path); ConsentStore
  library denies skipped — forbidden.
- Audit round 57 (simeononsecurity diff): `Policies\Microsoft\WMDRM
  DisableOnline=1` — Windows Media DRM license-acquisition calls
  never leave the machine (HKLM write + both backup lists).
  ConsentStore denies skipped — forbidden; IFEO CompatTelRunner in
  source already exists in the closed-PR archive (not re-landed);
  Office/VS/Adobe app telemetry out of product scope; sensor
  overrides same class as the deliberately-kept location access.
- Audit round 56 (optimizer diff): `WcmSvc\Tethering
  RemoteStartupDisabled=1` — paired devices can no longer turn on
  Mobile Hotspot remotely; local start unaffected (hellzerg/optimizer
  DisableTelemetry; under the WcmSvc backup parent). Rest of
  optimizer's telemetry block already covered (WiFiSense surface
  complete); Hotspot 2.0 keys skipped — semantics unverifiable;
  AllowProjectionToPC skipped — kills a legitimate Miracast feature.
- Audit round 55 (tiny11builder appx diff): blacklist
  +`DolbyLaboratories.DolbyDigitalPlusDecoderOEM` — the OEM Dolby
  audio codec pushed with Dolby hardware (removal leaves standard
  audio playback working). Rest of the tiny11 prefix list already
  covered (`DolbyAccess`, Copilot, Clipchamp, OutlookForWindows,
  Xbox stack…); WindowsCamera deliberately out (legit feature,
  same class as the mic). Coremaker `_`-suffixed names all match
  existing substrings.
- Audit round 54 (W4RH4WK service diff): `NetTcpPortSharing` added
  to the demote list — Net.Tcp Port Sharing hosts WCF NetTcp
  bindings only, so demand-start is invisible outside opted-in
  WCF services. Remaining W4RH4WK kills reviewed and rejected:
  WlanSvc (breaks Wi-Fi), wscsvc/WdNisSvc (security posture),
  RemoteAccess (breaks VPN), WbioSrvc (breaks Windows Hello),
  ndu (kernel driver), sensor permission deny (location left
  alone by design). DESIGN.md self-test counts synced to actual
  (py T1–T12 / C# T1–T8).

- Self-test coverage — `_EXTRA_DIAG_CHANNELS` and `DEFAULT_WHITELIST`
  added to the T9 py↔cs shared-list parity sweep and T10 duplicate
  guard; whitelist extracted to a module constant (was inline in
  `load_config`) matching `DEFAULT_BLACKLIST`. T9 also gained a
  symmetric `cfg["Whitelist"]` vs defaults assertion — previously
  only Blacklist drift was caught.
- Docs parity — LetApps* app-privacy value count corrected to the
  true covered set (19; DESIGN layer table said 24).
- Docs parity — hosts domain count corrected to the true
  _TELEMETRY_HOSTS length (520; README feature table + DESIGN layer
  table had drifted to 518 across the two host additions).
- Microsoft Learn non-Enterprise endpoints doc diff: adopted
  `iris.api.iris.microsoft.com` (canonical Windows Spotlight/Iris
  metadata API alongside the existing `ris.api.iris.microsoft.com`
  CDN variant, hosts → 520). All other non-Enterprise endpoints
  reviewed — WU/licensing/Store/SmartScreen/NCSI/OCSP/auth/CDN and
  Office/OneDrive/Skype/Teams consumer endpoints remain skip-class.
- ReviOS playbook diff: adopted `in-v10.events.data.microsoft.com`
  (India-region ARIA/v10 event-ingest variant, hosts → 519). All other
  ReviOS surfaces reviewed — registry (380 values: UI/OOBE/TPM-bypass/
  WU/Defender/perf/vendor/rejected classes), services (driver-level
  perf services excluded), tasks, hosts (Brave vendor telemetry, VS
  AppInsights, CDN/OneDrive instances), appx — remaining diffs are all
  skip-class or prefix-covered.
- Japanese-source diff (Qiita Windows IoT/UWF hardening article): kernel
  CKCL context-logger sessions now stopped — `Start`=0 written under
  `...\Control\Diagnostics\Performance\{BootCKCLSettings,
  SecondaryLogonCKCLSettings, ShutdownCKCLSettings}` at both diagnostic-
  disable sites (C# + Python). The parent key was already backed up and
  already received `DisableDiagnosticTracing`=1.
- Docs parity — telemetry-task count corrected to the true
  TELEMETRY_TASK_PATHS length (134; README row 21 + DESIGN diagram).
  The earlier "165" counted every `\Microsoft\` task-path string in the
  file, including the protected-system-task prefixes and Edge/OneDrive
  updater entries owned by other layers.
- privacy.sexy scheduled-task diff: adopted
  `\Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate` (WER
  error-details updater, tasks → 134). Remaining psx task diffs are
  Windows Update/UpdateOrchestrator, Defender maintenance, MDM policy,
  OneDrive update (opt-in), and third-party updater tasks (Google,
  Dropbox, Firefox, Nvidia, Adobe, Office ClickToRun) — all skip-class;
  `AitAgent` stays excluded (legacy task already reverted upstream).
- WindowsSpyBlocker data hosts diff: adopted `cache.datamart.windows.com`
  (diagnostic DataMart upload endpoint, listed in all spy-list formats,
  hosts → 518). Remaining wsb spy/extra diffs are CDN/instance endpoints
  (wns.windows.com, llnw.net, blob.core.windows.net), Defender/MAPs
  (spynet2/spynetalt), connectivity probes (ipv6.microsoft.com,
  msftncsi.com), or consumer/functional endpoints (OneDrive, Skype, Teams,
  Weather, Store) — all skip-class.
- RemoveDefaultMicrosoftStorePackages official target list diff (Microsoft
  Learn 25H2 policy docs): adopted `Microsoft.Microsoft365Copilot` (inbox
  Microsoft 365 Copilot app, blacklist → 235). The Xbox overlay entries
  (`Microsoft.XboxGameOverlay`/`Microsoft.XboxGamingOverlay`) were already
  covered by the `Microsoft.Xbox` prefix; remaining official targets
  (Paint, Calculator, Camera, Terminal, Notepad, MediaPlayer, etc.) are
  functional apps excluded by design.
- 25H2 inbox-app inventory diff (Tom4tot 25H2 appx audit): adopted
  `Microsoft.OfficePushNotificationUtility` (inbox Office push-notification
  stub, blacklist → 234). `Microsoft.OneDriveSync` skipped — OneDrive
  remains opt-in. `Microsoft.Office.ActionsServer` and
  `Microsoft.Windows.DevHome` were already covered.
- W4RH4WK/Debloat-Windows-10 hosts diff (+3 → 518 domains): adopted
  `www.bingads.microsoft.com` (www sibling of the existing Bing-ads
  endpoint), `livetileedge.dsx.mp.microsoft.com` (legacy live-tile
  content delivery — a dead surface on Win11), `any.edge.bing.com`
  (Bing edge endpoint behind Start-search web results). Skipped: the
  list's remaining 62 misses are Akamai/akadns/msedge CDN edges, OCSP
  (`hostedocsp.globalsign.com`), Defender cloud (`wdcp*`), Windows
  Update SLS, NCSI connectivity checks (`msftncsi.com` — same class as
  the reverted EnableActiveProbing change), Xbox/Skype/MSN consumer
  app endpoints, and IP-based firewall rules (out of mechanism scope).
- Self-test T12 further hardened on the per-user side: path expressions
  now expand loop vars (`CONST + "\\" + toast`), multiline
  paren-concatenated constants (`NAME = (r"a" r"b")`) resolve correctly,
  and both py/cs miss checks use the same containment semantics as the
  HKLM side (a write under a backed-up parent key is covered, matching
  `reg export`'s recursive subtree export). Verified non-vacuous: the
  three sibling-toast paths resolve and are covered via
  `...\Notifications\Settings`.
- Backup-coverage hardening: `SOFTWARE\Microsoft\.NETFramework` +
  `SOFTWARE\Wow6432Node\Microsoft\.NETFramework` added to both backup
  key lists — the .NET strong-crypto writes (dn_root/dn2 foreach loops)
  were the only HKLM write paths not covered by the registry-export
  safety net. Self-test T12's extractor strengthened so the gap class
  can't recur: py side now resolves `for VAR in (...)` loop-variable
  path tuples, cs side resolves `CreateSubKey(CONST)` and
  `foreach (var x in new[] {...})` arguments.
- 25H2 ADMX kill-named policy sweep (Disable*/TurnOff*/No*/Hide* — 406
  policies, 21 privacy-adjacent candidates): `DisableWidgetsBoard`=0 +
  `DisableWidgetsOnLockScreen`=0 under `SOFTWARE\Policies\Microsoft\Dsh`
  (NewsAndInterests.admx — the policies' enabledValue is 0, i.e. 0 turns
  the surface off) and `NoSystraySystemPromotion`=1 under
  `Software\Policies\Microsoft\Windows\Explorer` (Taskbar.admx — blocks
  OEM system-tray promotions). Remaining candidates were already covered
  (`DisabledByGroupPolicy`, `NoCloudApplicationNotification`) or
  skip-class (IE/legacy-Edge/functional UX/security).
- `NoGenTicket`=1 added under
  `Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform`
  (AVSValidationGP.admx NoAcquireGT policy — opt-out of sending KMS client
  activation data to Microsoft; complements the existing non-policy
  SPP-path write). Backup-key list covers the new Policies path.
- `LetAppsAccessSystemAIModels`=2 (ForceDeny) re-landed in
  DisableAppPermissions — verified present in the official 25H2 ADMX
  (AppPrivacy.admx enum: 0=user-in-control/1=force-allow/2=force-deny);
  the earlier revert (commit c382a17) predated the ADMX evidence.
  LetApps* deny list now 24 entries.
- Docs parity — remaining stale counts synced to implementation: LetApps*
  denies 23 (DESIGN was 16), AutoLogger sessions 18 + 3 diagnostic channels
  (README was 13), hosts block 514 domains (README was 515)
- Docs parity — telemetry-task count brought to current 165 (DESIGN.md
  diagram was 98, README row 21 was 125)
- 25H2 ADMX .adml deep-scan — `MicrosoftEdge\Books\
  EnableExtendedBooksTelemetry`=0 (legacy EdgeHTML Books telemetry; only
  uncovered telemetry-flagged policy left in the official catalog)
- Microsoft 25H2 ADMX reference (official Jan-2026 V3 catalog) — policy
  kills +10, each verified against the canonical .admx set:
  `InputPersonalization\ImplicitDataCollectionOff`=1,
  `TabletPC\TurnOffPenFeedback`=1, `PenTraining\DisablePenTraining`=1,
  `Windows Error Reporting\DisableArchive`=1, `ShareSheet\
  DisableShareAppPromotions`=1, `Internet Explorer\AllowServicePoweredQSA`=0,
  `DataCollection\ConfigureTelemetryForMicrosoft365Analytics`=0 (all
  Machine+User) + per-user `PushNotifications\DisallowNotificationMirroring`=1,
  `CloudContent\EnableOrganizationalMessages`=0,
  `Control Panel\International\HideCurrentLocation`=1
- dvandenburgh/Disable-Win11AI diff — `Explorer\HideFrequentlyUsedApps`=1
  (sibling of the already-covered HideRecentlyAddedApps policy)
- noverse.dev privacy/security pages — documented policy kills +7:
  `System\EnableMmx`=0 (Phone Link), `System\EnableAppUriHandlers`=0
  (apps-for-websites handoff), `ScriptedDiagnostics\EnableDiagnostics`=0 +
  `ScriptedDiagnosticsProvider\Policy\EnableQueryRemoteServer`=0 (online
  troubleshooting content), `Troubleshooting\AllowRecommendations\
  TroubleshootingAllowRecommendations`=0, `Policies\System\
  DontDisplayUserName`=1, per-user `CDP\EnableRemoteLaunchToast`=0
- noverse.dev copilot page — `CopilotHWKeyChoiceSet`=1 under per-user
  `Explorer\AutoInstalledPWAs`: suppresses the Copilot hardware-key
  choice prompt via the same fake-completed marker mechanism as the
  adjacent CopilotPWAPreinstallCompleted write
- noverse.dev sleep-study doc — diagnostic ETW channels +3 inside
  DisableTelemetryAutologgers: `Enabled`=0 under
  `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\` for
  `Microsoft-Windows-SleepStudy/Diagnostic`,
  `Microsoft-Windows-Kernel-Processor-Power/Diagnostic`,
  `Microsoft-Windows-UserModePowerService/Diagnostic`
  (wevtutil sl /e:false mechanism; open-only, never creates keys)
- noverse.dev scheduled-task catalog diff — telemetry tasks +1:
  `\Microsoft\Windows\Customer Experience Improvement Program\Uploader`
  (CEIP upload task, distinct from the Broker node UploadCachedReports)
- itsnileshhere/windows-iso-debloater diff — blacklist +2:
  `Microsoft.Windows.Copilot` (OS-inboxed Copilot package, distinct
  from Store `Microsoft.Copilot`), `Microsoft.Windows.Teams` (inbox
  Teams integration stub)
- RealSyferX/windows-11-debloat diff:
  - telemetry tasks +1 → `\Microsoft\Windows\Customer Experience
    Improvement Program Broker\UploadCachedReports` (cached CEIP
    report upload)
  - hosts +4 → 515: `telemetry.appex.bing.com`,
    `telemetry-uap.microsoft.com`,
    `redirection.telemetry.microsoft.com`,
    `prod.activity.windows.com`
  - `DiagSvc` already covered (diagsvc); `fhsvc`/CDN/STS/DHA endpoints
    skipped as functional
- KB5083769 / Neowin doc confirmation — `RemoveMicrosoftCopilotApp`=1
  additionally at Device scope (`HKLM\SOFTWARE\Policies\Microsoft\Windows\
  WindowsAI`); MS doc lists the policy at both `./Device/` and `./User/`
  WindowsAI, we previously wrote only the user hives.
- MS "manage connections" endpoint-doc diff (hosts +3 → 511):
  - `api.cdp.microsoft.com`, `msedge.api.cdp.microsoft.com` — Connected
    Devices Platform API (CDP services/policies already killed;
    server-side reinforcement)
  - `dmd.metaservices.microsoft.com` — device-metadata service endpoint
    (`PreventDeviceMetadataFromNetwork` channel)
  - (Skipped: Windows Update/SmartScreen/Store/OCSP/Teams/Office/OneDrive
    functional endpoints — blocking them breaks documented connectivity)
- Turtlecute33/Privacy.sexy-Revamped diff (maintained privacy.sexy fork):
  - Telemetry tasks +6 — Server CEIP node (`Server\ServerCeipAssistant`,
    `Server\ServerRoleCollector`, `Server\ServerRoleUsageCollector` —
    Windows Server CEIP, sibling of the client CEIP tasks already covered)
    and OOBE third-party app scan triggers
    (`UpdateOrchestrator\StartOobeAppsScan{AfterUpdate,LicenseAccepted,
    OobeAppReady}` — usoclient-driven OEM/Store app re-provisioning after
    updates)
  - `Speech_OneCore\Preferences` +`VoiceActivationDefaultOn`=0 on all user
    hives and HKLM (master "always-on voice listening" default — distinct
    value from the existing `VoiceActivationOn` write); Python also gained
    `VoiceActivationEnableAboveLockscreen`=0 (parity with the existing C#
    write)
  - (Skipped: Windows Update defer/pause tasks, Defender/Wd*/SmartScreen
    kills, vendor updaters (Google/Adobe/Firefox/Nvidia/Office), UI
    preferences, and previously-rejected `AllowInputPersonalization`/
    `GlobalUserDisabled`/`ShowCortanaButton`/`UsageTracking`/
    `AitAgent`)
- Subprocess output decoding parity (C#):
  - `Proc.Capture` now sets `StandardOutputEncoding`/`StandardErrorEncoding`
    to the system OEM code page (cp932 on ja-JP) via
    `CodePagesEncodingProvider` — .NET's UTF-8 default mojibaked localized
    powershell/reg/schtasks/winget output in logs (Python already decodes
    subprocess bytes as cp932)
- Atomic file writes (CS-lens durability audit):
  - hosts block and generated `config.json` now write via a same-dir temp
    file + rename (`os.replace` / `File.Move`) — a crash mid-write can no
    longer leave a truncated hosts file or half-written config on disk
- dvandenburgh/Disable-Win11AI re-diff (25H2 AI-surface sweep):
  - `DisableSpotlight` +`HideAIActionsMenu`=1 — documented 25H2 Explorer
    policy killing the "AI actions" File Explorer context-menu entry
  - `DisableRecall` +`AllowSnapshotExport`=0 — sibling snapshot-export
    kill (same semantics as `AllowRecallExport`, alternate name used
    by the source; kept alongside for coverage)
  - (Skipped: `IsEducationEnvironment` education-environment spoof flag;
    Explorer UX prefs — file-ext, frequent/recent lists, taskbar mode)

- zoicware/RemoveWindowsAI re-diff (post-#236/#238 head, ~30 new commits):
  - `_VELOCITY_AI_IDS` +`1561856655` (EnabledState=1) — obfuscated
    regID of FeatureId 58375086, the Explorer-side feature that
    depends on AIFabric (zoicware's Explorer-ribbon fix)
  - `MiscBloatServices` +`IsoEnvBroker` — agentic-AI sandbox/isolation
    broker service demoted to demand-start (zoicware disables=4)
  - (Covered already: ConsentStore generativeAI/systemAIModels denies,
    RecordUsageData, CopilotPWA preinstall markers, Voiess/Speion/
    Livtop/Ink.Handwriting, AI-event channels; skipped: Office vendor
    copilot-pinning keys, App-Paths/taskkill/CBS deletions,
    `AIContext` delete semantics, per-app mic deny — app already
    blacklisted)

- New-source sweep (Titanium-OS-Suite, retr0gr4d3/NMGW,
  fuxdasec/winlite, SysAdminDoc/Debloat-Win11 v2.3.11,
  Arcticforrecord/win11debloat-customization, kgntmr/quietpane,
  noid-privacy v2.2.5 SecurityBaseline, privacy.sexy, winutil head):
  - `DisableCDP`/consent block +`CdpSessionUserOverride`=0 per-user
    (Connected Devices Platform session-user override — Titanium)
  - blacklist +`PricelineCom.`/`GroupMe`/`Microsoft.Tips` (winlite —
    promoted stubs still shipping on 25H2 consumer images)
  - Everything else landed in skip classes: Defender/SmartScreen kills
    + scan tuning (Titanium/noid SecurityBaseline/winlite), firewall
    IP blocks (`BlockMSTelemetry` rule names), WU deferrals/access
    policy, audit/eventlog/admin merges, Kerberos/PKINIT/CredSSP/
    WinRM auth families, credential/encryption toggles, device-class
    controls, vendor policies (Adobe/CCleaner/Office/Brave/Edge
    autofill-password-SmartScreen), perf/gaming knobs, OOBE/UX prefs,
    feature-service kills (wuauserv/WlanSvc/W32Time/NlaSvc), live
    mic/cam/location ConsentStore caps (platform kills — per-app
    Copilot mic deny redundant since the app is blacklisted),
    `IsEducationEnvironment`/`GlobalUserDisabled` spoof flags

- self-test T9 hardened: `_USER_BACKUP_KEY_PATHS`,
  `_EXTRA_BACKUP_SERVICES` and `_EOL_PATH` joined the py<->cs
  shared-list parity assertions (previously only dup-free / backup-
  coverage transitive coverage — a dropped cs entry would have
  passed silently)

- OEM task patterns +`AMD`, `AUEP` (AMD User Experience Program telemetry tasks)

- hosts +18 (Win-Debloat Firewall diff): ARIA regional ingest
  (us/eu/az.pipe.aria), events variants (v20c, functional),
  AI-fabric/model endpoints (aimodels/models/directml/aifabric),
  Copilot backends (copilot.microsoft.com, sydney.bing.com,
  edgeservices.bing.com), OneSettings CDN edges
  (onesettings-public/bn2/co2.azureedge), widgetcdn + MSN feed
  content (shell/assets.msn.com). Skipped: wdcp* (Defender cloud
  boundary), ecs*/nexusrules Office vendor, config.edge.skype.com
- OEM task patterns +`AMD`, `AUEP` (AMD User Experience Program)

- Reclaim catalog diff: `DisableWindowsSpotlightOnLockScreen`=1
  (HKLM CloudContent), Edge `PinningWizardAllowed`=0 +
  `NewTabPageAllowedBackgroundTypes`=3, per-user
  `NoRecentDocsHistory`=1 (Policies\Explorer), AMD
  `UserExperienceProgram`=0 @ SOFTWARE\AMD\CN (+ backup path)

- hosts +`g.msn.com.nsatc.net` (Reclaim blocklist diff — MSN CNAME alias)

- REVERT (noid-privacy ADMX audit): removed `HideAIActionsMenu`
  (2 sites) and `LetAppsAccessSystemAIModels` from AppPrivacy —
  noid-privacy verified neither exists in the official 25H2 ADMX
  package; per the no-unverifiable-names rule both are dropped

- REVERT (noid-privacy v2.2.5): `WpadOverride` (HKLM + per-user)
  dropped — noid's primary-source review marks the scalar
  undocumented; documented `DisableWpad`=1 WinHTTP mechanism kept
- DisableEdgeBloat +`EnableUnsafeSwiftShader`=0 (documented Edge
  policy — kills the software WebGL/WebGPU renderer attack surface)

- per-user AI toggles (win-debloat Privacy): `DisableAIRewrite`=1
  (Notepad Rewrite) + `DisableSuperResolution`=1 (Photos AI)
- `MicrosoftCopilotElevationService` demoted — Copilot app's
  elevation channel (zoicware/RemoveWindowsAI; demote not delete)

- `RestrictRemoteClients`=1 @ RPC policy — denies unauthenticated
  remote RPC calls (MS Security Baseline; win-debloat Security)
- `AarSvc` (Agent Activation Runtime — Copilot voice/agent host)
  demoted (zoicware removes; we demote)

- telemetry tasks 95→96: `Customer Experience Improvement
  Program\BthSQM` — Bluetooth CEIP SQM uploader (hst-windows-utility)
- misc demote services +4: `cbdhsvc` (cloud-clipboard sync),
  `WpnUserService` (WNS push channel) [privacy.sexy], `amdlog`
  (AMD logging), `SsdpDiscovery` (SSDP discovery attack surface)
- blacklist 230→231: `828B5831.` publisher namespace
  (HiddenCityMysteryofShadows stub — winlite)

- hosts +1: `adl.windows.com` — Azure Data Lake diagnostic ingest
  front (WindowsSpyBlocker spy ruleset; rest of the ruleset is
  WU/CDN/auth/WNS functional infra — skipped)

- `DisableCloudClipboard` +`EnableCloudClipboard`=0 per-user
  (LeDragoX WinDebloatTools user-level switch — policy +
  auto-upload kills leave the local pref on)

- DisableEdgeBloat +5 (Edge policy catalog full sweep): `LocalBrowserDataShareEnabled`=0
  (Edge→Windows search data share), `GuidSwitchEnabled`=0,
  `CredentialProviderPromoEnabled`=0, `OutlookHubMenuEnabled`=0,
  `MicrosoftOfficeMenuEnabled`=0 — remaining promo/data-share
  surfaces after the 792-policy index diff

- `DisableTelemetry` +`DisableInternetExplorerLaunchViaCOM`=1
  (`Internet Explorer\Main`, HKLM) — Microsoft Security Baseline policy
  blocking legacy IE COM automation (noid-privacy baseline audit)

- `BlockTelemetryEndpoints` +44 hosts (462->506): Watson upload cabs
  (`ceus/eaus/weus*watcab`), km/um/modern Watson + OCA crash analysis,
  SQM front-end, telecommand, EU Watson/Office events, AppInsights/Aria
  ingest, Iris feed backends (fd/ris.api.iris + azure iris-de-*),
  vortex/settings aliases, MSN feed + Bing/AppNexus/omtrdc ads, Solitaire
  events, MyAnalytics/Viva, Vungle ad SDK, Insider enrollment
  (schrebra Windows.10.DNS.Block.List sweep)

- `DisableTelemetry` +`DisableAutomaticRestartSignOn`=1
  (`Policies\System`, HKLM + backup path) — Automatic Restart
  Sign-On off: Windows Update restarts no longer auto-log-in the
  last user (RyTuneX/Windows-On-Reins hardening diff)

- `BlockOemDriverUpdates` +`DontSearchWindowsUpdate`=1 — the GPO-pinned
  twin of `SearchOrderConfig=0` (`Policies\...\DriverSearching`,
  persists against non-policy resets)
- `DisableTelemetry` +SMB/Schannel hardening 5 values:
  `AllowInsecureGuestAuth`=0 (LanmanWorkstation — anonymous SMB off),
  `AllowInsecureRenego{Clients,Servers}`=0 + DH
  `Client/ServerMinKeyBitLength`=2048 (RapidOS protocols batch);
  backup paths added for all three roots

- `DisableTelemetry` +`AllowUserInfoAccess`=2
  (`Policies\Microsoft\Windows\System`) — documented GPO: apps no
  longer receive user name/account picture/domain info
  (WindowsMize Set-UserInfoSharing)

- `DisableMiscBloatServices` +6 Intel vendor services (83→89):
  `jhi_service` (DAL/ME host), `LMS` (vPro local mgmt),
  `igccservice`, `igfxCUIService2.0.0.0`, `cplspcon`, `cphs`
  (Graphics Command Center + control-panel helpers — WindowsMize
  Intel.ps1 diff; demand-start keeps install usable)

- `DisableTelemetry` +8 documented kills (WindowsMize telemetry diff):
  `DontReportInfectionInformation`=1 (MRT report channel — scan itself
  unaffected), `LimitDiagnosticLogCollection`/`LimitDumpCollection`=1,
  `DisableInstallTracing`/`DisablePCA`=1 (AppCompat),
  `DisableDiagnosticTracing`=1 (NT kernel diag tracing)
- +NVIDIA driver telemetry opt-outs: `SendTelemetryData`=0 +
  `SendNonNvDisplayDetails`=0 (`nvlddmkm\Global\Startup`) +
  `OptInOrOutPreference`=0 (`NvControlPanel2\Client`; pairs with the
  demoted `NvTelemetryContainer` service)
- skipped: `NoGenTicket` (closed-PR), `DisableEngine`/`SbEnable`
  (breaks app-compat shims), `RSoPLogging` (admin logging), NVIDIA
  `EnableRID*` feature flags

- `DisableTelemetry` +`DOTNET_CLI_TELEMETRY_OPTOUT`=1 +
  `POWERSHELL_TELEMETRY_OPTOUT`=1 machine env vars
  (`Session Manager\Environment`, REG_SZ) — documented opt-outs for
  .NET CLI and PS7 telemetry (WindowsMize Disable-{DotNet,PowerShell}Telemetry)

- `DisableCloudContent` +`ConfigureWindowsSpotlight`=0 (HKLM twin of
  the per-user spotlight kills)
- per-user SearchSettings +3: `IsStoreSuggestionsEnabled`,
  `IsGlobalFileSearchProviderToggleEnabled`, `IsWebSuggestionsEnabled`
  =0 (Start-search store/cloud/web suggestion toggles — WindowsMize)
- per-user Privacy +`PersonalizedOffersEnabled`=0 and
  `A9\SnapshotCapture\IsFilteringTelemetryEnabled`=0 (Recall
  snapshot filtering telemetry — both Settings-backed)
- `DisableTelemetry` +3 documented auth/logon hardening values:
  `DontDisplayLastUserName`=1, `NoLocalPasswordResetQuestions`=1,
  `DisablePasswordReveal`=1 (CredUI; backup paths added)

- `DisableTelemetry` +3 documented kills (RyTuneX PolicyHelper diff):
  `RegisterSpoolerRemoteRpcEndPoint`=0 (Print Spooler remote-RPC
  surface; local printing unaffected),
  `EnabledExecution`=0 (Scheduled Diagnostics engine),
  `AllowBroadcasting`=0 (GameDVR broadcast upload channel)
- skipped: WU/Defender/RDP/FVE/UAC/location/cam-mic/Store-removal/
  admin-lockdown/DoH/NCSI/vendor(Office,Chrome,Firefox,Adobe,Edge)
  classes and `AllowSignInOptions`/`DisableStartupSound` UX knobs

- `DisableTelemetryTasks` +1 (98→99):
  `UsageAndQualityInsights\UsageAndQualityInsights-MaintenanceTask`
  (UQI/OneSettings maintenance — WindowsMize task-list diff)

- `DisableTelemetryTasks` +24 (99→123, WindowsMize task-list diff):
  PcaWallpaperAppDetect, DUSM dusmtask, Diagnosis
  UnexpectedCodepath, PerformanceTrace RequestTrace, Flighting
  FeatureConfig BootstrapUsageDataReporting, input/peripheral
  settings sync ×7, language-settings sync, Provisioning
  Cellular/Logon, EnterpriseMgmt MDMMainten(e)nceTask ×2, theme
  sync ×2, RemoteAssistanceTask, Offline Files sync ×2,
  PushToInstall Registration, AppListBackup
  BackupNonMaintenance, ApplicationData DsSvcCleanup, User
  Profile HiveUploadTask — all named tasks only (folder-wide
  kills avoided since they hit functional tasks)

- `BlockTelemetryEndpoints` +`sqm.ppe.telemetry.microsoft.com`
  (506→507 — SQM pre-production endpoint; RyTuneX hosts diff)

- `DisableTelemetry` +5 (batlez-tweaks diff):
  `BlockUserFromShowingAccountDetailsOnSignin`=1 (sign-in
  screen account details hidden), `SQMClient\UploadDisableFlag`=1
  (pre-policy CEIP upload kill), TaggedEnergy
  `TelemetryMaxApplication`/`TelemetryMaxTagPerApplication`=0
  (per-app battery telemetry)
- `DisableSearchWebAndAds` per-user +4:
  `BackgroundAppGlobalToggle`=0, `Start_IrisRecommendationEnabled`=0,
  `VoiceActivationEnableAboveLockscreen`=0,
  `DeliveryOptimization\SystemSettingsDownloadMode`=0

- `_STARTUP_BLOAT_NAMES` +20 (et-optimizer Run-purge diff):
  ASCTray, BabylonToolbar, CoolWebSearch, Crossrider, DriverMax,
  FunWebProducts, MediaNewTab, MyWebSearch, PCOptimizerPro,
  RelevantKnowledge, SAntivirus, Segurazo, ShopperPro, SlimDrivers,
  SuperOptimizer, SweetPacks, UpdatePPShortCut, Vosteran,
  WebCompanion, WinZipDriverUpdater — browser-hijacker/adware PUPs +
  PUA-tier driver "optimizers"; TeamViewer (remote-admin) and
  system-name lookalikes (searchapp.exe/SearchIndexer.exe) left out
  to avoid false positives

- `DisableAppPermissions` +3 (Espionage724 App Permissions Deny):
  `LetAppsAccessGazeInput`/`LetAppsAccessHumanPresence`/
  `LetAppsAccessBackgroundSpatialPerception`=2 — newer sensor/AI
  capability force-denies
- `DisableTelemetry` +`SoftwareProtectionPlatform\NoGenTicket`=1
  (SPP generic-ticket licensing telemetry off)

- `DisableTelemetryTasks` +2 (123→125, winhance3 diff):
  `WindowsAI\RecallConfiguration` + `WindowsAI\RecallPipeline` —
  Recall snapshot/pipeline scheduler kills consistent with the
  existing Recall policy denies

- `DEFAULT_BLACKLIST` +2 (190→192, win-debloat-tools diff):
  `RandomSaladGamesLLC.` + `SAMSUNGELECTRONICSCO.LTD.` — casual-game
  and Samsung store stub publisher namespaces

## [Unreleased] — v1.61.1: restore log shows actual ledger kind in manual note

- Non-appx/provisioned entries (win32, startup, hosts) hit the shared manual
  branch which printed "(provisioned — ...)" — misleading. Now prints
  `kind=<value>` and a vendor/Settings hint instead. (C# + Python)

## [Unreleased] — v1.61.0: --restore re-register fallback for provisioned entries

- `provisioned` ledger entries previously went straight to manual-restore.
  They now attempt the same Get-AppxPackage -AllUsers re-register first — the
  package payload often still exists for another user profile, making the
  removal actually reversible without a Store reinstall. Falls back to the
  manual note when the payload is truly gone. (C# + Python parity)
- New-source sweep: PingMeBaby/Shush11, Arcticforrecord/win11debloat-
  customization (Raphire mirror), RealSyferX — all covered or empty.

## [Unreleased] — v1.60.9: timeout-kill for bounded C# process waits

- `ShowStatus` (sc query) and `RestoreStagedPackage` (DISM restore) waited
  30s/60s but left the child running on timeout — both now `Kill(true)` on
  timeout so a hung sc/DISM cannot outlive the call.
- Python side re-audited: every subprocess call already carries `timeout=`.

## [Unreleased] — v1.60.8: SysAdminDoc/Debloat-Win11 diff — OEM audio service demote (C# + Python)

- `DisableMiscBloatServices` +`WavesSvc64` — Waves MaxxAudio OEM audio-suite
  background daemon (SysAdminDoc/Debloat-Win11 v2.3.11 OEM module; demote keeps
  it restorable where the source deletes it).
- Audit: repo's full policy catalog + all module services/presets swept — all
  other entries already covered (agent-connector trio, Recall policies,
  `DisableRecallDataProviders` correctly user-scope) or UI-class skips.

## [Unreleased] — v1.60.7-mvp: tomytate/Win-Debloat full sweep + docs sync

- DisableSpotlight: hides the "Learn about this picture" desktop
  icon (`Explorer\HideDesktopIcons\NewStartPanel` `{2cc5ca98-…}`=1,
  per-user all hives) — Spotlight promo surface; added to user
  backup paths both impls
- Blacklist: `E046963F.` Lenovo publisher namespace (supersedes the
  `E046963F.LenovoCompanion` needle) + `Microsoft.Teams`
- Self-test T9 hardened: `_USER_BACKUP_KEY_PATHS`,
  `_EXTRA_BACKUP_SERVICES`, `_EOL_PATH` joined py<->cs list parity
- Doc count sync: tasks 95, services 76, hosts 442; version bump
  to 1.60.7-mvp everywhere

## [Unreleased] — v1.60.7-mvp: RegiLattice v6.35.0 policy diff

### Added
- `DisableSearchSuggestions` +`DoNotUseWebResults`=1 (Windows Search
  policy — hard kill for web results below the Bing/suggestion
  switches)
- `BlockProvisioning` +`DisableBITSNotification`=1 (BITS policy —
  download-status toasts off)
- `DisableTelemetry`/`SettingSync` block +`DisableSettingSyncDeviceOverride`=1
  (device-level sync override kill alongside the per-user overrides)
- `DisableTelemetry`/Windows-Backup block +`DisableCloudBackup`=1 +
  `DisableBackupNotifications`=1 (`Policies\Microsoft\Windows\Backup` —
  cloud-backup + nag-notification policy kills)
- `BackupKeyPaths`/`_BACKUP_KEY_PATHS` +`Policies\Microsoft\Windows\Backup`
  +`Policies\Microsoft\Windows\BITS`

(Skipped from the same diff: Office/Outlook/Adobe/Java/Firefox/VSCode
vendor values, RDP/Terminal-Server `f*` redirects, Defender/ATP and
NTLM/credential-delegation hardening, print-restore kills, gaze/dwell
accessibility toggles, WU/DO bandwidth and deferral policies.)

- `DisableTelemetryTasks` +`\GameBarPresenceWriter` (per-user root task
  writing "now playing" state for Game Bar/Xbox widgets — jonax1337/
  Reclaim 228-tweak diff; remaining Reclaim surface was UI/perf/vendor
  or already covered)
- Fresh-source sweep (hselimt/HST-WINDOWS-UTILITY, tomytate/Win-Debloat,
  emadadeldev/ittea, mhg778/Manolito, synoxvf/NOVA, filippobrundia/
  WinOpt, Ublaze/Windows11-Optimizer, dthcst/fregonator,
  IntersectCrewman/windows-11-debloat-pro):
  - `DisableSearchSuggestions` +`HistoryViewEnabled`=0 (per-user
    `CurrentVersion\Search` — Settings "Search history" toggle)
  - `DisableTelemetry` +`AppSuggestions`=0 (per-user
    `CurrentVersion\Privacy` — suggested-content surface)
  - `DisableRecall` +`IsRecallAllowed`=0 (per-user
    `CurrentVersion\Recall`) + `ClickToDoEnabled`=0 (per-user
    `Explorer\Advanced`) — user-level kills complementing the
    WindowsAI policies
  - Paint app-level AI toggles +4 names (`CocreatorEnabled`,
    `ImageCreatorEnabled`, `GenerativeFillEnabled`,
    `GenerativeEraseEnabled` — alternate `*Enabled` spellings alongside
    the existing `Enable*` names)
  - `MiscBloatServices` +`utcsvc` (Connected User Experiences and
    Telemetry — DiagTrack companion; registry demote works where
    `sc config` is refused)
  - `UserBackupKeyPaths`/`_USER_BACKUP_KEY_PATHS` +`CurrentVersion\Recall`
  - blacklist +`AcerIncorporated.`/`LenovoCorporation.` publisher
    prefixes (cover the full OEM suite families — the lone
    `AcerQuickAccess` needle is superseded)
  - `DisableTelemetryTasks` +`\CloudExperienceHost\CreateObjectTask`
    +`\RetailDemo\CleanupOfflineContent` (OOBE cloud-experience
    provisioning + RetailDemo offline-content cleanup — pairs with the
    killed RetailDemo service)
  - (Skipped: WU/AU policies, TPM bypass, Defender/PPL/BitLocker,
    printer/biometric/notification/LAN services, UI/perf/gaming
    preferences, unverifiable value names, Intel vendor tools,
    user-installed app needles)
- gdid-guard diff (rroy676/GDID-Guard — CDP device-graph exposure tool):
  - `DisableTelemetry` +per-user `PublishUserActivities`/
    `UploadUserActivities`=0 under `CurrentVersion\PublishUserActivities`
    and `CurrentVersion\UploadUserActivities` — the Settings
    activity-history toggles the HKLM policies don't reach
  - `UserBackupKeyPaths`/`_USER_BACKUP_KEY_PATHS` +both keys
  - hosts +3: `dds.microsoft.com`, `fd.dds.microsoft.com`,
    `cdpcs.access.microsoft.com` (Device Directory Service + CDP
    certificate fronts — the device-graph registration channel;
    `aad.cs.dds.microsoft.com` left out because it backs Entra device
    registration)
  - (Skipped: IdentityCRL/CDP data wipe — destructive cleanup; IP-based
    firewall blocks — hostnames preferred; CDPUserSvc Start=4 —
    demote-to-Manual already covers it)

- fortify + mxk/windows-secure-group-policy diffs (GDStudiosDev/fortify,
  mxk/windows-secure-group-policy Win11.PolicyRules — 525-entry 25H2
  baseline):
  - `DisableTelemetryTasks` +9: `WindowsAI\ClickToDo\ModelCachingIdle`/
    `ModelCachingLimit`/`ModelCachingUpdate`,
    `WindowsAI\Settings\InitialConfiguration`,
    `Flighting\FeatureConfig\UsageDataFlushing`/`UsageDataReceiver`/
    `GovernedFeatureUsageProcessing`, `PerformanceTrace\ShowFeedbackToast`,
    `Sustainability\SustainabilityTelemetry`
  - `MarkDeprovisioned` now also writes `AppxAllUserStore\EndOfLife`
    markers (the EOL flag Windows uses for retired inbox apps — the
    Store declines reinstall)
  - `DisableTelemetry` +11 (mxk documented-policy diff): legacy
    name-resolution/discovery broadcast kills — `DNSClient\EnableNetbios`=0,
    `Bowser`/`NetworkProvider` `EnableMailslots`=0, `LLTD`
    `AllowLLTDIOOnPublicNet`/`AllowRspndrOnPublicNet`=0 +
    `ProhibitLLTDIOOnPrivateNet`/`ProhibitRspndrOnPrivateNet`=1 —
    plus `AppCompat\DisableInstallTracing`=1, WinHTTP-layer
    `DisableWpad`=1, `MicrosoftEdgeDataOptIn`=0, OneDrive
    `PreventNetworkTrafficPreUserSignIn`=1
  - `DisableSearchSuggestions` +`NoWebServices`/`NoInternetOpenWith`=1
    (shell web-service + open-with online lookup promo)
  - `DisableSpotlight` +`LockScreenOverlaysDisabled`=1, `AllowOnlineTips`=0,
    `HideRecommendedPersonalizedSites`=1
  - `BackupKeyPaths` +`EndOfLife`, `WinHttp`, `Bowser`, `LLTD`,
    `NetworkProvider`, `Microsoft\OneDrive`
  - (Skipped: non-standard `PackageRemovalPolicies` node — the
    documented mechanism is `RemoveDefaultMicrosoftStorePackages` and
    already covered; Kerberos/PKINIT, CredSSP, Defender, Firewall,
    WinRM, RDP, FVE, SMB-signing, WU policy, IPv6 transition, LSA PPL,
    printer PointAndPrint, NTP, event-log sizing, mailslot-adjacent
    admin controls, Edge autofill/password-manager vendor prefs,
    Firefox policies, `SbEnable`/dead-feature names)

## [Unreleased] — v1.60.5-mvp: RegiLattice privacy/AI policy diff

### Added
- `DisableTelemetry` +26 registry writes (RegiLattice 7,718-tweak diff —
  policy kills only, capture/functional surfaces untouched):
  - Input/handwriting upload surfaces: `AllowHandwritingErrorReports`,
    `AllowInputDataUpload`, `AllowInkRecognitionLearning`,
    `AllowInkingAndTypingPersonalization` (InputPersonalization policy),
    `AllowHandwritingLMUpdate`, `AllowHandwritingPersonalizationUpload`,
    `AllowIMENetworkAccess`, `AllowHardwareKeyboardTextSuggestions`
    (TextInput policy), `AllowIMETelemetry` + `AllowCloudCandidates`
    (IME policy), `TypingDataCollectionEnabled` (SpellingAndTyping
    policy), `SpeechRecognitionTelemetryEnabled` (LanguageOptions
    policy), per-user `VoiceActivationOn` (Speech_OneCore\Preferences)
  - Copilot AI surfaces: `AllowCopilotClipboardAccess` +
    `AllowClipboardSuggestedActions` (System policy),
    `AllowCopilotScreenAccess` (AI\Copilot policy),
    `SuppressCopilotFirstRun` + `BlockCopilotHistorySync`
    (WindowsCopilot policy), `TurnOffAIDataAnalysis` (WindowsAI policy)
  - Collection pipelines: `DisableDeviceCensus` +
    `DisableOneDriveSyncDiagnostics` (DataCollection),
    `DisableUACompleteAutomation` + `DisablePropPageShim` (AppCompat),
    `StorageTelemetryEnabled` (CrashControl),
    `SuperFetchDisableTelemetry` (SuperFetch),
    `AllowDiagnosticDataUpload` (ScriptedDiagnostics),
    `AllowMessageBackup` (Messaging), `WiFiConfigSyncDisabled` +
    `WiFiSharingEnabled` (WcmSvc config), `AllowAchievementSharing` +
    `AllowGameStreamingUpload` (GameDVR)
- `BackupKeyPaths`/`_BACKUP_KEY_PATHS` +9 HKLM paths covering the new
  policy keys; `UserBackupKeyPaths`/`_USER_BACKUP_KEY_PATHS`
  +`Software\Microsoft\Speech_OneCore\Preferences`

### Fixed
- Docs sync: README counts now match the lists (84 telemetry tasks,
  439 null-routed hosts); `deploy_verify.bat` banner version bumped
  1.59.1 → 1.60.5 to match the shipped version

## [Unreleased] — v1.60.4-mvp: eplord/Win-Debloat7 diff

### Added
- `DisableCopilot` +`ComposeInlineEnabled` Edge-policy kill and 8 new
  telemetry/ad hosts (MSN/CDN + ads groups)

## [Unreleased] — v1.60.3-mvp: builtbybel/CrapFixer diff

### Added
- Ask-Copilot CLSID shell-extension block (`{CB3B0003-...}`) in
  `DisableCopilot`; Clipchamp CLSID block in
  `DisableConsumerExperiences`; per-user `ActivityHistoryEnabled`=0
  under the Privacy timeline path; 3 package-name stubs;
  `BackupKeyPaths` +`Shell Extensions\Blocked`

## [Unreleased] — v1.60.2-mvp: post-merge review remediation + Edge policies

### Fixed
- `RemoveDefaultStorePackages`: families recorded only in the legacy
  non-standard `PackageList` value were dropped on upgrade instead of
  being migrated into `DynamicRemovalList` — merged before delete
  (Devin Review on PR #35)
### Changed
- `DisableTelemetry`: removed `BlockAADWorkplaceJoin` and
  `KFMBlockOptIn` writes — workplace-join blocking and OneDrive
  known-folder-backup blocking are outside telemetry scope (Devin
  Review on PR #35)
### Added
- `DisableEdgeBloat` +3 documented Edge policies:
  `EdgeManagementEnabled`, `ShoppingInEdgeEnabled`,
  `EdgeWorkspaceEnabled`

## [Unreleased] — v1.60.1-mvp: Edge policy expansion

### Added
- tomytate/Win-Debloat7 (new source, full module sweep):
  telemetry tasks +14 (25H2 AI-subtree — `WindowsAI\RecallSnapshot`
  /`ModelMaintenance`/`AIPlatformServiceTask`/`WorkloadsHostTask`,
  `AISystem\AIAnalyzer`/`ModelUpdateTask`/`SemanticIndexTask`,
  `NarrativeFlows\UserJourneyTracker`, `Flighting\OneSettings\*
  RefreshCache`/`QuerySettings`, `AppxDeploymentClient\UcpdVelocity`,
  `UNP\RunCampaignManager`, `Setup\EOSNotify`/`EOSNotify2`);
  `DisableRecall` +`DisableScreenSemanticAnalysis`=1 (on-device
  screen semantic analysis CSP); `DisableTelemetry` +3 documented
  policies — RPC `EnableAuthEpResolution`, Kernel-DMA
  `DeviceEnumerationPolicy`, dump `EnableDumpEncryption`; misc
  demote +`SensorDataService`; HKLM backup +3 paths
- coolvitto 25H2 service list (hateblo, Japanese source): misc
  demote +`whesvc` (Windows Health and Optimized Experiences —
  PC-health/optimizer suggestion feed), +`dptftcs`/`ipfsvc`
  (Intel Dynamic Tuning telemetry + Innovation Platform Framework)
- `DisableCloudContent`: `SettingsPageVisibility` merged —
  `hide:home` → `hide:home;aicomponents;appactions` (hides the
  25H2 AI Components + App Actions settings pages)
- SysAdminDoc/Debloat-Win11 (new source, full modular
  sweep — PolicyCatalog/AppX/Services/Tasks/OEM/Edge/
  Privacy triaged): telemetry tasks +2
  (`Shell\FamilySafetyUpload`, `XblGameSave\XblGameSaveTask`
  — family-safety upload + Xbox save-sync collectors);
  OEM task patterns +5 (`Intel|Realtek|Waves|MSI|Razer`
  vendor needles); blacklist +13 OEM/feed needles
  (WavesAudio, DragonCenter, MysticLight, MSIAfterburner,
  ROGLiveService, ArmouryCrate, MyASUS, ASUSPCAssistant,
  Razer, AcerQuickAccess, LenovoUtility,
  `Microsoft.WidgetsPlatformRuntime`,
  `Microsoft.StartExperiencesApp`); misc demote services
  +5 (`InventorySvc`, `WpcMonSvc`, `MessagingService`,
  `GamingServices`, `GamingServicesNet`) + `lmhosts`
  cs-side parity fix + dynamic service counts in logs;
  Edge policy +10 (`EdgeCopilotEnabled`,
  `NewTabPageBingAIPromptEnabled`, `CrashReportingMode`,
  `EdgeWalletEnabled`, `EdgeWalletCheckoutEnabled`,
  `GamerModeEnabled`, `TravelAssistanceEnabled`,
  `ShowBrowserMigrationPrompt`,
  `ShowOfficeShortcutInFavoritesBar`,
  `QuickSearchShowMiniMenu`); Smart Clipboard kills
  (`EnableSmartClipboard`=0 policy + per-user
  SmartClipboard `Disabled`=1); `EnableRecall`=0 per-user
  shell toggle; WindowsBackup `DisableBackupUI`=1 policy;
  toast-above-lock kills
  (`NOC_GLOBAL_SETTING_ALLOW_(CRITICAL_)TOASTS_ABOVE_LOCK`);
  startup-bloat needles +3 (Razer, Synapse, Cortex).
  Skipped: UI/pref surfaces, WU deferral/UX, AutoRun
  duplicates, service wholesale kills, vendor uninstallers.
- Microsoft official new policies (windowslatest +
  Microsoft Japan blog): `RemoveMicrosoftCopilotApp`=1
  per-user WindowsAI (April 2026 "Remove Microsoft Copilot
  app" — auto-removes Copilot + M365 Copilot when not
  user-installed and unused >28 days); CopilotKeyboard
  admin policies ×3 per-user (`TurnOffSendTelementryData`
  — Microsoft's literal misspelling — usage data upload,
  `TurnOffCloudCandidate` — cloud text candidates,
  `TurnOffInternetIntegration` — Bing search/character/
  update nags), per Microsoft Japan June 2026 guidance.
- Qiita 24H2 new-policy list (Microsoft Group Policy
  Settings Reference): `DisableTelemetry` +3 under existing
  AppCompat backup — 24H2 app-inventory collectors
  `DisableAPISamping` (Microsoft's literal ADMX spelling),
  `DisableApplicationFootprint`, `DisableWin32AppBackup`
  (API-sampling / registry+file-usage footprint / Win32
  backup compat scans). Skipped: all Defender-side new
  policies (boundary), `AllowLegacyURLFields` (IE legacy
  URL fields — weakening direction).
- zoicware/RemoveWindowsAI (25H2, second pass):
  `RemoveDefaultStorePackages` now writes the DOCUMENTED
  mechanism — per-family subkeys with `RemovePackage`=1 +
  merged `DynamicRemovalList` REG_MULTI_SZ — replacing the
  non-standard `PackageList` value (stale value is deleted
  best-effort). Registry/hosts/tasks/packages otherwise
  already covered. Skipped: `MicrosoftWindows.Client.Photon`
  (zoicware itself comments it out — breaks WSAI runtime),
  IsoEnvBroker Start=4 (wholesale service kill — default
  is already manual), Office Copilot/content-safety kills
  (vendor apps), `ConfigureStartPins(JSON)` (user layout
  override), `CopilotLogonTelemetryTime`/`WakeApp` (value
  deletions — no write semantics), DefenderAiPlatformHost
  IFEO (Defender boundary).
- coolvitto hateblo (new source, Policy CSP - System full
  list): `DisableTelemetry` +10 — DataCollection processing
  kills (`AllowDesktopAnalyticsProcessing`/
  `AllowDeviceNameInDiagnosticData`/
  `AllowMicrosoftManagedDesktopProcessing`/
  `AllowUpdateComplianceProcessing`/`AllowWUfBCloudProcessing`/
  `DisableDiagnosticDataViewer`/`EnableOneSettingsAuditing`/
  `LimitEnhancedDiagnosticDataWindowsAnalytics`), System
  `EnableFontProviders`=0 (online font downloads),
  `AllowOOBEUpdates`=0 (OOBE in-setup update pulls). Backup
  +`Policies\Microsoft\Windows\OOBE`. Skipped:
  `DisableDeviceDelete` (inverse polarity — kills the delete
  capability itself), `DisableFileSyncNGSC` (OneDrive kill —
  rejected class), `DisableSR`/FileHistory `Disabled`
  (functional feature kills), ELAM `DriverLoadPolicy`
  (security boundary), `AllowLocation` (per-app design),
  `HideUnsupportedHardwareNotifications`=0 (shows warnings —
  opposite direction), TelemetryProxy (no proxy to set),
  MDM-only entries (no registry surface).
- atlantsecurity/windows-hardening-scripts (cmd suite, new
  source): `DisableTelemetry` +5 — `DisableSmartNameResolution`/
  `EnableICMPRedirect`/`DisableIPSourceRouting` (Tcpip +
  Tcpip6)/`DontDisplayNetworkSelectionUI`/`AuditLevel`
  (LSASS access auditing). Backup +3 (Tcpip/Tcpip6
  Parameters, LSASS.exe IFEO). Skipped: `EnableLUA`
  (UAC boundary), WSH `DisplayLogo`/Office macro rows
  (vendor/UI), `EnableOcspStaplingForSni` (commented out in
  source), `AuditLevel` PowerShell `EnableModuleLogging`
  (logging surface), printer `DisableWebPnPDownload` (already
  covered).
- ledg/WinDebloatTools (new source): `DisableSpotlight`
  +`IncludeEnterpriseSpotlight`=0 (Enterprise Spotlight
  content — inverse polarity, =0 disables), `DisableWidgets`
  +`ShellFeedsTaskbarOpenOnHover`=0 (taskbar feeds
  open-on-hover). Skipped: `NoAutoUpdate`/`ShowSleepOption`/
  `EnableMtcUvc`/`EnableMmx`/`DisableLocationScripting`
  (boundary/UI/location kills).
- Winnow (BiosSystem, second pass): `DisableCopilot`
  +`OnlineVoicesEnabled`=0 (Narrator\NoRoam — online voice
  downloads), `DisableCloudClipboard`
  +`EnableSuggestedClipboardActions`=0 (clipboard AI
  actions). User backup +`Narrator\NoRoam` (70→71).
- CoPilot-Cleaner (new source): `DisableEdgeBloat`
  +`DiscoverHubEnabled`=0 (Edge Discover-hub kill —
  value=0 sibling of `DefaultBingContextMenuEnabled`).

- LeDragoX/Win-Debloat-Tools (new source): blacklist +3 —
  `SAMSUNGELECTRONICS` (OEM stub namespace covering both
  publisher spellings), `4AE8B7C2.` (Booking.com stub
  publisher), `FACEBOOK.` (Facebook stub package);
  `MiscBloatServices` +`lmhosts` demoted (NetBIOS naming —
  pairs with existing NetBT demote); `DisableTelemetry`
  +`UserPreference=3` (HKLM WindowsMitigation — recommended
  troubleshooting auto-runs + uploads diagnostics). Backup
  +WindowsMitigation key. Skipped: ConsentStore value writes
  (closed-PR #34 content — must not re-land), WU UX
  (`UxOption`/`NoAutoRebootWithLoggedOnUsers`), Edge NoRemove
  (uninstall entry, out of scope), functional services
  (BITS/Spooler/WlanSvc/iphlpsvc/wscsvc/Defender-adjacent),
  vendor updaters (gupdate/RtkBtManServ), OneNote/Camera/
  BioEnrollment/ContactSupport (functional/system apps),
  task/app diffs all already covered.
- zoicware/RemoveWindowsAI (new source, actively maintained
  AI-removal suite): `DisableCopilot` +`SetCopilotHardwareKey`
  (CopilotKey policy — hardware-key remap), M365Copilot
  auto-start kills (`AutoStartDelayEnabled`/
  `IsCompanionWindowAvailable`), `MicrosoftCopilotAutoLaunch`
  (HKLM RunNotification — startup auto-open), generativeAI +
  systemAIModels ConsentStore `Value=Deny` + Capabilities
  `RecordUsageData=0` (usage recording off). Backup +5
  (ConsentStore generativeAI/systemAIModels, Capabilities
  generativeAI, RunNotification) + user backup +2
  (M365Copilot, CopilotKey). Skipped: Office 16.0 AI rows
  (vendor scope), Edge Local-State labs-flags edit (runtime
  file mutation), package/file deletion, Xbox GamingAI reg
  row (gaming feature), SettingsPageVisibility (its `hide:home`
  already written — merging `aicomponents;appactions` would
  need string merge; documented as follow-up), velocity ID
  58375086 (AI-fabric dep — explorer bug noted by source).
- burakarslan0110/WinToolify (new source, PS catalog):
  `DisableCopilot` +`HideAIActionsMenu` (HKLM Explorer policy —
  Explorer "AI actions" context-menu group) + voice-agent extras
  `AgentActivationOnLockScreenEnabled`/`AgentActivationLastUsed`
  (per-user), `DisableTelemetry` +`AllowClipboardHistory` (HKLM
  System policy — cloud clipboard pipeline, cbdhsvc demote の補強),
  per-user `PhoneLinkEnabled` (Mobility), Edge +2
  (`TextPredictionEnabled`/`MicrosoftEditorProofingEnabled` —
  editor proofing ships text to MS). Skipped: Office 16.0
  privacy/feedback rows (vendor), WU defer/locale kills,
  NCSI/location/sensor kills, SmartScreen-adjacent toggles,
  PasswordManager/autofill (functional), RDP `fDenyTSConnections`.
- itsfatduck/optimizerDuck (new source, C# WPF): telemetry
  autologgers 13->18 (`AppModel`/`Cellcore`/`CloudExperienceHostOobe`/
  `DataMarket`/`WdiContextLog` ETW sessions), `DisableTelemetry`
  +`PublishUserActivitiesOnUserConsent` (HKLM Windows\System),
  +`NoActiveHelp` (HKLM Assistance\Client — CEIP help pane),
  backup +Assistance\Client key. Skipped: location/sensor kills,
  Maps auto-update off (functional), Shell Extensions\Blocked,
  full-service baseline map (functional restore list).
- hselimt/HST-WINDOWS-UTILITY (new source): telemetry tasks +3 —
  `ApplicationData\appuriverifierdaily`/`*install` (app-uninstall
  verifier upload), `AppListBackup\Backup` (cloud profile store).
  Skipped: DiskFootprint\StorageSense (functional), Bluetooth/
  language-sync tasks, Google updater names (vendor), power plan.
- tomytate/Win-Debloat (new source): misc services +5 —
  `AIFabricUserSvc`/`ModelCatalogUserSvc`/`SemanticSearchUserSvc`/
  `NarrativeFlows`/`OneSettingsClientUserSvc` demoted (AI-fabric
  user listeners: model catalog, Copilot semantic-search
  orchestration, Recall narrative flow, OneSettings pull
  client). Skipped: `lltdsvc`/`upnphost` (functional LAN),
  `WbioSrvc` (biometric sign-in), `WSearch`/SysMain (perf).
- RajwanYair/RegiLattice security packs (same source):
  protocol/account hardening +9 — SSL 2.0/3.0 kill (extends
  TLS deprecation loop), Lsa `EveryoneIncludesAnonymous`=0 /
  `NoDefaultAdminOwner`=1 / `LimitBlankPasswordUse`=1 /
  `SCENoApplyLegacyAuditPolicy`=1, MSV1_0 NTLM
  `RestrictSendingNTLMTraffic`=2 + `AuditReceivingNTLMTraffic`=2,
  `Audit\ProcessCreationIncludeCmdLine`=1, `NetBT\Parameters\
  EnableLMHOSTS`=0. backup 103→105. Skipped: RunAsPPL/
  LsaCfgFlags (PPL boundary), Defender Spynet, FIPS mode,
  RestrictedAdmin (RDP functional), RestrictAnonymous=2
  (enumeration-upgrade risk over current =1).
- RajwanYair/RegiLattice (new source, 7,718-tweak registry
  toolkit): telemetry surface +5 — `DevDrive\DisableTelemetry`=1
  (Dev Drive telemetry), `Lxss\EnableTelemetry`=0 (WSL),
  `Policies\Microsoft\Speech\AllowCloudTTS`=0 (cloud TTS),
  `DataCollection\MaxTelemetryCacheSize`=0 (telemetry cache),
  `Appx\AllowAutomaticAppArchiving`=0 (auto-archive bloat).
  backup 101→103. Skipped: vendor telemetry (VS/VSCode/Office/
  Firefox/Skype), StorageSense (functional), perf/UI pack.
- bitlogik/HushWin (new source): `AppCompatFlags\
  ClientTelemetry` +3 — `IsCensusDisabled`/`DontRetryOnError`/
  `TaskEnableRun`=1 (CEIP census upload + retry + task-run
  gate under-layer). backup 100→101. Skipped: Remote
  Assistance kill (functional), Office ClientTelemetry
  (vendor scope).
- atlantsecurity/windows-hardening-scripts (278★, new
  source): telemetry hosts +13 MSN ad/analytics endpoints —
  rad/live.msn family (a/b/c.rad.msn+live, 0.r.msn,
  analytics.r.msn), adsyndication, blu.mobileads,
  b.ads2.msn, ads1.jp.msn, rel.msn, arc1.msn (419→431).
  Skipped: generic third-party adblock flood, `target.
  microsoft.com` (unverifiable), `msnbot-*` (crawler).
- milgradesec/windows-settings (40★ security config, new
  source): credential/protocol hardening +5 — Lsa
  `NoLMHash`=1 + `LmCompatibilityLevel`=5 (NTLMv2-only),
  FVE `DisableExternalDMAUnderLock`=1 (PCI-DMA under lock),
  `.NETFramework\v2.0.50727` SchUseStrongCrypto mirrors
  (legacy runtime TLS opt-in, 64/32), `AppCompat\
  VDMDisallowed`=1 (NTVDM kill — same class as
  DisableLegacyFeatures),
  `SafeDllSearchMode`=1, `DisableExceptionChainValidation`=0
  (SEHOP). Skipped: RunAsPPL (LSA PPL — plugin/auth break
  risk, boundary), DMA lock SKU caveat noted.
- Windows-Utility (ZuanCrisp winutil fork, new source):
  +4 — UScheduler_Oobe `WindowsUpdate` sibling (workCompleted
  marker; OOBE updater pass killed alongside Outlook/DevHome),
  per-user promo toasts `Windows.SystemToast.StartupApp` /
  `Windows.SystemToast.AccountHealth` / `Microsoft.SkyDrive.
  Desktop` Enabled=0.
- Win11Debloater (bunbunconmeow, new source): WindowsAI
  `AllowSnapshotting`=0 — sibling kill switch to
  TurnOffSavingSnapshots in the same CSP key.
- speedup-windows10 (balsamleti, new source): +2 —
  WindowsSelfHost\UI\Strings DiagnosticErrorText/
  DiagnosticLinkText blanked (insider diagnostic nag),
  legacy WindowsStore\WindowsUpdate AutoDownload=2
  (pre-policy store update suppression). Skipped:
  NoAutoUpdate/SetACL own-take (WU kill — boundary),
  AllowLockScreen=0 (UI).
- Reclaim (jonax1337/Reclaim, Tauri debloat tool, new
  source): hosts +3 (ads.yahoo.com, advertising.yahoo.com,
  feedback.microsoft.com). Skipped: msftncsi (NCSI —
  captive-portal, same class as prior revert), WU/Edge
  delivery CDNs, corp STS/ADFS, Office Nexus/CDN, msn.com
  content portals.
- Reclaim (jonax1337/Reclaim, Tauri debloat tool, new
  source): blacklist +5 consumer bloat — CandyCrush,
  MarchofEmpires, Plex, Viber, Royal Revolt was already
  covered by flaregamesGmbH. Skipped: Paint/Store/
  Terminal/Calculator/Camera/OneNote/Notepad/MeetNow/
  RemoteDesktop/FamilySafety removals (system components
  this tool keeps by design).
- Reclaim (jonax1337/Reclaim, Tauri debloat tool, new
  source): per-user +3 — Notepad `ShowStoreRecommendation`=0
  (store promo banner), Explorer `StartupNotify`=0
  (startup-impact toast), GameBar `GamePanelStartupTipIndex`=3
  (promo tip panel). Skipped: SmartScreen/AppHost kills
  (protection), PPL/RunAsPPL + RDP/Remote Assistance kills
  (security-boundary), MS account kill (`NoConnectedUser`),
  WU policy + UX set, StorageSense/WcmSvc metered (functional),
  services WSearch/Xbl*/MapsBroker=4 (functional), ~90
  performance/gaming/UI-pref values (mouse/keyboard/TDR/AFD/
  NIC/transparency/Explorer).
- DebloatAndSecurizeW11 (JulienVB, new source): velocity
  overrides +3 AI feature IDs (3189581453, 3552646797,
  450471565 via phantomofearth velocity lists). Skipped:
  ConsentStore denies (rejected category), office AI-
  training keys (vendor), DisableSR/EnableLUA (boundary),
  WU pause UX times (functional).
- 0Ai-Windows-Hardening (cervezagua, new source): Notepad
  AI-disable namespaces — HKLM Policies\Microsoft\Notepad
  + per-user Policies\Microsoft\Windows\WindowsNotepad
  DisableAIFeatures (some Store builds read these first).
  Skipped: ConsentStore systemAIModels Deny (rejected
  closed-PR category), RestrictedRemoteAdministration
  (breaks RDP), SmartActionsState (unverifiable).
- unslop-windows (PyPie-Studio, new source) + Winnow
  (BiosSystem, new source): Cross-Device Resume kill —
  MDM PolicyManager DisableCrossDeviceResume + per-user
  IsResumeAllowed/IsOneDriveResumeAllowed (stops sihost
  spawning CrossDeviceResumeHost at logon, 24H2+); TLS
  1.0/1.1 deprecation (SCHANNEL Enabled=0 +
  DisabledByDefault=1, Client+Server both). Skipped:
  Office Copilot policy (vendor), RDP/GPU-scheduler/
  BitLocker (functional/security boundary).
- 5cover/WinClean (new source): blacklist +2
  (BethesdaSoftworks.FalloutShelter, Microsoft.Advertising).
  Sycnex-derived scripts otherwise fully covered.
- privacyfilters/Microsoft-Blocker (new source,
  5,850-entry hosts list): telemetry hosts 197->416 —
  vortex/events-data regional TM aliases, watson/WER
  family, Clarity analytics, MSN/Bing ads, Office-app
  telemetry endpoints, xboxlive metrics. Skipped: Azure/
  enterprise/AppInsights SDK, NCSI, WU/Store/CDN,
  SmartScreen, 5,300 footprintdns wildcards.
- Winhance (memstechtips, new source C#): per-user
  ShowCopilotNudges=0, OneDrive KFMBlockOptIn=1
  (HKLM+per-user), AAD WorkplaceJoin
  BlockAADWorkplaceJoin=1 (HKLM+per-user).
  Skipped: Office AI keys, Defender notifications,
  Winlogon/perf/UI prefs. Backup 109->110, user 67->69.
- Raphire/Win11Debloat 2026.06 re-diff: per-user
  DragTrayEnabled=0 (CDP share drag tray); the rest of
  the new reg-file set already covered. Backup: CDP
  already in user backup list.
- SysAdminDoc/Debloat-Win11 (new source, v2.3.11):
  per-user WindowsBackup NotificationDisabled=1;
  rest of its 57-policy catalog already covered.
- zoicware per-user/registry re-diff: DisableCopilot
  +Copilot/Recall taskbar pins +TaskbarCompanion
  +PWA-preinstall flag +background-app kills
  (Copilot/OfficeHub DisabledByUser+SleepDisabled)
  +A9HomeContentEnabled sync handler; DisableAppPermissions
  +LetAppsAccessSystemAIModels +systemAIModels
  RecordUsageData +Paint targeting opt-out/get-started
  suppression (10 values) +Notepad ShowStoreBanner.
  Backup 106->109, user backup 62->66. Skipped: Office
  training/content-safety subkeys, VoiceAccess runtime,
  BrandedKey remap, file-assoc deletion, IFEO hijack.
- zoicware/RemoveWindowsAI re-diff (2026 updates):
  blacklist +7 -> 197 (Office.ActionsServer, WritingAssistant,
  Ink.Handwriting, Copilot+ AI component names Voiess/Speion/
  Livtop/Filons, WindowsWorkload.*). WindowsAI registry surface
  already covered; CBS-store removal stayed out of scope.
- Devin Review round (PR #35): fix BingAdsSuppression
  inverted write -- documented policy is
  BingAdsSuppressionEnabled and must be 1 to suppress
  Bing ads (0 disabled suppression); winget-restore
  availability probe so missing winget marks entries
  manual instead of throwing mid-loop; capability
  ledger now re-queries post-removal and records only
  capabilities actually gone.
- Microsoft Copilot ADMX docs (CopilotApp.admx +
  copilotupdate.admx): DisableCopilot +BrowsingEnabled
  +CopilotCoworkToolActionsEnabled @
  Policies\Microsoft\Copilot; EdgeUpdate
  Copilot-distribution guard Install/Update/
  CopilotUnificationAllowed{C50565E9-...}. Skipped:
  ComponentUpdatesEnabled (doc warns it can block
  security fixes), Uninstall/TargetChannel. Backup 104->106.
- Khotyz/WGO diff: DataCollection
  +LimitDiagnosticDataConfigurationSet; DisableCloudClipboard
  +per-user CloudClipboardAutomaticUpload; Edge
  +ConfigureTelemetryForDesktop. Skipped: location/sensor
  kills, WU pause, gaming TCP/visual tuning, DoH,
  Defender/SmartScreen/UAC, RemoveWindowsStore.
- Residual host diff (BSI list + hagezi microsoft.txt):
  hosts +6 -> 196 (events.data.microsoft.com universal
  ingest, pipe.dev.trafficmanager.net, Office
  diagnostics.front azurefd, arc.msn.com +
  arc.trafficmanager.net MSN ad-analytics). Skipped:
  AppCenter/AppInsights/Azure Monitor/LogAnalytics SDK
  endpoints (app-SDK boundary).
- winscript VoiceShortcut per-user kill; GTweak
  audited (Defender/SmartScreen/MRT only -- boundary);
  Aegis-Win11 audited (Brave/Edge-feature/UI/UAC --
  boundary). winscript source exhausted.
- winscript round 2 + Aegis-Win11: NVIDIA driver
  SendTelemetryData off (both Global\Startup forms);
  Search policy +PreventRemoteQueries; Edge +AllowSurfGame.
  Skipped: Defender scan tuning, WU service/service-name
  sweeps, Office QMEnable/VerboseLogging (vendor
  boundary), CCleaner, WMP UsageTracking (closed-PR).
- flick9000/winscript diff (large): DisableCopilot
  +CopilotDisabledReason region-fail trick +per-user
  AllowCopilotRuntime +NVIDIA FTS RID telemetry opt-outs;
  DisableSearchSuggestions +ConnectedSearchPrivacy=3
  +ConnectedSearchUseWebOverMeteredConnections +CortanaEnabled
  legacy master +policy DisableSearchHistory +per-user
  DeviceHistoryEnabled; DisableTelemetry +Maps
  AllowUntriggeredNetworkTrafficOnSettingsPage +SettingSync
  deep kills +11 (browser/startlayout/personalization/theme/
  appsync categories + user overrides). Backup 99->102,
  user backup 56->58. Skipped: WU timing/policy, VisualStudio/
  CCleaner vendor, WMDRM online, UI prefs, Brave.
- hagezi/dns-blocklists microsoft.txt + native.winoffice diff:
  hosts 151->190 — remaining vortex events ingest regions
  (au/eu/in/jp/uk/us mobile + v20), Office diagnostics
  endpoints (msa/cjs/entitlement/incidents/logging/
  supportexperience.diagnostics.office.com), activity-
  upload endpoints (*.activity.windows.com), trafficmanager
  ingest fronts, location inference. Skipped: Azure Monitor /
  App Insights / AppCenter (app-SDK telemetry, not OS),
  MSN content CDN.
- BSI (German federal SiSyPHuS work package) endpoint list
  diff (via craiu/mobiletrackers): hosts 137->151 —
  asimov/db5/geo settings-win akadns mirrors, au/de/uk
  vortex-win + v20 events ingest, sandbox ingest variants.
  Skipped: AppCenter/CodePush (per-app SDK telemetry, not OS),
  trafficmanager dev endpoint.
- TronScript (bmrf/tron) diff: blacklist +FrenchRiviera/
  Lucille/SeaofThieves stubs (187->190);
  DisableSearchSuggestions +AllowCortanaAboveLock.
  Skipped: task-file deletions (design disables, not deletes),
  WiFi-Sense values (feature removed 2017), Defender Spynet,
  ~750 user-installed-app wildcards, language packs,
  BioEnrollment/camera/DDV/BrowserChoice (functional).
- Microsoft documented-policy gap fill: DisableTelemetry
  +ConfigureTelemetryOptInChangeNotification/
  ConfigureTelemetryOptInSettingsUx (opt-in prompt/UX
  suppression); BlockInsiderPreview +ManagePreviewBuildsPolicyValue;
  CDM per-user +ShowWindowsWelcomeExperience;
  DisableSpotlight +UserProfileEngagement
  ShowSpotlightOnWelcome.
- WinRice diff: DisableTelemetry +Wdigest UseLogonCredential=0
  (plaintext credential caching off) +WPAD WpadOverride=1
  HKLM+all users (proxy auto-discovery poisoning vector);
  DisableRecall per-user +Notepad EnableCowriter +Paint
  EnableCocreator/EnableImageCreator +Photos EnableAIFeatures
  (app-level AI toggles beneath the policy kills). Backup
  99->101, user backup 52->56. Skipped: VBS toggle, UI prefs,
  WPAD functional concern none (kills attack surface only).
- winutil v2 tweaks.json diff (re-mine): DisableEdgeBloat
  +UrlKeyedAnonymizedDataCollectionEnabled (URL-keyed browsing
  data uploads); misc services +SharedAccess (ICS — demand-start).
  Remaining diffs all UI prefs/third-party browsers/functional
  or closed-PR content.
- noid-privacy Strict/Paranoid profile diff: DisableTelemetry
  +DisableOneSettingsDownloads (DataCollection alias path)
  +DisableGraphRecentItems +EnableCdp=0 (CDP master)
  +EnableWindowsBackup=0 +OneDrive policy kills
  (sync-admin reports/feedback/pre-signin traffic — OneDrive
  itself untouched) +user-policy tailored-experiences lock;
  DisableSearchSuggestions +ConnectedSearchUseWeb +global
  web-provider toggle +Bing provider registration kill;
  AppPrivacy +Calendar/GraphicsCaptureProgrammatic/
  GraphicsCaptureWithoutBorder force-denies. Backup 97->99.
  Skipped: AllowInputPersonalization (prior closed-PR content),
  location/mic/cam force-denies, clipboard-history/font-provider
  feature kills.
- noid-privacy EdgePolicies diff: +AddressBarTrendingSuggestEnabled
  (trending suggestions) +EdgeReadingModeServiceBasedExtractionEnabled
  (cloud content extraction upload) in DisableEdgeBloat. Skipped:
  SmartScreen override, auth schemes, IE-mode, ABE, SwiftShader,
  codec-pack removals (functional/security boundary).
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
- simeononsecurity/Windows-Optimize-Debloat + gordonbay/
  Windows-On-Reins (new sources): `DisableTelemetry`
  +`WiFiSenseCredShared` (WcmSvc features — Wi-Fi Sense credential
  sharing, sibling to PaidWifi/WiFiSenseOpen); `DisableEdgeBloat`
  +`ShowSearchSuggestionsGlobal` (Edge SearchScopes policy —
  search-provider suggestion uploads); `DisableTelemetry`
  +`DisableUPnPRegistrar` (WCN UPnP device registrar — legacy
  network-device discovery surface). Backup 109->111
  (SearchScopes + WCN\Registrars). Skipped: WMP `UsageTracking`
  (closed-PR #33 content), Defender Spynet reporting
  (`LocalSettingOverrideSpynetReporting` — AV boundary), CCleaner
  `CheckTrialOffer` (vendor), camera/mic/location kills,
  `NoPhysicalCameraLED` (security regression), `EnableActiveProbing`
  (NCSI — prior revert), UI/perf names.

### Fixed
- Dedupe: `_USER_BACKUP_KEY_PATHS` listed
  `Software\Microsoft\Windows\CurrentVersion\Search` twice (both
  impls) and cs `MiscBloatServices` listed `wercplsupport` twice —
  removed; T10 extended to the three backup lists so duplicates in
  them now fail the self-test gate (previously uncovered).
- T12 follow-up: `AllowAutomaticAppArchiving` writes to
  `SOFTWARE\Policies\Microsoft\Windows\Appx` had no backup ancestor —
  added parent key to `_BACKUP_KEY_PATHS`/`BackupKeyPaths`.

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
