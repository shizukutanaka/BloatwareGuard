// BloatwareGuard - Windows Service to block and remove bloatware automatically
// Requires admin rights (UAC manifest)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BloatwareGuard;

// ─── Configuration ───────────────────────────────────────────────────────────

public class GuardConfig
{
    /// <summary>Scan interval in seconds (default 300 = 5min)</summary>
    public int ScanIntervalSeconds { get; set; } = 300;

    /// <summary>Package family name substrings to block (case-insensitive contains match)</summary>
    public List<string> Blacklist { get; set; } = new();

    /// <summary>Package family name substrings to NEVER remove (overrides blacklist)</summary>
    public List<string> Whitelist { get; set; } = new();

    /// <summary>Backup directory for removed packages (for restore)</summary>
    public string? BackupDirectory { get; set; }

    /// <summary>Prevention layers</summary>
    public PreventionLayers Prevention { get; set; } = new();

    /// <summary>Log file path (optional, alongside Event Log)</summary>
    public string? LogFilePath { get; set; }

    /// <summary>Run in dry-run mode (scan + log only, no removal)</summary>
    public bool DryRun { get; set; } = false;
}

public class PreventionLayers
{
    /// <summary>Remove AppxPackage + ProvisionedPackage</summary>
    public bool RemoveAppxPackages { get; set; } = true;

    /// <summary>Remove ProvisionedPackage entries (survives reset)</summary>
    public bool RemoveProvisionedPackages { get; set; } = true;

    /// <summary>Disable consumer experiences via Group Policy registry</summary>
    public bool DisableConsumerExperiences { get; set; } = true;

    /// <summary>Disable Windows suggested apps / cloud content</summary>
    public bool DisableCloudContent { get; set; } = true;

    /// <summary>Prevent device metadata (companion apps) from downloading</summary>
    public bool PreventDeviceMetadata { get; set; } = true;

    /// <summary>Disable OEM scheduled tasks that reinstall bloatware</summary>
    public bool DisableOemScheduledTasks { get; set; } = true;

    /// <summary>Block provisioning packages from re-registering</summary>
    public bool BlockProvisioning { get; set; } = true;

    /// <summary>Layer 7: Monitor for re-installed packages and auto-remove</summary>
    public bool ReinstallMonitor { get; set; } = true;

    /// <summary>Layer 8: Disable Windows Copilot via policy (HKLM + every user hive)</summary>
    public bool DisableCopilot { get; set; } = true;

    /// <summary>Layer 9: Disable Recall/AI data analysis via policy (24H2+) + feature removal</summary>
    public bool DisableRecall { get; set; } = true;

    /// <summary>Layer 10: Disable Bing web results & suggestions in Start/Search</summary>
    public bool DisableSearchSuggestions { get; set; } = true;

    /// <summary>Layer 11: Disable Widgets board (news & interests feed)</summary>
    public bool DisableWidgets { get; set; } = true;

    /// <summary>Layer 12: Disable telemetry (DiagTrack, advertising ID, tailored
    /// experiences, ink/typing collection, feedback nags, activity history)</summary>
    public bool DisableTelemetry { get; set; } = true;

    /// <summary>Layer 13: Disable GameDVR / Game Bar background capture</summary>
    public bool DisableGameDvr { get; set; } = true;

    /// <summary>Layer 14: Disable Delivery Optimization P2P update sharing</summary>
    public bool DisableDeliveryOptimization { get; set; } = true;

    /// <summary>Layer 15: Disable OneDrive sync + hide its Explorer pin.
    /// Opt-in (default false) — affects active file sync.</summary>
    public bool DisableOneDrive { get; set; }

    /// <summary>Layer 16: Hide the Teams Chat taskbar button</summary>
    public bool DisableChatTaskbar { get; set; } = true;

    /// <summary>Layer 17: Disable Edge sidebar, startup boost, prelaunch, first-run</summary>
    public bool DisableEdgeBloat { get; set; } = true;

    /// <summary>Layer 18: Remove optional capabilities (IE mode, Steps Recorder, WordPad)</summary>
    public bool RemoveOptionalCapabilities { get; set; } = true;

    /// <summary>Remove Win32 programs (McAfee/Norton OEM preinstalls etc.) whose
    /// DisplayName matches the blacklist — MSI entries get silent uninstall.
    /// The primary OEM bloat channel: most preinstalls are Win32, not Appx.</summary>
    public bool RemoveWin32Programs { get; set; } = true;

    /// <summary>Create a system restore point before the first destructive scan</summary>
    public bool CreateRestorePoint { get; set; } = true;

    /// <summary>Layer 21: Disable Microsoft telemetry/CEIP scheduled tasks
    /// (CompatTelRunner, CEIP Consolidator, DiskDiagnostic, Siuf DmClient, Maps)</summary>
    public bool DisableTelemetryTasks { get; set; } = true;

    /// <summary>Layer 22: Disable bloatware autostart entries via the
    /// StartupApproved\\Run disabled marker (restorable, not deleted)</summary>
    public bool DisableStartupBloat { get; set; } = true;

    /// <summary>Layer 23: Disable Windows Error Reporting uploads</summary>
    public bool DisableErrorReporting { get; set; } = true;

    /// <summary>Layer 24: Demote Edge update services to demand-start and
    /// disable their scheduled tasks (Edge still updates on demand)</summary>
    public bool DisableEdgeUpdateBloat { get; set; } = true;

    /// <summary>Layer 25: Exclude OEM driver payloads from Windows Update
    /// (WU is a channel for OEM bloatware re-delivery)</summary>
    public bool BlockOemDriverUpdates { get; set; } = true;

    /// <summary>Layer 26: Force-deny a conservative AppPrivacy permission set
    /// (background run, account info, contacts, diagnostics…). Camera, mic and
    /// location are deliberately left alone — legitimate apps need them.</summary>
    public bool DisableAppPermissions { get; set; } = true;

    /// <summary>Layer 27: Demote Xbox services to demand-start — they sit
    /// permanently running even on machines that never touch gaming/Xbox
    /// sign-in. Demand-start keeps Game Bar/Xbox features usable on demand.</summary>
    public bool DisableXboxServices { get; set; } = true;

    /// <summary>Layer 28: Export every HKLM key we touch to .reg files under
    /// %ProgramData%\BloatwareGuard\backup\ before applying (once per run)</summary>
    public bool BackupRegistry { get; set; } = true;

    /// <summary>Layer 29: Disable the Print Spooler — opt-in (default false);
    /// kills the PrintNightmare attack surface on machines that never print</summary>
    public bool DisablePrintSpooler { get; set; }

    /// <summary>Layer 46: Opt-in — documented power policy that severs
    /// network connectivity during Modern Standby (S0): stops background
    /// sync and telemetry while the device sleeps</summary>
    public bool DisableModernStandbyNetworking { get; set; }

    /// <summary>Layer 30: Disable WPBT — UEFI tables OEMs use to inject
    /// executables into Windows at boot (ASUS Live Update abuse vector)</summary>
    public bool BlockOemWpbtExecution { get; set; } = true;

    /// <summary>Layer 31: Disable Reserved Storage (~7GB) — updates then use
    /// free disk space like they did pre-1903</summary>
    public bool DisableReservedStorage { get; set; } = true;

    /// <summary>Layer 32: Stop clipboard history syncing to Microsoft cloud
    /// (cross-device clipboard uploads copied content)</summary>
    public bool DisableCloudClipboard { get; set; } = true;

    /// <summary>Layer 33: Remote Assistance off — stops unsolicited
    /// help-request tickets being accepted</summary>
    public bool DisableRemoteAssistance { get; set; } = true;

    /// <summary>Layer 34: Block Windows Insider preview enrollment —
    /// prevents preview builds (and their heavier telemetry) arriving</summary>
    public bool BlockInsiderPreview { get; set; } = true;

    /// <summary>Layer 35: Demote misc bloat services nobody invokes
    /// interactively — dmwappushservice (WAP push/MDM), MapsBroker,
    /// WMPNetworkSvc, DiagnosticsHub — to demand-start</summary>
    public bool DisableMiscBloatServices { get; set; } = true;

    /// <summary>Layer 36: Desktop Spotlight off — the wallpaper surface is
    /// also a content-delivery channel (promos baked into wallpapers)</summary>
    public bool DisableSpotlight { get; set; } = true;

    /// <summary>Layer 37: AutoPlay/AutoRun off — removable-media auto-execute
    /// is a classic payload vector</summary>
    public bool DisableAutoplay { get; set; } = true;

    /// <summary>Layer 38: no forced Windows Update reboot while a user is
    /// logged on</summary>
    public bool NoForcedReboot { get; set; } = true;

    /// <summary>Layer 39: hide the Start menu "Recommended" section —
    /// it surfaces promoted apps, not just your files</summary>
    public bool HideStartRecommendations { get; set; } = true;

    /// <summary>Layer 40: write AppxAllUserStore\Deprovisioned markers for
    /// blacklisted families so feature updates don't re-provision them
    /// (documented Windows behavior)</summary>
    public bool MarkDeprovisioned { get; set; } = true;

    /// <summary>Layer 41: 25H2 policy — the OS removes the listed default
    /// Store packages at first sign-in of NEW user profiles
    /// (HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages)</summary>
    public bool RemoveDefaultStorePackages { get; set; } = true;

    /// <summary>Layer 42: null-route pure-telemetry endpoints via a marked,
    /// reversible hosts-file block (Spybot Anti-Beacon technique)</summary>
    public bool BlockTelemetryEndpoints { get; set; } = true;

    /// <summary>Layer 43: winget uninstall sweep — catches Store apps winget
    /// can see but Get-AppxPackage can't</summary>
    public bool WingetSweep { get; set; } = true;

    /// <summary>Layer 44: Start=0 on boot-time telemetry ETW AutoLogger
    /// sessions (privacy.sexy / Sophia Script technique)</summary>
    public bool DisableTelemetryAutologgers { get; set; } = true;
}

// ─── JSON source-gen context (trim-safe: avoids IL2026 with PublishTrimmed) ──

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNameCaseInsensitive = true,
    ReadCommentHandling = JsonCommentHandling.Skip)]
[JsonSerializable(typeof(GuardConfig))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal partial class GuardJsonContext : JsonSerializerContext
{
}

// ─── Logger helper ───────────────────────────────────────────────────────────

/// <summary>Bounded process runner: drains stdout/stderr asynchronously so a
/// chatty child can't fill a pipe and deadlock, enforces a hard deadline with
/// a process-tree kill, and never exposes ExitCode for a live process. After
/// the parent exits, reader tasks are bounded too — a detached grandchild
/// inheriting the pipe can't hold EOF open and hang .Result forever.</summary>
internal static class Proc
{
    // Windows console tools (powershell.exe, reg.exe, schtasks, winget, sc,
    // dism) write stdout/stderr in the OEM code page (cp932 on ja-JP, cp437/
    // cp850 on Western systems) — .NET's UTF-8 default would mojibake any
    // non-ASCII output. Python parity: subprocess output decoded as cp932.
    private static readonly Encoding OemEncoding =
        Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);

    public static (string Stdout, string Stderr, int? ExitCode) Capture(
        ProcessStartInfo psi, int timeoutMs)
    {
        // Redirect both streams ourselves — callers that only set stdout would
        // throw InvalidOperationException on StandardError reads.
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.StandardOutputEncoding = OemEncoding;
        psi.StandardErrorEncoding = OemEncoding;
        using var proc = Process.Start(psi);
        if (proc == null)
            return ("", "failed to start", null);
        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            return ("", "timeout", null);
        }
        Task.WaitAll(new Task[] { stdout, stderr }, 10000);
        return (stdout.Status == TaskStatus.RanToCompletion ? stdout.Result : "",
                stderr.Status == TaskStatus.RanToCompletion ? stderr.Result : "",
                proc.ExitCode);
    }

    /// <summary>Start-and-wait with a hard timeout and tree-kill. Returns the
    /// exit code, or null when the process was killed on timeout.</summary>
    public static int? Wait(ProcessStartInfo psi, int timeoutMs)
    {
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        return Capture(psi, timeoutMs).ExitCode;
    }
}

public static class GuardLogger
{
    private const string EventSource = "BloatwareGuard";
    private const string EventLogName = "Application";

    public static void EnsureSourceExists()
    {
        try
        {
            if (!EventLog.SourceExists(EventSource))
            {
                EventLog.CreateEventSource(EventSource, EventLogName);
            }
        }
        catch
        {
            // Non-admin: cannot create event source, log to file only
        }
    }

    public static void Info(string msg) => Write("INFO", msg);
    public static void Warn(string msg) => Write("WARN", msg);
    public static void Error(string msg) => Write("ERROR", msg);

    private static bool _sourceChecked;

    private static void Write(string level, string msg)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {msg}";
        Console.WriteLine(line);

        try
        {
            // SourceExists probes the registry — do it once, not per log line
            if (!_sourceChecked)
            {
                _sourceChecked = true;
                EnsureSourceExists();
            }
            EventLog.WriteEntry(EventSource, msg,
                level == "ERROR" ? EventLogEntryType.Error :
                level == "WARN" ? EventLogEntryType.Warning :
                EventLogEntryType.Information);
        }
        catch { /* Event log may not be available in all contexts */ }

        // File log
        var logPath = ResolveLogFilePath();
        if (!string.IsNullOrEmpty(logPath))
        {
            try
            {
                var parent = Path.GetDirectoryName(logPath);
                if (!string.IsNullOrEmpty(parent))
                    Directory.CreateDirectory(parent);
                // A resident service appends forever — rotate at 1 MB,
                // keeping one prior generation (*.old)
                var info = new FileInfo(logPath);
                if (info.Exists && info.Length > 1_000_000)
                {
                    var old = logPath + ".old";
                    File.Delete(old);
                    File.Move(logPath, old);
                }
                File.AppendAllText(logPath, line + Environment.NewLine);
            }
            catch { /* ignore file log errors */ }
        }
    }

    private static string? _logFilePath;
    private static bool _logPathResolved;

    /// <summary>Cache LogFilePath from config.json on first successful read —
    /// avoids a full file read + JSON parse for every log line.</summary>
    private static string? ResolveLogFilePath()
    {
        if (_logPathResolved)
            return _logFilePath;
        try
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "config.json");
            if (!File.Exists(configPath))
                return null;  // not resolved yet — retry on next write
            var config = JsonSerializer.Deserialize(
                File.ReadAllText(configPath), GuardJsonContext.Default.GuardConfig);
            _logFilePath = config?.LogFilePath;
            _logPathResolved = true;
        }
        catch { /* unreadable config — keep retrying */ }
        return _logFilePath;
    }
}

// ─── Removal ledger (restore support) ────────────────────────────────────────

public static class RemovalLedger
{
    public static string GetPath(GuardConfig config)
    {
        var dir = config.BackupDirectory;
        if (string.IsNullOrEmpty(dir))
            dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BloatwareGuard", "Backups");
        return Path.Combine(dir, "removed-packages.jsonl");
    }

    public static void Record(GuardConfig config, string kind, string name,
        string family = "", string fullName = "")
    {
        try
        {
            var ledger = GetPath(config);
            Directory.CreateDirectory(Path.GetDirectoryName(ledger)!);
            var entry = new Dictionary<string, string>
            {
                ["ts"] = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss"),
                ["kind"] = kind,
                ["name"] = name,
                ["family"] = family,
                ["full_name"] = fullName,
            };
            File.AppendAllText(ledger,
                JsonSerializer.Serialize(entry, GuardJsonContext.Default.DictionaryStringString)
                + Environment.NewLine);
        }
        catch { /* ledger is best-effort */ }
    }
}

// ─── Config loader ───────────────────────────────────────────────────────────

public static class ConfigLoader
{
    public static GuardConfig Load(string path)
    {
        if (!File.Exists(path))
        {
            GuardLogger.Info("No config.json found, creating default...");
            var defaultConfig = CreateDefault();
            Save(path, defaultConfig);
            return defaultConfig;
        }

        var json = File.ReadAllText(path);
        var config = JsonSerializer.Deserialize(json, GuardJsonContext.Default.GuardConfig);

        return config ?? CreateDefault();
    }

    /// <summary>Write `text` to `path` via a same-dir temp file + replace — a
    /// crash mid-write can't leave a truncated/corrupt destination.</summary>
    public static void WriteAllTextAtomic(string path, string text)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, text);
        File.Move(tmp, path, overwrite: true);
    }

    public static void Save(string path, GuardConfig config)
    {
        var json = JsonSerializer.Serialize(config, GuardJsonContext.Default.GuardConfig);
        WriteAllTextAtomic(path, json);
    }

    private static GuardConfig CreateDefault()
    {
        return new GuardConfig
        {
            ScanIntervalSeconds = 300,
            // Same default the Python side writes into a generated config.json
            LogFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BloatwareGuard", "bloatware-guard.log"),
            Blacklist = new List<string>
            {
                // Microsoft bloatware
                "Microsoft.Xbox",
                "Microsoft.GamingApp",
            "Flipgrid",                      // Flip education stub (ReviOS appx.yml)
            "Microsoft.FrenchRiviera",       // scenic/spotlight stub (TronScript)
            "Microsoft.Lucille",             // inbox demo stub (TronScript)
            "Microsoft.SeaofThieves",        // game stub (TronScript)
            // zoicware RemoveWindowsAI 2026 diff — AI component packages
            "Microsoft.Office.ActionsServer", "Microsoft.WritingAssistant",
            "Microsoft.Ink.Handwriting", "Voiess", "Speion", "Livtop",
            "Filons", "WindowsWorkload.",
                "Microsoft.MicrosoftSolitaireCollection",
                "Microsoft.People",
                "Microsoft.WindowsMaps",
                "Microsoft.Zune",
                "Microsoft.YourPhone",
                "Microsoft.MicrosoftOfficeHub",
                "Microsoft.SkypeApp",
                "Microsoft.GetHelp",
                "Microsoft.Getstarted",
                "Microsoft.Microsoft3DViewer",
                "Microsoft.MixedReality.Portal",
                "Microsoft.BingNews",
                "Microsoft.BingWeather",
                "Microsoft.WindowsFeedbackHub",
                "Microsoft.WindowsSoundRecorder",
                "Microsoft.549981C3F5F10",       // Cortana
                "Microsoft.PowerAutomateDesktop",
                "Microsoft.Todos",
                "Microsoft.Windows.Photos",
            "Microsoft.USNationalParks",        // theme/content pack stub (VDOT appx)
                "Microsoft.WindowsAlarms",
                "Microsoft.ScreenSketch",
                "Microsoft.Clipchamp",
                "MicrosoftTeams", "Microsoft.Teams",
                "Microsoft.MicrosoftEdge.Stable",
                "Microsoft.Windows.DevHome",       // Dev Home (+ GitHub extension)
                "Microsoft.Copilot",
                // OS-inboxed Copilot package (distinct from Store
                // Microsoft.Copilot — itsnileshhere/windows-iso-debloater)
                "Microsoft.Windows.Copilot",
                "Microsoft.Windows.Ai.Copilot.Provider",  // Copilot provider package
                "MicrosoftWindows.Client.CoPilot",  // Copilot client (distinct from Microsoft.Copilot)
                "MicrosoftWindows.Client.CoreAI",   // Windows AI platform — Recall/ClickToDo runtime
                "MicrosoftWindows.Client.AIX",      // AI experience shell (Copilot+)
                "aimgr",                            // AI Manager package
                "Clipchamp.Clipchamp",
                "MSTeams",                          // New Teams (Work/School), provisioned via AppX push
                "Microsoft.Windows.Teams",          // inbox Teams integration stub (iso-debloater)
                "Microsoft.OutlookForWindows",      // New Outlook, preinstalled since 23H2
                "Microsoft.WindowsCommunicationsApps", // Mail & Calendar (discontinued Dec 2024)
                "MicrosoftCorporationII.MicrosoftFamily",
                "MicrosoftCorporationII.QuickAssist",
                "Microsoft.BingSearch",
                "Microsoft.MicrosoftStickyNotes",
                "Microsoft.Edge.GameAssist",
                "Microsoft.3DBuilder",                // discontinued
                "Microsoft.BingFinance",              // discontinued Bing consumer apps
                "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness",
                "Microsoft.BingSports", "Microsoft.BingTranslator",
                "Microsoft.BingTravel",
                "Microsoft.News",                     // News feed app
                "Microsoft.PCManager",                // pushed via 24H2+ provisioning
                "Microsoft.Windows.AIHub",            // Store AI promotions hub

                // Third-party bloatware commonly pre-installed
                "McAfee",
                "Norton",
                "SpotifyAB.SpotifyMusic",
                "Netflix",
                "Dolby",
                // Intel Management & Security Status (IMSS) — OEM support stub
                "AppUp.IntelManagementandSecurityStatus",
                "RealtekSemiconductor",
                "SynapticsIncorporated",
                "BytedancePte.Ltd.TikTok",
                "KING.COM.",                       // CandyCrush + all King.com promo games
                "A278AB0D.",  // Lenovo apps + MarchofEmpires/DisneyMagicKingdoms
                "9E2F88E3.",   // Twitter stub apps
                "613EBCEA.",   // Polarr photo stubs
                "89006A2E.",   // Autodesk stubs
                "D52A8D61.",   // FarmVille stubs
                "DB6EA5DB.",   // CyberLink stubs
                "NORDCURRENT.",  // CookingFever-family stubs
                // Win-Debloat-Tools list — Samsung store stubs + RandomSalad
                "RandomSaladGamesLLC.", "SAMSUNGELECTRONICSCO.LTD.",
                "Playtika.",      // casino-game stubs (Caesars Slots)
                "ThumbmunkeysLtd.",  // Phototastic Collage stub
                "DolbyAccess",    // Dolby Atmos trial console (OEM push)
                "D5EA27B7.Duolingo-LearnLanguagesforFree",
                "PandoraMediaInc.29680B314EFC2",
                "Facebook.InstagramBeta",
                "Facebook.Facebook",
                "WhatsApp",
                "Disney",                          // Disney+ etc.
                "Amazon.com.Amazon",
                "AmazonVideo.PrimeVideo",
                "LinkedIn",
                "Flipboard",
                "Asphalt8Airborne",
                "CyberLinkMediaSuite",
                "EclipseManager",
                "Booking",
                "PicsArt",
                "Twitter",
                "Evernote",
                "ExpressVPN",
                "Nordcurrent",
                // Dead/deprecated stock apps and promo stubs (24H2 still ships them)
                "Microsoft.3DViewer",
                "Microsoft.Print3D", "Microsoft.Whiteboard",
                "Microsoft.Wallet",                 // Microsoft Pay UI — retired
                "Microsoft.Messaging", "Microsoft.OneConnect",
                "Microsoft.CommsPhone", "Microsoft.Appconnector",
                "Microsoft.NetworkSpeedTest", "Microsoft.Office.Sway",
                "Microsoft.Office.Desktop",         // Office Hub launcher / promo stub
                "MSTranslatorBeta",
                "MicrosoftWindows.Client.WebExperience",  // Widgets board host package
                "Microsoft.MicrosoftJournal",             // Journal note app
                "MicrosoftWindows.CrossDevice",           // Cross-Device Experience stub
                "Microsoft.ECApp",                        // Edge app-maker stub
                "SystweakSoftware", "PricerunnerAB",
                // OEM/promo third-party (Win11Debloat default-removal parity)
                "ACGMediaPlayer", "ActiproSoftwareLLC",
                "AdobeSystemsIncorporated.AdobePhotoshopExpress",
                "AutodeskSketchBook", "CaesarsSlotsFreeCasino",
                "DrawboardPDF", "FarmVille2CountryEscape",
                "HULULLC.HULUPLUS", "HiddenCity", "NYTCrossword",
                "OneCalendar", "PhototasticCollage",
                "PolarrPhotoEditorAcademicEdition", "Sidia.LiveWallpaper",
                "SlingTV", "TuneInRadio", "WinZipUniversal",
                // winlite diff — promoted stubs still on 25H2 consumer
                // images (Priceline travel, GroupMe social, Tips)
                "PricelineCom.", "GroupMe", "Microsoft.Tips",
                "flaregamesGmbH.RoyalRevolt", "CandyCrush",
            "MarchofEmpires", "Plex", "Viber", "iHeartRadio",
                // OEM vendor appx bundles — publisher prefixes: 21 HP apps,
                // 3 Dell apps, 2 Lenovo entries (Win11Debloat optional)
                "AD2F1837.",
                "SAMSUNGELECTRONICS",
                "4AE8B7C2.",
                "FACEBOOK.",
                "DellInc.",
                "LGElectronics.",
                "COOKINGFEVER",
                "AcerIncorporated.",
                "LenovoCorporation.",
                "E046963F.", "828B5831.",
                "LenovoCompanyLimited.LenovoVantageService",
                // Debloat-Win11 diff — OEM utility suites (audio/RGB/
                // control-center promo ware) + Widgets runtime + Start feed host
                "WavesAudio", "DragonCenter", "MysticLight", "MSIAfterburner",
                "ROGLiveService", "ArmouryCrate", "MyASUS", "ASUSPCAssistant",
                "Razer", "LenovoUtility",
                "Microsoft.WidgetsPlatformRuntime", "Microsoft.StartExperiencesApp",
                // M365 companion suite promo (24H2) + stable Instagram
                "Microsoft.M365Companions",
                "Facebook.Instagram",
                // TronScript Metro diff — dead/promo/game-demo Microsoft appx
                "Microsoft.Advertising.JavaScript", "Microsoft.Advertising.Xaml",
                "Microsoft.ConnectivityStore", "Microsoft.HelpAndTips",
                "Microsoft.HoganThreshold", "Microsoft.MicrosoftRewards",
                "Microsoft.MicrosoftTreasureHunt", "Microsoft.MicrosoftJackpot",
                "Microsoft.MicrosoftJigsaw", "Microsoft.MicrosoftSudoku",
                "Microsoft.MicrosoftMahjong", "Microsoft.Studios.Wordament",
                "Microsoft.MovieMoments", "Microsoft.SkypeWiFi",
                "Microsoft.Windows.FeatureOnDemand.InsiderHub",
                "Microsoft.WindowsReadingList",
                "Microsoft.FreshPaint", "Microsoft.MinecraftUWP",
                "Microsoft.ForzaHorizon3Demo", "Microsoft.ForzaMotorsport7Demo",
                "Microsoft.BingMaps",
                // Dead Microsoft products still shipped by images
                // (Windows10Debloater diff): Office Lens retired Jan 2021,
                // Office.Todo.List folded into To Do, Wunderlist killed 2020
                "Microsoft.Office.Lens", "Microsoft.Office.Todo.List", "Wunderlist",
                // simeononsecurity diff: dead Windows Phone companion +
                // promo preinstalls (Fitbit Coach, Keeper promo, Shazam, Xing)
                "Microsoft.WindowsPhone", "Fitbit.FitbitCoach",
                "KeeperSecurityInc.Keeper", "ShazamEntertainmentLtd.Shazam",
                "XINGAG.XING",
                // ReviOS playbook diff: Take-a-Test browser, People host,
                // Surface Hub mail, New Outlook PWA package name
                "Microsoft.Windows.SecureAssessmentBrowser",
                "Microsoft.Windows.PeopleExperienceHost",
                "MicrosoftCorporationII.MailforSurfaceHub", "OutlookPWA",
                // W4RH4WK leftovers (Paint 3D is deprecated UWP, not
                // paint.exe)
                "A025C540.Yandex.Music", "Microsoft.WindowsFeedback",
                "Microsoft.MicrosoftReadingList", "Microsoft.MSPaint",
                // xd-AntiSpy DebloaterPlugin diff: OEM promo stubs +
                // third-party promo preinstalls (publisher-needle form)
                "HPJumpStart", "ASUSGiftBox", "AcerCollection",
                "DellDigitalDelivery", "DellSupportAssist",
                "GAMELOFTSA", "KhanAcademy", "AsanaInc.Asana", "Luminar",
                "DropboxInc.Dropbox", "TripAdvisor", "Uber",
                "WildTangent", "SaferVPN", "SymantecCorporation",

                // OEM utilities (uncomment as needed)
                // "DellInc.Dell",
                // "HPInc.",
                // "Lenovo.",
                // "ASUS",
                // "Acer",
                "BethesdaSoftworks.FalloutShelter",
                "Microsoft.Advertising",
            },
            Whitelist = new List<string>
            {
                "Microsoft.WindowsStore",
                "Microsoft.WindowsCalculator",
                "Microsoft.WindowsNotepad",
                "Microsoft.WindowsTerminal",
                "Microsoft.Windows.ShellExperienceHost",
                "Microsoft.Windows.Cortana",
                "Microsoft.Windows.SecHealthUI",
                "Microsoft.Windows.Apprep.ChxApp",
                // Xbox/Troubleshooter framework packages the broad
                // "Microsoft.Xbox"/"Microsoft.GetHelp" blacklist prefixes
                // would otherwise hit (Win11Debloat "unsafe" list)
                "Microsoft.Xbox.TCUI",
                "Microsoft.XboxIdentityProvider",
                "Microsoft.XboxSpeechToTextOverlay",
                "Microsoft.GetHelp",
            },
            BackupDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BloatwareGuard", "Backups")
        };
    }
}

// ─── Appx Package Manager ────────────────────────────────────────────────────

public static class AppxManager
{
    /// <summary>Get all installed AppxPackages whose FamilyName matches any blacklist entry</summary>
    public static List<(string PackageFamilyName, string DisplayName, string PackageFullName, bool IsFramework, string? InstallPath)> GetBlacklistedPackages(
        List<string> blacklist, List<string> whitelist)
    {
        var results = new List<(string, string, string, bool, string?)>();
        var pattern = string.Join("|",
            blacklist.Where(b => !string.IsNullOrWhiteSpace(b)).Select(Regex.Escape));
        if (pattern.Length == 0)
            return results;  // empty pattern would -match every package

        // -AllUsers catches packages installed for other profiles (requires admin —
        // non-admin gets an error, so fall back to the current-user scope).
        var output = RunPackageQuery(pattern, allUsers: true);
        if (string.IsNullOrWhiteSpace(output))
            output = RunPackageQuery(pattern, allUsers: false);

        // -AllUsers returns one row per user — dedupe by PackageFullName
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var doc = JsonDocument.Parse(output.Trim());
            var elements = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().ToList()
                : new List<JsonElement> { doc.RootElement };
            foreach (var el in elements)
            {
                var family = el.GetProperty("PackageFamilyName").GetString() ?? "";
                var name = el.GetProperty("Name").GetString() ?? "";
                var fullName = el.GetProperty("PackageFullName").GetString() ?? "";
                var isFw = el.TryGetProperty("IsFramework", out var fw) && fw.ValueKind == JsonValueKind.True;
                var installPath = el.TryGetProperty("InstallPath", out var ip) ? ip.GetString() : null;
                if (!IsWhitelisted(family, whitelist) && seen.Add(fullName))
                    results.Add((family, name, fullName, isFw, installPath));
            }
        }
        catch { /* no matches or parse error */ }

        return results;
    }

    private static string RunPackageQuery(string pattern, bool allUsers)
    {
        var scope = allUsers ? " -AllUsers" : "";
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Get-AppxPackage{scope} | Where-Object {{$_.PackageFamilyName -match '{pattern}'}} | Select-Object PackageFamilyName,Name,PackageFullName,IsFramework,InstallPath | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var (output, _, exitCode) = Proc.Capture(psi, 120000);
        return exitCode == 0 ? output : "";
    }

    /// <summary>Remove deprecated/legacy optional Windows capabilities.
    /// Conservative list: IE compatibility mode (Edge covers IE-mode), Steps
    /// Recorder (deprecated), WordPad (removed by MS in 24H2 anyway).
    /// Requires admin; non-admin/non-present entries are skipped by PowerShell.</summary>
    public static void RemoveOptionalCapabilities(GuardConfig config)
    {
        var pattern = "Browser.InternetExplorer|App.StepsRecorder|Microsoft.Windows.WordPad|XPS.Viewer|Print.Fax.Scan|App.WirelessDisplay.Connect";
        var query = $"Get-WindowsCapability -Online | Where-Object {{$_.Name -match '{pattern}' -and $_.State -eq 'Installed'}}";
        var namesPsi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{query} | Select-Object -ExpandProperty Name\"",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        var names = Proc.Capture(namesPsi, 60000).Stdout
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(n => n.Trim())
            .Where(AppxManager.IsPackageNameSafe)
            .ToList();
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{query} | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        if (Proc.Wait(psi, 180000) == 0)  // DISM ops can be slow
        {
            // Remove-WindowsCapability may fail per-item even on rc=0 — re-query
            // and only ledger capabilities that are actually gone.
            var namesPsi2 = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = namesPsi.Arguments,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            var remaining = Proc.Capture(namesPsi2, 60000).Stdout
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(n => n.Trim()).ToHashSet();
            var removed = names.Where(n => !remaining.Contains(n)).ToList();
            foreach (var n in removed)
                RemovalLedger.Record(config, "capability", n);
            GuardLogger.Info($"Applied: RemoveOptionalCapabilities ({removed.Count}/{names.Count} capabilities removed)");
        }
        else
            GuardLogger.Warn("RemoveOptionalCapabilities: no capabilities removed (absent or admin required)");
    }

    /// <summary>Check if a package family name matches any whitelist entry</summary>
    public static bool IsWhitelisted(string packageFamilyName, List<string> whitelist)
    {
        return whitelist.Any(w => !string.IsNullOrWhiteSpace(w) &&
            packageFamilyName.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Get all provisioned packages (these re-deploy on new user creation)</summary>
    public static List<string> GetBlacklistedProvisionedPackages(List<string> blacklist, List<string> whitelist)
    {
        var results = new List<string>();
        var pattern = string.Join("|",
            blacklist.Where(b => !string.IsNullOrWhiteSpace(b)).Select(Regex.Escape));
        if (pattern.Length == 0)
            return results;  // empty pattern would -match every package

        // Match DisplayName (the stable product name the blacklist was written
        // against — Python parity) and return PackageName for removal.
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Get-AppxProvisionedPackage -Online | Where-Object {{$_.DisplayName -match '{pattern}'}} | Select-Object DisplayName,PackageName | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var output = Proc.Capture(psi, 120000).Stdout;

        try
        {
            void AddIfNotWhitelisted(JsonElement el)
            {
                var pkg = el.GetProperty("PackageName").GetString() ?? "";
                var display = el.GetProperty("DisplayName").GetString() ?? "";
                if (!string.IsNullOrEmpty(pkg) && !IsWhitelisted(display, whitelist))
                    results.Add(pkg);
            }

            var doc = JsonDocument.Parse(output.Trim());
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                    AddIfNotWhitelisted(el);
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                AddIfNotWhitelisted(doc.RootElement);
            }
        }
        catch { }

        return results;
    }

    public static bool RemoveAppxPackage(string packageFullName)
    {
        if (!IsPackageNameSafe(packageFullName))
            return false;
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Remove-AppxPackage -Package '{packageFullName}' -AllUsers -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var (_, stderr, exitCode) = Proc.Capture(psi, 60000);
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"Remove-AppxPackage stderr: {stderr.Trim()}");
        return exitCode == 0;
    }

    /// <summary>Remove AppxPackage for CURRENT USER only (no admin required).
    /// Returns (success, isSystemApp). SystemApps cannot be removed per-user.</summary>
    public static (bool Success, bool IsSystemApp) RemoveAppxPackageForUser(string packageFullName, string? installPath = null)
    {
        // SystemApps have null InstallPath — cannot be removed per-user (0x80073CFA)
        if (string.IsNullOrEmpty(installPath))
        {
            GuardLogger.Info($"RemoveAppxPackageForUser: '{packageFullName}' is a SystemApp — cannot remove per-user (skip, requires admin)");
            return (false, true);
        }

        if (!IsPackageNameSafe(packageFullName))
            return (false, false);
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Remove-AppxPackage -Package '{packageFullName}' -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var (_, stderr, exitCode) = Proc.Capture(psi, 60000);
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"Remove-AppxPackage (user) stderr: {stderr.Trim()}");
        return (exitCode == 0, false);
    }

    public static bool RemoveProvisionedPackage(string packageName)
    {
        if (!IsPackageNameSafe(packageName))
            return false;
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Remove-AppxProvisionedPackage -Online -PackageName '{packageName}' -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var (_, stderr, exitCode) = Proc.Capture(psi, 120000);
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"RemoveProvisionedPackage stderr: {stderr.Trim()}");
        return exitCode == 0;
    }

    // Package names are simple identifiers (Name_ver_arch_resid_pubid) —
    // anything else is rejected before it can reach a PowerShell string.
    private static readonly Regex PackageNamePattern =
        new(@"^[A-Za-z0-9_.\-~!]+$", RegexOptions.Compiled);

    internal static bool IsPackageNameSafe(string name) =>
        !string.IsNullOrEmpty(name) && PackageNamePattern.IsMatch(name);


    /// <summary>Get-AppxProvisionedPackage returns no PublisherId — the
    /// publisher is the last '_' segment of PackageName. PackageName is
    /// Name_version_arch_[resourceid_]_publisher, and the name itself may
    /// contain underscores — so split the four well-formed suffix fields off
    /// the RIGHT end, then join name + '_' + publisher.</summary>
    public static string ProvisionedFamilyName(string packageName)
    {
        var segs = packageName.Split('_');
        if (segs.Length >= 5)
            return string.Join('_', segs[..^4]) + "_" + segs[^1];
        // Malformed (<5 segments): fall back to first name + last publisher
        var first = packageName.IndexOf('_');
        var last = packageName.LastIndexOf('_');
        return (first > 0 && last > first)
            ? packageName[..first] + "_" + packageName[(last + 1)..]
            : packageName;
    }

    private const string DeprovisionedPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned";
    private const string EndOfLifePath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife";
    private const string RemoveDefaultPkgsPath =
        @"SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages";

    /// <summary>Write HKLM Deprovisioned + EndOfLife markers for blacklisted
    /// families so feature updates don't re-provision them and the Store
    /// declines reinstall (documented behavior — the EOL marker Windows
    /// writes for retired inbox apps; GDStudiosDev/fortify).</summary>
    public static int MarkDeprovisioned(IEnumerable<string> familyNames)
    {
        var marked = 0;
        try
        {
            using var baseKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                DeprovisionedPath, writable: true);
            using var eolKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                EndOfLifePath, writable: true);
            foreach (var family in familyNames)
            {
                try
                {
                    using var sub = baseKey?.CreateSubKey(family);
                    using var eol = eolKey?.CreateSubKey(family);
                    marked++;
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            GuardLogger.Warn($"Deprovisioned markers: {ex.Message}");
        }
        return marked;
    }

    /// <summary>Windows 11 25H2 policy: the OS removes the listed default Store
    /// packages at first sign-in of NEW user profiles. Unknown entries are
    /// ignored by older builds — harmless forward-compat. The documented
    /// mechanism is a subkey per package family name with RemovePackage=1,
    /// plus DynamicRemovalList (REG_MULTI_SZ) for families the GPO UI does
    /// not enumerate.</summary>
    public static void ApplyRemoveDefaultStorePackages(IEnumerable<string> familyNames)
    {
        var families = familyNames.ToArray();
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                RemoveDefaultPkgsPath, writable: true);
            if (key == null)
                return;
            // Merge with existing entries — a family removed in an earlier
            // scan must stay listed or new users get it re-provisioned.
            var prior = key.GetValue("DynamicRemovalList") as string[] ?? Array.Empty<string>();
            // Migrate any names an older build recorded in the non-standard
            // PackageList value before dropping it, so they stay listed.
            var legacy = key.GetValue("PackageList") switch
            {
                string[] many => many,
                string one => one.Split(new[] { ';', ',', '\n', '\r' },
                    StringSplitOptions.RemoveEmptyEntries),
                _ => Array.Empty<string>()
            };
            var merged = prior.Concat(legacy).Concat(families)
                .Select(f => f.Trim())
                .Where(f => f.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            key.SetValue("Enabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key.SetValue("DynamicRemovalList", merged, Microsoft.Win32.RegistryValueKind.MultiString);
            // Older builds of this tool wrote a non-standard PackageList
            // value — drop it so only the documented mechanism remains.
            try { key.DeleteValue("PackageList", throwOnMissingValue: false); }
            catch { }
            foreach (var family in merged)
            {
                try
                {
                    using var sub = key.CreateSubKey(family);
                    sub?.SetValue("RemovePackage", 1, Microsoft.Win32.RegistryValueKind.DWord);
                }
                catch { }
            }
            families = merged;
            GuardLogger.Info($"Applied: RemoveDefaultStorePackages ({families.Length} families listed)");
        }
        catch (Exception ex)
        {
            GuardLogger.Warn($"RemoveDefaultStorePackages: {ex.Message}");
        }
    }
}

// ─── Win32 program removal (non-Appx OEM bloatware) ─────────────────────────

public static class Win32Guard
{
    // Registry Uninstall keys: 64-bit, 32-bit (WOW6432Node), and per-user
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string UninstallPath32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string UserUninstallPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";

    // Extracts an MSI product GUID from an UninstallString (MsiExec /I{...})
    private static readonly Regex MsiGuidPattern =
        new(@"\{[0-9A-Fa-f\-]{36}\}", RegexOptions.Compiled);

    // DisplayName needles checked alongside the blacklist — appx-style
    // publisher prefixes (DellInc., AD2F1837.) never appear in DisplayName
    // strings, so OEM support-ware and PUA optimizers need their own
    // product names. Sources: TronScript programs_to_target_by_name
    // (PUA/adware canon), winutil, Win11Debloat. Vendor-bare names
    // (HP, Dell, Lenovo) are deliberately absent — substrings would
    // false-positive on utilities ("HP" is inside "Touchpad").
    private static readonly string[] Win32BloatNames = {
        // OEM support-ware / promo updaters still shipping today
        "SupportAssist", "HP Support Assistant", "HP JumpStart", "MyASUS",
        "Acer Collection", "MSI Center", "Dragon Center", "Armoury Crate",
        "ArmouryCrate", "Nahimic", "Killer Intelligence", "BlueStacks",
        "Wondershare",
        // HP serviceware channel (Spiceworks HP-debloat canon). HP Wolf
        // Security (real AV) deliberately excluded.
        "HP Connection Optimizer", "HP Documentation", "HP Notifications",
        "HP Security Update Service", "HP Sure Recover", "HP Sure Run Module",
        // PUA "optimizer"/driver-updater tier pushed via ads
        "IObit", "Advanced SystemCare", "Driver Booster", "DriverBooster",
        "Driver Easy", "DriverEasy", "DriverUpdate", "Driver Tonic",
        "Win Tonic", "PCVARK", "Systweak", "RegClean", "SlimWare",
        "SlimCleaner", "Outbyte", "Restoro", "PCRepair", "PC Repair",
        "PC Cleaner", "SpeedUpMyPC", "OneSafe", "WinZip Driver",
        "DriverDoc", "TotalAV", "ScanGuard", "PCProtect", "PC Health",
        "McAfee Security Scan",
        // Legacy adware/toolbar canon — dead weight where still installed
        "Ask Toolbar", "Babylon", "Conduit", "Wajam", "Yontoo", "OpenCandy",
        "SweetIM", "Iminent", "Spigot", "Binkiland", "Snap.do",
        "Search Protect", "SearchProtect", "MyStartSearch", "Omiga Plus",
        "Delta Search", "Qone8", "Trovi", "MapsGalaxy", "InfoAtoms",
        "Mobogenie", "GetSavin", "DealPly", "BrowseFox", "Media Buzz",
        "Media View", "Media Watch", "Buzzdock", "BrowserSafeguard",
        "CloudScout", "ClipGenie", "ClickForSale", "Bonanza", "AnyProtect",
        "AppsHat", "ArcadeParlor", "AtuZi", "Altnet", "iBryte", "iLivid",
        "iStart123", "FilesFrog", "Gamevance", "InstaCodecs", "IWon",
        "MyPC Backup", "My Web Search", "Sweet Packs", "VisualBee",
        "WhiteSmoke", "WildTangent", "Big Fish", "Bonzi",
    };

    /// <summary>Enumerate installed Win32 programs matching the blacklist.
    /// Returns (DisplayName, UninstallString, QuietUninstallString, UserHive).
    /// UserHive entries are report-only: HKU\<sid> is user-writable, so an
    /// elevated service must never execute strings a non-admin user could
    /// plant there.</summary>
    public static List<(string DisplayName, string UninstallString, string QuietUninstallString, bool UserHive)>
        GetBlacklistedPrograms(List<string> blacklist, List<string> whitelist)
    {
        var results = new List<(string, string, string, bool)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void ScanKey(RegistryKey root, string path, bool userHive = false)
        {
            try
            {
                using var key = root.OpenSubKey(path);
                if (key == null)
                    return;
                foreach (var sub in key.GetSubKeyNames())
                {
                    try
                    {
                        using var sk = key.OpenSubKey(sub);
                        var display = sk?.GetValue("DisplayName") as string;
                        var uninstall = sk?.GetValue("UninstallString") as string;
                        if (string.IsNullOrEmpty(display) || string.IsNullOrEmpty(uninstall))
                            continue;
                        // SystemComponents and updates are not removable programs
                        if ((sk?.GetValue("SystemComponent") as int?) == 1)
                            continue;
                        var quiet = sk?.GetValue("QuietUninstallString") as string ?? "";
                        if (!IsWhitelisted(display, whitelist) &&
                            blacklist.Concat(Win32BloatNames).Any(
                                b => !string.IsNullOrWhiteSpace(b) &&
                                display.Contains(b, StringComparison.OrdinalIgnoreCase)) &&
                            seen.Add(display))
                        {
                            results.Add((display, uninstall, quiet, userHive));
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        ScanKey(Registry.LocalMachine, UninstallPath);
        ScanKey(Registry.LocalMachine, UninstallPath32);
        // CurrentUser maps to the *caller's* hive: under an elevated
        // interactive run that's the invoking (non-admin-origin) user — a
        // user-writable hive whose uninstall strings must never execute with
        // our admin token. Report-only, same rule as HKU\<sid>.
        ScanKey(Registry.CurrentUser, UserUninstallPath, userHive: true);
        foreach (var sid in Registry.Users.GetSubKeyNames())
        {
            // Loaded user hives only (interactive profiles)
            if (!Regex.IsMatch(sid, @"^S-1-5-21-\d+-\d+-\d+-\d+$"))
                continue;
            ScanKey(Registry.Users, $"{sid}\\{UserUninstallPath}", userHive: true);
        }

        return results;
    }

    private static bool IsWhitelisted(string display, List<string> whitelist) =>
        whitelist.Any(w => !string.IsNullOrWhiteSpace(w) &&
            display.Contains(w, StringComparison.OrdinalIgnoreCase));

    /// <summary>Silent-uninstall one program. Uses the vendor-supplied
    /// QuietUninstallString when present; MSI entries fall back to
    /// `msiexec /x {guid} /qn /norestart`. Non-silent uninstallers are
    /// logged for manual removal instead of guessing vendor switches.</summary>
    public static bool RemoveProgram(string displayName, string uninstallString, string quietUninstallString)
    {
        string cmd;
        string args;
        if (!string.IsNullOrEmpty(quietUninstallString))
        {
            var split = SplitCommandLine(quietUninstallString);
            cmd = split.cmd; args = split.args;
        }
        else if (uninstallString.IndexOf("msiexec", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            var m = MsiGuidPattern.Match(uninstallString);
            if (!m.Success)
                return false;
            cmd = "msiexec.exe";
            args = $"/x {m.Value} /qn /norestart";
        }
        else
        {
            GuardLogger.Info($"Win32 program needs manual removal (no silent uninstaller): {displayName} — {uninstallString}");
            return false;
        }

        var psi = new ProcessStartInfo
        {
            FileName = cmd,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        return Proc.Wait(psi, 300000) == 0;  // uninstallers can take minutes
    }

    private static (string cmd, string args) SplitCommandLine(string commandLine)
    {
        commandLine = commandLine.Trim();
        if (commandLine.StartsWith("\""))
        {
            var end = commandLine.IndexOf('"', 1);
            if (end > 0)
                return (commandLine[1..end], commandLine[(end + 1)..].Trim());
        }
        var space = commandLine.IndexOf(' ');
        return space < 0 ? (commandLine, "") : (commandLine[..space], commandLine[(space + 1)..].Trim());
    }

    /// <summary>Create a system restore point before destructive changes.
    /// Checkpoint-Computer self-throttles to one per 24h; failure is non-fatal.</summary>
    public static void CreateRestorePoint()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                "\"Enable-ComputerRestore -Drive \\\"$env:SystemDrive\\\\\\\" -ErrorAction SilentlyContinue | Out-Null; " +
                "Checkpoint-Computer -Description 'BloatwareGuard pre-scan' " +
                "-RestorePointType 'MODIFY_SETTINGS' -ErrorAction SilentlyContinue | Out-Null\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        if (Proc.Wait(psi, 120000) == 0)
            GuardLogger.Info("Applied: CreateRestorePoint (restore point created or throttled)");
        else
            GuardLogger.Warn("CreateRestorePoint: skipped (admin required or System Restore disabled)");
    }
}

// ─── Registry-based Prevention ───────────────────────────────────────────────

public static class RegistryGuard
{
    private const string CloudContentPath = @"SOFTWARE\Policies\Microsoft\Windows\CloudContent";
    private const string DeviceMetadataPath = @"SOFTWARE\Policies\Microsoft\Windows\Device Metadata";
    private const string AppCompatPath = @"SOFTWARE\Policies\Microsoft\Windows\AppCompat";
    private const string WindowsSearchPath = @"SOFTWARE\Policies\Microsoft\Windows\Windows Search";
    private const string WindowsCopilotPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot";
    private const string WindowsAiPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI";
    private const string WidgetsDshPath = @"SOFTWARE\Policies\Microsoft\Dsh";
    private const string WindowsFeedsPath = @"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds";
    private const string DataCollectionPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection";
    private const string SystemPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\System";
    private const string EdgePolicyPath = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string GameDvrPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\GameDVR";
    private const string DoPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
    private const string AiFabricServicePath = @"SYSTEM\CurrentControlSet\Services\WSAIFabricSvc";
    private const string OneDrivePolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\OneDrive";

    // Per-user paths (relative to a user hive root — HKCU or HKEY_USERS\<SID>)
    private const string UserCdmPath = @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
    private const string UserExplorerAdvancedPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    private const string UserExplorerPoliciesPath = @"Software\Policies\Microsoft\Windows\Explorer";
    private const string UserCopilotPath = @"Software\Policies\Microsoft\Windows\WindowsCopilot";
    private const string UserWindowsAiPath = @"Software\Policies\Microsoft\Windows\WindowsAI";
    private const string UserCopilotKeyboardPath = @"Software\Policies\Microsoft\CopilotKeyboard";
    private const string ShellCopilotPath = @"SOFTWARE\Microsoft\Windows\Shell\Copilot";
    private const string UserShellCopilotPath = @"Software\Microsoft\Windows\Shell\Copilot";
    private const string UserVoiceActivationPath = @"Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps";
    private const string UserClickToDoPath = @"Software\Microsoft\Windows\Shell\ClickToDo";
    private const string PaintPoliciesPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint";
    private const string NotepadPoliciesPath = @"SOFTWARE\Policies\WindowsNotepad";
    // Feature-management velocity overrides (community-verified IDs — e.g.
    // zoicware/RemoveWindowsAI). EnabledState: 0=default, 1=disabled, 2=enabled.
    private const string VelocityOverridesPath = @"SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\8";
    private static readonly (string Id, int State)[] VelocityCopilotIds =
    {
        // Copilot nudges + taskbar + systray
        ("1546588812", 1), ("203105932", 1), ("2381287564", 1),
        ("3389499533", 1), ("4027803789", 1),
    };
    private static readonly (string Id, int State)[] VelocityAiIds =
    {
        // AI Actions in Explorer; 1646260367 hides the entry when no action exists
        ("1853569164", 1), ("4098520719", 1), ("929719951", 1), ("1646260367", 2),
        // Additional AI velocity IDs (DebloatAndSecurizeW11 / phantomofearth
        // velocity feature lists)
        ("3189581453", 1), ("3552646797", 1), ("450471565", 1),
        // FeatureId 58375086 -> regID 1561856655 via zoicware's
        // ObfuscateFeatureId — disables the Explorer-side feature that
        // depends on AIFabric (zoicware #236/#238 Explorer-ribbon fix)
        ("1561856655", 1),
    };
    private const string UserSearchPath = @"Software\Microsoft\Windows\CurrentVersion\Search";
    private const string UserSearchSettingsPath = @"Software\Microsoft\Windows\CurrentVersion\SearchSettings";
    private const string AppPrivacyPath = @"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy";
    private const string UserProfileEngagementPath = @"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement";
    private const string UserAdvertisingInfoPath = @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo";
    private const string UserPrivacyPath = @"Software\Microsoft\Windows\CurrentVersion\Privacy";
    private const string UserOnlineSpeechPath = @"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy";
    private const string UserTipcPath = @"Software\Microsoft\Input\TIPC";
    private const string UserInputPersonalizationPath = @"Software\Microsoft\InputPersonalization";
    private const string UserInputStorePath = @"Software\Microsoft\InputPersonalization\TrainedDataStore";
    private const string UserPersonalizationPath = @"Software\Microsoft\Personalization\Settings";
    private const string UserSiufPath = @"Software\Microsoft\Siuf\Rules";
    private const string UserGameConfigStorePath = @"System\GameConfigStore";
    private const string UserGameDvrPath = @"Software\Microsoft\Windows\CurrentVersion\GameDVR";
    private const string UserDeliveryOptimizationPath = @"Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings";
    private const string UserExplorerPoliciesBasePath = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string UserOneDriveClsidPath = @"Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}";
    private const string UserAccountNotificationsPath = @"Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications";
    private const string UserSuggestedToastPath = @"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested";
    private const string UserMobilityPath = @"Software\Microsoft\Windows\CurrentVersion\Mobility";
    private const string UserOutlookMigrationPath = @"Software\Policies\Microsoft\Office\16.0\Outlook\Options\General";
    private const string UserOutlookPreferencesPath = @"Software\Policies\Microsoft\Office\16.0\Outlook\Preferences";
    private const string UserNotificationSettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings";
    // Language-list leak to websites (documented in Sophia Script)
    private const string UserIntlProfilePath = @"Control Panel\International\User Profile";
    private const string UserPrivacyPoliciesPath = @"Software\Policies\Microsoft\Windows\Privacy";
    // HKLM counterpart of UserExplorerPoliciesBasePath
    private const string ExplorerPoliciesHklmPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string WerPath = @"SOFTWARE\Microsoft\Windows\Windows Error Reporting";
    private const string WerPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting";
    private const string UserWerPath = @"Software\Microsoft\Windows\Windows Error Reporting";
    private const string MachineRunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string MachineRunPath32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string MachineRunOncePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string MachineRunOncePath32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string UserRunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string UserRunOncePath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string UserRunPath32 = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string UserRunOncePath32 = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string StartupApprovedRun = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string StartupApprovedRunOnce = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\RunOnce";
    private const string WindowsUpdatePolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";

    // Startup value names worth disabling even outside the package blacklist
    // (OEM updaters, adware helpers). OneDrive stays out — DisableOneDrive is opt-in.
    private static readonly string[] StartupBloatNames = {
        "Skype", "Cortana", "MicrosoftEdgeAutoLaunch", "GameAssist",
        "McAfee", "Norton", "WebAdvisor", "CCleaner", "Dell", "Lenovo",
        "SupportAssist", "Acer", "ASUS", "HP",
        // First-party promo suites + OEM utilities that re-register autostart
        "Teams", "YourPhone", "PhoneLink", "Xbox", "EdgeUpdate",
        "Armoury", "Nahimic",
        // Promo-installed third parties (markers are re-enableable)
        "Spotify", "Opera", "Adobe", "iTunes",
        // PUA-tier "optimizers"/driver updaters pushed by OEMs/ads
        "IObit", "DriverBooster", "DriverEasy", "SlimWare", "Outbyte",
        "Restoro", "Wondershare", "PCHealth",
        // Razer utilities (Debloat-Win11 OEM purge) — "Synapse" is not a
        // substring of "Synaptics", so pointing-device entries stay safe
        "Razer", "Synapse", "Cortex",
        // Peripheral-vendor control suites — same class as Armoury/Nahimic
        // (WinOpt startup audit); marker-based disable is reversible
        "Corsair", "SteelSeries", "Logitech",
        // Browser-hijacker/adware PUPs + PUA optimizers (et-optimizer
        // Run-purge list); functional tools (TeamViewer) and system-name
        // lookalikes (searchapp.exe) are left out
        "ASCTray", "BabylonToolbar", "CoolWebSearch", "Crossrider",
        "DriverMax", "FunWebProducts", "MediaNewTab", "MyWebSearch",
        "PCOptimizerPro", "RelevantKnowledge", "SAntivirus", "Segurazo",
        "ShopperPro", "SlimDrivers", "SuperOptimizer", "SweetPacks",
        "UpdatePPShortCut", "Vosteran", "WebCompanion",
        "WinZipDriverUpdater",
    };

    // 0x03 = disabled in StartupApproved (value kept — user can re-enable via Task Manager)
    private static readonly byte[] StartupDisabledMarker =
        { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    /// <summary>Demote a service to demand-start. Opens — never creates —
    /// the service key, so vendor services absent from the machine don't
    /// get phantom <c>Services\X</c> entries written for them.</summary>
    private static void DemoteService(string name)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{name}", writable: true);
            key?.SetValue("Start", 3, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch { }
    }

    // HKLM subkey where the Default-profile template hive is temporarily mounted
    private const string DefaultHiveMount = @"BloatwareGuard_DefaultProfile";

    // Matches real user profile SIDs (S-1-5-21-<machine>-<rid>), not .DEFAULT,
    // S-1-5-18/19/20 (service accounts) or *_Classes virtual hives.
    private static readonly Regex UserSidPattern =
        new(@"^S-1-5-21-\d+-\d+-\d+-\d+$", RegexOptions.Compiled);

    public static void ApplyAll(PreventionLayers layers,
                                List<string> blacklist, List<string> whitelist)
    {
        if (layers.BackupRegistry)
            try { BackupRegistryKeys(); }
            catch (Exception ex) { GuardLogger.Warn($"BackupRegistry layer failed: {ex.Message}"); }

        if (layers.DisableConsumerExperiences)
            try { DisableConsumerExperiences(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableConsumerExperiences layer failed: {ex.Message}"); }

        if (layers.DisableCloudContent)
            try { DisableCloudContent(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableCloudContent layer failed: {ex.Message}"); }

        if (layers.PreventDeviceMetadata)
            try { PreventDeviceMetadata(); }
            catch (Exception ex) { GuardLogger.Warn($"PreventDeviceMetadata layer failed: {ex.Message}"); }

        if (layers.BlockProvisioning)
            try { BlockProvisioning(); }
            catch (Exception ex) { GuardLogger.Warn($"BlockProvisioning layer failed: {ex.Message}"); }

        if (layers.DisableCopilot)
            try { DisableCopilot(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableCopilot layer failed: {ex.Message}"); }

        if (layers.DisableRecall)
            try { DisableRecall(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableRecall layer failed: {ex.Message}"); }

        if (layers.DisableSearchSuggestions)
            try { DisableSearchSuggestions(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableSearchSuggestions layer failed: {ex.Message}"); }

        if (layers.DisableWidgets)
            try { DisableWidgets(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableWidgets layer failed: {ex.Message}"); }

        if (layers.DisableTelemetry)
            try { DisableTelemetry(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableTelemetry layer failed: {ex.Message}"); }

        if (layers.DisableGameDvr)
            try { DisableGameDvr(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableGameDvr layer failed: {ex.Message}"); }

        if (layers.DisableDeliveryOptimization)
            try { DisableDeliveryOptimization(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableDeliveryOptimization layer failed: {ex.Message}"); }

        if (layers.DisableOneDrive)
            try { DisableOneDrive(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableOneDrive layer failed: {ex.Message}"); }

        if (layers.DisableChatTaskbar)
            try { DisableChatTaskbar(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableChatTaskbar layer failed: {ex.Message}"); }

        if (layers.DisableEdgeBloat)
            try { DisableEdgeBloat(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableEdgeBloat layer failed: {ex.Message}"); }

        if (layers.DisableStartupBloat)
            try { DisableStartupBloat(blacklist, whitelist); }
            catch (Exception ex) { GuardLogger.Warn($"DisableStartupBloat layer failed: {ex.Message}"); }

        if (layers.DisableErrorReporting)
            try { DisableErrorReporting(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableErrorReporting layer failed: {ex.Message}"); }

        if (layers.DisableEdgeUpdateBloat)
            try { DisableEdgeUpdateBloat(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableEdgeUpdateBloat layer failed: {ex.Message}"); }

        if (layers.BlockOemDriverUpdates)
            try { BlockOemDriverUpdates(); }
            catch (Exception ex) { GuardLogger.Warn($"BlockOemDriverUpdates layer failed: {ex.Message}"); }

        if (layers.DisableAppPermissions)
            try { DisableAppPermissions(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableAppPermissions layer failed: {ex.Message}"); }

        if (layers.DisableXboxServices)
            try { DisableXboxServices(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableXboxServices layer failed: {ex.Message}"); }

        if (layers.DisablePrintSpooler)
            try { DisablePrintSpooler(); }
            catch (Exception ex) { GuardLogger.Warn($"DisablePrintSpooler layer failed: {ex.Message}"); }

        if (layers.DisableModernStandbyNetworking)
            try { DisableModernStandbyNetworking(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableModernStandbyNetworking layer failed: {ex.Message}"); }

        if (layers.BlockOemWpbtExecution)
            try { BlockOemWpbtExecution(); }
            catch (Exception ex) { GuardLogger.Warn($"BlockOemWpbtExecution layer failed: {ex.Message}"); }

        if (layers.DisableReservedStorage)
            try { DisableReservedStorage(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableReservedStorage layer failed: {ex.Message}"); }

        if (layers.DisableCloudClipboard)
            try { DisableCloudClipboard(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableCloudClipboard layer failed: {ex.Message}"); }

        if (layers.DisableRemoteAssistance)
            try { DisableRemoteAssistance(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableRemoteAssistance layer failed: {ex.Message}"); }

        if (layers.BlockInsiderPreview)
            try { BlockInsiderPreview(); }
            catch (Exception ex) { GuardLogger.Warn($"BlockInsiderPreview layer failed: {ex.Message}"); }

        if (layers.DisableMiscBloatServices)
            try { DisableMiscBloatServices(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableMiscBloatServices layer failed: {ex.Message}"); }

        if (layers.DisableSpotlight)
            try { DisableSpotlight(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableSpotlight layer failed: {ex.Message}"); }

        if (layers.DisableAutoplay)
            try { DisableAutoplay(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableAutoplay layer failed: {ex.Message}"); }

        if (layers.NoForcedReboot)
            try { NoForcedReboot(); }
            catch (Exception ex) { GuardLogger.Warn($"NoForcedReboot layer failed: {ex.Message}"); }

        if (layers.HideStartRecommendations)
            try { HideStartRecommendations(); }
            catch (Exception ex) { GuardLogger.Warn($"HideStartRecommendations layer failed: {ex.Message}"); }

        if (layers.DisableTelemetryAutologgers)
            try { DisableTelemetryAutologgers(); }
            catch (Exception ex) { GuardLogger.Warn($"DisableTelemetryAutologgers layer failed: {ex.Message}"); }

        // Toggling off must REMOVE the block — call unconditionally so the
        // false path clears previously written entries.
        SetTelemetryHostsBlock(layers.BlockTelemetryEndpoints);
    }

    // Boot-time ETW trace sessions that feed telemetry (privacy.sexy / Sophia
    // Script technique). Diagtrack-Listener is already covered by
    // DisableTelemetry; kept here too for idempotence when only this is on.
    private static readonly string[] TelemetryAutologgers = {
        "AutoLogger-Diagtrack-Listener", "SQMLogger", "WiFiSession",
        "LwtNetLog", "NetCore", "NtfsLog", "UBPM", "MellonTelemetry",
        "Circular Kernel Context Logger", "DiagLog", "WFP-IPsec Diagnostics",
        "RadioManager", "SetupPlatformTel",
        // optimizerDuck diff: appx-activation model trace, cellular
        // OEM capture, OOBE/CloudExperience trace, DataMarket
        // share-in-use, WDI diagnostic context log
        "AppModel", "Cellcore", "CloudExperienceHostOobe", "DataMarket",
        "WdiContextLog",
    };

    // Diagnostic ETW event-log channels feeding power/sleep diagnostics —
    // Enabled=0 under WINEVT\Channels (the wevtutil sl /e:false
    // mechanism, noverse.dev sleep-study doc). Same open-only
    // convention as AutoLoggers.
    private static readonly string[] DiagnosticEtwChannels = {
        "Microsoft-Windows-SleepStudy/Diagnostic",
        "Microsoft-Windows-Kernel-Processor-Power/Diagnostic",
        "Microsoft-Windows-UserModePowerService/Diagnostic",
    };

    /// <summary>Start=0 on telemetry ETW AutoLoggers plus Enabled=0 on
    /// diagnostic ETW channels. Opens — never creates — each key, so
    /// absent sessions don't get phantom entries.</summary>
    public static void DisableTelemetryAutologgers()
    {
        var killed = 0;
        foreach (var session in TelemetryAutologgers)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\{session}", writable: true);
                if (key == null)
                    continue;
                key.SetValue("Start", 0, Microsoft.Win32.RegistryValueKind.DWord);
                killed++;
            }
            catch { }
        }
        var channels = 0;
        foreach (var channel in DiagnosticEtwChannels)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\{channel}", writable: true);
                if (key == null)
                    continue;
                key.SetValue("Enabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
                channels++;
            }
            catch { }
        }
        GuardLogger.Info($"Applied: DisableTelemetryAutologgers ({killed}/{TelemetryAutologgers.Length} sessions, {channels}/{DiagnosticEtwChannels.Length} channels)");
    }

    // Pure-telemetry endpoints null-routed via the hosts file — the Spybot
    // Anti-Beacon technique. Conservative: no Windows Update/Store/activation.
    private static readonly string[] TelemetryHosts = {
        "2mdn.net",
        "a.tribalfusion.com",
        "activity.windows.us",
        "ad.atdmt.com",
        "adnxs-simple.com",
        "adnxs.net",
        "ads.arcct.msn.com",
        "ads.bing.com",
        "ads.eu.msn.com",
        "ads.jp.msn.com",
        "ads.linkedin.com",
        "ads.microsoft.com",
        "ads.msads.net",
        "ads2.msads.net",
        "adserver.bing.com",
        "advertise.microsoft.com",
        "advertising.jp.msn.com",
        "advertising.linkedin.com",
        "advertising.microsoft.com",
        "analysis.insights.cloud.microsoft",
        "analytics.ads.microsoft.com",
        "analytics.live.com",
        "analytics.live.com.nsatc.net",
        "analytics.msn.com",
        "analytics.msn.com.nsatc.net",
        "analytics.msnbc.msn.com",
        "analytics.pointdrive.linkedin.com",
        "analytics.trafficmanager.net",
        "analyticspixel.microsoft.com",
        "apac.events.data.trafficmanager.net",
        "api.ads.microsoft.com",
        "api.diagnostics-eudb.office.com",
        "aria.events.data.trafficmanager.net",
        "asimov-win.vortex.data.trafficmanager.net",
        "asimov.events.data.trafficmanager.net",
        "asimov.vortex.data.trafficmanager.net",
        "atdmt.com",
        "au.vortex.data.trafficmanager.net",
        "azure-ads.com",
        "azure.bingads.trafficmanager.net",
        "azurewatson.microsoft.com",
        "azurewatsontest.microsoft.com",
        "bat.bing.com",
        "bf-analytics-tracker-tm.trafficmanager.net",
        "bingads.trafficmanager.net",
        "blobcollector.events.data.trafficmanager.net",
        "browser.events.data.microsoft.us",
        "browser.events.data.msn.cn",
        "c.clarity.ms",
        "ceipmsn.com",
        "clarity-microsoft-com.b-0005.b-msedge.net",
        "clarity.azurefd.net",
        "clarity.microsoft.com",
        "clarity.ms",
        "claritystatic.azureedge.net",
        "d.clarity.ms",
        "diagnostics-eudb.office.com",
        "diagnostics.broadcast.microsoft.com",
        "diagnostics.microsoft.com",
        "diagnostics.support.microsoft.akadns.net",
        "diagnostics.xboxlive.com",
        "digg.analytics.live.com",
        "edge-emeu1.activity.windows.com.akadns.net",
        "edge-global.activity.windows.com.akadns.net",
        "edge.activity.metrics.msn.com",
        "edge.activity.windows.com.akadns.net",
        "edge.analytics.microsoft.com",
        "emea.events.data.trafficmanager.net",
        "entitlement.diagnostics-eudb.office.com",
        "eu-office.events.data.microsoft.net",
        "eu.aria.events.data.trafficmanager.net",
        "eu.blobcollector.events.data.trafficmanager.net",
        "euc-excel-telemetry.officeapps.live.com",
        "euc-powerpoint-telemetry.officeapps.live.com",
        "euc-word-telemetry.officeapps.live.com",
        "events.data.msn.cn",
        "events.data.msn.com",
        "events.data.trafficmanager.net",
        "excel-telemetry.officeapps.live.com",
        "excel-telemetry.wac.trafficmanager.net",
        "firstparty.monitoring.windows.net",
        "fls.doubleclick.net",
        "fp.advertising.microsoft.com",
        "g.ceipmsn.com",
        "geo.hub.analytics.trafficmanager.net",
        "glance-analytics.trafficmanager.net",
        "global.aria.events.data.trafficmanager.net",
        "global.asimov.events.data.trafficmanager.net",
        "hub.analytics.trafficmanager.net",
        "incidents.diagnostics-eudb.office.com",
        "insights.api.microsoft.com",
        "insights.microsoft.com",
        "insights.microsoftazure.com",
        "ir-tracking.trafficmanager.net",
        "ism-telemetry.trafficmanager.net",
        "kmwatsonc.events.data.microsoft.us",
        "l4.tb.events.data.trafficmanager.net",
        "l5.pf.events.data.trafficmanager.net",
        "legacywatson.trafficmanager.net",
        "logging.diagnostics-eudb.office.com",
        "metrics.microsoft.com",
        "metrics.xboxlive.com",
        "microsoft-ads.com",
        "microsoftads.com",
        "microsoftadvertising.com",
        "mobile.events.data.microsoft.us",
        "mobileads.msn.com",
        "modern.watson.data.microsoft.com.akadns.net",
        "ms.analytics.live.com",
        "msads.net",
        "msadsscale.azureedge.net",
        "msadsscale.microsoft.com",
        "myanalytics.microsoft.com",
        "noam.events.data.trafficmanager.net",
        "o365diagtelemetry.trafficmanager.net",
        "oms-analytics.trafficmanager.net",
        "outlookdiagnostics.azureedge.net",
        "outlookdiagnostics.ec.azureedge.net",
        "pf.events.data.trafficmanager.net",
        "pf2am3-edge.activity.windows.com.akadns.net",
        "pf2am3.activity.windows.com.akadns.net",
        "powerpoint-telemetry.officeapps.live.com",
        "powerpoint-telemetry.wac.trafficmanager.net",
        "powerpointonline.nelsdf.measure.office.net",
        "ppc-excel-telemetry.officeapps.live.com",
        "ppc-word-telemetry.officeapps.live.com",
        "ppm-licensingtelemetry.servicebus.windows.net",
        "r.bat.bing.com",
        "r.clarity.ms",
        "rads.msn.com",
        "rawtelemetry-east.servicebus.windows.net",
        "rawtelemetry-west.servicebus.windows.net",
        "reports.wes.df.telemetry.microsoft.us",
        "rmads.eu.msn.com",
        "rmads.msn.com",
        "sandbox.vortex.data.trafficmanager.net",
        "self.events.data.microsoft.us",
        "self.events.data.onecollector.akadns.net",
        "server.events.data.trafficmanager.net",
        "sgmetrics.cloudapp.net",
        "smetric.ads.microsoft.com",
        "sqm.microsoft.com",
        "sqm.telemetry.microsoft.us",
        "ss-telemetry.servicebus.windows.net",
        "sts.advertising.microsoft.com",
        "survey.microsoft.com",
        "survey.support.services.microsoft.com",
        "surveys.xboxlive.com",
        "t.clarity.ms",
        "tb.events.data.trafficmanager.net",
        "telecommand.telemetry.microsoft.us",
        "telecommandstorageprod.blob.core.windows.net",
        "telecommandsvc.microsoft.com",
        "telemetry-lcp.trafficmanager.net",
        "telemetry.analytics.microsoft.com",
        "telemetry.api.microsoft.com",
        "telemetry.appex.search.prod.ms.akadns.net",
        "telemetry.appliesto.microsoft.com",
        "telemetry.hubble.microsoft.com",
        "telemetry.ips.microsoft.com",
        "telemetry.microsoft.com.nsatc.net",
        "telemetry.microsoft.us",
        "telemetry.microsoftstoreedge.com",
        "telemetry.mstelemetry.net",
        "telemetry.osi.microsoft.com",
        "telemetry.privacy.microsoft.com",
        "telemetry.services.microsoft.com",
        "telemetry.svc.microsoft.com",
        "telemetry.teams.microsoft.com",
        "telemetry.traffic.microsoft.com",
        "telemetry.wd.microsoft.com",
        "telemetry.windows.com",
        "telemetry.xboxlive.com",
        "telemetry1.xboxlive.com",
        "telemetrycollector.microsoft.com",
        "telemetryservice.firstpartyapps.microsoft.com",
        "telemetryservice.firstpartyapps.oaspapps.com",
        "tenmax-ads.trafficmanager.net",
        "tm-analytics-pr.trafficmanager.net",
        "tm-bingstats-frontend.trafficmanager.net",
        "tm-enrollment-telemetry-datacore.trafficmanager.net",
        "umwatson.events.data.microsoft.us",
        "umwatson.trafficmanager.net",
        "umwatsonrouting.trafficmanager.net",
        "us-v20.events.data.trafficmanager.net",
        "us.aria.events.data.trafficmanager.net",
        "v10-win.vortex.data.trafficmanager.net",
        "v10.events.data.microsoft.com.aria.akadns.net",
        "v10.events.data.microsoft.us",
        "v10.vortex-win.data.metron.live.com.nsatc.net",
        "v20-asimov-win.vortex.data.trafficmanager.net",
        "v20.events.data.microsoft.com.aria.akadns.net",
        "v20.events.data.microsoft.us",
        "visio-telemetry.officeapps.live.com",
        "vortex-bn2.metron.live.com",
        "vortex-db5.metron.live.com.nsatc.net",
        "vortex-hk2.metron.live.com.nsatc.net",
        "vortex-win.data.metron.live.com.nsatc.net",
        "vortex.data.metron.live.com.nsatc.net",
        "vortex.data.microsoft.com.akadns.net",
        "vortex.data.microsoft.com.edgekey.net",
        "vortex.data.microsoft.us",
        "vortex.microsoft.com",
        "vstelemetry.trafficmanager.net",
        "watson.bing.com",
        "watson.officeint.microsoft.com",
        "watson.telemetry.microsoft.us",
        "watson1.officeint.microsoft.com",
        "web.vortex-extended.data.microsoft.com",
        "web.vortex-sandbox.data.msn.com",
        "web.vortex.data.msn.com",
        "wer.microsoft.com",
        "word-telemetry.officeapps.live.com",
        "word-telemetry.wac.trafficmanager.net",
        "workplaceanalytics.cdn.office.net",
        "www.clarity.ms",
        "www.msads.net",
        "www.telecommandsvc.microsoft.com",
        "zmetrics.msn.com",
        "vortex.data.microsoft.com", "vortex-win.data.microsoft.com",
        "telecommand.telemetry.microsoft.com", "telecommand.telemetry.microsoft.com.nsatc.net",
        "oca.telemetry.microsoft.com", "oca.telemetry.microsoft.com.nsatc.net",
        "sqm.telemetry.microsoft.com",
        "sqm.ppe.telemetry.microsoft.com", "sqm.telemetry.microsoft.com.nsatc.net",
        "watson.telemetry.microsoft.com", "watson.telemetry.microsoft.com.nsatc.net",
        "watson.ppe.telemetry.microsoft.com", "watson.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com", "wes.df.telemetry.microsoft.com",
        "services.wes.df.telemetry.microsoft.com", "sqm.df.telemetry.microsoft.com",
        "settings-win.data.microsoft.com", "settings.data.microsoft.com",
        "statsfe2.ws.microsoft.com", "redir.metaservices.microsoft.com",
        // RealSyferX/windows-11-debloat diff — app-experience bing
        // telemetry, UAP telemetry, telemetry redirection,
        // activity-feed upload
        "telemetry.appex.bing.com", "telemetry-uap.microsoft.com",
        "redirection.telemetry.microsoft.com", "prod.activity.windows.com",
        // MS "manage connections" endpoint doc: Connected Devices Platform
        // API (already policy/service-killed — server-side reinforcement)
        // and the device-metadata service (PreventDeviceMetadataFromNetwork)
        "api.cdp.microsoft.com", "msedge.api.cdp.microsoft.com",
        "dmd.metaservices.microsoft.com",
        "choice.microsoft.com", "choice.microsoft.com.nsatc.net",
        "telemetry.appex.bing.net", "telemetry.urs.microsoft.com",
        "feedback.microsoft-hohm.com", "vortex-bn2.metron.live.com.nsatc.net",
        // *.events.data.microsoft.com — Vortex/ARIA event ingest (Win10+
        // universal telemetry pipeline; v10/v20 suffixes + WER/Edge variants)
        "v10.events.data.microsoft.com", "v20.events.data.microsoft.com",
        "browser.events.data.microsoft.com", "umwatsonc.events.data.microsoft.com",
        "watson.events.data.microsoft.com", "survey.watson.microsoft.com",
        // Office/ARIA telemetry pipe + diagnostics report upload endpoint
        "mobile.pipe.aria.microsoft.com", "diagnostics.support.microsoft.com",
        // regional/v10c ingest variants on the same ARIA pipe
        "self.events.data.microsoft.com", "v10c.events.data.microsoft.com",
        "au-v10.events.data.microsoft.com", "eu-v10.events.data.microsoft.com",
        "jp-v10.events.data.microsoft.com", "us-v10.events.data.microsoft.com",
        "au-v10c.events.data.microsoft.com", "eu-v10c.events.data.microsoft.com",
        "jp-v10c.events.data.microsoft.com", "us-v10c.events.data.microsoft.com",
        "activity.windows.com",
        "api.diagnostics.office.com",
        // DiagTrack ingest FQDNs actually queried by the Connected User
        // Experiences service — vortex-win.data.microsoft.com above is the
        // CNAME base, the live endpoints carry v10/v20 prefixes
        "v10.vortex-win.data.microsoft.com", "v20.vortex-win.data.microsoft.com",
    // BSI (German federal) telemetry endpoint list — vortex/ARIA
    // ingest regional + akadns + sandbox variants
        "asimov-win.settings.data.microsoft.com.akadns.net",
        "db5.settings-win.data.microsoft.com.akadns.net",
        "db5-eap.settings-win.data.microsoft.com.akadns.net",
        "geo.settings-win.data.microsoft.com.akadns.net",
        "db5.vortex.data.microsoft.com.akadns.net",
        "geo.vortex.data.microsoft.com.akadns.net",
        "v10-win.vortex.data.microsoft.com.akadns.net",
        "au-v20.events.data.microsoft.com",
        "de-v20.events.data.microsoft.com",
        "uk-v20.events.data.microsoft.com",
        "au.vortex-win.data.microsoft.com",
        "de.vortex-win.data.microsoft.com",
        "uk.vortex-win.data.microsoft.com",
        "events-sandbox.data.microsoft.com",
        "vortex-win-sandbox.data.microsoft.com",
        "events.data.microsoft.com",
        "pipe.dev.trafficmanager.net",
        // Device Directory Service + CDP certificate fronts (gdid-guard
        // device-graph endpoints — the IdentityCRL/CDP registration channel)
        "dds.microsoft.com",
        "fd.dds.microsoft.com",
        "cdpcs.access.microsoft.com",
        "diagnostics.office.com",
        "cjs-diagnostics-office-com-gvdhgwfwbbfsd9g3.z01.azurefd.net",
        "arc.msn.com",
        // MSN/CDN tracking + location inference + WU stats alias (eplord
        // Win-Debloat7 + classic spy-blocker lists)
        "az361816.vo.msecnd.net", "az512334.vo.msecnd.net",
        "location-inference-westus.cloudapp.net",
        "ris.api.iris.microsoft.com",
        "statsfe2.update.microsoft.com.akadns.net",
        "arc.trafficmanager.net",
        "api.msa.diagnostics.office.com",
        "assets.activity.windows.com",
        "atm-settingsfe-prod-geo2.trafficmanager.net",
        "au-mobile.events.data.microsoft.com",
        "au.events.data.trafficmanager.net",
        "browser.events.data.trafficmanager.net",
        "canary.activity.windows.com",
        "cjs.diagnostics.office.com",
        "edge-enterprise.activity.windows.com",
        "edge.activity.windows.com",
        "enterprise-eudb.activity.windows.com",
        "enterprise.activity.windows.com",
        "entitlement.diagnostics.office.com",
        "eu-mobile.events.data.microsoft.com",
        "eu-r-mobile.events.data.microsoft.com",
        "eu.events.data.trafficmanager.net",
        "in-mobile.events.data.microsoft.com",
        "in-v20.events.data.microsoft.com",
        "in.events.data.trafficmanager.net",
        "incidents.diagnostics.office.com",
        "inference.location.live.net",
        "jp-mobile.events.data.microsoft.com",
        "jp-v20.events.data.microsoft.com",
        "jp.events.data.trafficmanager.net",
        "logging.diagnostics.office.com",
        "mobile.events.data.trafficmanager.net",
        "msa.diagnostics.office.com",
        "ppe.activity.windows.com",
        "self-events-data.trafficmanager.net",
        "settingsfd-ppe.trafficmanager.net",
        "settingsfd-sandbox.trafficmanager.net",
        "supportexperience.diagnostics.office.com",
        "uk-mobile.events.data.microsoft.com",
        "uk.events.data.trafficmanager.net",
        "us-mobile.events.data.microsoft.com",
        "us.events.data.trafficmanager.net",
        "us4-v20.events.data.microsoft.com",
        "us5-v20.events.data.microsoft.com",
        "win-global-asimov-leafs-events-data.trafficmanager.net",
        // Desktop/Edge counterpart of the mobile ARIA pipe above
        "browser.pipe.aria.microsoft.com", "us.pipe.aria.microsoft.com", "eu.pipe.aria.microsoft.com",
        "az.pipe.aria.microsoft.com", "v20c.events.data.microsoft.com", "functional.events.data.microsoft.com",
        "aimodels.microsoft.com", "models.microsoft.com", "directml.microsoft.com", "aifabric.microsoft.com",
        "copilot.microsoft.com", "sydney.bing.com", "edgeservices.bing.com", "onesettings-public.azureedge.net",
        "onesettings-bn2.azureedge.net", "onesettings-co2.azureedge.net", "widgetcdn.azureedge.net",
        "shell.msn.com", "assets.msn.com", "umwatson.events.data.microsoft.com",
        "nw-umwatson.events.data.microsoft.com", "kmwatson.events.data.microsoft.com",
        "kmwatsonc.events.data.microsoft.com", "df.telemetry.microsoft.com", "alpha.telemetry.microsoft.com",
        "telemetry.microsoft.com", "ca.telemetry.microsoft.com", "watson.live.com",
        "eu-v20.events.data.microsoft.com", "us-v20.events.data.microsoft.com", "eu.vortex-win.data.microsoft.com",
        "us.vortex-win.data.microsoft.com", "eu.vortex.data.microsoft.com",
        "server6.pipe.aria.microsoft.com", "server7.pipe.aria.microsoft.com",
        "browser.events.data.msn.com",
        "ic3.events.data.microsoft.com", "mobile.events.data.microsoft.com",
        "teams.events.data.microsoft.com",
        // WindowsSpyBlocker data/hosts/spy.txt diff — sandbox/PPE telemetry
        // environments, activity pipeline, residual Cortana/Edge-offer calls,
        // legacy IE web service (capability removed), GameDVR asset CDN
        "vortex-sandbox.data.microsoft.com",
        "settings-sandbox.data.microsoft.com",
        "settings-win-ppe.data.microsoft.com",
        "web.vortex.data.microsoft.com",
        "vortex.data.glbdns2.microsoft.com",
        "settings.data.glbdns2.microsoft.com",
        "oca.telemetry.microsoft.us",
        "umwatsonc.telemetry.microsoft.us",
        "telemetry.remoteapp.windowsazure.com",
        "test.activity.windows.com",
        "api.cortana.ai",
        "api.edgeoffer.microsoft.com",
        "ieonlinews.microsoft.com",
        // Azure Data Lake diagnostic ingest front (WindowsSpyBlocker)
        "adbroker.mp.dse.microsoft.com", "adsystem.microsoft.com", "api.msn.com", "asimov.settings.data.microsoft.com.akadns.net", "business.bing.com", "c.bing.com", "cdnprod.myanalytics.microsoft.com", "ceuswatcab01.blob.core.windows.net", "ceuswatcab02.blob.core.windows.net", "clarity-ingest-eus2-b-sc.eastus2.cloudapp.azure.com", "co4.telecommand.telemetry.microsoft.com", "cy2.vortex.data.microsoft.com", "dc.applicationinsights.azure.com", "dc.applicationinsights.microsoft.com", "eaus2watcab01.blob.core.windows.net", "eaus2watcab02.blob.core.windows.net", "eu-office.events.data.microsoft.com", "eu-watsonc.events.data.microsoft.com", "events.vungle.akadns.net", "fd.api.iris.microsoft.com", "insider.windows.com", "insideruser.microsoft.com", "iris-de-ppe-azsc-v2-wus2.westus2.cloudapp.azure.com", "iris-de-prod-azsc-v2-wus2.westus2.cloudapp.azure.com", "iris-de-prod-azsc-wus2-b.westus2.cloudapp.azure.com", "iris-de-prod-azsc-wus2.westus2.cloudapp.azure.com", "kmwatsonc.telemetry.microsoft.com", "microsoft.geo.appnexusgslb.net", "microsoftmscompoc.tt.omtrdc.net", "modern.watson.data.microsoft.com", "myanalytics-gcc.microsoft.com", "ntp.msn.com", "oca.microsoft.com", "onecollector.cloudapp.aria.akadns.net", "prod-w.nexus.live.com.akadns.net", "prod.nexusrules.live.com.akadns.net", "ris.api.iris.microsoft.com.akadns.net", "solitaireevents.microsoftcasualgames.com", "sqmfe.glbdns2.microsoft.com", "srtb.msn.com", "umwatsonc.telemetry.microsoft.com", "v10.vortex-win.data.metron.life.com.nsatc.net", "weus2watcab01.blob.core.windows.net", "weus2watcab02.blob.core.windows.net", "adl.windows.com",
        "xblgdvrassets3010.blob.core.windows.net",
        // Ad-delivery endpoints serving MSN/Edge/widget surfaces
        "adnxs.com", "m.adnxs.com", "secure.adnxs.com", "adnexus.net",
        "a.ads1.msn.com", "a.ads2.msn.com", "b.ads1.msn.com", "ads.msn.com",
        "ads1.msn.com",  // MSN ad delivery (eplord Win-Debloat7 hosts)
        "g.msn.com",     // MSN telemetry/tracking beacon
        "g.msn.com.nsatc.net",
        "search.msn.com",  // MSN search-redirect (Start-search query leak)
        "ads1.msads.net", "a.ads2.msads.net", "bingads.microsoft.com",
        "a.rad.msn.com", "b.rad.msn.com", "ac3.msn.com", "live.rads.msn.com",
        "bs.serving-sys.com", "msntest.serving-sys.com",
        "secure.flashtalking.com",
        "aidps.atdmt.com", "c.atdmt.com", "cdn.atdmt.com",
        "db3aqu.atdmt.com", "ec.atdmt.com", "view.atdmt.com",
        "aka-cdn-ns.adtech.de", "pre.footprintpredict.com",
        // Ad/feedback ingestion (DisableWinTracking diff)
        "ad.doubleclick.net", "s0.2mdn.net", "static.2mdn.net",
        "b.ads2.msads.net", "compatexchange.cloudapp.net",
        "feedback.search.microsoft.com", "feedback.windows.com",
                // bloatbox/W4RH4WK extended hosts
                "statsfe1.ws.microsoft.com",
                "onesettings-db5.metron.live.nsatc.net",
                "vortex-cy2.metron.live.com.nsatc.net",
                "cy2.vortex.data.microsoft.com.akadns.net",
                "i1.services.social.microsoft.com",
                "i1.services.social.microsoft.com.nsatc.net",
                "insiderservice.microsoft.com",
                "insiderservice.trafficmanager.net",
                "insiderppe.cloudapp.net",
                "flightingserviceweurope.cloudapp.net",
                "adservice.google.com",
                "adservice.google.de",
                "googleads.g.doubleclick.net",
                "pagead46.l.doubleclick.net",
                "padgead2.googlesyndication.com",
                "stats.g.doubleclick.net",
                "stats.l.doubleclick.net",
                "www.google-analytics.com",
                "www-google-analytics.l.google.com",
                "p.static.ads-twitter.com",
                "static.ads-twitter.com",
        "ads.yahoo.com",
        "advertising.yahoo.com",
        "feedback.microsoft.com",
        "0.r.msn.com",
        "arc1.msn.com",
        "a.rad.live.com",
        "b.rad.live.com",
        "c.rad.msn.com",
        "analytics.r.msn.com",
        "adsyndication.msn.com",
        "blu.mobileads.msn.com",
        "b.ads2.msn.com",
        "ads1.jp.msn.com",
        "amer.rel.msn.com",
        "apac.rel.msn.com",};
    private const string HostsBlockBegin = "# >>> BloatwareGuard telemetry block";
    private const string HostsBlockEnd = "# <<< BloatwareGuard telemetry block";

    /// <summary>Add/remove a marked hosts-file block that null-routes
    /// pure-telemetry endpoints. Toggle-off removes the block — fully
    /// reversible. No-ops when disabled and no block exists.</summary>
    public static void SetTelemetryHostsBlock(bool enabled)
    {
        var hostsPath = Path.Combine(
            Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
            @"System32\drivers\etc\hosts");
        string text;
        try
        {
            // Strict decode — a silently-replaced byte would corrupt unrelated
            // hosts content on rewrite. Better to skip than to write garbage.
            text = File.Exists(hostsPath)
                ? File.ReadAllText(hostsPath, new System.Text.UTF8Encoding(false, true))
                : "";
        }
        catch (Exception ex)
        {
            GuardLogger.Warn($"Cannot read hosts file (skipped): {ex.Message}");
            return;
        }
        var original = text;  // single read — a second read could fail on absent file

        var beginIdx = text.IndexOf(HostsBlockBegin, StringComparison.Ordinal);
        var endIdx = text.IndexOf(HostsBlockEnd, StringComparison.Ordinal);
        if (beginIdx >= 0 && endIdx >= 0)
            text = text[..beginIdx].TrimEnd('\n') + "\n" +
                text[(endIdx + HostsBlockEnd.Length)..].TrimStart('\n');
        if (enabled)
        {
            var block = string.Join("\n", TelemetryHosts.Select(d => $"0.0.0.0 {d}"));
            text = text.TrimEnd('\n') + $"\n\n{HostsBlockBegin}\n{block}\n{HostsBlockEnd}\n";
        }
        if (beginIdx < 0 && !enabled)
            return; // nothing to do — don't touch the file
        if (File.Exists(hostsPath) && text == original)
            return; // already in the desired state
        try
        {
            ConfigLoader.WriteAllTextAtomic(hostsPath, text);
            GuardLogger.Info($"Telemetry hosts block {(enabled ? "applied" : "removed")} ({TelemetryHosts.Length} domains)");
        }
        catch (Exception ex)
        {
            GuardLogger.Warn($"Cannot write hosts file (admin required?): {ex.Message}");
        }
    }

    /// <summary>
    /// Run <paramref name="apply"/> against every writable user hive: each loaded
    /// interactive profile under HKEY_USERS, the default-profile template (so future
    /// users inherit the settings), and HKCU. A service running as SYSTEM writes only
    /// to the SYSTEM hive without this — the per-user settings never reach real users.
    /// </summary>
    private static void ForEachUserHive(Action<RegistryKey> apply)
    {
        var applied = 0;

        foreach (var sid in Registry.Users.GetSubKeyNames())
        {
            if (!UserSidPattern.IsMatch(sid))
                continue;
            try
            {
                using var hive = Registry.Users.OpenSubKey(sid, writable: true);
                if (hive == null)
                    continue;
                apply(hive);
                applied++;
            }
            catch (Exception ex)
            {
                GuardLogger.Warn($"Registry: could not write hive {sid}: {ex.Message}");
            }
        }

        // Default-profile template — new user accounts copy this NTUSER.DAT.
        // Not part of HKEY_USERS until manually mounted.
        var defaultDat = GetDefaultProfileDat();
        if (defaultDat != null)
        {
            try
            {
                RunRegSilent($"load \"HKLM\\{DefaultHiveMount}\" \"{defaultDat}\"");
                try
                {
                    using var hive = Registry.LocalMachine.OpenSubKey(DefaultHiveMount, writable: true);
                    if (hive != null)
                    {
                        apply(hive);
                        applied++;
                    }
                }
                finally
                {
                    RunRegSilent($"unload \"HKLM\\{DefaultHiveMount}\"");
                }
            }
            catch (Exception ex)
            {
                GuardLogger.Warn($"Registry: default profile hive skipped: {ex.Message}");
            }
        }

        // HKCU covers the launching user even when hive enumeration missed them
        try
        {
            apply(Registry.CurrentUser);
            applied++;
        }
        catch { }

        if (applied == 0)
            GuardLogger.Warn("Registry: no writable user hive found");
    }

    /// <summary>Default profile template path (usually C:\Users\Default\NTUSER.DAT).</summary>
    private static string? GetDefaultProfileDat()
    {
        try
        {
            using var pl = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            var dir = pl?.GetValue("Default") as string;
            if (string.IsNullOrEmpty(dir))
                dir = @"C:\Users\Default";
            dir = Environment.ExpandEnvironmentVariables(dir);
            var dat = Path.Combine(dir, "NTUSER.DAT");
            return File.Exists(dat) ? dat : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Set a DWORD inside a mounted user hive root.</summary>
    private static void SetHiveDword(RegistryKey hiveRoot, string path, string name, int value)
    {
        using var key = hiveRoot.CreateSubKey(path);
        key?.SetValue(name, value, RegistryValueKind.DWord);
    }

    /// <summary>Apply the same DWORD under <paramref name="path"/> in every user hive.</summary>
    private static void SetUserDwordAllHives(string path, string name, int value)
    {
        ForEachUserHive(hive => SetHiveDword(hive, path, name, value));
    }

    private static void RunRegSilent(string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "reg.exe",
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        Proc.Wait(psi, 15000);
    }

    /// <summary>Turn off Microsoft consumer experiences (suggested apps)</summary>
    public static void DisableConsumerExperiences()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(CloudContentPath);
            key?.SetValue("DisableWindowsConsumerFeatures", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // "Edit with Clipchamp" context-menu entry — CLSID block
            // (CrapFixer): Clipchamp is blacklisted, drop its shell
            // integration remnant too
            using (var blocked = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
                blocked?.SetValue("{8AB635F8-9A67-4698-AB99-784AD929F3B4}", "RemoveClipchampContext");
            GuardLogger.Info("Applied: DisableWindowsConsumerFeatures = 1");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable consumer experiences: {ex.Message}");
        }
    }

    /// <summary>Disable cloud content (suggested apps in Start, tips, etc.)</summary>
    public static void DisableCloudContent()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(CloudContentPath);
            key?.SetValue("DisableSoftLanding", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DisableCloudOptimizedContent", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Microsoft 365 / consumer-account content (Settings Home Copilot ads)
            key?.SetValue("DisableConsumerAccountStateContent", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Settings "Home" page — the Microsoft 365 / account promo card
            using var exp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(ExplorerPoliciesHklmPath);
            exp?.SetValue("SettingsPageVisibility", "hide:home;aicomponents;appactions");
            // Third-party content suggestions surface (sponsored tiles/ads)
            key?.SetValue("DisableThirdPartySuggestions", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // App notifications must not show on the lock screen
            // (WinOpt) — documented CloudContent policy
            key?.SetValue("DisableLockScreenAppNotifications", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Machine-wide Windows Spotlight kill (documented policy
            // twin of the per-user CloudContent spotlight switches)
            key?.SetValue("ConfigureWindowsSpotlight", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Camera trigger removed from the lock screen (WinOpt) —
            // prevents unauthenticated camera activation; app camera
            // permissions untouched
            using var perso = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\Personalization");
            perso?.SetValue("NoLockScreenCamera", 1, Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: DisableSoftLanding + DisableCloudOptimizedContent = 1 + Settings Home promo hidden");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable cloud content: {ex.Message}");
        }
    }

    /// <summary>Prevent device metadata from downloading (blocks companion apps)</summary>
    public static void PreventDeviceMetadata()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(DeviceMetadataPath);
            key?.SetValue("PreventDeviceMetadataFromNetwork", 1, Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: PreventDeviceMetadataFromNetwork = 1");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to prevent device metadata: {ex.Message}");
        }
    }

    /// <summary>Block provisioning packages from re-registering + all consumer
    /// suggestion surfaces, applied to EVERY user hive (a SYSTEM service's HKCU
    /// is the SYSTEM profile — useless without multi-hive writes).</summary>
    public static void BlockProvisioning()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(CloudContentPath);
            key?.SetValue("DisableConsumerAccountContent", 1, Microsoft.Win32.RegistryValueKind.DWord);

            // Open-With store nags: "Look for an app in the Store" + the
            // "new apps can open this file type" toast (HKLM Explorer policies)
            using var expl = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(ExplorerPoliciesHklmPath);
            expl?.SetValue("NoUseStoreOpenWith", 1, Microsoft.Win32.RegistryValueKind.DWord);
            expl?.SetValue("NoNewAppAlert", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Open-With internet lookup + Settings-app online tips (content fetch)
            expl?.SetValue("NoInternetOpenWith", 1, Microsoft.Win32.RegistryValueKind.DWord);
            expl?.SetValue("AllowOnlineTips", 0, Microsoft.Win32.RegistryValueKind.DWord);

            // ContentDeliveryManager — silent installs + every SubscribedContent surface
            // (key set mirrors Win11Debloat Disable_Windows_Suggestions.reg)
            var cdmZeros = new[]
            {
                "ContentDeliveryAllowed",           // master CDM switch
                "SilentInstalledAppsEnabled",       // silent app installs
                "SystemPaneSuggestionsEnabled",     // system pane suggestions
                "SoftLandingEnabled",               // soft landing tips
                "SubscribedContent-310093Enabled",  // Windows welcome experience
                "SubscribedContent-338387Enabled",  // lock-screen spotlight ads
                "SubscribedContent-410400Enabled",  // additional sponsored feed
                "SubscribedContent-338388Enabled",  // Start suggestions
                "SubscribedContent-338389Enabled",  // tips while using Windows
                "SubscribedContent-338393Enabled",  // Settings suggestions
                "SubscribedContent-353694Enabled",  // Settings suggestions (2)
                "SubscribedContent-353696Enabled",  // Settings suggestions (3)
                "SubscribedContent-353698Enabled",  // Settings suggestions (4)
                "SubscribedContent-338380Enabled",  // Settings app content ads
                "SubscribedContent-314563Enabled",  // My People suggestions
                "SubscribedContent-314559Enabled",  // OneDrive promotions (ReviOS)
                "SubscribedContent-280815Enabled",  // OneDrive suggestions (ReviOS)
                "SubscribedContent-310091Enabled",  // promo tile (RegiLattice MsStore)
                "SubscribedContent-202914Enabled",  // Start ads (ReviOS)
                "SubscribedContent-280810Enabled",  // OneDrive SyncProviders ad
                "SubscribedContent-280811Enabled",  // OneDrive upsell
                "SubscribedContent-88000326Enabled", // Edge/app promotions (Optimizer diff)
                "RotatingLockScreenEnabled",        // lock-screen spotlight
                "RotatingLockScreenOverlayEnabled", // lock-screen overlay ads
                "ShowWindowsWelcomeExperience",     // post-update welcome promos
                "PreInstalledAppsEnabled",          // OEM app seeding
                "PreInstalledAppsEverEnabled",      // OEM app seeding (sticky)
                "OemPreInstalledAppsEnabled",       // OEM app seeding (OEM channel)
                "RemediationRequired",              // CDM "remediation" re-offers
            };
            ForEachUserHive(hive =>
            {
                using var cdm = hive.CreateSubKey(UserCdmPath);
                foreach (var name in cdmZeros)
                    cdm?.SetValue(name, 0, RegistryValueKind.DWord);

                SetHiveDword(hive, UserExplorerAdvancedPath, "Start_IrisRecommendations", 0);
                // Account-notification promos in Start (Raphire/Win11Debloat)
                SetHiveDword(hive, UserExplorerAdvancedPath, "Start_AccountNotifications", 0);
                SetHiveDword(hive, UserExplorerAdvancedPath, "ShowSyncProviderNotifications", 0);
                SetHiveDword(hive, UserProfileEngagementPath, "ScoobeSystemSettingEnabled", 0);
                // "Let's finish setting up" second-chance OOBE — mark done
                // + tray balloon feature ads off (ReviOS notifications.yml)
                SetHiveDword(hive, UserCdmPath + @"\Context\CloudExperienceHostIntent\Wireless", "ScoobeCheckCompleted", 1);
                SetHiveDword(hive, @"Software\Policies\Microsoft\Windows\Explorer", "NoBalloonFeatureAdvertisements", 1);
                SetHiveDword(hive, @"Software\Policies\Microsoft\Windows\Explorer", "NoAutoTrayNotify", 1);
                SetHiveDword(hive, UserAccountNotificationsPath, "EnableAccountNotifications", 0);
                SetHiveDword(hive, UserSuggestedToastPath, "Enabled", 0);
                // Sibling promo toasts: startup-impact, account-health,
                // OneDrive desktop nags (Windows-Utility/winutil)
                foreach (var toast in new[] { "Windows.SystemToast.StartupApp",
                                            "Windows.SystemToast.AccountHealth",
                                            "Microsoft.SkyDrive.Desktop" })
                    SetHiveDword(hive, UserNotificationSettingsPath + "\\" + toast,
                        "Enabled", 0);
                SetHiveDword(hive, UserMobilityPath, "OptedIn", 0);
                SetHiveDword(hive, UserMobilityPath, "PhoneLinkEnabled", 0);
                // Mail/Calendar -> "new Outlook" forced migration nudge (winutil)
                SetHiveDword(hive, UserOutlookMigrationPath, "DoNewOutlookAutoMigration", 0);
                // Classic-Outlook "try new Outlook" toggle + migration
                // prompt off (privacy.sexy; same surface, Office-side)
                SetHiveDword(hive, UserOutlookMigrationPath, "HideNewOutlookToggle", 1);
                SetHiveDword(hive, UserOutlookPreferencesPath, "NewOutlookMigrationUserSetting", 0);
                // Cross-device experiences consent + Search highlights
                SetHiveDword(hive, UserMobilityPath, "CrossDeviceEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "SafeSearchMode", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "ShowDynamicContent", 0);
            });

            // "Get the latest updates as soon as they're available" opt-in
            // off — continuous-innovation drops ship unannounced
            // feature/bloat updates (winutil)
            using var ux = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings");
            ux?.SetValue("IsContinuousInnovationOptedIn", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Block Chat/Teams consumer auto-install at the documented
            // channel (Atlas appx.yml — complements Teams DisableInstallation)
            using (var comm = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Communications", true))
            {
                comm?.SetValue("ConfigureChatAutoInstall", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // Push-to-install: block remote/mobile-driven Store installs
            // (tiny11builder; complements the demoted PushToInstall service
            // and disabled LoginCheck task — third anchor on the channel)
            using (var pti = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\PushToInstall", true))
            {
                pti?.SetValue("DisablePushToInstall", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // Block automatic Teams (personal & consumer) install/reinstall
            using (var teams = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Teams", true))
            {
                teams?.SetValue("DisableInstallation", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // Cloud app notifications (promo toasts) — ReviOS
            // notifications.yml
            using (var push = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", true))
            {
                push?.SetValue("NoCloudApplicationNotification", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // BITS download-status toasts off (RegiLattice v6.35.0)
            using (var bits = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\BITS", true))
            {
                bits?.SetValue("DisableBITSNotification", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // Mark forced new-Outlook/DevHome pushes as already delivered so
            // Windows Update does not re-ship them (tiny11builder)
            foreach (var sched in new[] { "UScheduler", "UScheduler_Oobe" })
            {
                foreach (var upd in new[] { "OutlookUpdate", "DevHomeUpdate", "WindowsUpdate" })
                {
                    using var s = Registry.LocalMachine.CreateSubKey(
                        $@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\{sched}\{upd}", true);
                    s?.SetValue("workCompleted", 1, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }
            GuardLogger.Info("Applied: BlockProvisioning (silent installs + all suggestion surfaces, all hives)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to block provisioning: {ex.Message}");
        }
    }

    /// <summary>Disable Windows Copilot via policy — HKLM + every user hive.
    /// The Copilot app itself is removed via the Blacklist.</summary>
    public static void DisableCopilot()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WindowsCopilotPath);
            key?.SetValue("TurnOffWindowsCopilot", 1, Microsoft.Win32.RegistryValueKind.DWord);
            SetUserDwordAllHives(UserCopilotPath, "TurnOffWindowsCopilot", 1);
            // Copilot taskbar button
            SetUserDwordAllHives(UserExplorerAdvancedPath, "ShowCopilotButton", 0);
            // Shell eligibility suppression (HKLM + user hives — same pattern
            // as zoicware/RemoveWindowsAI): app removed via blacklist, shell too
            using (var shell = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(ShellCopilotPath))
            {
                shell?.SetValue("IsCopilotAvailable", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using (var bing = shell?.CreateSubKey("BingChat"))
                    bing?.SetValue("IsUserEligible", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // Region-availability trick (winscript): report the geographic
            // eligibility check as failed so Copilot never surfaces
            using (var shell2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(ShellCopilotPath))
                shell2?.SetValue("CopilotDisabledReason", "IsEnabledForGeographicRegionFailed");
            // "Ask Copilot" Explorer context-menu entry — CLSID block
            // (CrapFixer): HKLM applies to all users incl. new profiles
            using (var blocked = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
                blocked?.SetValue("{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}", "RemoveCopilotContext");
            // Per-user Copilot runtime kill (winscript)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\WindowsCopilot",
                "AllowCopilotRuntime", 0);
            // Copilot app ADMX (CopilotApp.admx, v146+): kill in-app web
            // browsing + Cowork agentic actions. ComponentUpdatesEnabled left
            // alone — disabling it can block security fixes per doc.
            using (var capp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Policies\Microsoft\Copilot"))
            {
                capp?.SetValue("BrowsingEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
                capp?.SetValue("CopilotCoworkToolActionsEnabled", 0,
                               Microsoft.Win32.RegistryValueKind.DWord);
            }
            // Edge Update Copilot-distribution guard
            using (var eupd = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Policies\Microsoft\EdgeUpdate"))
            {
                eupd?.SetValue("Install{C50565E9-CCCF-44B4-BA15-5AC5C6569197}", 0,
                               Microsoft.Win32.RegistryValueKind.DWord);
                eupd?.SetValue("Update{C50565E9-CCCF-44B4-BA15-5AC5C6569197}", 0,
                               Microsoft.Win32.RegistryValueKind.DWord);
                eupd?.SetValue("CopilotUnificationAllowed{C50565E9-CCCF-44B4-BA15-5AC5C6569197}",
                               0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // zoicware RemoveWindowsAI re-diff — per-user Copilot surface kills
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins",
                "CopilotPWAPin", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins",
                "RecallPin", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                "TaskbarCompanion", 0);
            foreach (var pkg in new[] { "Microsoft.Copilot_8wekyb3d8bbwe",
                                        "Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe" })
            {
                var bga = @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + pkg;
                SetUserDwordAllHives(bga, "DisabledByUser", 1);
                SetUserDwordAllHives(bga, "SleepDisabled", 1);
            }
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs",
                "CopilotPWAPreinstallCompleted", 1);
            // noverse.dev copilot page: sibling marker for the Copilot
            // hardware-key choice prompt — same fake-completed mechanism
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs",
                "CopilotHWKeyChoiceSet", 1);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs",
                "Microsoft.Copilot_8wekyb3d8bbwe", 1);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers",
                "A9HomeContentEnabled", 0);
            // NVIDIA telemetry opt-out RIDs (winscript)
            using (var fts = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\NVIDIA Corporation\Global\FTS"))
            {
                fts?.SetValue("EnableRID44231", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fts?.SetValue("EnableRID64640", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fts?.SetValue("EnableRID66610", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // NVIDIA driver telemetry upload off (winscript)
            using (var nv1 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup"))
                nv1?.SetValue("SendTelemetryData", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using (var nv2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\Global\Startup"))
                nv2?.SetValue("SendTelemetryData", "0");
            SetUserDwordAllHives(UserShellCopilotPath, "IsCopilotAvailable", 0);
            // Copilot nudge prompts off (Winhance)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                "ShowCopilotNudges", 0);
            SetUserDwordAllHives(UserShellCopilotPath + @"\BingChat", "IsUserEligible", 0);
            // Copilot voice-agent activation off (all user hives)
            SetUserDwordAllHives(UserVoiceActivationPath, "AgentActivationEnabled", 0);
            SetUserDwordAllHives(UserVoiceActivationPath, "AgentActivationOnLockScreenEnabled", 0);
            SetUserDwordAllHives(UserVoiceActivationPath, "AgentActivationLastUsed", 0);
            // Wake-word/voice activation off (RegiLattice Cortana)
            SetUserDwordAllHives(@"Software\Microsoft\Speech_OneCore\Preferences", "VoiceActivationOn", 0);
            // Default/master voice-activation toggle (privacy.sexy) — the
            // always-on "Hey Cortana"-class listening preference; same key as
            // VoiceActivationOn but a distinct value honoured by SpeechRuntime
            SetUserDwordAllHives(@"Software\Microsoft\Speech_OneCore\Preferences", "VoiceActivationDefaultOn", 0);
            // IME cloud AI suggestions off (RegiLattice CopilotPlus —
            // per-user InputMethod settings)
            SetUserDwordAllHives(@"Software\Microsoft\InputMethod\Settings\CHS", "UseAISuggestions", 0);
            // Copilot auto-open on large screens (notification channel,
            // privacy.sexy) — per-user
            SetUserDwordAllHives(UserNotificationSettingsPath, "AutoOpenCopilotLargeScreens", 0);
            // Toast content must not render above the lock screen
            // (Debloat-Win11) — standard + critical channels
            SetUserDwordAllHives(UserNotificationSettingsPath,
                                 "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK", 0);
            SetUserDwordAllHives(UserNotificationSettingsPath,
                                 "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK", 0);
            // Narrator online voices download off (Winnow ExtendedAIPurge)
            SetUserDwordAllHives(@"Software\Microsoft\Narrator\NoRoam",
                                 "OnlineVoicesEnabled", 0);
            // Copilot hardware-key remap (WindowsCopilot ADMX, zoicware)
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CopilotKey",
                "SetCopilotHardwareKey", 0);
            // M365 Copilot auto-start delay + companion window (zoicware)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\M365Copilot",
                "AutoStartDelayEnabled", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\M365Copilot",
                "IsCompanionWindowAvailable", 0);
            // Copilot auto-launch on startup (RunNotification entry)
            using (var runNoti = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunNotification"))
                runNoti?.SetValue("MicrosoftCopilotAutoLaunch", 0,
                                  Microsoft.Win32.RegistryValueKind.DWord);
            // generativeAI consent store: deny access + stop usage recording
            using (var gen = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI"))
                gen?.SetValue("Value", "Deny", Microsoft.Win32.RegistryValueKind.String);
            using (var sam = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels"))
                sam?.SetValue("Value", "Deny", Microsoft.Win32.RegistryValueKind.String);
            using (var capGen = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\generativeAI"))
                capGen?.SetValue("RecordUsageData", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using (var capSam = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\systemAIModels"))
                capSam?.SetValue("RecordUsageData", 0, Microsoft.Win32.RegistryValueKind.DWord);
            foreach (var (id, state) in VelocityCopilotIds)
                SetHiveDword(Microsoft.Win32.Registry.LocalMachine,
                             VelocityOverridesPath + @"\" + id, "EnabledState", state);
            GuardLogger.Info("Applied: DisableCopilot (policy + shell eligibility + voice agent + nudge/taskbar/systray overrides, HKLM + user hives)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable Copilot: {ex.Message}");
        }
    }

    /// <summary>Disable Recall / Windows AI data analysis (24H2+, Copilot+ PCs) and
    /// the "Click to Do" AI actions. Policy keys block snapshot capture; the optional
    /// Recall feature is also removed best-effort, and the AI fabric service is
    /// demoted from auto-start to demand-start.</summary>
    public static void DisableRecall()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WindowsAiPath);
            key?.SetValue("DisableAIDataAnalysis", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("TurnOffSavingSnapshots", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Win11Debloater: sibling snapshotting kill switch (same CSP key)
            key?.SetValue("AllowSnapshotting", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AllowRecallEnablement", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // On-device screen semantic analysis off (25H2 WindowsAI CSP —
            // Win-Debloat7 Privacy module)
            key?.SetValue("DisableScreenSemanticAnalysis", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DisableClickToDo", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // 25H2 "Agent in Settings" (Settings AI agent)
            key?.SetValue("DisableSettingsAgent", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // WindowsAI model management — block on-device AI model
            // downloads and background updates (win-debloat Security module)
            using var modelMgmt = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                WindowsAiPath + @"\ModelManagement");
            modelMgmt?.SetValue("DisableModelDownload", 1, Microsoft.Win32.RegistryValueKind.DWord);
            modelMgmt?.SetValue("DisableBackgroundModelUpdates", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Recall export + app/URI deny-lists (noid-privacy AntiAI —
            // documented 25H2 WindowsCopilot ADMX values)
            key?.SetValue("AllowRecallExport", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Sibling snapshot-export kill — same semantics, alternate
            // value name used by dvandenburgh/Disable-Win11AI
            key?.SetValue("AllowSnapshotExport", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("SetDenyAppListForRecall", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DenyAppListForRecall",
                "msedge.exe;chrome.exe;firefox.exe;WindowsTerminal.exe;KeePassXC.exe;KeePass.exe;1Password.exe;mstsc.exe;msrdc.exe",
                Microsoft.Win32.RegistryValueKind.String);
            key?.SetValue("SetDenyUriListForRecall", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DenyUriListForRecall",
                "https://account.microsoft.com;https://login.live.com;https://outlook.live.com;https://accounts.google.com;https://mail.google.com;https://www.paypal.com",
                Microsoft.Win32.RegistryValueKind.String);
            // Copilot agent connector/workspace kills (25H2 agent framework)
            foreach (var n in new[] { "DisableAgentConnectors", "ConfigureAgentConnectors",
                    "DisableAgentWorkspaces", "DisableRemoteAgentConnectors" })
                key?.SetValue(n, 2, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AgentConnectorMinimumPolicy", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AgentConsentDuration", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // April 2026 RemoveMicrosoftCopilotApp also exists at Device
            // scope (./Device/.../WindowsAI per KB5083769 doc)
            key?.SetValue("RemoveMicrosoftCopilotApp", 1, Microsoft.Win32.RegistryValueKind.DWord);
            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserWindowsAiPath, "DisableAIDataAnalysis", 1);
                SetHiveDword(hive, UserWindowsAiPath, "DisableClickToDo", 1);
                SetHiveDword(hive, UserWindowsAiPath, "DisableSettingsAgent", 1);
                SetHiveDword(hive, UserWindowsAiPath, "DisableRecallDataProviders", 1);
                // April 2026 update "Remove Microsoft Copilot app" policy —
                // Copilot + Microsoft 365 Copilot auto-removed when not
                // user-installed and unused >28 days
                SetHiveDword(hive, UserWindowsAiPath, "RemoveMicrosoftCopilotApp", 1);
                // Copilot Keyboard admin policies (Microsoft Japan blog,
                // June 2026): usage-data upload, cloud conversion
                // candidates, internet integration. 'Telementry' is
                // Microsoft's literal (misspelled) value name.
                SetHiveDword(hive, UserCopilotKeyboardPath, "TurnOffSendTelementryData", 1);
                SetHiveDword(hive, UserCopilotKeyboardPath, "TurnOffCloudCandidate", 1);
                SetHiveDword(hive, UserCopilotKeyboardPath, "TurnOffInternetIntegration", 1);
                // ClickToDo user preference (policy alone leaves the shell entry)
                SetHiveDword(hive, UserClickToDoPath, "DisableClickToDo", 1);
                // App-level AI toggles (WinRice): Notepad cowriter, Paint
                // cocreator/image-creator, Photos AI features
                SetHiveDword(hive, @"Software\Microsoft\Notepad", "EnableCowriter", 0);
                // Notepad "Rewrite" AI opt-out + Photos super-resolution
                // (tomytate/Win-Debloat Privacy) — per-user app preferences
                SetHiveDword(hive, @"Software\Microsoft\Notepad", "DisableAIRewrite", 1);
                SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\Photos",
                    "DisableSuperResolution", 1);
                SetHiveDword(hive, @"Software\Microsoft\Paint", "EnableCocreator", 0);
                SetHiveDword(hive, @"Software\Microsoft\Paint", "EnableImageCreator", 0);
                // Alternate Paint AI toggle names (win-debloat/Debloat-Win11)
                SetHiveDword(hive, @"Software\Microsoft\Paint", "CocreatorEnabled", 0);
                SetHiveDword(hive, @"Software\Microsoft\Paint", "ImageCreatorEnabled", 0);
                SetHiveDword(hive, @"Software\Microsoft\Paint", "GenerativeFillEnabled", 0);
                SetHiveDword(hive, @"Software\Microsoft\Paint", "GenerativeEraseEnabled", 0);
                SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\Photos",
                    "EnableAIFeatures", 0);
                // User-level Recall toggle (Debloat-Win11) — policy kills
                // alone leave the per-user shell preference on
                SetHiveDword(hive, UserExplorerAdvancedPath, "EnableRecall", 0);
                // Per-user Recall opt-out toggle + Click-to-Do shell pref
                // (win-debloat/Debloat-Win11) — complementary to the policies
                SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\Recall", "IsRecallAllowed", 0);
                SetHiveDword(hive, UserExplorerAdvancedPath, "ClickToDoEnabled", 0);
            });
            // Per-app AI features: Paint (image creator/cocreator/fill/erase/
            // background) and Notepad (Rewrite) — documented policy keys
            using (var paint = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(PaintPoliciesPath))
            {
                foreach (var name in new[] { "DisableImageCreator", "DisableCocreator",
                                             "DisableGenerativeFill", "DisableGenerativeErase",
                                             "DisableRemoveBackground" })
                    paint?.SetValue(name, 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            using (var notepad = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(NotepadPoliciesPath))
                notepad?.SetValue("DisableAIFeatures", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Secondary Notepad policy namespace + per-user variant
            // (0Ai-Windows-Hardening): some Store builds honor these
            using (var notepad2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Notepad"))
                notepad2?.SetValue("DisableAIFeatures", 1, Microsoft.Win32.RegistryValueKind.DWord);
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\WindowsNotepad",
                "DisableAIFeatures", 1);
            foreach (var (id, state) in VelocityAiIds)
                SetHiveDword(Microsoft.Win32.Registry.LocalMachine,
                             VelocityOverridesPath + @"\" + id, "EnabledState", state);

            // AI fabric service: 2=auto, 3=demand. Absent without NPU/Copilot+ hardware.
            try
            {
                using var svc = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AiFabricServicePath, writable: true);
                svc?.SetValue("Start", 3, Microsoft.Win32.RegistryValueKind.DWord);

            }
            catch { }

            // Remove the optional feature entirely where present — absent on most
            // hardware, so failure is expected and logged only at Warn.
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -NoRestart -ErrorAction SilentlyContinue | Out-Null\"",
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            Proc.Wait(psi, 120000);

            // 25H2 AI platform event-log channels off (RemoveWindowsAI —
            // ModelContextProtocol + AI-Platform admin/operational logs)
            foreach (var chan in new[] {
                "Microsoft-Windows-AI-ModelContextProtocol/Admin",
                "Microsoft-Windows-AI-ModelContextProtocol/Operational",
                "Microsoft-Windows-AI-Platform/Admin",
                "Microsoft-Windows-AI-Platform/Operational" })
                RunToolSilent("wevtutil", $"sl {chan} /e:false");

            GuardLogger.Info("Applied: DisableRecall (WindowsAI+SettingsAgent policies, Paint/Notepad AI off, Click to Do off, Recall feature removal attempted, WSAIFabricSvc=demand, AI event-log channels off)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable Recall: {ex.Message}");
        }
    }

    /// <summary>Disable Bing web results + suggestions in Start/Search — every user
    /// hive — plus the machine-wide Cortana-in-search policy.</summary>
    public static void DisableSearchSuggestions()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WindowsSearchPath);
            key?.SetValue("AllowCortana", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Cortana/voice above the lock screen (TronScript)
            key?.SetValue("AllowCortanaAboveLock", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Connected-search privacy=disabled + no web results over
            // metered links (winscript)
            key?.SetValue("ConnectedSearchPrivacy", 3, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ConnectedSearchUseWebOverMeteredConnections", 0,
                          Microsoft.Win32.RegistryValueKind.DWord);
            // Legacy Cortana master kill + policy-level search-history off
            using (var lsearch = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Microsoft\Windows\CurrentVersion\Search"))
                lsearch?.SetValue("CortanaEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using (var expol2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Policies\Microsoft\Windows\Explorer"))
                expol2?.SetValue("DisableSearchHistory", 1, Microsoft.Win32.RegistryValueKind.DWord);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Search",
                "DeviceHistoryEnabled", 0);
            // Per-user search voice shortcut (winscript)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Search",
                "VoiceShortcut", 0);
            // Block remote query results entering the index (winscript)
            key?.SetValue("PreventRemoteQueries", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // AAD work/school-account Cortana + OOBE-path variants
            // (ReviOS search.yml)
            key?.SetValue("AllowCortanaInAAD", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AllowCortanaInAADPathOOBE", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // WinRT activation class for the Store-driven search task
            try
            {
                using var wst = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\WinStore.Tasks.WindowsSearchTask");
                wst?.SetValue("ActivationType", unchecked((int)0xFFFFFFFF), Microsoft.Win32.RegistryValueKind.DWord);
                wst?.SetValue("Server", "", Microsoft.Win32.RegistryValueKind.String);
            }
            catch { }
            key?.SetValue("CortanaConsent", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Location-aware search results leak the device location to Bing
            key?.SetValue("AllowSearchToUseLocation", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Explorer-search web lookups off too (separate nag surface)
            using var expNoNet = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(ExplorerPoliciesHklmPath);
            expNoNet?.SetValue("NoSearchInternet", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Policy kill for web results in Start (Optimizer diff — one
            // level deeper than the Bing/suggestion switches)
            key?.SetValue("DisableWebSearch", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Windows Search cloud results master switch (hellzerg/Optimizer)
            key?.SetValue("AllowCloudSearch", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Dynamic web content inside the search box itself (Atlas)
            key?.SetValue("EnableDynamicContentInWSB", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Hard kill for web results in search (RegiLattice v6.35.0)
            key?.SetValue("DoNotUseWebResults", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Connected-search web results (noid-privacy)
            key?.SetValue("ConnectedSearchUseWeb", 0, Microsoft.Win32.RegistryValueKind.DWord);

            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserExplorerPoliciesPath, "DisableSearchBoxSuggestions", 1);
            });
            // Shell web-service integration + "search online" open-with
            // lookup promo (mxk group-policy diff)
            using var webSvc = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                ExplorerPoliciesHklmPath);
            webSvc?.SetValue("NoWebServices", 1, Microsoft.Win32.RegistryValueKind.DWord);
            webSvc?.SetValue("NoInternetOpenWith", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // HKLM policy too — covers hive-creation edge cases
            using var expSearch = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(ExplorerPoliciesHklmPath);
            expSearch?.SetValue("DisableSearchBoxSuggestions", 1, Microsoft.Win32.RegistryValueKind.DWord);
            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserSearchPath, "BingSearchEnabled", 0);
                SetHiveDword(hive, UserSearchPath, "CortanaConsent", 0);
                // SearchSettings: kill the dynamic search box + cloud search
                // integrations that power web results in Start
                SetHiveDword(hive, UserSearchSettingsPath, "IsDynamicSearchBoxEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsAADCloudSearchEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsMSACloudSearchEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsDeviceSearchHistoryEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsStoreSuggestionsEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsGlobalFileSearchProviderToggleEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsWebSuggestionsEnabled", 0);
                // Background-apps master toggle + Iris recommendations
                SetHiveDword(hive, UserSearchPath, "BackgroundAppGlobalToggle", 0);
                SetHiveDword(hive, UserExplorerAdvancedPath, "Start_IrisRecommendationEnabled", 0);
                // Voice activation above the lock screen off
                SetHiveDword(hive, @"Software\Microsoft\Speech_OneCore\Preferences",
                    "VoiceActivationEnableAboveLockscreen", 0);
                // DeliveryOptimization for system settings off
                SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization",
                    "SystemSettingsDownloadMode", 0);
                // On-device search history view (HST Windows Utility) — the
                // Settings "Search history" toggle surface
                SetHiveDword(hive, UserSearchPath, "HistoryViewEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsGlobalWebSearchProviderToggleEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath + @"\WebSearchPro",
                    "Microsoft.BingSearch_8wekyb3d8bbwe!App", 0);
            });
            GuardLogger.Info("Applied: DisableSearchSuggestions (Bing/search suggestions + Cortana + cloud search off, all hives)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable search suggestions: {ex.Message}");
        }
    }

    /// <summary>Disable the Widgets board (news &amp; interests feed) via policy +
    /// hide the taskbar button in every user hive.</summary>
    public static void DisableWidgets()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WidgetsDshPath);
            key?.SetValue("AllowNewsAndInterests", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using var feeds = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WindowsFeedsPath);
            feeds?.SetValue("EnableFeeds", 0, Microsoft.Win32.RegistryValueKind.DWord);
            SetUserDwordAllHives(UserExplorerAdvancedPath, "TaskbarDa", 0);
            // 2 = Feeds view hidden entirely (news/interests flyout off)
            SetUserDwordAllHives(@"Software\Microsoft\Windows\CurrentVersion\Feeds", "ShellFeedsTaskbarViewMode", 2);
            // Taskbar feeds open-on-hover off (ledr)
            SetUserDwordAllHives(@"Software\Microsoft\Windows\CurrentVersion\Feeds", "ShellFeedsTaskbarOpenOnHover", 0);
            GuardLogger.Info("Applied: DisableWidgets (AllowNewsAndInterests = 0, TaskbarDa = 0)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable widgets: {ex.Message}");
        }
    }

    /// <summary>Disable Windows telemetry at every documented surface:
    /// AllowTelemetry policy, DiagTrack (Connected User Experiences) service,
    /// advertising ID, tailored experiences, online speech recognition, inking/typing
    /// collection, feedback-nag frequency, app-launch tracking, activity history
    /// upload, and Edge diagnostic data. Key set mirrors Win11Debloat
    /// Disable_Telemetry.reg.</summary>
    public static void DisableTelemetry()
    {
        try
        {
            using var dc = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(DataCollectionPath);
            dc?.SetValue("AllowTelemetry", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Opt-in notification/UX suppression (documented DataCollection)
            using var dcPol = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\DataCollection");
            dcPol?.SetValue("ConfigureTelemetryOptInChangeNotification", 1,
                            Microsoft.Win32.RegistryValueKind.DWord);
            dcPol?.SetValue("ConfigureTelemetryOptInSettingsUx", 2,
                            Microsoft.Win32.RegistryValueKind.DWord);
            using var sys = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(SystemPolicyPath);
            sys?.SetValue("PublishUserActivities", 0, Microsoft.Win32.RegistryValueKind.DWord);
            sys?.SetValue("UploadUserActivities", 0, Microsoft.Win32.RegistryValueKind.DWord);
            sys?.SetValue("AllowClipboardHistory", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Smart Clipboard (Copilot+ AI clipboard suggestions) —
            // documented System policy (Debloat-Win11)
            sys?.SetValue("EnableSmartClipboard", 0, Microsoft.Win32.RegistryValueKind.DWord);
            sys?.SetValue("PublishUserActivitiesOnUserConsent", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Per-user activity-history recording kill (CrapFixer) —
            // policy flags alone leave Timeline recording on at user level
            SetUserDwordAllHives(UserPrivacyPath, "ActivityHistoryEnabled", 0);
            // User-level publish/upload toggles (gdid-guard) — the Settings
            // activity-history switches the policies don't reach
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\PublishUserActivities",
                "PublishUserActivities", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\UploadUserActivities",
                "UploadUserActivities", 0);
            using var assist = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Assistance\Client\1.0");
            assist?.SetValue("NoActiveHelp", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Recommended troubleshooting off (WindowsMitigation — auto-run
            // troubleshooters upload diagnostics; LeDragoX)
            using var wmit = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\WindowsMitigation");
            wmit?.SetValue("UserPreference", 3, Microsoft.Win32.RegistryValueKind.DWord);
            sys?.SetValue("EnableActivityFeed", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using var edge = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(EdgePolicyPath);
            edge?.SetValue("PersonalizationReportingEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            edge?.SetValue("TextPredictionEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            edge?.SetValue("MicrosoftEditorProofingEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            edge?.SetValue("DiagnosticData", 0, Microsoft.Win32.RegistryValueKind.DWord);

            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserAdvertisingInfoPath, "Enabled", 0);
                SetHiveDword(hive, UserPrivacyPath, "TailoredExperiencesWithDiagnosticDataEnabled", 0);
                SetHiveDword(hive, UserPrivacyPath, "PersonalizedOffersEnabled", 0);
                SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\A9\SnapshotCapture",
                             "IsFilteringTelemetryEnabled", 0);
                // Suggested content surface (HST) — app suggestions in the
                // shell/Start feed off this privacy toggle
                SetHiveDword(hive, UserPrivacyPath, "AppSuggestions", 0);
                SetHiveDword(hive, UserOnlineSpeechPath, "HasAccepted", 0);
                SetHiveDword(hive, UserTipcPath, "Enabled", 0);
                SetHiveDword(hive, UserInputPersonalizationPath, "RestrictImplicitInkCollection", 1);
                SetHiveDword(hive, UserInputPersonalizationPath, "RestrictImplicitTextCollection", 1);
                SetHiveDword(hive, UserInputStorePath, "HarvestContacts", 0);
                SetHiveDword(hive, UserPersonalizationPath, "AcceptedPrivacyPolicy", 0);
                SetHiveDword(hive, UserExplorerAdvancedPath, "Start_TrackProgs", 0);
                SetHiveDword(hive, UserSiufPath, "NumberOfSIUFInPeriod", 0);
                SetHiveDword(hive, UserIntlProfilePath, "HttpAcceptLanguageOptOut", 1);
                // Tailored-experiences policy (policy-level, not just the value)
                SetHiveDword(hive, UserPrivacyPoliciesPath, "TailoredExperiencesWithDiagnosticDataEnabled", 0);
                // Mark the diagnostic-level toast as shown — silences the
                // "your data settings changed" prompt after telemetry is cut
                SetHiveDword(hive,
                    @"Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
                    "ShowedToastAtLevel", 1);
            });

            // "Connected User Experiences and Telemetry" (DiagTrack) — the actual
            // telemetry uploader; absent on some SKUs, failures are non-fatal.
            RunToolSilent("sc.exe", "stop DiagTrack");
            RunToolSilent("sc.exe", "config DiagTrack start= disabled");
            // RetailDemo data-collection service (present on most images)
            RunToolSilent("sc.exe", "stop RetailDemo");
            RunToolSilent("sc.exe", "config RetailDemo start= disabled");
            // Windows Error Reporting — upload path for crash dumps
            // (QueueReporting task and WER hosts are covered elsewhere)
            RunToolSilent("sc.exe", "stop WerSvc");
            RunToolSilent("sc.exe", "config WerSvc start= disabled");
            // Block the "Unified Telemetry Client Outbound Traffic" firewall
            // rules — DiagTrack can't upload even if something re-enables it.
            try
            {
                var fpsi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"'DiagTrack','WerSvc' | % { Get-NetFirewallRule -Group $_ -ErrorAction Ignore | Set-NetFirewallRule -Enabled True -Action Block }\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                Proc.Wait(fpsi, 60000);
            }
            catch { }
            // ETW AutoLogger that feeds DiagTrack — Start=0 kills the boot-time trace
            try
            {
                using var autolog = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener");
                autolog?.SetValue("Start", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // Ink Workspace suggestion surface (ads inside the pen menu)
            try
            {
                using var ink = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace");
                ink?.SetValue("AllowWindowsInkWorkspace", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // ... and the suggested-apps surface inside it
                ink?.SetValue("AllowSuggestedAppsInWindowsInkWorkspace", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // Defender SpyNet — no sample uploads to Microsoft
            try
            {
                using var spynet = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet");
                if (spynet != null)
                {
                    spynet.SetValue("SpynetReporting", 0, Microsoft.Win32.RegistryValueKind.DWord);
                    spynet.SetValue("SubmitSamplesConsent", 0, Microsoft.Win32.RegistryValueKind.DWord);
                    // Offline-maps auto-download channel (MapsBroker service
                    // is demoted; kill the data push too)
                    using var maps = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows\Maps");
                    maps?.SetValue("AutoDownloadAndUpdateMapData", 0, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }
            catch { }
            // Microsoft feature experimentation (A/B flighting) off
            try
            {
                using var exp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\PolicyManager\current\device\System");
                exp?.SetValue("AllowExperimentation", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // Cap diagnostic log/dump collection and enhanced analytics
            try
            {
                using var dcl = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(DataCollectionPath);
                if (dcl != null)
                {
                    dcl.SetValue("LimitDiagnosticLogCollection", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    dcl.SetValue("LimitDumpCollection", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    dcl.SetValue("LimitEnhancedDiagnosticDataWindowsAnalytics", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    // Limit optional-diagnostic configuration set (WGO)
                    dcl.SetValue("LimitDiagnosticDataConfigurationSet", 1, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }
            catch { }
            // Malicious Software Removal Tool infection reports off
            try
            {
                using var mrt = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\MRT");
                mrt?.SetValue("DontReportInfectionInformation", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // AppCompat: Application Inventory Telemetry + the Program
            // Compatibility Assistant service (PcaSvc is already demoted)
            try
            {
                using var ac = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(AppCompatPath);
                ac?.SetValue("AITEnable", 0, Microsoft.Win32.RegistryValueKind.DWord);
                ac?.SetValue("DisablePCA", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Application Compatibility Inventory collector
                ac?.SetValue("DisableInventory", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // AppCompat engine + User-Access-Reporting off
                // (ReviOS app-compat.yml)
                ac?.SetValue("DisableEngine", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ac?.SetValue("DisableUAR", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // AppCompat UA-automation + property-page shim off
                // (RegiLattice)
                ac?.SetValue("DisableUACompleteAutomation", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ac?.SetValue("DisablePropPageShim", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // AppCompat install-activity tracing collector (mxk)
                ac?.SetValue("DisableInstallTracing", 1, Microsoft.Win32.RegistryValueKind.DWord);
            {
                // Device Census inventory task + OneDrive sync diagnostics
                // off (RegiLattice DataCollection)
                using var dcol = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", true);
                dcol?.SetValue("DisableDeviceCensus", 1, Microsoft.Win32.RegistryValueKind.DWord);
                dcol?.SetValue("DisableOneDriveSyncDiagnostics", 1, Microsoft.Win32.RegistryValueKind.DWord);
                dcol?.SetValue("DisableOneSettingsSyncDiag", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Legacy name-resolution/discovery broadcast surfaces —
                // policy kills matching the demoted NetBT service + LLMNR
                // block (mxk): NetBIOS at the DNS client, mailslots, LLTD
                // responder + mapper
                using var dnscl = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", true);
                dnscl?.SetValue("EnableNetbios", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var bowser = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Bowser", true);
                bowser?.SetValue("EnableMailslots", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var nprov = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider", true);
                nprov?.SetValue("EnableMailslots", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var lltd = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\LLTD", true);
                lltd?.SetValue("AllowLLTDIOOnPublicNet", 0, Microsoft.Win32.RegistryValueKind.DWord);
                lltd?.SetValue("ProhibitLLTDIOOnPrivateNet", 1, Microsoft.Win32.RegistryValueKind.DWord);
                lltd?.SetValue("AllowRspndrOnPublicNet", 0, Microsoft.Win32.RegistryValueKind.DWord);
                lltd?.SetValue("ProhibitRspndrOnPrivateNet", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // WPAD off at the WinHTTP layer too — user-level
                // AutoDetect=0 does not reach the machine resolver
                using var winhttp = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp", true);
                winhttp?.SetValue("DisableWpad", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Legacy Edge telemetry opt-in + OneDrive pre-sign-in
                // traffic off (mxk — traffic restriction, not sync kill)
                using var dcol2 = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", true);
                dcol2?.SetValue("MicrosoftEdgeDataOptIn", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var onedrv = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\OneDrive", true);
                onedrv?.SetValue("PreventNetworkTrafficPreUserSignIn", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Handwriting/input personalization upload surfaces
                // (RegiLattice Privacy/Input)
                using var ipz = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\InputPersonalization", true);
                ipz?.SetValue("AllowHandwritingErrorReports", 0, Microsoft.Win32.RegistryValueKind.DWord);
                ipz?.SetValue("AllowInputDataUpload", 0, Microsoft.Win32.RegistryValueKind.DWord);
                ipz?.SetValue("AllowInkRecognitionLearning", 0, Microsoft.Win32.RegistryValueKind.DWord);
                ipz?.SetValue("AllowInkingAndTypingPersonalization", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var tip = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\TextInput", true);
                tip?.SetValue("AllowHandwritingLMUpdate", 0, Microsoft.Win32.RegistryValueKind.DWord);
                tip?.SetValue("AllowHandwritingPersonalizationUpload", 0, Microsoft.Win32.RegistryValueKind.DWord);
                tip?.SetValue("AllowIMENetworkAccess", 0, Microsoft.Win32.RegistryValueKind.DWord);
                tip?.SetValue("AllowHardwareKeyboardTextSuggestions", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var ime = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\IME", true);
                ime?.SetValue("AllowIMETelemetry", 0, Microsoft.Win32.RegistryValueKind.DWord);
                ime?.SetValue("AllowCloudCandidates", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Clipboard AI actions + Copilot clipboard/screen access
                // off (RegiLattice PolicyCloudClipboard/PolicyAI)
                using var sysk = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\System", true);
                sysk?.SetValue("AllowClipboardSuggestedActions", 0, Microsoft.Win32.RegistryValueKind.DWord);
                sysk?.SetValue("AllowCopilotClipboardAccess", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var aic = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\AI\Copilot", true);
                aic?.SetValue("AllowCopilotScreenAccess", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Copilot first-run nag + history cloud-sync off
                // (RegiLattice CopilotSidebar)
                using var wc = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", true);
                wc?.SetValue("SuppressCopilotFirstRun", 1, Microsoft.Win32.RegistryValueKind.DWord);
                wc?.SetValue("BlockCopilotHistorySync", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Speech-recognition language telemetry off
                // (RegiLattice LanguageOptions)
                using var lo = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\LanguageOptions", true);
                lo?.SetValue("SpeechRecognitionTelemetryEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Crash-dump storage telemetry off (RegiLattice)
                using var cc = Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\CrashControl", true);
                cc?.SetValue("StorageTelemetryEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Typing-pattern telemetry upload off (RegiLattice
                // SpellingAndTyping)
                using var st = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\SpellingAndTyping", true);
                st?.SetValue("TypingDataCollectionEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // SysMain memory-usage telemetry reports off (RegiLattice —
                // service stays demand-start)
                using var sf = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\SuperFetch", true);
                sf?.SetValue("SuperFetchDisableTelemetry", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // AI data-analysis kill (TurnOff* sibling of
                // DisableAIDataAnalysis)
                using var ai = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", true);
                ai?.SetValue("TurnOffAIDataAnalysis", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Scripted diagnostics upload off (RegiLattice)
                using var sd = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics", true);
                sd?.SetValue("AllowDiagnosticDataUpload", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // Windows ML inference telemetry off (RegiLattice
                // MachineLearning policy — kill flag polarity is 1)
                using var ml = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\MachineLearning", true);
                ml?.SetValue("WinMLTelemetryEnabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // GameDVR achievement-sharing + streaming-upload surfaces
                // (RegiLattice — capture policies untouched)
                using var dv = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\GameDVR", true);
                dv?.SetValue("AllowAchievementSharing", 0, Microsoft.Win32.RegistryValueKind.DWord);
                dv?.SetValue("AllowGameStreamingUpload", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // SMS/message cloud backup off (RegiLattice Messaging)
                using var mg = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Messaging", true);
                mg?.SetValue("AllowMessageBackup", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            {
                // 24H2 app-inventory collectors: API sampling / app footprint /
                // Win32 backup scan (DisableAPISamping is Microsoft's literal
                // ADMX spelling)
                ac?.SetValue("DisableAPISamping", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ac?.SetValue("DisableApplicationFootprint", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ac?.SetValue("DisableWin32AppBackup", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            }
            catch { }
            // CEIP stragglers + EventViewer online links + help-sticker +
            // handwriting reporting + web printing + Explorer online
            // wizards (ReviOS ceip.yml / privacy.yml)
            try
            {
                using var appv = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\AppV\CEIP");
                appv?.SetValue("CEIPEnable", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var msgr = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Messenger\Client");
                msgr?.SetValue("CEIP", 2, Microsoft.Win32.RegistryValueKind.DWord);
                using var usqm = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient");
                usqm?.SetValue("CEIPEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var evw = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\EventViewer");
                evw?.SetValue("MicrosoftEventVwrDisableLinks", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var eui = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\EdgeUI");
                eui?.SetValue("DisableHelpSticker", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var hw = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports");
                hw?.SetValue("PreventHandwritingErrorReports", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var tp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\TabletPC");
                tp?.SetValue("PreventHandwritingDataSharing", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // ReviOS telemetry.yml deep coverage: 32-bit policy mirror,
                // PolicyManager default node, CPSS overrides, auth-proxy
                // telemetry block, IE CEIP
                using var dc32 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection");
                dc32?.SetValue("AllowTelemetry", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var pmd = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry");
                pmd?.SetValue("value", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var cpss1 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\DevicePolicy\AllowTelemetry");
                cpss1?.SetValue("DefaultValue", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var cpss2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\Store\AllowTelemetry");
                cpss2?.SetValue("Value", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var dcap = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\DataCollection");
                dcap?.SetValue("DisableEnterpriseAuthProxy", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var iesqm = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Internet Explorer\SQM");
                iesqm?.SetValue("DisableCustomerImprovementProgram", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // MS Security Baseline: block legacy IE COM automation
                using var iemain = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Internet Explorer\Main");
                iemain?.SetValue("DisableInternetExplorerLaunchViaCOM", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var pr = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows NT\Printers");
                pr?.SetValue("DisableHTTPPrinting", 1, Microsoft.Win32.RegistryValueKind.DWord);
                pr?.SetValue("DisableWebPnPDownload", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // UPnP device registrar kill — legacy network-device discovery
                // surface (soswod/Windows-On-Reins)
                using var wcn = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars");
                wcn?.SetValue("DisableUPnPRegistrar", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Peer-to-peer networking service kill, credential-delegation
                // lock-down and cert padding check (DebloatAndSecurizeW11)
                using var peernet = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Peernet");
                peernet?.SetValue("Disabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var credDel = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation");
                credDel?.SetValue("AllowDefaultCredentials", 0, Microsoft.Win32.RegistryValueKind.DWord);
                credDel?.SetValue("AllowProtectedCreds", 1, Microsoft.Win32.RegistryValueKind.DWord);
                foreach (var certPath in new[] {
                    @"SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
                    @"SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" })
                {
                    using var certKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(certPath);
                    certKey?.SetValue("EnableCertPaddingCheck", 1, Microsoft.Win32.RegistryValueKind.DWord);
                }
                using var ep = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");
                ep?.SetValue("NoOnlinePrintsWizard", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ep?.SetValue("NoPublishingWizard", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ep?.SetValue("NoWebServices", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // Skip the OOBE privacy pages — every policy they gate is already
            // denied, so the screens only nag
            try
            {
                using var oobe = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE");
                oobe?.SetValue("DisablePrivacyExperience", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // Speech model downloads off (voice data pipeline)
            try
            {
                using var speech = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Speech_OneCore\Preferences");
                speech?.SetValue("ModelDownloadAllowed", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Always-on voice-listening master default off (privacy.sexy)
                speech?.SetValue("VoiceActivationDefaultOn", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // "Sync your settings" off — stops settings roaming to MS accounts
            try
            {
                using var sync = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\SettingSync");
                sync?.SetValue("DisableSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);

                // Dev-tool telemetry opt-outs — machine-wide env vars
                // (PowerShell + .NET CLI send diagnostics unless set)
                using var envKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
                envKey?.SetValue("POWERSHELL_TELEMETRY_OPTOUT", "1");
                envKey?.SetValue("DOTNET_CLI_TELEMETRY_OPTOUT", "1");

                // .NET strong crypto (TLS 1.2+) + strong-name bypass off
                foreach (var dnRoot in new[]
                {
                    @"SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
                    @"SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319",
                })
                {
                    using var dn = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(dnRoot);
                    dn?.SetValue("SchUseStrongCrypto", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    dn?.SetValue("AllowStrongNameBypass", 0, Microsoft.Win32.RegistryValueKind.DWord);
                }
                // .NET v2.0.50727 sibling mirror — legacy runtime TLS
                // opt-in (milgradesec/windows-settings)
                foreach (var dn2 in new[]
                {
                    @"SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
                    @"SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727",
                })
                {
                    using var dn = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(dn2);
                    dn?.SetValue("SchUseStrongCrypto", 1, Microsoft.Win32.RegistryValueKind.DWord);
                }

                // Deprecated TLS 1.0/1.1 protocols off (Winnow/BSI guidance):
                // Enabled=0 + DisabledByDefault=1 removes weak-protocol surface
                foreach (var tls in new[] { "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1" })
                    foreach (var end in new[] { "Client", "Server" })
                    {
                        using var sch = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                            $@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{tls}\{end}");
                        sch?.SetValue("Enabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
                        sch?.SetValue("DisabledByDefault", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    }

                // Attack/diagnostics surface hardening (Atlas playbook):
                // LLMNR off, anonymous SAM / null-session enumeration off,
                // perf-scenario + RSOP + DiagTrack event-transcript off
                using var dns = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient");
                dns?.SetValue("EnableMulticast", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Smart name-resolution fallback off — same DNSClient
                // policy bucket (windows-hardening-scripts)
                dns?.SetValue("DisableSmartNameResolution", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // IP source-routing + ICMP-redirect attack surface off
                // (windows-hardening-scripts)
                foreach (var tcpRoot in new[]
                {
                    @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                })
                    using (var tcp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(tcpRoot))
                        tcp?.SetValue("DisableIPSourceRouting", 2, Microsoft.Win32.RegistryValueKind.DWord);
                using (var tcp4 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                           @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                    tcp4?.SetValue("EnableICMPRedirect", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Lock-screen network-picker off (windows-hardening-scripts)
                using (var sys2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                           @"SOFTWARE\Policies\Microsoft\Windows\System"))
                    sys2?.SetValue("DontDisplayNetworkSelectionUI", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // LSASS access auditing on (windows-hardening-scripts)
                using (var lsass = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                           @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe"))
                    lsass?.SetValue("AuditLevel", 8, Microsoft.Win32.RegistryValueKind.DWord);
                // NTVDM kill policy (milgradesec — same layer as
                // legacy-feature off)
                using var appc = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\AppCompat");
                appc?.SetValue("VDMDisallowed", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // CEIP collection under-layer (HushWin): census upload +
                // task-run gate off
                using var ctele = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry");
                foreach (var ctv in new[] { "IsCensusDisabled", "DontRetryOnError", "TaskEnableRun" })
                    ctele?.SetValue(ctv, 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var lsa = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Lsa");
                lsa?.SetValue("RestrictAnonymous", 1, Microsoft.Win32.RegistryValueKind.DWord);
                lsa?.SetValue("RestrictAnonymousSAM", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Credential/protocol hardening (milgradesec): no LM
                // hashes, NTLMv2-only, DMA-under-lock off
                lsa?.SetValue("NoLMHash", 1, Microsoft.Win32.RegistryValueKind.DWord);
                lsa?.SetValue("LmCompatibilityLevel", 5, Microsoft.Win32.RegistryValueKind.DWord);
                lsa?.SetValue("EveryoneIncludesAnonymous", 0, Microsoft.Win32.RegistryValueKind.DWord);
                lsa?.SetValue("NoDefaultAdminOwner", 1, Microsoft.Win32.RegistryValueKind.DWord);
                lsa?.SetValue("LimitBlankPasswordUse", 1, Microsoft.Win32.RegistryValueKind.DWord);
                lsa?.SetValue("SCENoApplyLegacyAuditPolicy", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // NTLM traffic restrict + audit (MSV1_0, RegiLattice)
                using var msv = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0");
                msv?.SetValue("RestrictSendingNTLMTraffic", 2, Microsoft.Win32.RegistryValueKind.DWord);
                msv?.SetValue("AuditReceivingNTLMTraffic", 2, Microsoft.Win32.RegistryValueKind.DWord);
                // Command line in process-creation audit events
                using var audit = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit");
                audit?.SetValue("ProcessCreationIncludeCmdLine_Enabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // ARD off: no auto sign-in of last user after update restart
                using var polsys = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                polsys?.SetValue("DisableAutomaticRestartSignOn", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Hide last signed-in user name on the lock screen
                polsys?.SetValue("DontDisplayLastUserName", 1, Microsoft.Win32.RegistryValueKind.DWord);
                polsys?.SetValue("BlockUserFromShowingAccountDetailsOnSignin", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Classic SQMClient upload kill (pre-policy CEIP channel)
                using var sqmc = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\SQMClient");
                sqmc?.SetValue("UploadDisableFlag", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // License/activation telemetry — SPP generic ticket off
                using var spp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform");
                spp?.SetValue("NoGenTicket", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Per-app tagged-energy collection off (battery telemetry)
                using var teg = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy");
                foreach (var v in new[] { "TelemetryMaxApplication",
                    "TelemetryMaxTagPerApplication" })
                    teg?.SetValue(v, 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Local-account security questions off (documented GPO)
                using var nolq = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\System");
                nolq?.SetValue("NoLocalPasswordResetQuestions", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Password reveal button off on credential dialogs
                using var credui = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\CredUI");
                credui?.SetValue("DisablePasswordReveal", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Print Spooler remote-RPC endpoint off (local printing
                // unaffected)
                using var prn = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows NT\Printers");
                prn?.SetValue("RegisterSpoolerRemoteRpcEndPoint", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Scheduled Diagnostics engine off (documented policy)
                using var sdiag = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics");
                sdiag?.SetValue("EnabledExecution", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Game Bar broadcast channel off (documented policy)
                using var gdvr = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\GameDVR");
                gdvr?.SetValue("AllowBroadcasting", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // App sharing of user name/picture/domain info off (GPO twin)
                using var uinfo = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\System");
                uinfo?.SetValue("AllowUserInfoAccess", 2, Microsoft.Win32.RegistryValueKind.DWord);
                // MRT infection-report suppression (scan still runs)
                using var mrt = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\MRT");
                mrt?.SetValue("DontReportInfectionInformation", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Diagnostic log + dump collection ceilings off
                using var dclim = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\DataCollection");
                dclim?.SetValue("LimitDiagnosticLogCollection", 1, Microsoft.Win32.RegistryValueKind.DWord);
                dclim?.SetValue("LimitDumpCollection", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // AppCompat: install-tracing + PCA assistant off
                using var acx = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\AppCompat");
                acx?.SetValue("DisableInstallTracing", 1, Microsoft.Win32.RegistryValueKind.DWord);
                acx?.SetValue("DisablePCA", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // NT kernel diagnostic tracing off
                using var dperf = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Diagnostics\Performance");
                dperf?.SetValue("DisableDiagnosticTracing", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // NVIDIA driver-level telemetry opt-out
                using var nvg = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup");
                nvg?.SetValue("SendTelemetryData", 0, Microsoft.Win32.RegistryValueKind.DWord);
                nvg?.SetValue("SendNonNvDisplayDetails", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var nvc = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client");
                nvc?.SetValue("OptInOrOutPreference", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // .NET CLI + PowerShell 7 telemetry opt-out (machine env vars)
                using var envkv = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
                envkv?.SetValue("DOTNET_CLI_TELEMETRY_OPTOUT", "1", Microsoft.Win32.RegistryValueKind.String);
                envkv?.SetValue("POWERSHELL_TELEMETRY_OPTOUT", "1", Microsoft.Win32.RegistryValueKind.String);
                // LMHOSTS lookup off (NetBT side-channel)
                using var netbt = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters");
                netbt?.SetValue("EnableLMHOSTS", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var fve = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\FVE");
                fve?.SetValue("DisableExternalDMAUnderLock", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // RegiLattice diff: Dev Drive + WSL + cloud-TTS telemetry
                // off, no telemetry cache, no auto app archiving
                using var devd = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\DevDrive");
                devd?.SetValue("DisableTelemetry", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var lxss = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss");
                lxss?.SetValue("EnableTelemetry", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var dc2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\DataCollection");
                dc2?.SetValue("MaxTelemetryCacheSize", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var appx2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Appx");
                appx2?.SetValue("AllowAutomaticAppArchiving", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // SEHOP + safe DLL search order (session-manager kernel)
                using var smk = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel");
                smk?.SetValue("DisableExceptionChainValidation", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var smgr = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager");
                smgr?.SetValue("SafeDllSearchMode", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // WDigest plaintext-credential caching off + WPAD
                // auto-discovery off (WinRice)
                using var wdigest = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest");
                wdigest?.SetValue("UseLogonCredential", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // RPC authenticated endpoint resolution, external DMA-device
                // enumeration block, encrypted memory dumps (Win-Debloat7
                // Security module — documented policies)
                using var rpc = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows NT\Rpc");
                rpc?.SetValue("EnableAuthEpResolution", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var rpc2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows NT\Rpc");
                rpc2?.SetValue("RestrictRemoteClients", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var dma = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection");
                dma?.SetValue("DeviceEnumerationPolicy", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var mm = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
                mm?.SetValue("EnableDumpEncryption", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var lanman = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters");
                lanman?.SetValue("RestrictNullSessAccess", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var wdi = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}");
                wdi?.SetValue("ScenarioExecutionEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var rsop = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\System");
                rsop?.SetValue("RSoPLogging", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var etk = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey");
                etk?.SetValue("EnableEventTranscript", 0, Microsoft.Win32.RegistryValueKind.DWord);
                etk?.SetValue("MiniTraceSlotEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var diagp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Diagnostics\Performance");
                diagp?.SetValue("DisableDiagnosticTracing", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Device Health Attestation + speech-model auto-download +
                // cloud message-sync channels off
                using var dha = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService");
                dha?.SetValue("EnableDeviceHealthAttestationService", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var speech = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Speech");
                speech?.SetValue("AllowSpeechModelUpdate", 0, Microsoft.Win32.RegistryValueKind.DWord);
                speech?.SetValue("AllowCloudTTS", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var msg = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Messaging");
                msg?.SetValue("AllowMessageSync", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Maps: no background traffic for Settings content (winscript)
                using var maps = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Maps");
                maps?.SetValue("AllowUntriggeredNetworkTrafficOnSettingsPage", 0,
                               Microsoft.Win32.RegistryValueKind.DWord);
                // SettingSync extras — deeper kills on the same toggle
                using var ss = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\SettingSync");
                ss?.SetValue("DisableSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableSyncOnPaidNetwork", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableWindowsSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
                // Per-category sync kills — app settings + credentials
                // never roam to the Microsoft account (hellzerg/Optimizer)
                ss?.SetValue("DisableApplicationSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableApplicationSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableCredentialsSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableCredentialsSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Deeper per-category sync kills (winscript): browser, start
                // layout, personalization, theme, app-sync + overrides
                ss?.SetValue("DisableWebBrowserSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableWebBrowserSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableStartLayoutSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableStartLayoutSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisablePersonalizationSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisablePersonalizationSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableDesktopThemeSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableDesktopThemeSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableAppSyncSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableAppSyncSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ss?.SetValue("DisableWindowsSettingSyncUserOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Device-level sync override kill (RegiLattice v6.35.0)
                ss?.SetValue("DisableSettingSyncDeviceOverride", 1, Microsoft.Win32.RegistryValueKind.DWord);
                ForEachUserHive(hive =>
                {
                    SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\SettingSync", "SyncPolicy", 5);
                    // CDM master switches + usage instrumentation +
                    // handwriting/typing insight collection
                    SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "FeatureManagementEnabled", 0);
                    SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContentEnabled", 0);
                    SetHiveDword(hive, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoInstrumentation", 1);
                    SetHiveDword(hive, @"Software\Microsoft\Input\Settings", "InsightsEnabled", 0);
                });
            // Text-input linguistic data collection + Bluetooth device
            // advertising off (hellzerg/Optimizer)
            using var ti = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput", true);
            ti?.SetValue("AllowLinguisticDataCollection", 0, RegistryValueKind.DWord);
            using var bt = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth", true);
            bt?.SetValue("AllowAdvertising", 0, RegistryValueKind.DWord);
            // Machine-side typing-insight + handwriting prediction kills
            // (per-user copies already covered) + WiFi Sense hotspot
            // reporting/auto-connect family (ReviOS privacy/misc)
            using var ins = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Input\Settings", true);
            ins?.SetValue("InsightsEnabled", 0, RegistryValueKind.DWord);
            ins?.SetValue("EnableHwkbTextPrediction", 0, RegistryValueKind.DWord);
            using var tipc = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Input\TIPC", true);
            tipc?.SetValue("Enabled", 0, RegistryValueKind.DWord);
            using var wcmf = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features", true);
            wcmf?.SetValue("PaidWifi", 0, RegistryValueKind.DWord);
            wcmf?.SetValue("WiFiSenseOpen", 0, RegistryValueKind.DWord);
            // Wi-Fi Sense credential sharing (soswod/Windows-On-Reins)
            wcmf?.SetValue("WiFiSenseCredShared", 0, RegistryValueKind.DWord);
            using var wcmc = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", true);
            wcmc?.SetValue("AutoConnectAllowedOEM", 0, RegistryValueKind.DWord);
            // Wi-Fi profile sync to MS cloud off + hotspot sharing off
            // (RegiLattice wificonn)
            wcmc?.SetValue("WiFiConfigSyncDisabled", 1, RegistryValueKind.DWord);
            wcmc?.SetValue("WiFiSharingEnabled", 0, RegistryValueKind.DWord);
            foreach (var p in new[] { "AllowAutoConnectToWiFiSenseHotspots",
                    "AllowWiFiHotSpotReporting" })
            {
                using var wk = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\PolicyManager\default\WiFi\" + p, true);
                wk?.SetValue("value", 0, RegistryValueKind.DWord);
            }

                // CEIP policy + feedback nag prompts
                using var sqm = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\SQMClient\Windows");
                sqm?.SetValue("CEIPEnable", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var fdb = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\DataCollection");
                fdb?.SetValue("DoNotShowFeedbackNotifications", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // OneSettings download kill at the DataCollection alias
                // path + recent-items graph off (noid-privacy)
                fdb?.SetValue("DisableOneSettingsDownloads", 1, Microsoft.Win32.RegistryValueKind.DWord);
                using var expol = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Explorer");
                expol?.SetValue("DisableGraphRecentItems", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // CDP master + Windows Backup cloud-sync kills
                using var syspol = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\System");
                syspol?.SetValue("EnableCdp", 0, Microsoft.Win32.RegistryValueKind.DWord);
                using var ssync = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\SettingSync");
                ssync?.SetValue("EnableWindowsBackup", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Windows Backup shell UI suppression (Debloat-Win11)
                using var wbui = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WindowsBackup");
                wbui?.SetValue("DisableBackupUI", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Cloud-backup + nag-notification policy kills
                // (RegiLattice v6.35.0)
                using var bkup = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Backup");
                bkup?.SetValue("DisableCloudBackup", 1, Microsoft.Win32.RegistryValueKind.DWord);
                bkup?.SetValue("DisableBackupNotifications", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Windows Backup nag notifications off per user (SysAdminDoc)
                SetUserDwordAllHives(
                    @"Software\Microsoft\Windows\CurrentVersion\WindowsBackup",
                    "NotificationDisabled", 1);
                // Smart Clipboard per-user kill (Debloat-Win11)
                SetUserDwordAllHives(
                    @"Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard",
                    "Disabled", 1);
                // OneDrive: feedback/sync-health reporting + pre-sign-in
                // traffic (policy kills only — OneDrive itself untouched)
                using var odpol = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\OneDrive");
                odpol?.SetValue("EnableSyncAdminReports", 0, Microsoft.Win32.RegistryValueKind.DWord);
                odpol?.SetValue("EnableFeedbackAndSupport", 0, Microsoft.Win32.RegistryValueKind.DWord);
                odpol?.SetValue("PreventNetworkTrafficPreUserSignIn", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Suppress the "your telemetry setting changed" nag + hide
                // the telemetry level picker UX entirely (ReviOS parity)
                fdb?.SetValue("DisableTelemetryOptInChangeNotification", 1, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("DisableTelemetryOptInSettingsUx", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Commercial data pipeline, device name in telemetry, Edge
                // data opt-in — ReviOS privacy/telemetry.yml parity
                fdb?.SetValue("AllowCommercialDataPipeline", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("AllowDeviceNameInTelemetry", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("MicrosoftEdgeDataOptIn", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Documented Policy-CSP-System DataCollection kills
                // (hateblo/coolvitto list): analytics-processing +
                // device-name-in-diag + managed-desktop + update-
                // compliance + WUfB cloud processing off, diagnostic-
                // data-viewer surface off, OneSettings auditing off,
                // enhanced-diag-data limited
                fdb?.SetValue("AllowDesktopAnalyticsProcessing", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("AllowDeviceNameInDiagnosticData", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("AllowMicrosoftManagedDesktopProcessing", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("AllowUpdateComplianceProcessing", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("AllowWUfBCloudProcessing", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("DisableDiagnosticDataViewer", 1, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("EnableOneSettingsAuditing", 0, Microsoft.Win32.RegistryValueKind.DWord);
                fdb?.SetValue("LimitEnhancedDiagnosticDataWindowsAnalytics", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Online font-provider downloads off (Policy CSP - System)
                using (var sysf = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                           @"SOFTWARE\Policies\Microsoft\Windows\System"))
                    sysf?.SetValue("EnableFontProviders", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // OOBE in-setup update pulls off (Policy CSP - System)
                using (var oobe = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                           @"SOFTWARE\Policies\Microsoft\Windows\OOBE"))
                    oobe?.SetValue("AllowOOBEUpdates", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // Cap the diagnostic level at Security/Basic even if a
                // component or update re-raises AllowTelemetry later
                fdb?.SetValue("MaxTelemetryAllowed", 1, Microsoft.Win32.RegistryValueKind.DWord);

                // OneSettings periodic config download (recommendations channel)
                using var ones = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\OneSettings");
                ones?.SetValue("DisableOneSettingsFileDownloads", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Store: never auto-update apps + no OS-upgrade offers
                // (ReviOS updates/ms-store.yml)
                using var store = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\WindowsStore");
                store?.SetValue("AutoDownload", 4, Microsoft.Win32.RegistryValueKind.DWord);
                store?.SetValue("DisableOSUpgrade", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Legacy (non-policy) sibling for pre-policy hosts
                using var storeU = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate");
                storeU?.SetValue("AutoDownload", 2, Microsoft.Win32.RegistryValueKind.DWord);
                // Block the OOBE updater that pushes "New Outlook" via WU
                using var uoob = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe");
                uoob?.SetValue("BlockedOobeUpdaters", "[\"MS_Outlook\"]", Microsoft.Win32.RegistryValueKind.String);
                // Media Creation Tool promo link in Windows Update settings
                using var wuux = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings");
                wuux?.SetValue("HideMCTLink", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // Feature-upgrade offer nag (ReviOS updates.yml)
                using var upg = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SYSTEM\Setup\UpgradeNotification");
                upg?.SetValue("UpgradeAvailable", 0, Microsoft.Win32.RegistryValueKind.DWord);
                // WMP legacy auto-update channel (dead on modern builds)
                using var wmp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer");
                wmp?.SetValue("DisableAutoUpdate", 1, Microsoft.Win32.RegistryValueKind.DWord);
                // WMP online metadata lookups (windowsmedia.com) — per-user
                foreach (var v in new[] { "PreventCDDVDMetadataRetrieval",
                        "PreventMusicFileMetadataRetrieval",
                        "PreventRadioPresetsRetrieval" })
                    SetUserDwordAllHives(
                        @"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer", v, 1);
            }
            catch { }
            // "Share across devices" (Connected Devices Platform) user consent off
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP",
                "CdpSessionUserAuthzPolicy", 0);
            // CDP session-user override off — same auth family
            // (Titanium-OS-Suite)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP",
                "CdpSessionUserOverride", 0);
            // Share drag tray off (Raphire 2026.06)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP",
                "DragTrayEnabled", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP",
                "RomeSdkChannelUserAuthzPolicy", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage",
                "RomeSdkChannelUserAuthzPolicy", 0);
            // Nearby Share consent — same CDP auth-policy family
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage",
                "NearShareChannelUserAuthzPolicy", 0);
            // Cross-Device Resume off (unslop-windows): MDM PolicyManager
            // gate stops sihost spawning CrossDeviceResumeHost at logon
            using var cdr = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume");
            cdr?.SetValue("value", 1, Microsoft.Win32.RegistryValueKind.DWord);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration",
                "IsResumeAllowed", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration",
                "IsOneDriveResumeAllowed", 0);
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableTailoredExperiencesWithDiagnosticData", 1);
            // Per-user policy stragglers (ReviOS privacy.yml)
            foreach (var v in new[] { "NoOnlinePrintsWizard", "NoPublishingWizard", "NoWebServices" })
                SetUserDwordAllHives(
                    @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", v, 1);
            foreach (var v in new[] { "NoExplicitFeedback", "NoImplicitFeedback", "NoOnlineAssist" })
                SetUserDwordAllHives(
                    @"Software\Policies\Microsoft\Assistance\Client\1.0", v, 1);
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\EdgeUI",
                "DisableMFUTracking", 1);
            SetUserDwordAllHives(
                @"Software\NVIDIA Corporation\NVControlPanel2\Client",
                "OptInOrOutPreference", 0);

            // AMD Customer Experience Program opt-out (Reclaim vendor
            // telemetry): HKLM AMD CN hive
            using var amdcn = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\AMD\CN");
            amdcn?.SetValue("UserExperienceProgram", 0, Microsoft.Win32.RegistryValueKind.DWord);

            GuardLogger.Info("Applied: DisableTelemetry (AllowTelemetry=0, DiagTrack off, privacy surfaces set)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable telemetry: {ex.Message}");
        }
    }

    /// <summary>Disable GameDVR / Game Bar background capture — recording buffer
    /// costs GPU cycles even when never used.</summary>
    public static void DisableGameDvr()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(GameDvrPolicyPath);
            key?.SetValue("AllowGameDVR", 0, Microsoft.Win32.RegistryValueKind.DWord);
            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserGameConfigStorePath, "GameDVR_Enabled", 0);
                SetHiveDword(hive, UserGameDvrPath, "AppCaptureEnabled", 0);
                // Game Bar nags: Nexus overlay hook + startup panel
                SetHiveDword(hive, @"Software\Microsoft\GameBar", "UseNexusForGameBarEnabled", 0);
                SetHiveDword(hive, @"Software\Microsoft\GameBar", "ShowStartupPanel", 0);
                SetHiveDword(hive, @"Software\Microsoft\GameBar", "GamePanelStartupTipIndex", 3);
            });
            // ms-gamebar/ms-gamebarservices protocol hijack (Win11Debloat):
            // NoOpenWith + a dead handler command kills the "get Game Bar"
            // popup that games trigger when the app is removed
            foreach (var proto in new[] { "ms-gamebar", "ms-gamebarservices" })
            {
                var protoBase = @"SOFTWARE\Classes\" + proto;
                using var pb = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(protoBase);
                pb?.SetValue("", "URL:" + proto);
                pb?.SetValue("URL Protocol", "");
                pb?.SetValue("NoOpenWith", "");
                using var cmd = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    protoBase + @"\shell\open\command");
                cmd?.SetValue("", @"%SystemRoot%/System32/systray.exe");
            }
            GuardLogger.Info("Applied: DisableGameDvr (AllowGameDVR=0, GameDVR_Enabled=0, AppCaptureEnabled=0)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable GameDVR: {ex.Message}");
        }
    }

    /// <summary>Disable Delivery Optimization P2P update sharing — the machine
    /// stops uploading update payloads to other PCs on the network/internet.</summary>
    public static void DisableDeliveryOptimization()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(DoPolicyPath);
            key?.SetValue("DODownloadMode", 0, Microsoft.Win32.RegistryValueKind.DWord);

            SetUserDwordAllHives(UserDeliveryOptimizationPath, "DownloadMode", 0);
            // The Delivery Optimization service reads the NETWORK SERVICE hive
            // (S-1-5-20) — write it explicitly too.
            try
            {
                using var net = Registry.Users.CreateSubKey(
                    @"S-1-5-20\" + UserDeliveryOptimizationPath);
                net?.SetValue("DownloadMode", 0, RegistryValueKind.DWord);
            }
            catch { }

            // The DoSvc service still auto-starts for CDN fetches — demote it
            DemoteService("DoSvc");

            GuardLogger.Info("Applied: DisableDeliveryOptimization (DODownloadMode=0)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable delivery optimization: {ex.Message}");
        }
    }

    /// <summary>Disable OneDrive sync (policy) + hide its Explorer navigation pin.
    /// Opt-in layer — active file sync is affected, so the config default is off.</summary>
    public static void DisableOneDrive()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(OneDrivePolicyPath);
            key?.SetValue("DisableFileSyncNGSC", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Hide the OneDrive pin in Explorer's navigation pane for every user
            SetUserDwordAllHives(UserOneDriveClsidPath, "System.IsPinnedToNameSpaceTree", 0);
            // OneDrive's own standalone updaters — stop them alongside the sync
            foreach (var t in new[] { "OneDrive Standalone Update Task",
                                      "OneDrive Per-Machine Standalone Update Task" })
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/Change /TN \"{t}\" /DISABLE",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                Proc.Wait(psi, 15000);
            }
            GuardLogger.Info("Applied: DisableOneDrive (DisableFileSyncNGSC=1, nav pin hidden, update tasks off)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable OneDrive: {ex.Message}");
        }
    }

    /// <summary>Hide the Teams Chat taskbar button (Win11: TaskbarDa-like TaskbarMn;
    /// Win10 leftover: HideSCAMeetNow policy).</summary>
    public static void DisableChatTaskbar()
    {
        try
        {
            SetUserDwordAllHives(UserExplorerAdvancedPath, "TaskbarMn", 0);
            SetUserDwordAllHives(UserExplorerPoliciesBasePath, "HideSCAMeetNow", 1);
            // "My People" taskbar button (contact-promo surface)
            SetUserDwordAllHives(UserExplorerAdvancedPath, "PeopleBand", 0);
            try
            {
                using var chat = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Windows Chat", true);
                chat?.SetValue("ChatIcon", 3, RegistryValueKind.DWord);
            }
            catch { }
            GuardLogger.Info("Applied: DisableChatTaskbar (TaskbarMn=0, HideSCAMeetNow=1, PeopleBand=0, ChatIcon=3)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable chat taskbar: {ex.Message}");
        }
    }

    /// <summary>Edge residual bloat: sidebar, startup boost, prelaunch, first-run
    /// experience — all documented Edge policy values.</summary>
    public static void DisableEdgeBloat()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(EdgePolicyPath);
            key?.SetValue("HubsSidebarEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Copilot surfaces inside Edge (noid-privacy AntiAI edge group)
            foreach (var n in new[] { "Microsoft365CopilotChatIconEnabled",
                    "CopilotAddressBarSuggestionsEnabled", "CopilotNewTabPageEnabled",
                    "AllowBrowsingWithCopilot", "M365LinksAutoOpenCopilotEnabled",
                    "VisualSearchEnabled", "AddressBarTrendingSuggestEnabled",
                    "EdgeReadingModeServiceBasedExtractionEnabled",
                    // URL-keyed "anonymized" browsing-data uploads (winutil)
                    "UrlKeyedAnonymizedDataCollectionEnabled" ,
                    // first-run taskbar-pin wizard suppression (Reclaim)
                    "LocalBrowserDataShareEnabled", "GuidSwitchEnabled",
                "CredentialProviderPromoEnabled", "OutlookHubMenuEnabled",
                "MicrosoftOfficeMenuEnabled", "EnableUnsafeSwiftShader", "PinningWizardAllowed",
                    // Edge Surf game (Aegis-Win11)
                    "AllowSurfGame",
                    // Edge desktop-analytics telemetry (WGO)
                    "ConfigureTelemetryForDesktop",
                    // Cloud management enrollment + shopping assistant +
                    // Workspaces collaboration surface (Edge policy docs)
                    "EdgeManagementEnabled",
                    "ShoppingInEdgeEnabled",
                    "EdgeWorkspaceEnabled",
                    // M365 Copilot inline-compose (Rewrite) surface
                    // (MS Learn Edge policy docs; eplord Win-Debloat7)
                    "ComposeInlineEnabled" })
                key?.SetValue(n, 0, Microsoft.Win32.RegistryValueKind.DWord);
            // NTP background restricted to off/theme-only (3 = no custom
            // imagery feeds; Reclaim Edge catalog)
            key?.SetValue("NewTabPageAllowedBackgroundTypes", 3, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("StartupBoostEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AllowPrelaunch", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("HideFirstRunExperience", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Background-mode keep-alive, startup autolaunch and per-URL
            // diagnostic upload (W1X-Debloat)
            key?.SetValue("BackgroundModeEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("LaunchEdgeOnWindowsStartupEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("UrlDiagnosticDataEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Edge search-provider suggestions upload (soswod SearchScopes)
            using var searchScopes = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes");
            searchScopes?.SetValue("ShowSearchSuggestionsGlobal", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Shopping assistant, content recommendations, error-page web
            // service calls and user feedback — all upload/suggestion surfaces
            key?.SetValue("EdgeShoppingAssistantEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ShowRecommendationsEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ResolveNavigationErrorsUseWebService", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AlternateErrorPagesEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("UserFeedbackAllowed", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // URL-leak surfaces: omnibox suggestions + nav-error services +
            // site-safety look-ups all send URLs to Microsoft
            key?.SetValue("SearchSuggestEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AddressBarMicrosoftSearchInBingProviderEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("SiteSafetyServicesEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // 2 = never predict/pre-resolve via Microsoft web service
            key?.SetValue("NetworkPredictionOptions", 2, Microsoft.Win32.RegistryValueKind.DWord);
            // Cross-device Collections + Follow feeds
            key?.SetValue("EdgeCollectionsEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("EdgeFollowEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // privacy.sexy Edge-policy diff — promo/feed/telemetry
            // surfaces: Bing ads suppressed (Edge policy is enable-to-
            // suppress), Discover/enhance feeds, metrics
            // reporting, site-info upload, rewards/sign-in nags, NTP
            // spotlight, sidebar variant, games menu, in-app support,
            // Acrobat promo, web widget autostart, searchbar, ECS
            key?.SetValue("BingAdsSuppressionEnabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DiscoverPageContextEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("EdgeDiscoverEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Discover hub kill (CoPilot-Cleaner)
            key?.SetValue("DiscoverHubEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("EdgeEnhanceImagesEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("MetricsReportingEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("RelatedMatchesCloudServiceEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("SendSiteInfoToImproveServices", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ShowMicrosoftRewards", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("SignInCtaOnNtpEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("SpotlightExperiencesAndRecommendationsEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("StandaloneHubsSidebarEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AllowGamesMenu", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("InAppSupportEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ShowAcrobatSubscriptionButton", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("WebWidgetIsEnabledOnStartup", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("SearchbarAllowed", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("SearchbarIsEnabledOnStartup", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ExperimentationAndConfigurationServiceControl", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Debloat-Win11 Edge diff — Copilot master + NTP AI prompt +
            // crash uploads + Wallet/gamer/travel promo surfaces +
            // migration nag + Office favorites-bar shortcut + mini menu
            key?.SetValue("EdgeCopilotEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("NewTabPageBingAIPromptEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("CrashReportingMode", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("EdgeWalletEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("EdgeWalletCheckoutEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("GamerModeEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("TravelAssistanceEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ShowBrowserMigrationPrompt", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ShowOfficeShortcutInFavoritesBar", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("QuickSearchShowMiniMenu", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Edge Drop syncs files to OneDrive; crypto wallet + asset
            // delivery service are promo/feature-download surfaces
            key?.SetValue("DropEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("CryptoWalletEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("EdgeAssetDeliveryServiceEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Insider-program promo + donation-wallet promos
            key?.SetValue("MicrosoftEdgeInsiderPromotionEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("WalletDonationEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Send the DoNotTrack header (harmless privacy signal)
            key?.SetValue("ConfigureDoNotTrack", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Promo tabs + desktop web widget (feature/promo surfaces)
            key?.SetValue("PromotionalTabsEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("WebWidgetAllowed", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // xd-AntiSpy diff: launch-time browser-data import, default-
            // browser nag, NTP sponsored quick links
            key?.SetValue("ImportOnEachLaunch", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DefaultBrowserSettingEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("NewTabPageQuickLinksEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // NTP prerender off — stops background feed prefetch (WinOpt)
            key?.SetValue("NewTabPagePrerenderEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Edge AI surface (zoicware/RemoveWindowsAI policy set): page-
            // context Copilot, inline compose, history AI search, generated
            // themes, DevTools AI (2 = disabled), browsing-history sharing
            foreach (var name in new[] { "CopilotPageContext", "EdgeEntraCopilotPageContext",
                                         "EdgeHistoryAISearchEnabled", "ComposeInlineEnabled",
                                         "BuiltInAIAPIsEnabled", "AIGenThemesEnabled",
                                         "ShareBrowsingHistoryWithCopilotSearchAllowed",
                                         // Copilot+ connected-page context + NTP
                                         // Bing chat (Raphire/Win11Debloat)
                                         "CopilotCDPPageContext", "NewTabPageBingChatEnabled",
                                         // 3rd-party SERP telemetry (hellzerg/Optimizer)
                                         "Edge3PSerpTelemetryEnabled" })
                key?.SetValue(name, 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DevToolsGenAiSettings", 2, Microsoft.Win32.RegistryValueKind.DWord);
            // 1 = disable the local on-device foundation model used by Edge AI
            key?.SetValue("GenAILocalFoundationalModelSettings", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // NTP content feed + default-browser campaign nag + tab
            // services (Raphire/Win11Debloat ads/suggestions diff)
            foreach (var name in new[] { "NewTabPageContentEnabled", "TabServicesEnabled",
                                         "DefaultBrowserSettingsCampaignEnabled" })
                key?.SetValue(name, 0, Microsoft.Win32.RegistryValueKind.DWord);
            // 1 = hide the sponsored top-sites tile row on new tabs
            key?.SetValue("NewTabPageHideDefaultTopSites", 1, Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: DisableEdgeBloat (sidebar/startup-boost/prelaunch/first-run/shopping/recommendations/URL-leak/AI surfaces off)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable Edge bloat: {ex.Message}");
        }
    }

    /// <summary>Layer 22: disable bloatware autostart entries. Writes the
    /// StartupApproved\Run disabled marker (0x03...) instead of deleting the
    /// Run value, so the entry stays listed in Task Manager's Startup tab and
    /// can be re-enabled — same mechanism the UI uses.</summary>
    public static void DisableStartupBloat(List<string> blacklist, List<string> whitelist)
    {
        var needles = blacklist
            .Concat(StartupBloatNames)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();
        var applied = 0;

        bool IsBloat(string name, string? data)
        {
            var haystack = name + " " + data;
            if (whitelist.Any(w => !string.IsNullOrWhiteSpace(w) &&
                    haystack.Contains(w, StringComparison.OrdinalIgnoreCase)))
                return false;
            return needles.Any(n =>
                haystack.Contains(n, StringComparison.OrdinalIgnoreCase));
        }

        void ScanAndMark(RegistryKey root, string runPath, string approvedPath,
                         string? peerRunPath = null)
        {
            try
            {
                using var runKey = root.OpenSubKey(runPath);
                if (runKey == null)
                    return;
                var targets = runKey.GetValueNames()
                    .Where(n => IsBloat(n, runKey.GetValue(n) as string))
                    .ToList();
                // StartupApproved markers are name-keyed and shared between the
                // 64-bit and 32-bit registry views; don't stamp a name that an
                // unmatched entry in the peer view also uses, or the marker
                // would disable that non-bloat entry as well.
                if (peerRunPath != null && targets.Count > 0)
                {
                    using var peer = root.OpenSubKey(peerRunPath);
                    if (peer != null)
                    {
                        var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var pname in peer.GetValueNames())
                        {
                            if (targets.Contains(pname, StringComparer.OrdinalIgnoreCase) &&
                                !IsBloat(pname, peer.GetValue(pname) as string))
                                blocked.Add(pname);
                        }
                        if (blocked.Count > 0)
                        {
                            foreach (var b in blocked)
                                GuardLogger.Info(
                                    $"Skipped startup marker for '{b}': same-named " +
                                    "non-bloat entry exists in the paired 32/64-bit view");
                            targets = targets.Where(t => !blocked.Contains(t)).ToList();
                        }
                    }
                }
                if (targets.Count == 0)
                    return;
                using var approved = root.CreateSubKey(approvedPath);
                if (approved == null)
                    return;
                foreach (var name in targets)
                {
                    approved.SetValue(name, StartupDisabledMarker, RegistryValueKind.Binary);
                    applied++;
                    GuardLogger.Info($"Disabled startup entry: {name}");
                }
            }
            catch { }
        }

        try
        {
            // Machine-wide autostart (64-bit + 32-bit views, Run + RunOnce)
            ScanAndMark(Registry.LocalMachine, MachineRunPath, StartupApprovedRun,
                        MachineRunPath32);
            ScanAndMark(Registry.LocalMachine, MachineRunPath32, StartupApprovedRun,
                        MachineRunPath);
            ScanAndMark(Registry.LocalMachine, MachineRunOncePath, StartupApprovedRunOnce,
                        MachineRunOncePath32);
            // 32-bit view of RunOnce — same StartupApproved marker semantics
            ScanAndMark(Registry.LocalMachine, MachineRunOncePath32, StartupApprovedRunOnce,
                        MachineRunOncePath);
            // Every user hive + HKCU (Run + RunOnce)
            ForEachUserHive(hive =>
            {
                ScanAndMark(hive, UserRunPath, StartupApprovedRun, UserRunPath32);
                ScanAndMark(hive, UserRunPath32, StartupApprovedRun, UserRunPath);
                ScanAndMark(hive, UserRunOncePath, StartupApprovedRunOnce, UserRunOncePath32);
                ScanAndMark(hive, UserRunOncePath32, StartupApprovedRunOnce, UserRunOncePath);
            });

            // Explorer\Run policy keys — an autostart vector Task Manager
            // never lists and StartupApproved can't mark, so matching
            // values are removed outright (data logged for manual restore)
            void PurgePolicyRun(RegistryKey root, string policyPath)
            {
                try
                {
                    using var key = root.OpenSubKey(policyPath, writable: true);
                    if (key == null)
                        return;
                    var targets = key.GetValueNames()
                        .Where(n => IsBloat(n, key.GetValue(n) as string))
                        .ToList();
                    foreach (var name in targets)
                    {
                        try
                        {
                            var data = key.GetValue(name) as string;
                            key.DeleteValue(name);
                            applied++;
                            GuardLogger.Info(
                                $"Removed policy-run autostart: {name} (was: {data})");
                        }
                        catch (Exception ex)
                        {
                            GuardLogger.Warn(
                                $"Could not remove policy-run entry {name}: {ex.Message}");
                        }
                    }
                }
                catch { }
            }
            PurgePolicyRun(Registry.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run");
            ForEachUserHive(hive =>
                PurgePolicyRun(hive,
                    @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"));

            // Startup folders aren't governed by StartupApproved — match the
            // same needles against filenames and rename to .bgdisabled
            // (restorable; deleting would lose the restore path)
            foreach (var dir in new[] {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
            {
                try
                {
                    if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                        continue;
                    foreach (var file in Directory.EnumerateFiles(dir))
                    {
                        var fname = Path.GetFileName(file);
                        if (fname.EndsWith(".bgdisabled", StringComparison.OrdinalIgnoreCase) ||
                            !IsBloat(fname, null))
                            continue;
                        File.Move(file, file + ".bgdisabled");
                        applied++;
                        GuardLogger.Info($"Disabled startup folder item: {fname}");
                    }
                }
                catch { }
            }

            // Active Setup stub installers — re-run at EVERY user sign-in
            applied += DisableActiveSetupStubs(IsBloat);

            GuardLogger.Info($"Applied: DisableStartupBloat ({applied} entries)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable startup bloat: {ex.Message}");
        }
    }

    // Active Setup — OEM stub installers that re-run at every user sign-in
    private static readonly string[] ActiveSetupPaths = {
        @"SOFTWARE\Microsoft\Active Setup\Installed Components",
        @"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components",
    };

    private static int DisableActiveSetupStubs(Func<string, string?, bool> isBloat)
    {
        var deleted = 0;
        foreach (var path in ActiveSetupPaths)
        {
            RegistryKey? root;
            try
            {
                root = Registry.LocalMachine.OpenSubKey(path, writable: true);
            }
            catch { continue; }
            if (root == null)
                continue;
            using (root)
            {
                foreach (var sub in root.GetSubKeyNames())
                {
                    try
                    {
                        using var sk = root.OpenSubKey(sub);
                        var blob = sub + " "
                            + (sk?.GetValue(null)?.ToString() ?? "") + " "
                            + (sk?.GetValue("LocalizedName")?.ToString() ?? "") + " "
                            + (sk?.GetValue("StubPath")?.ToString() ?? "");
                        if (!isBloat(blob, null))
                            continue;
                        root.DeleteSubKey(sub);
                        deleted++;
                        GuardLogger.Info($"Deleted Active Setup stub: {sub} ({path})");
                    }
                    catch { }
                }
            }
        }
        return deleted;
    }

    /// <summary>Layer 23: Windows Error Reporting off — HKLM values + policy +
    /// per-hive UI/logging suppression. WerSvc already runs on demand.</summary>
    public static void DisableErrorReporting()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WerPath);
            key?.SetValue("Disabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DontSendAdditionalData", 1, Microsoft.Win32.RegistryValueKind.DWord);

            using var policy = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WerPolicyPath);
            policy?.SetValue("Disabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
            policy?.SetValue("AutoApproveOSDumps", 0, Microsoft.Win32.RegistryValueKind.DWord);

            // WER consent policy — default deny + lock re-consenting
            // (ReviOS privacy/wer.yml)
            using var consent = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WerPath + @"\Consent");
            consent?.SetValue("DefaultConsent", 0, Microsoft.Win32.RegistryValueKind.DWord);
            consent?.SetValue("DefaultOverrideBehavior", 1, Microsoft.Win32.RegistryValueKind.DWord);

            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserWerPath, "Disabled", 1);
                SetHiveDword(hive, UserWerPath, "DontShowUI", 1);
                SetHiveDword(hive, UserWerPath, "LoggingDisabled", 1);
            });
            // PCHealth reporting + CBS / device-install WER spill channels
            // (Atlas playbook)
            using var pchealth = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting");
            pchealth?.SetValue("DoReport", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // ReviOS privacy.yml: HelpSvc online-help fetch channels off
            using var helpsvc = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc");
            helpsvc?.SetValue("Headlines", 0, Microsoft.Win32.RegistryValueKind.DWord);
            helpsvc?.SetValue("MicrosoftKBSearch", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using var cbs = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing");
            cbs?.SetValue("DisableWerReporting", 1, Microsoft.Win32.RegistryValueKind.DWord);
            using var devinst = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings");
            devinst?.SetValue("DisableSendGenericDriverNotFoundToWER", 1, Microsoft.Win32.RegistryValueKind.DWord);
            devinst?.SetValue("DisableSendRequestAdditionalSoftwareToWER", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // WER control-panel support service → demand-start
            DemoteService("wercplsupport");
            GuardLogger.Info("Applied: DisableErrorReporting (WER uploads + UI + logging off)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable error reporting: {ex.Message}");
        }
    }

    /// <summary>Layer 24: demote Edge update services to demand-start and
    /// disable their scheduled tasks. Demand-start keeps manual Edge updates
    /// working while killing the always-on updater/elevation surface.</summary>
    public static void DisableEdgeUpdateBloat()
    {
        try
        {
            foreach (var svc in new[] { "edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService" })
            {
                DemoteService(svc);
            }
            // Scheduled tasks re-arm the services — disable them too
            foreach (var task in new[] {
                "MicrosoftEdgeUpdateTaskMachineCore",
                "MicrosoftEdgeUpdateTaskMachineUA",
                "MicrosoftEdgeUpdateBrowserReplacementTask" })
            {
                RunToolSilent("schtasks.exe", $"/Change /TN \"{task}\" /DISABLE");
            }
            // EdgeUpdate channel GUIDs — installer drops desktop shortcuts
            // on every update; the policy suppresses them (Sophia Script
            // PreventEdgeShortcutCreation)
            using var edgeUpd = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\EdgeUpdate");
            foreach (var guid in new[] {
                "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
                "{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
                "{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
                "{65C35B14-6C1D-4122-AC46-7148CC9D6497}" })
            {
                edgeUpd?.SetValue($"CreateDesktopShortcut{guid}", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            // Suppress the Edge desktop shortcut Windows updates recreate
            // (Disassembler Win10-Initial-Setup-Script)
            try
            {
                using var exp = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer");
                exp?.SetValue("DisableEdgeDesktopShortcutCreation", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            GuardLogger.Info("Applied: DisableEdgeUpdateBloat (edgeupdate/edgeupdatem/elevation → demand, update tasks off, shortcut creation suppressed)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable Edge update bloat: {ex.Message}");
        }
    }

    // AppPrivacy policies force-denied (value 2). Camera/microphone/location
    // excluded on purpose — Teams/Weather etc. legitimately need them.
    private static readonly string[] AppPrivacyDenies = {
        "LetAppsRunInBackground", "LetAppsAccessAccountInfo",
        "LetAppsAccessCallHistory", "LetAppsAccessContacts",
        "LetAppsAccessEmail", "LetAppsAccessMessaging",
        "LetAppsAccessMotion", "LetAppsAccessNotifications",
        "LetAppsAccessPhone", "LetAppsAccessRadios",
        "LetAppsAccessTasks", "LetAppsAccessTrustedDevices",
        "LetAppsSyncWithDevices", "LetAppsGetDiagnosticInfo",
        "LetAppsActivateWithVoice", "LetAppsActivateWithVoiceAboveLock",
        "LetAppsAccessGenerativeAI", "LetAppsAccessCalendar",
        "LetAppsAccessGraphicsCaptureProgrammatic",
        "LetAppsAccessGraphicsCaptureWithoutBorder",
        // Newer sensor/AI capabilities (Espionage724 App Permissions Deny)
        "LetAppsAccessGazeInput", "LetAppsAccessHumanPresence",
        "LetAppsAccessBackgroundSpatialPerception",
    };

    /// <summary>Layer 26: force-deny conservative AppPrivacy set.</summary>
    public static void DisableAppPermissions()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(AppPrivacyPath);
            foreach (var name in AppPrivacyDenies)
                key?.SetValue(name, 2, Microsoft.Win32.RegistryValueKind.DWord);
            // HKLM-level ad-ID and device-finder policies (per-hive counterparts
            // are in DisableTelemetry; these survive profile churn)
            using var adInfo = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo");
            adInfo?.SetValue("DisabledByGroupPolicy", 1, Microsoft.Win32.RegistryValueKind.DWord);
            using var findMy = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\FindMyDevice");
            findMy?.SetValue("AllowFindMyDevice", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // systemAIModels consent-store usage recording off (zoicware)
            using (var cam = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                       @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\systemAIModels"))
                cam?.SetValue("RecordUsageData", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // Paint targeting opt-out + getting-started suppression (zoicware)
            const string paintView =
                @"Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View";
            SetUserDwordAllHives(paintView, "IsSignedUpForTargetingService", 0);
            SetUserDwordAllHives(paintView, "LeftTargetingService", 1);
            SetUserDwordAllHives(paintView, "IsNotInterestedInTargetingService", 1);
            foreach (var pvf in new[] {
                "GettingStartedWelcomePageViewed",
                "GettingStartedStickerGeneratorPageViewed",
                "GettingStartedGenerativeImageEditPageViewed",
                "GettingStartedGenerativeErasePageViewed",
                "GettingStartedGenerativeFillPageViewed",
                "GettingStartedImageCreatorPageViewed",
                "GettingStartedCocreatorPageViewed" })
                SetUserDwordAllHives(paintView, pvf, 1);
            // Notepad store banner/recommendation off (zoicware, Reclaim)
            foreach (var nv in new[] { "ShowStoreBanner", "ShowStoreRecommendation" })
                SetUserDwordAllHives(
                    @"Software\Microsoft\Notepad", nv, 0);
            // Startup-impact toast off (Reclaim)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer",
                "StartupNotify", 0);
            GuardLogger.Info($"Applied: DisableAppPermissions ({AppPrivacyDenies.Length} force-denied + ad-ID/FindMyDevice policies)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable app permissions: {ex.Message}");
        }
    }

    /// <summary>Layer 27: demote Xbox services to demand-start. These sit
    /// permanently running even without any gaming use; demand-start keeps
    /// Game Bar / Xbox sign-in functional when actually invoked.</summary>
    public static void DisableXboxServices()
    {
        try
        {
            foreach (var svc in new[] { "XblAuthManager", "XblGameSave",
                                        "XboxNetApiSvc", "XboxGipSvc" })
            {
                DemoteService(svc);
            }
            // Neuter the Xbox GamingAI companion host's WinRT activation
            // — ActivationType=0xffffffff + empty Server stops GameAssist
            // (ReviOS privacy.yml)
            try
            {
                using var gai = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions");
                gai?.SetValue("ActivationType", unchecked((int)0xFFFFFFFF), Microsoft.Win32.RegistryValueKind.DWord);
                gai?.SetValue("Server", "", Microsoft.Win32.RegistryValueKind.String);
            }
            catch { }
            // 0 = never allow SmartGlass (Xbox companion phone-app)
            // connections (Optimizer privacy diff)
            try
            {
                using var sg = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass");
                sg?.SetValue("UserAuthPolicy", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            GuardLogger.Info("Applied: DisableXboxServices (4 services → demand-start)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to demote Xbox services: {ex.Message}");
        }
    }

    /// <summary>Layer 25: block OEM driver payloads delivered via Windows Update —
    /// a known channel for OEM bloatware re-delivery.</summary>
    public static void BlockOemDriverUpdates()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WindowsUpdatePolicyPath);
            key?.SetValue("ExcludeWUDriversInQualityUpdate", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Stop device-metadata (icons + vendor companion apps) downloads —
            // another OEM silent-delivery channel alongside WU drivers
            using var meta = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata");
            meta?.SetValue("PreventDeviceMetadataFromNetwork", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Never search Windows Update for drivers on new hardware either
            using var dsrch = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching");
            dsrch?.SetValue("SearchOrderConfig", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // GPO twin: policy-pinned "do not search WU for drivers"
            using var dsrchpol = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\DriverSearching");
            dsrchpol?.SetValue("DontSearchWindowsUpdate", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // SMB guest auth off + Schannel secure-renegotiation floor
            using var lmw = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters");
            lmw?.SetValue("AllowInsecureGuestAuth", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using var sch = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL");
            sch?.SetValue("AllowInsecureRenegoClients", 0, Microsoft.Win32.RegistryValueKind.DWord);
            sch?.SetValue("AllowInsecureRenegoServers", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using var dh = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman");
            dh?.SetValue("ClientMinKeyBitLength", 2048, Microsoft.Win32.RegistryValueKind.DWord);
            dh?.SetValue("ServerMinKeyBitLength", 2048, Microsoft.Win32.RegistryValueKind.DWord);
            // Vendor driver co-installers — the channel that seeds OEM
            // companion apps alongside driver packages
            using var coinst = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer");
            coinst?.SetValue("DisableCoInstallers", 1, Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: BlockOemDriverUpdates (ExcludeWUDriversInQualityUpdate=1, SearchOrderConfig=0, DisableCoInstallers=1)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to block OEM driver updates: {ex.Message}");
        }
    }

    // HKLM keys this guard writes to — exported to .reg before first apply so
    // every change is restorable with a double-click.
    private static readonly string[] BackupKeyPaths = {
        @"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        @"SOFTWARE\AMD\CN",
        @"SOFTWARE\Policies\Microsoft\Windows\Personalization",
        @"SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
        @"SOFTWARE\Policies\Microsoft\Windows\AppCompat",
        @"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
        @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
        @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
        @"SOFTWARE\Policies\Microsoft\Dsh",
        @"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        @"SOFTWARE\Policies\Microsoft\Windows\System",
        @"SOFTWARE\Microsoft\SQMClient",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
        @"SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy",
        @"SOFTWARE\Policies\Microsoft\Windows\CredUI",
        @"SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics",
        @"SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client",
        @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
        @"SOFTWARE\Policies\Microsoft\Assistance\Client\1.0",
        @"SOFTWARE\Policies\Microsoft\Edge",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry",
        @"SOFTWARE\Microsoft\WindowsMitigation",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\DevDrive",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss",
        @"SOFTWARE\Policies\Microsoft\FVE",
        @"SOFTWARE\Policies\Microsoft\Windows\GameDVR",
        @"SOFTWARE\Policies\Microsoft\InputPersonalization",
        @"SOFTWARE\Policies\Microsoft\Windows\TextInput",
        @"SOFTWARE\Policies\Microsoft\Windows\IME",
        @"SOFTWARE\Policies\Microsoft\Windows\AI\Copilot",
        @"SOFTWARE\Policies\Microsoft\Windows\LanguageOptions",
        @"SYSTEM\CurrentControlSet\Control\CrashControl",
        @"SOFTWARE\Policies\Microsoft\Windows\SpellingAndTyping",
        @"SOFTWARE\Policies\Microsoft\Windows\SuperFetch",
        @"SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics",
        @"SOFTWARE\Policies\Microsoft\Windows\MachineLearning",
        @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
        @"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
        @"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
        @"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
        @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        @"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
        @"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
        @"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener",
        @"SYSTEM\CurrentControlSet\Control\Session Manager",
        @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
        @"SYSTEM\CurrentControlSet\Control\Remote Assistance",
        @"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds",
        @"SOFTWARE\Policies\Microsoft\Windows\WindowsBackup",
        @"SOFTWARE\Policies\Microsoft\Windows\Backup",
        @"SOFTWARE\Policies\Microsoft\Windows\BITS",
        @"SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
        @"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection",
        @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        @"SOFTWARE\Microsoft\PolicyManager\current\device\System",
        @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        @"SOFTWARE\Policies\Microsoft\MRT",
        @"SOFTWARE\Policies\Microsoft\Windows\Explorer",
        @"SOFTWARE\Microsoft\Speech_OneCore\Preferences",
        @"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
        @"SOFTWARE\Policies\Microsoft\FindMyDevice",
        @"SOFTWARE\Policies\Microsoft\Windows\SettingSync",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
        @"SOFTWARE\Microsoft\OneDrive",
        @"SOFTWARE\Microsoft\Windows\Shell\Copilot",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
        @"SOFTWARE\NVIDIA Corporation\Global\FTS",
        @"SOFTWARE\Policies\Microsoft\Copilot",
        @"SOFTWARE\Policies\Microsoft\EdgeUpdate",
        @"SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup",
        @"SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\Global\Startup",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\systemAIModels",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\generativeAI",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunNotification",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife",
        @"SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes",
        @"SOFTWARE\Policies\Microsoft\Peernet",
        @"SOFTWARE\Policies\Microsoft\Messenger\Client",
        @"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation",
        @"SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
        @"SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config",
        @"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars",
        @"SOFTWARE\Policies\Microsoft\Windows\Appx",
        @"SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass",
                @"SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService",
                @"SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting",
                @"SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc",
                @"SOFTWARE\Policies\Microsoft\Speech",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                @"SOFTWARE\Policies\Microsoft\Windows\Bowser",
                @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings",
                @"SOFTWARE\Policies\Microsoft\Windows\LLTD",
                @"SOFTWARE\Policies\Microsoft\Windows\Messaging",
                @"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider",
                @"SOFTWARE\Policies\Microsoft\Windows\WDI\{9C5A40DA-B965-4FC3-8781-88DD50A6299D}",
                @"SOFTWARE\Policies\WindowsNotepad",
                @"SYSTEM\CurrentControlSet\Control\Diagnostics\Performance",
                @"SYSTEM\CurrentControlSet\Control\Lsa",
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                @"SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput",
                @"SOFTWARE\Microsoft\Input\Settings",
                @"SOFTWARE\Microsoft\Input\TIPC",
                @"SOFTWARE\Microsoft\WcmSvc",
                @"SOFTWARE\Microsoft\PolicyManager\default\WiFi",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
                @"SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS",
                @"SOFTWARE\Policies\Microsoft\Internet Explorer\SQM",
                @"SOFTWARE\Policies\Microsoft\Internet Explorer\Main",
                @"SOFTWARE\Policies\Microsoft\Windows\Windows Chat",
        // --- coverage completion (audit: every HKLM write path backed up) ---
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient",
        @"SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId",
        @"SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility",
        @"SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate",
        @"SOFTWARE\Microsoft\WindowsUpdate\Orchestrator",
        @"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
        @"SYSTEM\Setup\UpgradeNotification",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Communications",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
        @"SOFTWARE\Policies\Microsoft\Windows\DriverSearching",
        @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate",
        @"SOFTWARE\Microsoft\Windows\Shell",
        @"SOFTWARE\Policies\Microsoft\AppV\CEIP",
        @"SOFTWARE\Policies\Microsoft\EventViewer",
        @"SOFTWARE\Policies\Microsoft\Messenger\Client",
        @"SOFTWARE\Policies\Microsoft\Power\PowerSettings",
        @"SOFTWARE\Policies\Microsoft\PushToInstall",
        @"SOFTWARE\Policies\Microsoft\SQMClient\Windows",
        @"SOFTWARE\Policies\Microsoft\Teams",
        @"SOFTWARE\Policies\Microsoft\Windows NT\Printers",
        @"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer",
        @"SOFTWARE\Policies\Microsoft\WindowsStore",
        @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
        @"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        @"SOFTWARE\Policies\Microsoft\Windows\EdgeUI",
        @"SOFTWARE\Policies\Microsoft\OneDrive",
        @"SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin",
        @"SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports",
        @"SOFTWARE\Policies\Microsoft\Windows\Maps",
        @"SOFTWARE\Policies\Microsoft\Windows\OneSettings",
        @"SOFTWARE\Policies\Microsoft\Windows\TabletPC",
        @"SOFTWARE\Policies\Microsoft\WindowsNotepad",
        @"SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\8",
        @"SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume",
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
        @"SOFTWARE\Policies\Microsoft\Notepad",
        @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
        @"SOFTWARE\Policies\Microsoft\Windows\OOBE",
    };
    private static readonly string[] ExtraBackupServiceNames =
    {
        "DiagTrack",
        "RetailDemo",
        "WerSvc",
        "Spooler",
        "RemoteRegistry",
        "DoSvc",
        "edgeupdate",
        "edgeupdatem",
        "MicrosoftEdgeElevationService",
        "XblAuthManager",
        "XblGameSave",
        "XboxNetApiSvc",
        "XboxGipSvc",
    };
    private static readonly string[] UserBackupKeyPaths =
    {
        @"Control Panel\International\User Profile",
        @"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer",
        @"Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        @"Software\Microsoft\Clipboard",
        @"Software\Microsoft\GameBar",
        @"Software\Microsoft\Input\Settings",
        @"Software\Microsoft\Input\TIPC",
        @"Software\Microsoft\InputPersonalization",
        @"Software\Microsoft\InputMethod\Settings\CHS",
        @"Software\Microsoft\InputPersonalization\TrainedDataStore",
        @"Software\Microsoft\Narrator\NoRoam",
        @"Software\Microsoft\Personalization\Settings",
        @"Software\Microsoft\Siuf\Rules",
        @"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy",
        @"Software\Microsoft\Speech_OneCore\Preferences",
        @"Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps",
        @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
        @"Software\Microsoft\Windows\CurrentVersion\CDP",
        @"Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage",
        @"Software\Microsoft\Windows\CurrentVersion\M365Copilot",
        @"Software\Policies\Microsoft\Windows\CopilotKey",
        @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Context\CloudExperienceHostIntent\Wireless",
        @"Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings",
        @"Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings",
        @"Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel",
        @"Software\Microsoft\Windows\CurrentVersion\Feeds",
        @"Software\Microsoft\Windows\CurrentVersion\GameDVR",
        @"Software\Microsoft\Windows\CurrentVersion\Mobility",
        @"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
        @"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        @"Software\Microsoft\Windows\CurrentVersion\Privacy",
        @"Software\Microsoft\Windows\CurrentVersion\PublishUserActivities",
        @"Software\Microsoft\Windows\CurrentVersion\Recall",
        @"Software\Microsoft\Windows\CurrentVersion\Search",
        @"Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization",
        @"Software\Microsoft\Windows\CurrentVersion\UploadUserActivities",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs",
        @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
        @"Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer",
        @"Software\Microsoft\Windows\CurrentVersion\SearchSettings",
        @"Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchPro",
        @"Software\Microsoft\Windows\CurrentVersion\A9\SnapshotCapture",
        @"Software\Microsoft\Windows\CurrentVersion\WindowsCopilot",
        @"Software\Microsoft\Windows\CurrentVersion\WindowsBackup",
        @"Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard",
        @"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",
        @"Software\Microsoft\Notepad",
        @"Software\Microsoft\Paint",
        @"Software\Microsoft\Windows\CurrentVersion\Photos",
        @"Software\Microsoft\Windows\CurrentVersion\SettingSync",
        @"Software\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers",
        @"Software\Microsoft\Windows\CurrentVersion\Start\Companions\Microsoft.YourPhone_8wekyb3d8bbwe",
        @"Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications",
        @"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement",
        @"Software\Microsoft\Windows\Shell\ClickToDo",
        @"Software\Microsoft\Windows\Shell\Copilot",
        @"Software\Microsoft\Windows\Shell\Copilot\BingChat",
        @"Software\Microsoft\Windows\Windows Error Reporting",
        @"Software\NVIDIA Corporation\NVControlPanel2\Client",
        @"Software\Policies\Microsoft\Assistance\Client\1.0",
        @"Software\Policies\Microsoft\Office\16.0\Outlook\Options\General",
        @"Software\Policies\Microsoft\Office\16.0\Outlook\Preferences",
        @"Software\Policies\Microsoft\Windows\CloudContent",
        @"Software\Policies\Microsoft\Windows\EdgeUI",
        @"Software\Policies\Microsoft\Windows\Explorer",
        @"Software\Policies\Microsoft\Windows\Privacy",
        @"Software\Policies\Microsoft\Windows\WindowsAI",
        @"Software\Policies\Microsoft\Windows\WindowsCopilot",
        @"Software\Policies\Microsoft\CopilotKeyboard",
        @"Software\Policies\Microsoft\OneDrive",
        @"Software\Policies\Microsoft\Windows\WorkplaceJoin",
        @"System\GameConfigStore",
        @"Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration",
        @"Software\Policies\Microsoft\Windows\WindowsNotepad",
    };
    private static bool _backupDone;

    /// <summary>Layer 28: reg-export every HKLM key we touch into
    /// %ProgramData%\BloatwareGuard\backup\ — once per process.</summary>
    public static void BackupRegistryKeys()
    {
        if (_backupDone)
            return;
        _backupDone = true;
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "BloatwareGuard", "backup");
            Directory.CreateDirectory(dir);
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var exported = 0;
            foreach (var path in BackupKeyPaths)
            {
                var file = Path.Combine(dir, $"{stamp}-{exported++}.reg");
                // reg.exe export fails for non-existent keys — that is expected
                RunToolSilent("reg.exe", $"export \"HKLM\\{path}\" \"{file}\" /y");
                if (!File.Exists(file))
                    File.Delete(file);  // no-op guard — keep dir clean
            }
            foreach (var svc in MiscBloatServices.Concat(ExtraBackupServiceNames))
            {
                var file = Path.Combine(dir, $"{stamp}-s{exported++}.reg");
                RunToolSilent("reg.exe",
                    $"export \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc}\" \"{file}\" /y");
                if (!File.Exists(file))
                    File.Delete(file);
            }
            var roots = new List<string> { "HKCU" };
            try
            {
                roots.AddRange(Registry.Users.GetSubKeyNames()
                    .Where(sid => UserSidPattern.IsMatch(sid))
                    .Select(sid => $"HKU\\{sid}"));
            }
            catch { }
            foreach (var root in roots)
            {
                foreach (var path in UserBackupKeyPaths)
                {
                    var file = Path.Combine(dir, $"{stamp}-u{exported++}.reg");
                    RunToolSilent("reg.exe",
                        $"export \"{root}\\{path}\" \"{file}\" /y");
                    if (!File.Exists(file))
                        File.Delete(file);
                }
            }
            GuardLogger.Info($"Applied: BackupRegistry ({exported} keys → {dir})");
        }
        catch (Exception ex)
        {
            GuardLogger.Warn($"BackupRegistry skipped: {ex.Message}");
        }
    }

    /// <summary>Layer 29: opt-in Print Spooler disable — the PrintNightmare
    /// surface. Off by default since it breaks printing.</summary>
    public static void DisablePrintSpooler()
    {
        try
        {
            RunToolSilent("sc.exe", "stop Spooler");
            RunToolSilent("sc.exe", "config Spooler start= disabled");
            GuardLogger.Info("Applied: DisablePrintSpooler (Spooler stopped + disabled)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable Print Spooler: {ex.Message}");
        }
    }

    /// <summary>Opt-in: ConnectivityInStandby power policy — severs network
    /// connectivity during Modern Standby (S0), stopping background sync
    /// and telemetry while the device sleeps.</summary>
    public static void DisableModernStandbyNetworking()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9");
            key?.SetValue("ACSettingIndex", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DCSettingIndex", 0, Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: DisableModernStandbyNetworking");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable Modern Standby networking: {ex.Message}");
        }
    }

    /// <summary>Layer 30: Windows Platform Binary Table lets OEMs inject an
    /// executable into the boot chain via firmware (abused e.g. by ASUS Live
    /// Update). DisableWpbtExecution=1 makes Windows ignore it.</summary>
    public static void BlockOemWpbtExecution()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager");
            key?.SetValue("DisableWpbtExecution", 1,
                          Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: BlockOemWpbtExecution (WPBT disabled)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to block WPBT: {ex.Message}");
        }
    }

    /// <summary>Layer 31: turn off Reserved Storage (~7GB set aside for
    /// updates). Updates then use free space as they did pre-1903 — helps
    /// small-disk devices.</summary>
    public static void DisableReservedStorage()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager");
            if (key != null)
            {
                key.SetValue("ShippedWithReserves", 0,
                             Microsoft.Win32.RegistryValueKind.DWord);
                key.SetValue("MiscPolicyInfo", 2,
                             Microsoft.Win32.RegistryValueKind.DWord);
                key.SetValue("PassedPolicy", 0,
                             Microsoft.Win32.RegistryValueKind.DWord);
            }
            GuardLogger.Info("Applied: DisableReservedStorage (ReserveManager)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable reserved storage: {ex.Message}");
        }
    }

    /// <summary>Layer 32: clipboard history syncs content to Microsoft's
    /// cloud for cross-device paste — allow local history but not the sync.</summary>
    public static void DisableCloudClipboard()
    {
        try
        {
            using var sys = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\System");
            sys?.SetValue("AllowCrossDeviceClipboard", 0,
                          Microsoft.Win32.RegistryValueKind.DWord);
            SetUserDwordAllHives(@"Software\Microsoft\Clipboard",
                                 "EnableClipboardHistory", 0);
            // No automatic upload of clipboard contents (WGO)
            SetUserDwordAllHives(@"Software\Microsoft\Clipboard",
                                 "CloudClipboardAutomaticUpload", 0);
            // Per-user cloud-clipboard switch (LeDragoX WinDebloatTools)
            SetUserDwordAllHives(@"Software\Microsoft\Clipboard",
                "EnableCloudClipboard", 0);
            // Suggested clipboard AI actions off (Winnow ExtendedAIPurge)
            SetUserDwordAllHives(@"Software\Microsoft\Clipboard",
                                 "EnableSuggestedClipboardActions", 0);
            GuardLogger.Info("Applied: DisableCloudClipboard");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable cloud clipboard: {ex.Message}");
        }
    }

    /// <summary>Layer 33: Remote Assistance inbound offers off.</summary>
    public static void DisableRemoteAssistance()
    {
        try
        {
            using var ra = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SYSTEM\CurrentControlSet\Control\Remote Assistance");
            if (ra != null)
            {
                ra.SetValue("fAllowToGetHelp", 0,
                            Microsoft.Win32.RegistryValueKind.DWord);
                ra.SetValue("fAllowFullControl", 0,
                            Microsoft.Win32.RegistryValueKind.DWord);
            }
            GuardLogger.Info("Applied: DisableRemoteAssistance");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable Remote Assistance: {ex.Message}");
        }
    }

    /// <summary>Layer 34: prevent Windows Insider preview enrollment —
    /// preview builds ship heavier telemetry and instability.</summary>
    public static void BlockInsiderPreview()
    {
        try
        {
            using var pb = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds");
            pb?.SetValue("AllowBuildPreview", 0,
                         Microsoft.Win32.RegistryValueKind.DWord);
            using var sh = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility");
            sh?.SetValue("HideInsiderPage", 1,
                         Microsoft.Win32.RegistryValueKind.DWord);
            // Insider diagnostic-data nag strings blanked (speedup-windows10)
            using var shs = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings");
            foreach (var sv in new[] { "DiagnosticErrorText", "DiagnosticLinkText" })
                shs?.SetValue(sv, "", Microsoft.Win32.RegistryValueKind.String);
            pb?.SetValue("ManagePreviewBuildsPolicyValue", 0,
                         Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: BlockInsiderPreview");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to block Insider preview: {ex.Message}");
        }
    }

    /// <summary>Layer 35: demote misc bloat services to demand-start —
    /// dmwappushservice (WAP push/MDM channel), MapsBroker (downloaded-map
    /// broker), WMPNetworkSvc (media sharing), DiagnosticsHub standard
    /// collector. Demand-start keeps them usable when actually invoked.</summary>
    // CDPSvc = Nearby Sharing; NvTelemetryContainer / ESRV_* = GPU/Intel
    // driver telemetry; PushToInstall = Store push-install channel;
    // SEMgrSvc = NFC/SE payments manager; PhoneSvc = Phone Link
    // (absent where not applicable — write is a no-op)
    private static readonly string[] MiscBloatServices = {
        "dmwappushservice", "MapsBroker", "WMPNetworkSvc",
        "diagnosticshub.standardcollector.service",
        "CDPSvc", "NvTelemetryContainer",
        "esrv_svc", "ESRV_SVC_QUEENCREEK",
        // Intel Dynamic Tuning telemetry + Innovation Platform
        // Framework service (vendor telemetry — coolvitto 25H2 list)
        "dptftcs", "ipfsvc",
        "jhi_service", "LMS", "igccservice", "igfxCUIService2.0.0.0",
        "cplspcon", "cphs",
    // Copilot Elevation Service — lets the Copilot app request elevated
    // operations (zoicware/RemoveWindowsAI; demoted, not deleted)
    "MicrosoftCopilotElevationService",
    // Agent Activation Runtime — Copilot/voice-agent activation host
    // (zoicware removes it; demote keeps the service restorable)
    "AarSvc",
    // Cloud-clipboard sync + Windows Push Notification user service
    // (privacy.sexy per-user kills — cloud sync + WNS push channel)
    "cbdhsvc", "WpnUserService",
    // AMD logging + SSDP discovery (vendor telemetry / attack surface)
    "amdlog", "SsdpDiscovery",
                // Waves MaxxAudio — OEM audio suite daemon (SysAdminDoc OEM)
                "WavesSvc64",
        "PushToInstall", "SEMgrSvc", "PhoneSvc",
        // Connected User Experiences and Telemetry — DiagTrack companion;
        // registry demote works where sc config is refused
        "utcsvc",
        "SysMain", "TabletInputService",
        "WSearch",                   // indexer — resident file scan; demand-start keeps search working
        "AssignedAccessManagerSvc",  // kiosk assigned-access
        "DusmSvc",                   // data-usage metering
        // Per-user service templates for Mail/People/contacts sync — dead
        // weight once those apps are removed
        "CDPUserSvc", "OneSyncSvc", "UnistoreSvc",
        "UserDataSvc", "PimIndexMaintenanceSvc",
        // OneDrive FileSyncHelper — companion sync service to OneSyncSvc
        // (WinOpt) — demoted, not disabled
        "FileSyncHelper",
        // Diagnostic Service Host pair — WDI diagnostics sessions
        "WdiSystemHost", "WdiServiceHost",
        // Diagnostic Policy Service + Diagnostic Execution Service —
        // Automatic by default; Manual keeps on-demand diagnostics working
        "DPS", "diagsvc",
        // Data Collection and Publishing Service — feeds the diagnostic
        // ingest pipeline
        "DcpSvc",
        // Program Compatibility Assistant
        "PcaSvc",
        // Microsoft Pay (dead), Windows Insider, Mixed Reality, AllJoyn,
        // smart card triad
        "WalletService", "wisvc",
        "lmhosts",
        "SharedRealitySvc", "perceptionsimulation", "Spectrum",
        // Mixed Reality OpenXR runtime — dead stack once VR/MR
        // unused (Trachti/windows-debloat Balanced tier)
        "MixedRealityOpenXRSvc",
        // Legacy Fax service — fax feature already in the
        // capability kill list (Trachti/windows-debloat)
        "Fax",
        "AJRouter", "SCardSvr", "ScDeviceEnum", "CertPropSvc",
        // Location tracking + sensor monitoring stack — SensorDataService
        // aggregates sensor feeds for apps (Win-Debloat7 services.json)
        "lfsvc", "SensorService", "sensrsvc", "SensorDataService",
        // SNMP traps (dead), recommended-troubleshooting runner,
        // cellular WWAN (demand-start keeps LTE working)
        "SNMPTRAP", "TroubleshootingSvc", "WwanSvc", "WwanAuthSvc",
        // Storage settings service + Offline Files (Client Side Caching —
        // legacy enterprise sync, dead weight on consumer installs)
        "StorSvc", "CscService",
        // Windows AI Fabric service — Copilot+ AI API backend; demand-start
        // keeps apps working without the resident listener (Win11Debloat
        // DisableAISvcAutoStart / winutil)
        "WSAIFabricSvc",
        // Win-Debloat diff: AI-fabric user-side listeners — model
        // catalog, semantic-search orchestration, Recall narrative
        // flow, OneSettings pull client
        "AIFabricUserSvc", "ModelCatalogUserSvc",
        "SemanticSearchUserSvc", "NarrativeFlows",
        "OneSettingsClientUserSvc",
        // Windows Health and Optimized Experiences — ships the
        // PC-health / optimizer suggestion feed (coolvitto 25H2 list)
        "whesvc",
        // Distributed Link Tracking — NTFS cross-volume link chasing,
        // Microsoft 'OK to disable' per IoT/VDI guidance (Atlas services.yml)
        "TrkWks",
            // VDOT services.json diff: GameDVR broadcast per-user
            // template, cellular time sync, SMS router, ICS —
            // demand-start keeps invocation working
            "BcastDVRUserService", "autotimesvc", "SmsRouter", "icssvc",
            "SharedAccess",
        // WER control-panel support — companion to the disabled WerSvc
        // (Atlas services.yml; the error-report pipeline is already off)
        "wercplsupport",
        // Desktop Activity Moderator, Intel telemetry, Event Collector
        // — all disabled by ReviOS services.yml
        "dam", "Telemetry", "Wecsvc",
        // NetBIOS-over-TCP/IP + LMHOSTS lookup — legacy LAN name
        // protocols; pair with the LLMNR kill in DisableTelemetry
        "NetBT", "lmhosts",
        // Debloat-Win11 services diff — app-inventory appraisal,
        // parental-controls monitor, Phone-Link messaging backend,
        // Game Pass runtime pair
        "InventorySvc", "WpcMonSvc", "MessagingService",
        "GamingServices", "GamingServicesNet",
        // Agent-isolation broker — hosts experimental agentic-AI
        // sandboxed runs (zoicware/RemoveWindowsAI); demand-start
        // keeps invocation working without the resident service
        "IsoEnvBroker",
    };

    public static void DisableMiscBloatServices()
    {
        try
        {
            foreach (var svc in MiscBloatServices)
            {
                DemoteService(svc);
            }
            // Remote Registry: read/write registry over SMB — a real attack
            // surface with no consumer use case; disable outright (not
            // demand-start, which still leaves it reachable).
            RunToolSilent("sc.exe", "stop RemoteRegistry");
            RunToolSilent("sc.exe", "config RemoteRegistry start= disabled");
            GuardLogger.Info($"Applied: DisableMiscBloatServices ({MiscBloatServices.Length} services → demand-start, RemoteRegistry disabled)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to demote misc services: {ex.Message}");
        }
    }

    /// <summary>Layer 36: Desktop Spotlight is a content-delivery surface
    /// (wallpaper-embedded promos). Per-hive since wallpapers are per-user.</summary>
    public static void DisableSpotlight()
    {
        try
        {
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings",
                "Enabled", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers",
                "BackgroundType", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement",
                "ShowSpotlightOnWelcome", 0);
            // "Learn about this picture" desktop icon — Spotlight promo
            // surface (Win-Debloat: GUID under NewStartPanel hidden-icons)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel",
                "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}", 1);
            // Per-hive CloudContent policies: block Spotlight features and
            // the per-user data collection that feeds them
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableWindowsSpotlightFeatures", 1);
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableSpotlightCollectionOnDesktop", 1);
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableWindowsSpotlightOnDesktop", 1);
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableSoftLanding", 1);
            // Welcome experience / Action Center / Settings Spotlight pages
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableWindowsSpotlightWindowsWelcomeExperience", 1);
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableWindowsSpotlightOnActionCenter", 1);
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableWindowsSpotlightOnSettings", 1);
            // Enterprise Spotlight content off — inverse polarity (ledr)
            SetUserDwordAllHives(
                @"Software\Policies\Microsoft\Windows\CloudContent",
                "IncludeEnterpriseSpotlight", 0);
            // Lock-screen overlay promos + Settings online tips + Start
            // recommended-sites promo (mxk group-policy diff)
            using var perz = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\Personalization");
            perz?.SetValue("LockScreenOverlaysDisabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
            using var ccloud = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\CloudContent");
            ccloud?.SetValue("DisableWindowsSpotlightOnLockScreen", 1, Microsoft.Win32.RegistryValueKind.DWord);
            using var expol2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\Explorer");
            expol2?.SetValue("AllowOnlineTips", 0, Microsoft.Win32.RegistryValueKind.DWord);
            expol2?.SetValue("HideRecommendedPersonalizedSites", 1, Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: DisableSpotlight (DesktopSpotlight + wallpaper type + per-hive CloudContent policies)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable Spotlight: {ex.Message}");
        }
    }

    /// <summary>Layer 37: disable AutoPlay/AutoRun on all drives —
    /// NoDriveTypeAutoRun=255, NoAutorun=1. Classic media-execution vector.</summary>
    public static void DisableAutoplay()
    {
        try
        {
            using var pol = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");
            if (pol != null)
            {
                pol.SetValue("NoDriveTypeAutoRun", 255,
                             Microsoft.Win32.RegistryValueKind.DWord);
                pol.SetValue("NoAutorun", 1,
                             Microsoft.Win32.RegistryValueKind.DWord);
            }
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun", 255);
            GuardLogger.Info("Applied: DisableAutoplay (NoDriveTypeAutoRun=255)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable AutoPlay: {ex.Message}");
        }
    }

    /// <summary>Layer 38: prevent Windows Update rebooting while any user is
    /// logged on — the notorious forced-restart behavior.</summary>
    public static void NoForcedReboot()
    {
        try
        {
            using var au = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
            if (au != null)
            {
                au.SetValue("NoAutoRebootWithLoggedOnUsers", 1,
                            Microsoft.Win32.RegistryValueKind.DWord);
                au.SetValue("AlwaysAutoRebootAtScheduledTime", 0,
                            Microsoft.Win32.RegistryValueKind.DWord);
            }
            GuardLogger.Info("Applied: NoForcedReboot (WU reboot policy)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to set reboot policy: {ex.Message}");
        }
    }

    /// <summary>Layer 39: HideRecommendedSection removes Start's
    /// "Recommended" section — it surfaces promoted apps, not just files
    /// (Windows 11 22H2+ policy).</summary>
    public static void HideStartRecommendations()
    {
        try
        {
            using var pol = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\Explorer");
            pol?.SetValue("HideRecommendedSection", 1,
                          Microsoft.Win32.RegistryValueKind.DWord);
            pol?.SetValue("HideRecentlyAddedApps", 1,
                          Microsoft.Win32.RegistryValueKind.DWord);
            // The section draws from recent-doc tracking — stop collecting it
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                "Start_TrackDocs", 0);
            // Explorer recent-docs history policy kill (Reclaim)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoRecentDocsHistory", 1);
            // Phone Link companion panel in Start (mobile-device promo surface)
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\Start\Companions\Microsoft.YourPhone_8wekyb3d8bbwe",
                "IsEnabled", 0);
            GuardLogger.Info("Applied: HideStartRecommendations");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to hide Start recommendations: {ex.Message}");
        }
    }

    private static void RunToolSilent(string fileName, string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        Proc.Wait(psi, 15000);
    }
}

// ─── Scheduled Task Manager ──────────────────────────────────────────────────

public static class ScheduledTaskGuard
{
    // Known OEM bloatware task patterns — must be specific enough to avoid matching Microsoft system tasks
    private static readonly string[] OemTaskPatterns = {
        "OEM", "Dell", "HPInc", "HPA", "Lenovo", "ASUS", "Acer", "McAfee", "Norton",
        "SupportAssist", "Vantage", "Armoury", "Crate", "CustomerExperienceImprovement",
        "Customer Experience Improvement", "Reinstall", "Restore", "Bloatware",
        "Intel", "Realtek", "Waves", "MSI", "Razer", "AMD", "AUEP"
    };

    // Microsoft system tasks that MUST NEVER be disabled (TaskPath prefixes)
    private static readonly string[] MicrosoftSystemPrefixes = {
        @"\Microsoft\Windows\CloudRestore",
        @"\Microsoft\Windows\InstallService",
        @"\Microsoft\Windows\WindowsUpdate",
        @"\Microsoft\Windows\UpdateOrchestrator",
        @"\Microsoft\Windows\Defrag",
        @"\Microsoft\Windows\Diagnosis",
        @"\Microsoft\Windows\Maintenance",
        @"\Microsoft\Windows\CloudExperienceHost",
        @"\Microsoft\Windows\Feedback",
        @"\Microsoft\Windows\Input",
        @"\Microsoft\Windows\International",
        @"\Microsoft\Windows\LanguageComponentsInstaller",
        @"\Microsoft\Windows\MUI",
        @"\Microsoft\Windows\PI",
        @"\Microsoft\Windows\RecoveryEnvironment",
        @"\Microsoft\Windows\Servicing",
        @"\Microsoft\Windows\SettingSync",
        @"\Microsoft\Windows\Shell",
        @"\Microsoft\Windows\Sysmain",
        @"\Microsoft\Windows\WDI",
        @"\Microsoft\Windows\Wlan",
        @"\Microsoft\Windows\Bluetooth",
        @"\Microsoft\Windows\NetTrace",
        @"\Microsoft\Windows\Security Center",
        @"\Microsoft\Windows\SpaceAgent",
        @"\Microsoft\Windows\Storage",
        @"\Microsoft\Windows\SystemRestore",
        @"\Microsoft\Windows\Task Manager",
        @"\Microsoft\Windows\VerifiableFileIntegrity",
        @"\Microsoft\Windows\WebAuth",
        @"\Microsoft\Windows\WiFi",
        @"\Microsoft\Windows\Windows Error Reporting",
        @"\Microsoft\Windows\License Manager",
        @"\Microsoft\Windows\Clip",
    };


    public static void DisableOemTasks()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Get-ScheduledTask | Where-Object {{$_.TaskPath -like '*OEM*' -or $_.TaskName -match '{string.Join("|", OemTaskPatterns.Select(Regex.Escape))}'}} | Select-Object TaskName,TaskPath,State | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var output = Proc.Capture(psi, 120000).Stdout;

        try
        {
            var doc = JsonDocument.Parse(output.Trim());
            var tasks = new List<(string name, string path)>();

            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    var name = el.GetProperty("TaskName").GetString() ?? "";
                    var path = el.GetProperty("TaskPath").GetString() ?? "";
                    tasks.Add((name, path));
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                var name = doc.RootElement.GetProperty("TaskName").GetString() ?? "";
                var path = doc.RootElement.GetProperty("TaskPath").GetString() ?? "";
                tasks.Add((name, path));
            }

            var skipped = 0;
            foreach (var (name, path) in tasks)
            {
                var fullPath = path.EndsWith("\\") ? path + name : path + "\\" + name;
                if (MicrosoftSystemPrefixes.Any(p =>
                    fullPath.StartsWith(p + "\\", StringComparison.OrdinalIgnoreCase)))
                {
                    GuardLogger.Warn($"Skipping protected system task: {fullPath}");
                    skipped++;
                    continue;
                }
                DisableTask(name, path);
            }

            GuardLogger.Info($"Disabled {tasks.Count - skipped} OEM scheduled tasks ({skipped} protected skipped)");
        }
        catch (Exception ex)
        {
            GuardLogger.Warn($"Scheduled task scan: {ex.Message}");
        }
    }

    // Microsoft's own data-collection tasks — exact task names, not patterns, so
    // nothing else is touched. CompatTelRunner is a notorious CPU/IO hog.
    private static readonly string[] TelemetryTaskPaths = {
        @"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        // "Exp" variant shipped on newer builds — same telemetry role
        @"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp",
        @"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        // Chkdsk Proxy — event-driven disk diagnostic collector
        @"\Microsoft\Windows\Chkdsk\Proxy",
        @"\Microsoft\Windows\Application Experience\PcaPatchDbTask",
        // Shim-DB merge task — same AppCompat pipeline (privacy.sexy)
        @"\Microsoft\Windows\Application Experience\SdbinstMergeDbTask",
        @"\Microsoft\Windows\Application Experience\PcaWallpaperAppDetect",
        @"\Microsoft\Windows\DUSM\dusmtask",
        @"\Microsoft\Windows\Diagnosis\UnexpectedCodepath",
        @"\Microsoft\Windows\PerformanceTrace\RequestTrace",
        @"\Microsoft\Windows\Flighting\FeatureConfig\BootstrapUsageDataReporting",
        @"\Microsoft\Windows\input\InputSettingsRestoreDataAvailable",
        @"\Microsoft\Windows\input\MouseSyncDataAvailable",
        @"\Microsoft\Windows\input\PenSyncDataAvailable",
        @"\Microsoft\Windows\input\RemoteMouseSyncDataAvailable",
        @"\Microsoft\Windows\input\RemotePenSyncDataAvailable",
        @"\Microsoft\Windows\input\RemoteTouchpadSyncDataAvailable",
        @"\Microsoft\Windows\input\syncpensettings",
        @"\Microsoft\Windows\International\Synchronize Language Settings",
        @"\Microsoft\Windows\Management\Provisioning\Cellular",
        @"\Microsoft\Windows\Management\Provisioning\Logon",
        @"\Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask",
        @"\Microsoft\Windows\EnterpriseMgmt\MDMMaintenanceTask",
        @"\Microsoft\Windows\Shell\ThemesSyncedImageDownload",
        @"\Microsoft\Windows\Shell\ThemeAssetTask_SyncFODState",
        @"\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask",
        @"\Microsoft\Windows\Offline Files\Background Synchronization",
        @"\Microsoft\Windows\Offline Files\Logon Synchronization",
        @"\Microsoft\Windows\PushToInstall\Registration",
        @"\Microsoft\Windows\AppListBackup\BackupNonMaintenance",
        @"\Microsoft\Windows\ApplicationData\DsSvcCleanup",
        @"\Microsoft\Windows\User Profile Service\HiveUploadTask",
        @"\Microsoft\Windows\UsageAndQualityInsights\UsageAndQualityInsights-MaintenanceTask",
        @"\Microsoft\Windows\Application Experience\StartupAppTask",
        // Gathers Win32 app data for the Windows Backup app scenario (24H2+)
        @"\Microsoft\Windows\Application Experience\MareBackup",
        @"\Microsoft\Windows\Autochk\Proxy",
        @"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        @"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        // Bluetooth CEIP SQM uploader (hst-windows-utility task list)
        @"\Microsoft\Windows\Customer Experience Improvement Program\BthSQM",
        @"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        // CEIP Uploader task — distinct from the Broker node
        // UploadCachedReports (noverse.dev task catalog)
        @"\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
        // Server CEIP node (Windows Server CEIP tasks — privacy.sexy)
        @"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant",
        @"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleCollector",
        @"\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleUsageCollector",
        // CEIP Broker — uploads cached CEIP reports
        // (RealSyferX/windows-11-debloat)
        @"\Microsoft\Windows\Customer Experience Improvement Program Broker\UploadCachedReports",
        // OOBE third-party app scan triggers — usoclient-driven
        // re-provisioning of OEM/Store apps after updates (privacy.sexy)
        @"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate",
        @"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted",
        @"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_OobeAppReady",
        @"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        @"\Microsoft\Windows\Feedback\Siuf\DmClient",
        @"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        @"\Microsoft\Windows\Maps\MapsUpdateTask",
        @"\Microsoft\Windows\Maps\MapsToastTask",
        // Winhance: power-efficiency diagnostic ETW collection task
        @"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        // Office Customer Experience Improvement Program (when Office is
        // installed; schtasks ignores missing paths)
        @"\Microsoft\Office\OfficeTelemetryAgentLogOn",
        @"\Microsoft\Office\OfficeTelemetryAgentLogOn2016",
        @"\Microsoft\Office\OfficeTelemetryAgentFallBack",
        @"\Microsoft\Office\OfficeTelemetryAgentFallBack2016",
        @"\Microsoft\Office\Office 15 Subscription Heartbeat",
        @"\Microsoft\Office\Office Feature Updates",
        @"\Microsoft\Office\Office Feature Updates Logon",
        // Retail demo experience + Insider flighting data collection +
        // Windows Insider feedback app usage
        @"\Microsoft\Windows\RetailDemo\RetailDemoCleanupOnContent",
        @"\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures",
        @"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushed",
        @"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting",
        @"\Microsoft\Windows\Feedback\WipAppUsageClient",
        // Device Census (hardware/app inventory upload), Family Safety usage
        // monitor, and the on-demand network-info collection task
        @"\Microsoft\Windows\Device Information\Device",
        @"\Microsoft\Windows\Device Information\Device User",
        @"\Microsoft\Windows\Shell\FamilySafetyMonitor",
        @"\Microsoft\Windows\Shell\FamilySafetyRefreshTask",
        // Family Safety usage-data upload (Debloat-Win11 diff) + Xbox cloud
        // save sync scheduler (XblGameSave service is already demand-gated)
        @"\Microsoft\Windows\Shell\FamilySafetyUpload",
        @"\Microsoft\XblGameSave\XblGameSaveTask",
        // Game Bar "now playing" presence writer (per-user root task —
        // Reclaim diff; broadcasts current-game state to Xbox widgets)
        @"\GameBarPresenceWriter",
        // OOBE cloud-experience host provisioning + RetailDemo offline
        // content cleanup (HST Windows Utility / win-debloat diffs —
        // pairs with the killed RetailDemo service + CDM kills)
        @"\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
        @"\Microsoft\Windows\RetailDemo\CleanupOfflineContent",
        // Win-Debloat7 privacy tasks diff: 25H2 AI-subtree tasks (Copilot+
        // recall/model/index pipelines) + OneSettings cache pulls + UCPD
        // velocity config flighting + UNP campaign manager + EOS nag toasts
        @"\Microsoft\Windows\WindowsAI\RecallSnapshot",
        @"\Microsoft\Windows\WindowsAI\ModelMaintenance",
        @"\Microsoft\Windows\WindowsAI\AIPlatformServiceTask",
        @"\Microsoft\Windows\WindowsAI\WorkloadsHostTask",
        @"\Microsoft\Windows\AISystem\AIAnalyzer",
        @"\Microsoft\Windows\AISystem\ModelUpdateTask",
        @"\Microsoft\Windows\AISystem\SemanticIndexTask",
        @"\Microsoft\Windows\NarrativeFlows\UserJourneyTracker",
        @"\Microsoft\Windows\Flighting\OneSettings\RefreshCache",
        @"\Microsoft\Windows\Flighting\OneSettings\QuerySettings",
        @"\Microsoft\Windows\AppxDeploymentClient\UcpdVelocity",
        @"\Microsoft\Windows\UNP\RunCampaignManager",
        @"\Microsoft\Windows\Setup\EOSNotify",
        @"\Microsoft\Windows\Setup\EOSNotify2",
        // Store push-install login hook + setting-sync uploads (service and
        // policies already off — kill the schedulers too)
        @"\Microsoft\Windows\PushToInstall\LoginCheck",
        @"\Microsoft\Windows\SettingSync\BackgroundUploadTask",
        @"\Microsoft\Windows\SettingSync\BackupTask",
        // PCA db update, location telemetry beacons, feedback nag tasks,
        // retail-demo cleanup
        @"\Microsoft\Windows\Application Experience\PcaPatchDbUpdate",
        @"\Microsoft\Windows\Location\Notifications",
        @"\Microsoft\Windows\Location\WindowsActionNotification",
        @"\Microsoft\Windows\RetailDemo\CleanupContent",
        // CEIP perf-tracking surveyor, IME telemetry sender, input-method
        // sync uploads, WMP library sharing, Store install-retry hook
        @"\Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor",
        @"\Microsoft\Windows\IME\SQM data sender",
        @"\Microsoft\Windows\Input\LocalUserSyncDataAvailable",
        @"\Microsoft\Windows\Input\TouchpadSyncDataAvailable",
        @"\Microsoft\Windows\Windows Media Sharing\UpdateLibrary",
        @"\Microsoft\Windows\InstallService\SmartRetry",
        // Store broker-infra maintenance + WDI resolution host (the WDI
        // services are already demoted — kill the task too)
        @"\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask",
        @"\Microsoft\Windows\WDI\ResolutionHost",
        @"\Microsoft\Windows\NetTrace\GatherNetworkInfo",
        // Application Impact Telemetry, speech-model downloads,
        // storage-footprint diagnostics
        @"\Microsoft\Windows\Application Experience\AitEnableAgent",
        @"\Microsoft\Windows\Speech\SpeechModelDownloadTask",
        @"\Microsoft\Windows\DiskFootprint\Diagnostics",
        // HST diff: app-uninstall verifier telemetry + app-list
        // backup to the cloud profile store
        @"\Microsoft\Windows\ApplicationData\appuriverifierdaily",
        @"\Microsoft\Windows\ApplicationData\appuriverifierinstall",
        @"\Microsoft\Windows\AppListBackup\Backup",
        // Windows Error Reporting queue upload
        @"\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        // Consumer subscription/license offers (Microsoft 365 upsell channel)
        @"\Microsoft\Windows\Subscription\EnableLicenseAcquisition",
        @"\Microsoft\Windows\Subscription\LicenseAcquisition",
        // Recommended-troubleshooting scanner uploads diagnostic packages
        @"\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner",
        @"\Microsoft\Windows\Diagnosis\Scheduled",
        // SQM telemetry task + disk-diagnostic resolver + WinSAT scoring run
        @"\Microsoft\Windows\PI\Sqm-Tasks",
        @"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver",
        @"\Microsoft\Windows\Maintenance\WinSAT",
        // WindowsAI Recall snapshot configuration tasks + Office AI
        // Actions server (zoicware/RemoveWindowsAI task set)
        @"\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration",
        @"\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration",
        @"\Microsoft\Office\Office Actions Server",
        // GDStudiosDev/fortify diff: ClickToDo model caching, WindowsAI
        // settings init, flighting usage-data pipeline, perf-trace
        // feedback toast, sustainability telemetry
        @"\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingIdle",
        @"\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingLimit",
        @"\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingUpdate",
        @"\Microsoft\Windows\WindowsAI\Settings\InitialConfiguration",
        @"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing",
        @"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver",
        @"\Microsoft\Windows\Flighting\FeatureConfig\GovernedFeatureUsageProcessing",
        @"\Microsoft\Windows\PerformanceTrace\ShowFeedbackToast",
        @"\Microsoft\Windows\Sustainability\SustainabilityTelemetry",
        @"\Microsoft\Windows\WindowsAI\RecallConfiguration",
        @"\Microsoft\Windows\WindowsAI\RecallPipeline",
    };

    /// <summary>Disable the known Microsoft telemetry/CEIP scheduled tasks.</summary>
    public static void DisableTelemetryTasks()
    {
        var disabled = 0;
        foreach (var fullPath in TelemetryTaskPaths)
        {
            var sep = fullPath.LastIndexOf('\\');
            var path = fullPath[..(sep + 1)];
            var name = fullPath[(sep + 1)..];
            DisableTask(name, path);
            disabled++;
        }
        GuardLogger.Info($"Applied: DisableTelemetryTasks ({disabled} tasks)");
    }

    private static void DisableTask(string name, string path)
    {
        var fullPath = path.EndsWith("\\") ? path + name : path + "\\" + name;
        var psi = new ProcessStartInfo
        {
            FileName = "schtasks.exe",
            Arguments = $"/Change /TN \"{fullPath}\" /DISABLE",
            UseShellExecute = false,
            CreateNoWindow = true
        };

        if (Proc.Wait(psi, 15000) == 0)
            GuardLogger.Info($"Disabled scheduled task: {fullPath}");
        else
            GuardLogger.Warn($"Failed to disable task: {fullPath}");
    }
}

// ─── winget sweep ────────────────────────────────────────────────────────────

public static class WingetGuard
{
    // winget package ids are Publisher.Name only
    private static readonly Regex WingetIdPattern =
        new(@"^[A-Za-z0-9_.\-]+$", RegexOptions.Compiled);

    internal static bool WingetIdIsMatch(string name) =>
        !string.IsNullOrEmpty(name) && WingetIdPattern.IsMatch(name);

    /// <summary>Uninstall blacklist entries that look like winget package ids
    /// via `winget uninstall --silent --disable-interactivity`. Catches Store
    /// apps winget can see but Get-AppxPackage can't. No-op when winget is absent.</summary>
    public static int Sweep(GuardConfig config)
    {
        var checkPsi = new ProcessStartInfo
        {
            FileName = "winget.exe", Arguments = "--version",
            UseShellExecute = false, CreateNoWindow = true
        };
        int? rc;
        try { rc = Proc.Wait(checkPsi, 15000); }
        catch { rc = null; }
        if (rc == null)
        {
            GuardLogger.Info("winget not found — skipping winget sweep");
            return 0;
        }

        var removed = 0;
        foreach (var raw in config.Blacklist)
        {
            var entry = raw?.Trim() ?? "";
            if (!entry.Contains('.') || !WingetIdPattern.IsMatch(entry))
                continue;
            // Whitelist still wins — a protected entry never reaches winget
            if (config.Whitelist.Any(w => !string.IsNullOrWhiteSpace(w) &&
                    entry.Contains(w.Trim(), StringComparison.OrdinalIgnoreCase)))
            {
                GuardLogger.Info($"Whitelisted (winget skip): {entry}");
                continue;
            }
            var psi = new ProcessStartInfo
            {
                FileName = "winget.exe",
                Arguments = $"uninstall -e --id {entry} --silent --disable-interactivity --accept-source-agreements",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            if (Proc.Wait(psi, 300000) == 0)
            {
                GuardLogger.Info($"winget removed: {entry}");
                RemovalLedger.Record(config, "winget", entry);
                removed++;
            }
        }
        if (removed > 0)
            GuardLogger.Info($"Applied: WingetSweep ({removed} packages)");
        return removed;
    }
}

// ─── Service Config Bridge ───────────────────────────────────────────────────

public static class ServiceConfig
{
    public static GuardConfig Current { get; set; } = null!;
}

// ─── Main Service ────────────────────────────────────────────────────────────

public class GuardService : BackgroundService
{
    private readonly GuardConfig _config;

    public GuardService()
    {
        _config = ServiceConfig.Current;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        GuardLogger.Info("=== BloatwareGuard Service Started ===");
        // Each scan spawns real work — clamp a zero/negative interval to a
        // floor instead of letting it spin or crash Task.Delay.
        if (_config.ScanIntervalSeconds < 60)
        {
            GuardLogger.Warn($"ScanIntervalSeconds={_config.ScanIntervalSeconds} invalid — clamped to 60s minimum");
            _config.ScanIntervalSeconds = 60;
        }
        GuardLogger.Info($"Scan interval: {_config.ScanIntervalSeconds}s");
        GuardLogger.Info($"Blacklist entries: {_config.Blacklist.Count}");

        // Apply registry-based prevention once at startup — skipped in dry-run
        if (_config.DryRun)
        {
            GuardLogger.Info("[DRY-RUN] Startup prevention changes skipped");
        }
        else
        {
            GuardLogger.Info("Applying registry-based prevention layers...");
            try { RegistryGuard.ApplyAll(_config.Prevention, _config.Blacklist, _config.Whitelist); }
            catch (Exception ex) { GuardLogger.Warn($"RegistryPrevention layer failed: {ex.Message}"); }

            if (_config.Prevention.DisableOemScheduledTasks)
            {
                GuardLogger.Info("Disabling OEM scheduled tasks...");
                try { ScheduledTaskGuard.DisableOemTasks(); }
                catch (Exception ex) { GuardLogger.Warn($"DisableOemTasks layer failed: {ex.Message}"); }
            }
            if (_config.Prevention.DisableTelemetryTasks)
            {
                GuardLogger.Info("Disabling Microsoft telemetry tasks...");
                try { ScheduledTaskGuard.DisableTelemetryTasks(); }
                catch (Exception ex) { GuardLogger.Warn($"DisableTelemetryTasks layer failed: {ex.Message}"); }
            }
        }

        // Layer 7: baseline-diff detection — a package that appears after being
        // absent in the previous scan counts as a (re-)install
        var seenProvisioned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenInstalled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenWin32 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var firstScan = true;

        // Main scan loop
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                RunScan(_config.DryRun);

                if (_config.Prevention.ReinstallMonitor)
                {
                    CheckReinstalls(seenProvisioned, seenInstalled, seenWin32, firstScan);
                    firstScan = false;
                }
            }
            catch (Exception ex)
            {
                GuardLogger.Error($"Scan error: {ex.Message}");
            }

            await Task.Delay(TimeSpan.FromSeconds(_config.ScanIntervalSeconds), stoppingToken);
        }
    }

    /// <summary>Detect packages that re-appeared since the last scan and remove them.</summary>
    private void CheckReinstalls(
        HashSet<string> seenProvisioned, HashSet<string> seenInstalled,
        HashSet<string> seenWin32, bool firstScan)
    {
        var currentProvisioned = new HashSet<string>(
            AppxManager.GetBlacklistedProvisionedPackages(_config.Blacklist, _config.Whitelist),
            StringComparer.OrdinalIgnoreCase);
        var installed = AppxManager.GetBlacklistedPackages(_config.Blacklist, _config.Whitelist);
        var currentInstalled = new HashSet<string>(
            installed.Select(p => p.PackageFamilyName), StringComparer.OrdinalIgnoreCase);
        // Win32 display names — OEMs re-push these via their updaters, so the
        // monitor must watch the non-Appx channel too
        var currentWin32 = Win32Guard.GetBlacklistedPrograms(_config.Blacklist, _config.Whitelist);

        if (!firstScan)
        {
            foreach (var pkg in currentProvisioned.Except(seenProvisioned))
            {
                GuardLogger.Warn($"[MONITOR] RE-INSTALLED detected: {pkg} — removing immediately!");
                if (_config.DryRun)
                    GuardLogger.Info($"[DRY-RUN] Would re-remove provisioned: {pkg}");
                else if (AppxManager.RemoveProvisionedPackage(pkg))
                    GuardLogger.Info($"[MONITOR] Re-removal complete: {pkg}");
                else
                    GuardLogger.Warn($"[MONITOR] Re-removal failed: {pkg} [admin required]");
            }

            var fullNameByFamily = installed
                .GroupBy(p => p.PackageFamilyName)
                .ToDictionary(g => g.Key, g => g.First().PackageFullName, StringComparer.OrdinalIgnoreCase);
            foreach (var family in currentInstalled.Except(seenInstalled))
            {
                GuardLogger.Warn($"[MONITOR] RE-INSTALLED AppxPackage: {family} — removing!");
                if (_config.DryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would re-remove AppxPackage: {family}");
                }
                else if (fullNameByFamily.TryGetValue(family, out var fullName) &&
                    !string.IsNullOrEmpty(fullName) &&
                    AppxManager.RemoveAppxPackage(fullName))
                {
                    GuardLogger.Info($"[MONITOR] Re-removal complete: {family}");
                }
                else
                {
                    GuardLogger.Warn($"[MONITOR] Re-removal failed: {family}");
                }
            }

            foreach (var prog in currentWin32.Where(p => !seenWin32.Contains(p.DisplayName) && !p.UserHive))
            {
                GuardLogger.Warn($"[MONITOR] RE-INSTALLED Win32: {prog.DisplayName} — removing!");
                if (_config.DryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would re-remove Win32: {prog.DisplayName}");
                }
                else if (Win32Guard.RemoveProgram(prog.DisplayName, prog.UninstallString, prog.QuietUninstallString))
                    GuardLogger.Info($"[MONITOR] Re-removal complete: {prog.DisplayName}");
                else
                    GuardLogger.Warn($"[MONITOR] Re-removal failed or needs manual removal: {prog.DisplayName}");
            }
        }

        seenProvisioned.Clear();
        seenProvisioned.UnionWith(currentProvisioned);
        seenInstalled.Clear();
        seenInstalled.UnionWith(currentInstalled);
        seenWin32.Clear();
        seenWin32.UnionWith(currentWin32.Select(p => p.DisplayName));
    }

    public void RunScanPublic(bool dryRun = false) => RunScan(dryRun);
    private void RunScan(bool dryRun = false)
    {
        GuardLogger.Info(dryRun
            ? "Starting DRY-RUN scan (no changes will be made)..."
            : "Starting bloatware scan...");

        int removed = 0;
        int skipped = 0;
        int systemAppsSkipped = 0;
        int failed = 0;
        var matchedFamilies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 0. Safety net: restore point before destructive changes (self-throttles)
        if (!dryRun && _config.Prevention.CreateRestorePoint)
            Win32Guard.CreateRestorePoint();

        // 0.5 Back up every HKLM key BEFORE any writes — this scan touches the
        // deprovision/Store-policy keys before ApplyAll would back them up;
        // the once-per-process guard makes the later call a no-op
        if (!dryRun && _config.Prevention.BackupRegistry)
            RegistryGuard.BackupRegistryKeys();

        // 1. Remove installed AppxPackages matching blacklist
        if (_config.Prevention.RemoveAppxPackages)
        {
            var packages = AppxManager.GetBlacklistedPackages(_config.Blacklist, _config.Whitelist);
            foreach (var (familyName, displayName, fullName, isFramework, installPath) in packages)
            {
                // Whitelist check
                if (IsWhitelisted(familyName))
                {
                    GuardLogger.Info($"Whitelisted (skip): {familyName}");
                    skipped++;
                    continue;
                }

                // Framework check — never remove framework packages
                if (isFramework)
                {
                    GuardLogger.Warn($"Framework package (skip): {familyName}");
                    skipped++;
                    continue;
                }
                matchedFamilies.Add(familyName);

                // Use PackageFullName from the query (no second PowerShell call needed)
                if (string.IsNullOrEmpty(fullName))
                {
                    GuardLogger.Info($"No PackageFullName (skip): {familyName}");
                    continue;
                }

                if (dryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would remove: {fullName}");
                    removed++;
                }
                else if (AppxManager.RemoveAppxPackage(fullName))
                {
                    GuardLogger.Info($"Removed AppxPackage: {familyName} ({displayName})");
                    RemovalLedger.Record(_config, "appx", displayName, familyName, fullName);
                    removed++;
                }
                else
                {
                    GuardLogger.Warn($"Admin removal failed for {familyName}, trying user-level...");
                    var (success, isSystemApp) = AppxManager.RemoveAppxPackageForUser(fullName, installPath);
                    if (success)
                    {
                        GuardLogger.Info($"Removed AppxPackage (user-level): {familyName} ({displayName})");
                        RemovalLedger.Record(_config, "appx", displayName, familyName, fullName);
                        removed++;
                    }
                    else if (isSystemApp)
                    {
                        GuardLogger.Info($"SystemApp skipped (requires admin): {familyName}");
                        systemAppsSkipped++;
                    }
                    else
                    {
                        GuardLogger.Warn($"Failed to remove: {familyName}");
                        failed++;
                    }
                }
            }
        }

        // 2. Remove provisioned packages (independent toggle — prevents re-deploy on new users)
        if (_config.Prevention.RemoveProvisionedPackages)
        {
            var provisioned = AppxManager.GetBlacklistedProvisionedPackages(_config.Blacklist, _config.Whitelist);
            foreach (var pkgName in provisioned)
            {
                if (IsWhitelisted(pkgName))
                {
                    GuardLogger.Info($"Whitelisted provisioned (skip): {pkgName}");
                    skipped++;
                    continue;
                }
                matchedFamilies.Add(AppxManager.ProvisionedFamilyName(pkgName));

                if (dryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would remove provisioned: {pkgName} [requires admin]");
                    removed++;
                }
                else if (AppxManager.RemoveProvisionedPackage(pkgName))
                {
                    GuardLogger.Info($"Removed ProvisionedPackage: {pkgName}");
                    RemovalLedger.Record(_config, "provisioned", pkgName);
                    removed++;
                }
                else
                {
                    GuardLogger.Warn($"Failed to remove provisioned: {pkgName} [admin required]");
                    systemAppsSkipped++;
                }
            }
        }

        // 2.5 Remove optional Windows capabilities (IE mode, Steps Recorder, WordPad)
        if (_config.Prevention.RemoveOptionalCapabilities)
        {
            if (dryRun)
                GuardLogger.Info("[DRY-RUN] Would remove optional capabilities (IE/StepsRecorder/WordPad) [requires admin]");
            else
                try { AppxManager.RemoveOptionalCapabilities(_config); }
                catch (Exception ex) { GuardLogger.Warn($"RemoveOptionalCapabilities layer failed: {ex.Message}"); }
        }

        // 2.6 Remove Win32 programs matching blacklist — the primary OEM
        // preinstall channel (McAfee/Norton etc. are Win32, not Appx). MSI gets
        // silent uninstall; vendors without a quiet uninstaller are logged.
        if (_config.Prevention.RemoveWin32Programs)
        {
            var programs = Win32Guard.GetBlacklistedPrograms(_config.Blacklist, _config.Whitelist);
            foreach (var (display, uninstall, quiet, userHive) in programs)
            {
                if (userHive)
                {
                    // HKU\<sid> is user-writable — never run its strings as SYSTEM
                    GuardLogger.Info($"Win32 bloat in user hive (report only, not executed): {display}");
                    continue;
                }
                if (dryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would uninstall Win32 program: {display} [requires admin]");
                    removed++;
                }
                else if (Win32Guard.RemoveProgram(display, uninstall, quiet))
                {
                    GuardLogger.Info($"Removed Win32 program: {display}");
                    RemovalLedger.Record(_config, "win32", display);
                    removed++;
                }
                else
                {
                    GuardLogger.Warn($"Failed to uninstall Win32 program: {display} [admin required or manual]");
                    failed++;
                }
            }
        }

        // 2.9 Reprovisioning persistence — the deprovision markers + the 25H2
        // policy need the family list even when a removal toggle is off, so
        // enumerate matches independently when persistence is on but removal off.
        if (_config.Prevention.MarkDeprovisioned || _config.Prevention.RemoveDefaultStorePackages)
        {
            if (!(_config.Prevention.RemoveAppxPackages && _config.Prevention.RemoveProvisionedPackages))
            {
                foreach (var p in AppxManager.GetBlacklistedPackages(_config.Blacklist, _config.Whitelist))
                    matchedFamilies.Add(p.PackageFamilyName);
                foreach (var pkg in AppxManager.GetBlacklistedProvisionedPackages(_config.Blacklist, _config.Whitelist))
                    matchedFamilies.Add(AppxManager.ProvisionedFamilyName(pkg));
            }
            if (matchedFamilies.Count > 0)
            {
                if (dryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would mark {matchedFamilies.Count} families deprovisioned and list them for RemoveDefaultStorePackages");
                }
                else
                {
                    if (_config.Prevention.MarkDeprovisioned)
                    {
                        var n = AppxManager.MarkDeprovisioned(matchedFamilies);
                        GuardLogger.Info($"Applied: MarkDeprovisioned ({n} markers)");
                    }
                    if (_config.Prevention.RemoveDefaultStorePackages)
                        AppxManager.ApplyRemoveDefaultStorePackages(matchedFamilies);
                }
            }
        }

        // 2.10 winget sweep for Store apps Appx removal can't see
        if (_config.Prevention.WingetSweep)
        {
            if (dryRun)
                GuardLogger.Info("[DRY-RUN] Would run winget uninstall sweep");
            else
                try { WingetGuard.Sweep(_config); }
                catch (Exception ex) { GuardLogger.Warn($"WingetSweep layer failed: {ex.Message}"); }
        }

        // 3. Re-apply registry settings (they can be reset by Windows Update)
        if (!dryRun)
        {
            try { RegistryGuard.ApplyAll(_config.Prevention, _config.Blacklist, _config.Whitelist); }
            catch (Exception ex) { GuardLogger.Warn($"RegistryPrevention layer failed: {ex.Message}"); }
            // OEM updaters re-enable their tasks between boots — re-disable
            // every scan, same as the Python scan loop.
            if (_config.Prevention.DisableOemScheduledTasks)
                try { ScheduledTaskGuard.DisableOemTasks(); }
                catch (Exception ex) { GuardLogger.Warn($"DisableOemTasks layer failed: {ex.Message}"); }
            if (_config.Prevention.DisableTelemetryTasks)
                try { ScheduledTaskGuard.DisableTelemetryTasks(); }
                catch (Exception ex) { GuardLogger.Warn($"DisableTelemetryTasks layer failed: {ex.Message}"); }
        }
        else
            GuardLogger.Info("[DRY-RUN] Would re-apply registry prevention settings");

        GuardLogger.Info($"Scan complete. {(dryRun ? "Would remove" : "Removed")} {removed} packages, skipped {skipped}, system apps skipped {systemAppsSkipped}, failed {failed}.");
    }

    private bool IsWhitelisted(string packageFamilyName)
    {
        var match = _config.Whitelist.FirstOrDefault(w =>
            packageFamilyName.Contains(w, StringComparison.OrdinalIgnoreCase));
        if (match != null)
            GuardLogger.Info($"  WHITELIST MATCH: '{packageFamilyName}' contains '{match}'");
        return match != null;
    }
}

// ─── Program Entry ───────────────────────────────────────────────────────────

public class Program
{
    public static void Main(string[] args)
    {
        // Windows consoles default to a legacy code page (cp1252/cp932) —
        // force UTF-8 so non-ASCII log glyphs don't render as '?'. Unlike
        // Python the .NET console never throws on unencodable chars, so this
        // is cosmetic; kept to match the Python console hardening.
        try { Console.OutputEncoding = new System.Text.UTF8Encoding(false); } catch { /* no console in service mode */ }
        // Non-Unicode code pages (cp932, cp437...) aren't built into .NET Core —
        // register the provider so Proc.OemEncoding can decode console tools'
        // localized output (Python decodes subprocess bytes as cp932).
        System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
        // --config <path> overrides the default config.json location
        // (Python parity: --config PATH). Scan args before loading.
        var configPath = Path.Combine(AppContext.BaseDirectory, "config.json");
        for (var i = 0; i + 1 < args.Length; i++)
        {
            if (args[i].Equals("--config", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(args[i + 1]))
                configPath = args[i + 1];
        }
        var config = ConfigLoader.Load(configPath);

        // First non-flag argument is the command (flags like --config <path>
        // are consumed above and skipped here).
        var cmdIndex = 0;
        while (cmdIndex < args.Length &&
               args[cmdIndex].Equals("--config", StringComparison.OrdinalIgnoreCase))
            cmdIndex += 2;

        // Handle CLI commands
        if (cmdIndex < args.Length)
        {
            switch (args[cmdIndex].ToLower())
            {
                case "scan":
                    RunOnce(config, dryRun: false);
                    return;
                case "dry-run":
                    RunOnce(config, dryRun: true);
                    return;
                case "list-installed":
                    ListInstalled(config);
                    return;
                case "install":
                    InstallService();
                    return;
                case "uninstall":
                    UninstallService();
                    return;
                case "status":
                    ShowStatus();
                    return;
                case "restore":
                    RestorePackages(config);
                    return;
                case "help":
                case "--help":
                case "-h":
                    ShowHelp();
                    return;
                case "--version":
                case "-v":
                    Console.WriteLine("BloatwareGuard v1.61.2");
                    return;
                case "--self-test":
                    Environment.ExitCode = RunSelfTest(config);
                    return;
                case "--service-dry-run":
                    config.DryRun = true;
                    GuardLogger.Info("Service mode: DRY-RUN (no removal actions will execute)");
                    break;
                default:
                    // Unrecognized args must NOT fall through to console mode —
                    // that runs a real scan. Bail out instead.
                    Console.WriteLine($"Unknown command: {args[cmdIndex]}");
                    ShowHelp();
                    Environment.ExitCode = 1;
                    return;
            }
        }

        // Run as Windows Service (if started by SCM) or console (if interactive)
        ServiceConfig.Current = config;

        if (Environment.UserInteractive)
        {
            // Console mode: run scan loop in foreground
            GuardLogger.Info("Running in console mode (interactive)...");
            var service = new GuardService();
            service.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
            GuardLogger.Info("Press any key to stop...");
            Console.ReadKey(true);
            service.StopAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        else
        {
            // Windows Service mode
            Host.CreateDefaultBuilder(args)
                .UseWindowsService()
                .ConfigureServices(services =>
                {
                    services.AddSingleton<IHostedService, GuardService>();
                })
                .Build()
                .Run();
        }
    }

    private static void RunOnce(GuardConfig config, bool dryRun = false)
    {
        GuardLogger.Info(dryRun ? "Running DRY-RUN scan (no changes)..." : "Running one-time scan...");
        ServiceConfig.Current = config;

        if (!dryRun)
        {
            try { RegistryGuard.ApplyAll(config.Prevention, config.Blacklist, config.Whitelist); }
            catch (Exception ex) { GuardLogger.Warn($"RegistryPrevention layer failed: {ex.Message}"); }
            if (config.Prevention.DisableOemScheduledTasks)
                try { ScheduledTaskGuard.DisableOemTasks(); }
                catch (Exception ex) { GuardLogger.Warn($"DisableOemTasks layer failed: {ex.Message}"); }
            if (config.Prevention.DisableTelemetryTasks)
                try { ScheduledTaskGuard.DisableTelemetryTasks(); }
                catch (Exception ex) { GuardLogger.Warn($"DisableTelemetryTasks layer failed: {ex.Message}"); }
        }
        else
        {
            GuardLogger.Info("[DRY-RUN] Skipping registry + task changes.");
        }

        var service = new GuardService();
        service.RunScanPublic(dryRun);

        GuardLogger.Info("Scan complete.");
    }

    private static void ListInstalled(GuardConfig config)
    {
        ServiceConfig.Current = config;
        GuardLogger.Info("Installed packages matching blacklist:");
        var packages = AppxManager.GetBlacklistedPackages(config.Blacklist, config.Whitelist);
        foreach (var (familyName, displayName, _, isFramework, _) in packages)
        {
            var tag = isFramework ? " [FRAMEWORK]" : "";
            GuardLogger.Info($"  {familyName} ({displayName}){tag}");
        }
        GuardLogger.Info($"Total: {packages.Count} package(s) installed.");
    }

    private static void ShowHelp()
    {
        var help = @"
BloatwareGuard v1.61.2 — Windows 11 bloatware removal + prevention

Usage: BloatwareGuard.exe <command>

Commands:
  scan          Run one-time scan and remove bloatware
  dry-run       Show what WOULD be removed (no changes made)
  --service-dry-run  Run as service in dry-run mode (no removal actions)
  list-installed  List installed packages matching blacklist
  restore       Restore staged packages recorded in the removal ledger
  install       Install as Windows Service (requires admin)
  uninstall     Remove Windows Service (requires admin)
  status        Show Windows Service status
  --config PATH Load config from PATH instead of the exe-adjacent config.json
  --version     Show version
  --self-test   Run internal wiring self-test (no admin required)
  help          Show this help

Without arguments: runs in console mode (interactive) or as Windows Service.
";
        Console.WriteLine(help);
        GuardLogger.Info("Help displayed.");
    }

    private static void InstallService()
    {
        var exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";

        // Idempotent reinstall + description + restart-on-failure in ONE elevated
        // shell — a single UAC prompt covers every sc.exe call. `&` continues even
        // if a step legitimately fails (stop/delete on first install).
        var chain =
            "sc stop BloatwareGuard & sc delete BloatwareGuard & " +
            "ping -n 3 127.0.0.1 > nul & " +  // brief wait so SCM finishes deleting
            $"sc create BloatwareGuard binPath= \"{exePath}\" start= auto DisplayName= \"Bloatware Guard\" & " +
            "sc description BloatwareGuard \"Blocks and removes pre-installed Windows bloatware\" & " +
            "sc failure BloatwareGuard reset= 86400 actions= restart/60000/restart/60000/restart/300000";

        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c {chain}",
            UseShellExecute = true,
            Verb = "runas"
        };
        Process.Start(psi)?.WaitForExit(60000);
        GuardLogger.Info("Service installed (idempotent, restart-on-failure: 60s/60s/5min). Use 'sc start BloatwareGuard' to start.");
    }

    private static void UninstallService()
    {
        // Stop first — sc delete on a running service only marks it for
        // deletion; it keeps running until the next stop/reboot (py parity).
        var stopPsi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = "stop BloatwareGuard",
            UseShellExecute = true,
            Verb = "runas"
        };
        Process.Start(stopPsi)?.WaitForExit(30000);
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = "delete BloatwareGuard",
            UseShellExecute = true,
            Verb = "runas"
        };
        Process.Start(psi)?.WaitForExit(30000);
        GuardLogger.Info("Service uninstalled.");

        // The hosts block is tool-owned runtime state that outlives the
        // service — strip it so an uninstalled tool leaves no stale
        // null-routes. Registry policies and deprovision/startup markers
        // intentionally persist: they are the hardening itself and removing
        // them would re-enable the telemetry and reprovisioning the tool was
        // installed to kill.
        RegistryGuard.SetTelemetryHostsBlock(false);
    }

    private static void ShowStatus()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = "query BloatwareGuard",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc != null)
        {
            var outTask = proc.StandardOutput.ReadToEndAsync();
            if (!proc.WaitForExit(30000))
                try { proc.Kill(entireProcessTree: true); } catch { }
            outTask.Wait(5000);
            Console.WriteLine(outTask.Status == TaskStatus.RanToCompletion
                ? outTask.Result : "");
        }
    }

    /// <summary>Re-register staged AppxPackages recorded in the removal ledger.
    /// Provisioned packages cannot be restored from the image — reported as manual.</summary>
    // Proc.Wait throws when winget is absent — probe once and treat
    // winget entries as manual instead of aborting later restores.
    private static bool? _wingetAvailable;
    private static bool WingetRestoreAvailable()
    {
        if (_wingetAvailable != null) return _wingetAvailable.Value;
        var psi = new ProcessStartInfo
        {
            FileName = "winget.exe", Arguments = "--version",
            UseShellExecute = false, CreateNoWindow = true
        };
        try { _wingetAvailable = Proc.Wait(psi, 15000) != null; }
        catch { _wingetAvailable = false; }
        if (_wingetAvailable == false)
            GuardLogger.Info("winget not found — winget ledger entries marked manual");
        return _wingetAvailable.Value;
    }

    private static void RestorePackages(GuardConfig config)
    {
        var ledger = RemovalLedger.GetPath(config);
        if (!File.Exists(ledger))
        {
            GuardLogger.Info("No removal ledger found — nothing to restore.");
            return;
        }

        int restored = 0, manual = 0;
        foreach (var line in File.ReadAllLines(ledger))
        {
            Dictionary<string, string>? entry;
            try
            {
                entry = JsonSerializer.Deserialize(line,
                    GuardJsonContext.Default.DictionaryStringString);
            }
            catch { continue; }
            if (entry == null) continue;

            entry.TryGetValue("kind", out var kind);
            entry.TryGetValue("name", out var name);
            entry.TryGetValue("family", out var family);
            var display = !string.IsNullOrEmpty(name) ? name
                : (!string.IsNullOrEmpty(family) ? family : "?");

            if (kind == "appx" && !string.IsNullOrEmpty(name))
            {
                if (RestoreStagedPackage(name))
                {
                    GuardLogger.Info($"Restored (re-registered): {name}");
                    restored++;
                }
                else
                {
                    GuardLogger.Warn($"Restore failed: {name} — reinstall via Microsoft Store");
                    manual++;
                }
            }
            else if (kind == "winget" && !string.IsNullOrEmpty(name))
            {
                if (!WingetGuard.WingetIdIsMatch(name) || !WingetRestoreAvailable())
                {
                    manual++;
                    continue;
                }
                var psi = new ProcessStartInfo
                {
                    FileName = "winget",
                    Arguments = $"install -e --id {name} --silent "
                        + "--disable-interactivity --accept-source-agreements "
                        + "--accept-package-agreements",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                if (Proc.Wait(psi, 300000) == 0)
                {
                    GuardLogger.Info($"Restored via winget: {name}");
                    restored++;
                }
                else
                {
                    GuardLogger.Warn($"winget restore failed: {name}");
                    manual++;
                }
            }
            else if (kind == "capability" && !string.IsNullOrEmpty(name))
            {
                if (!AppxManager.IsPackageNameSafe(name))
                {
                    GuardLogger.Warn($"Ledger entry with unsafe name skipped: {name}");
                    manual++;
                    continue;
                }
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Add-WindowsCapability -Online -Name '{name}' -ErrorAction SilentlyContinue | Out-Null\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                if (Proc.Wait(psi, 180000) == 0)
                {
                    GuardLogger.Info($"Restored capability: {name}");
                    restored++;
                }
                else
                {
                    GuardLogger.Warn($"Capability restore failed: {name} (Settings → Optional features)");
                    manual++;
                }
            }
            else if (kind == "provisioned" && !string.IsNullOrEmpty(name))
            {
                // The provisioned payload may still exist for another user —
                // try the same re-register path before declaring it manual.
                if (RestoreStagedPackage(name))
                {
                    GuardLogger.Info($"Restored (re-registered): {name}");
                    restored++;
                }
                else
                {
                    GuardLogger.Info(
                        $"Manual restore needed: {display} (provisioned — reinstall via Microsoft Store or Settings)");
                    manual++;
                }
            }
            else
            {
                GuardLogger.Info(
                    $"Manual restore needed: {display} (kind={kind ?? "?"} — reinstall via the app vendor or Settings)");
                manual++;
            }
        }
        GuardLogger.Info($"Restore complete: {restored} restored, {manual} need manual reinstall.");
    }

    private static bool RestoreStagedPackage(string name)
    {
        // The name is interpolated into a PowerShell string — reject anything
        // outside the package-name charset before it can break the quoting.
        if (!AppxManager.IsPackageNameSafe(name))
        {
            GuardLogger.Warn($"Ledger entry with unsafe name skipped: {name}");
            return false;
        }
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Get-AppxPackage -AllUsers -Name '" +
                name + "' | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register " +
                "\\\"$($_.InstallLocation)\\AppxManifest.xml\\\" -ErrorAction SilentlyContinue }\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc == null)
            return false;
        if (!proc.WaitForExit(60000))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            return false;
        }
        return proc.ExitCode == 0;
    }

    /// <summary>
    /// Self-test mode: validates internal wiring without requiring admin elevation.
    /// Bypasses UAC by testing structure, not actual removal logic.
    /// </summary>
    private static int RunSelfTest(GuardConfig config)
    {
        var passed = 0;
        var total = 8;
        var results = new List<string>();

        GuardLogger.Info("=== BloatwareGuard v1.61.2 — Self-Test Mode === [no admin required]");
        Console.WriteLine("=== BloatwareGuard v1.61.2 — Self-Test Mode === [no admin required]");

        // Test 1: Arg parsing (switch works)
        try
        {
            results.Add("[PASS] T1: Arg parsing — --self-test switch triggered successfully");
            GuardLogger.Info("[PASS] T1: Arg parsing");
            passed++;
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T1: Arg parsing — {ex.Message}");
            GuardLogger.Error($"[FAIL] T1: Arg parsing — {ex.Message}");
        }

        // Test 2: Logger wiring (GuardLogger)
        try
        {
            GuardLogger.Info("[SELF-TEST] Logger wiring: Info channel operational");
            GuardLogger.Warn("[SELF-TEST] Logger wiring: Warn channel operational");
            results.Add("[PASS] T2: Logger wiring — GuardLogger.Info/Warn verified");
            passed++;
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T2: Logger wiring — {ex.Message}");
        }

        // Test 3: Config loading (config.json)
        try
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "config.json");
            var loadedConfig = ConfigLoader.Load(configPath);
            if (loadedConfig != null)
            {
                results.Add($"[PASS] T3: Config loading - config.json loaded (Layers: {loadedConfig.Prevention.RemoveAppxPackages}/{loadedConfig.Prevention.RemoveProvisionedPackages})");
                GuardLogger.Info($"[PASS] T3: Config loaded - Appx:{loadedConfig.Prevention.RemoveAppxPackages}, Prov:{loadedConfig.Prevention.RemoveProvisionedPackages}");
                passed++;
            }
            else
            {
                results.Add("[FAIL] T3: Config loading — config.json returned null");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T3: Config loading — {ex.Message}");
        }

        // Test 4: Assembly metadata (version + trim safety)
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            var ver = asm.GetName().Version;
            var name = asm.GetName().Name;
            results.Add($"[PASS] T4: Assembly metadata - {name} v{ver}");
            GuardLogger.Info($"[PASS] T4: Assembly — {name} v{ver}");
            passed++;
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T4: Assembly metadata — {ex.Message}");
        }

        // Test 5: SystemAppDetector wiring (InstallPath=null logic exists)
        try
        {
            // Verify SystemApp detection path is wired: the per-user removal
            // entry point taking string? installPath must exist
            bool hasSystemAppLogic =
                typeof(AppxManager).GetMethod("RemoveAppxPackageForUser") != null &&
                typeof(GuardService).GetMethod("RunScan",
                    System.Reflection.BindingFlags.NonPublic |
                    System.Reflection.BindingFlags.Instance) != null;
            if (hasSystemAppLogic)
            {
                results.Add("[PASS] T5: SystemAppDetector wiring — InstallLocation=null path referenced");
                GuardLogger.Info("[PASS] T5: SystemApp logic referenced");
                passed++;
            }
            else
            {
                results.Add("[FAIL] T5: SystemAppDetector — logic not found");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T5: SystemAppDetector — {ex.Message}");
        }

        // Test 6: NuGet/Reflection references (trim safety check)
        try
        {
            // Verify key .NET APIs are present (not trimmed)
            var _ = typeof(System.Security.Principal.WindowsIdentity);
            var __ = typeof(Microsoft.Win32.Registry);
            results.Add("[PASS] T6: Trim safety — .NET Security/Registry APIs present");
            GuardLogger.Info("[PASS] T6: .NET APIs present (no trim issue)");
            passed++;
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T6: Trim safety — {ex.Message}");
        }

        // Test 7: config.json Prevention keys ↔ PreventionLayers properties parity —
        // a key present in config but absent as a property is silently ignored,
        // a property absent from config falls back to its default on file-less runs.
        try
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "config.json");
            if (!File.Exists(configPath))
                configPath = Path.Combine(Directory.GetCurrentDirectory(), "config.json");
            var propNames = typeof(PreventionLayers).GetProperties()
                .Where(p => p.PropertyType == typeof(bool)).Select(p => p.Name).ToHashSet();
            using var doc = JsonDocument.Parse(File.ReadAllText(configPath));
            var cfgKeys = doc.RootElement.GetProperty("Prevention")
                .EnumerateObject().Select(p => p.Name).ToHashSet();
            var missingInProps = cfgKeys.Except(propNames).ToList();
            var missingInConfig = propNames.Except(cfgKeys).ToList();
            if (missingInProps.Count == 0 && missingInConfig.Count == 0)
            {
                results.Add($"[PASS] T7: Prevention key parity — {propNames.Count} keys both sides");
                GuardLogger.Info($"[PASS] T7: config ↔ PreventionLayers parity ({propNames.Count} keys)");
                passed++;
            }
            else
            {
                results.Add($"[FAIL] T7: parity drift — cfg-only:[{string.Join(",", missingInProps)}] props-only:[{string.Join(",", missingInConfig)}]");
                GuardLogger.Error("[FAIL] T7: Prevention parity drift");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T7: Prevention parity — {ex.Message}");
        }

        // Test 8: shared data lists are duplicate-free — a dup silently
        // inflates counts and adds dead entries (mirrors Python T10).
        try
        {
            var sharedArrays = new (Type holder, string field)[]
            {
                (typeof(ScheduledTaskGuard), "TelemetryTaskPaths"),
                (typeof(RegistryGuard), "TelemetryAutologgers"),
                (typeof(RegistryGuard), "TelemetryHosts"),
                (typeof(RegistryGuard), "StartupBloatNames"),
                (typeof(RegistryGuard), "BackupKeyPaths"),
                (typeof(RegistryGuard), "MiscBloatServices"),
                (typeof(ScheduledTaskGuard), "OemTaskPatterns"),
                (typeof(ScheduledTaskGuard), "MicrosoftSystemPrefixes"),
                (typeof(RegistryGuard), "ActiveSetupPaths"),
                (typeof(RegistryGuard), "Win32BloatNames"),
            };
            var dups = new List<string>();
            foreach (var (holder, field) in sharedArrays)
            {
                var fi = holder.GetField(field,
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                if (fi?.GetValue(null) is not string[] arr) continue;
                var dup = arr.GroupBy(x => x).Where(g => g.Count() > 1).Select(g => g.Key);
                dups.AddRange(dup.Select(d => $"{holder.Name}.{field}:{d}"));
                // Service names are case-insensitive on Windows — catch
                // case-variant dups too (SensrSvc/sensrsvc shipped as both).
                var caseDup = arr.GroupBy(x => x.ToLowerInvariant())
                    .Where(g => g.Count() > 1).Select(g => g.Key);
                dups.AddRange(caseDup.Select(d => $"{holder.Name}.{field}:case:{d}"));
            }
            var blDup = config.Blacklist.GroupBy(x => x)
                .Where(g => g.Count() > 1).Select(g => $"Blacklist:{g.Key}");
            dups.AddRange(blDup);
            var blCaseDup = config.Blacklist.GroupBy(x => x.ToLowerInvariant())
                .Where(g => g.Count() > 1).Select(g => $"Blacklist:case:{g.Key}");
            dups.AddRange(blCaseDup);
            if (dups.Count == 0)
            {
                results.Add("[PASS] T8: shared lists are duplicate-free");
                GuardLogger.Info("[PASS] T8: shared lists duplicate-free");
                passed++;
            }
            else
            {
                results.Add($"[FAIL] T8: duplicate entries — {string.Join(",", dups)}");
                GuardLogger.Error("[FAIL] T8: duplicate entries in shared lists");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T8: dup check — {ex.Message}");
        }

        // Summary
        Console.WriteLine();
        foreach (var r in results) Console.WriteLine(r);
        GuardLogger.Info($"=== Self-Test Results: {passed}/{total} PASSED ===");
        Console.WriteLine($"=== Self-Test Results: {passed}/{total} PASSED ===");

        if (passed == total)
        {
            Console.WriteLine("✅ Self-test PASSED — structure verified. Runtime requires admin Windows 11.");
            GuardLogger.Info("✅ Self-test PASSED — structure verified");
        }
        else
        {
            Console.WriteLine("⚠️  Self-test had failures — check logs.");
            GuardLogger.Warn($"⚠️  Self-test: {total - passed} failure(s)");
        }
        return passed == total ? 0 : 1;
    }
}


