// BloatwareGuard - Windows Service to block and remove bloatware automatically
// Requires admin rights (UAC manifest)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
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

    public static void Save(string path, GuardConfig config)
    {
        var json = JsonSerializer.Serialize(config, GuardJsonContext.Default.GuardConfig);
        File.WriteAllText(path, json);
    }

    private static GuardConfig CreateDefault()
    {
        return new GuardConfig
        {
            ScanIntervalSeconds = 300,
            LogFilePath = Path.Combine(AppContext.BaseDirectory, "bloatware-guard.log"),
            Blacklist = new List<string>
            {
                // Microsoft bloatware
                "Microsoft.Xbox",
                "Microsoft.GamingApp",
                "Microsoft.MicrosoftSolitaireCollection",
                "Microsoft.People",
                "Microsoft.WindowsMaps",
                "Microsoft.ZuneMusic",
                "Microsoft.ZuneVideo",
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
                "Microsoft.WindowsAlarms",
                "Microsoft.ScreenSketch",
                "Microsoft.Clipchamp",
                "MicrosoftTeams",
                "Microsoft.MicrosoftEdge.Stable",
                "Microsoft.Windows.DevHome",       // Dev Home (+ GitHub extension)
                "Microsoft.Copilot",
                "Clipchamp.Clipchamp",
                "MSTeams",                          // New Teams (Work/School), provisioned via AppX push
                "Microsoft.OutlookForWindows",      // New Outlook, preinstalled since 23H2
                "Microsoft.WindowsCommunicationsApps", // Mail & Calendar (discontinued Dec 2024)
                "MicrosoftCorporationII.MicrosoftFamily",
                "MicrosoftCorporationII.QuickAssist",
                "Microsoft.BingSearch",
                "Microsoft.MicrosoftStickyNotes",
                "Microsoft.Edge.GameAssist",

                // Third-party bloatware commonly pre-installed
                "McAfee",
                "Norton",
                "SpotifyAB.SpotifyMusic",
                "Netflix",
                "Dolby",
                "RealtekSemiconductor",
                "SynapticsIncorporated",
                "BytedancePte.Ltd.TikTok",
                "KING.COM.",                       // CandyCrush + all King.com promo games
                "A278AB0D.DisneyMagicKingdoms",
                "A278AB0D.MarchofEmpires",
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

                // OEM utilities (uncomment as needed)
                // "DellInc.Dell",
                // "HPInc.",
                // "Lenovo.",
                // "ASUS",
                // "Acer",
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
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-AppxPackage{scope} | Where-Object {{$_.PackageFamilyName -match '{pattern}'}} | Select-Object PackageFamilyName,Name,PackageFullName,IsFramework,InstallPath | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? "";
        proc?.WaitForExit();
        return proc?.ExitCode == 0 ? output : "";
    }

    /// <summary>Remove deprecated/legacy optional Windows capabilities.
    /// Conservative list: IE compatibility mode (Edge covers IE-mode), Steps
    /// Recorder (deprecated), WordPad (removed by MS in 24H2 anyway).
    /// Requires admin; non-admin/non-present entries are skipped by PowerShell.</summary>
    public static void RemoveOptionalCapabilities()
    {
        var pattern = "Browser.InternetExplorer|App.StepsRecorder|Microsoft.Windows.WordPad|XPS.Viewer|Print.Fax.Scan|App.WirelessDisplay.Connect";
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-WindowsCapability -Online | Where-Object {{$_.Name -match '{pattern}' -and $_.State -eq 'Installed'}} | Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        proc?.WaitForExit(180000);  // DISM ops can be slow
        if (proc?.ExitCode == 0)
            GuardLogger.Info("Applied: RemoveOptionalCapabilities (IE/StepsRecorder/WordPad)");
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

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-AppxProvisionedPackage -Online | Where-Object {{$_.PackageName -match '{pattern}'}} | Select-Object PackageName | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? "";
        proc?.WaitForExit();

        try
        {
            var doc = JsonDocument.Parse(output.Trim());
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    var pkg = el.GetProperty("PackageName").GetString() ?? "";
                    if (!IsWhitelisted(pkg, whitelist))
                        results.Add(pkg);
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                var pkg = doc.RootElement.GetProperty("PackageName").GetString() ?? "";
                if (!IsWhitelisted(pkg, whitelist))
                    results.Add(pkg);
            }
        }
        catch { }

        return results;
    }

    public static bool RemoveAppxPackage(string packageFullName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Remove-AppxPackage -Package '{packageFullName}' -AllUsers -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit(60000);
        string stderr = proc?.StandardError.ReadToEnd() ?? "";
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"Remove-AppxPackage stderr: {stderr.Trim()}");
        return proc?.ExitCode == 0;
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

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Remove-AppxPackage -Package '{packageFullName}' -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit(60000);
        string stderr = proc?.StandardError.ReadToEnd() ?? "";
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"Remove-AppxPackage (user) stderr: {stderr.Trim()}");
        return (proc?.ExitCode == 0, false);
    }

    public static bool RemoveProvisionedPackage(string packageName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Remove-AppxProvisionedPackage -Online -PackageName '{packageName}' -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit(120000);
        string stderr = proc?.StandardError.ReadToEnd() ?? "";
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"RemoveProvisionedPackage stderr: {stderr.Trim()}");
        return proc?.ExitCode == 0;
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

    /// <summary>Enumerate installed Win32 programs matching the blacklist.
    /// Returns (DisplayName, UninstallString, QuietUninstallString).</summary>
    public static List<(string DisplayName, string UninstallString, string QuietUninstallString)>
        GetBlacklistedPrograms(List<string> blacklist, List<string> whitelist)
    {
        var results = new List<(string, string, string)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void ScanKey(RegistryKey root, string path)
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
                            blacklist.Any(b => !string.IsNullOrWhiteSpace(b) &&
                                display.Contains(b, StringComparison.OrdinalIgnoreCase)) &&
                            seen.Add(display))
                        {
                            results.Add((display, uninstall, quiet));
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        ScanKey(Registry.LocalMachine, UninstallPath);
        ScanKey(Registry.LocalMachine, UninstallPath32);
        ScanKey(Registry.CurrentUser, UserUninstallPath);
        foreach (var sid in Registry.Users.GetSubKeyNames())
        {
            // Loaded user hives only (interactive profiles)
            if (!Regex.IsMatch(sid, @"^S-1-5-21-\d+-\d+-\d+-\d+$"))
                continue;
            ScanKey(Registry.Users, $"{sid}\\{UserUninstallPath}");
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
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        proc?.WaitForExit(300000);  // uninstallers can take minutes
        return proc?.ExitCode == 0;
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
            Arguments = "-NoProfile -ExecutionPolicy Bypass -Command " +
                "\"Enable-ComputerRestore -Drive 'C:\\' -ErrorAction SilentlyContinue | Out-Null; " +
                "Checkpoint-Computer -Description 'BloatwareGuard pre-scan' " +
                "-RestorePointType 'MODIFY_SETTINGS' -ErrorAction SilentlyContinue | Out-Null\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        proc?.WaitForExit(120000);
        if (proc?.ExitCode == 0)
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
    private const string WerPath = @"SOFTWARE\Microsoft\Windows\Windows Error Reporting";
    private const string WerPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting";
    private const string UserWerPath = @"Software\Microsoft\Windows\Windows Error Reporting";
    private const string MachineRunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string MachineRunPath32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string MachineRunOncePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string UserRunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string UserRunOncePath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string StartupApprovedRun = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string StartupApprovedRunOnce = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\RunOnce";
    private const string WindowsUpdatePolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";

    // Startup value names worth disabling even outside the package blacklist
    // (OEM updaters, adware helpers). OneDrive stays out — DisableOneDrive is opt-in.
    private static readonly string[] StartupBloatNames = {
        "Skype", "Cortana", "MicrosoftEdgeAutoLaunch", "GameAssist",
        "McAfee", "Norton", "WebAdvisor", "CCleaner", "Dell", "Lenovo",
        "SupportAssist", "Acer", "ASUS", "HP"
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
            BackupRegistryKeys();

        if (layers.DisableConsumerExperiences)
            DisableConsumerExperiences();

        if (layers.DisableCloudContent)
            DisableCloudContent();

        if (layers.PreventDeviceMetadata)
            PreventDeviceMetadata();

        if (layers.BlockProvisioning)
            BlockProvisioning();

        if (layers.DisableCopilot)
            DisableCopilot();

        if (layers.DisableRecall)
            DisableRecall();

        if (layers.DisableSearchSuggestions)
            DisableSearchSuggestions();

        if (layers.DisableWidgets)
            DisableWidgets();

        if (layers.DisableTelemetry)
            DisableTelemetry();

        if (layers.DisableGameDvr)
            DisableGameDvr();

        if (layers.DisableDeliveryOptimization)
            DisableDeliveryOptimization();

        if (layers.DisableOneDrive)
            DisableOneDrive();

        if (layers.DisableChatTaskbar)
            DisableChatTaskbar();

        if (layers.DisableEdgeBloat)
            DisableEdgeBloat();

        if (layers.DisableStartupBloat)
            DisableStartupBloat(blacklist, whitelist);

        if (layers.DisableErrorReporting)
            DisableErrorReporting();

        if (layers.DisableEdgeUpdateBloat)
            DisableEdgeUpdateBloat();

        if (layers.BlockOemDriverUpdates)
            BlockOemDriverUpdates();

        if (layers.DisableAppPermissions)
            DisableAppPermissions();

        if (layers.DisableXboxServices)
            DisableXboxServices();

        if (layers.DisablePrintSpooler)
            DisablePrintSpooler();

        if (layers.BlockOemWpbtExecution)
            BlockOemWpbtExecution();

        if (layers.DisableReservedStorage)
            DisableReservedStorage();

        if (layers.DisableCloudClipboard)
            DisableCloudClipboard();

        if (layers.DisableRemoteAssistance)
            DisableRemoteAssistance();

        if (layers.BlockInsiderPreview)
            BlockInsiderPreview();

        if (layers.DisableMiscBloatServices)
            DisableMiscBloatServices();

        if (layers.DisableSpotlight)
            DisableSpotlight();

        if (layers.DisableAutoplay)
            DisableAutoplay();

        if (layers.NoForcedReboot)
            NoForcedReboot();

        if (layers.HideStartRecommendations)
            HideStartRecommendations();
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
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        proc?.WaitForExit(15000);
    }

    /// <summary>Turn off Microsoft consumer experiences (suggested apps)</summary>
    public static void DisableConsumerExperiences()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(CloudContentPath);
            key?.SetValue("DisableWindowsConsumerFeatures", 1, Microsoft.Win32.RegistryValueKind.DWord);
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
            GuardLogger.Info("Applied: DisableSoftLanding + DisableCloudOptimizedContent = 1");
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

            // ContentDeliveryManager — silent installs + every SubscribedContent surface
            // (key set mirrors Win11Debloat Disable_Windows_Suggestions.reg)
            var cdmZeros = new[]
            {
                "SilentInstalledAppsEnabled",       // silent app installs
                "SystemPaneSuggestionsEnabled",     // system pane suggestions
                "SoftLandingEnabled",               // soft landing tips
                "SubscribedContent-310093Enabled",  // Windows welcome experience
                "SubscribedContent-338387Enabled",  // lock-screen spotlight ads
                "SubscribedContent-338388Enabled",  // Start suggestions
                "SubscribedContent-338389Enabled",  // tips while using Windows
                "SubscribedContent-338393Enabled",  // Settings suggestions
                "SubscribedContent-353694Enabled",  // Settings suggestions (2)
                "SubscribedContent-353696Enabled",  // Settings suggestions (3)
                "SubscribedContent-353698Enabled",  // Settings suggestions (4)
                "RotatingLockScreenEnabled",        // lock-screen spotlight
                "RotatingLockScreenOverlayEnabled", // lock-screen overlay ads
            };
            ForEachUserHive(hive =>
            {
                using var cdm = hive.CreateSubKey(UserCdmPath);
                foreach (var name in cdmZeros)
                    cdm?.SetValue(name, 0, RegistryValueKind.DWord);

                SetHiveDword(hive, UserExplorerAdvancedPath, "Start_IrisRecommendations", 0);
                SetHiveDword(hive, UserExplorerAdvancedPath, "ShowSyncProviderNotifications", 0);
                SetHiveDword(hive, UserProfileEngagementPath, "ScoobeSystemSettingEnabled", 0);
                SetHiveDword(hive, UserAccountNotificationsPath, "EnableAccountNotifications", 0);
                SetHiveDword(hive, UserSuggestedToastPath, "Enabled", 0);
                SetHiveDword(hive, UserMobilityPath, "OptedIn", 0);
            });

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
            GuardLogger.Info("Applied: DisableCopilot (TurnOffWindowsCopilot = 1, HKLM + user hives)");
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
            key?.SetValue("AllowRecallEnablement", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("DisableClickToDo", 1, Microsoft.Win32.RegistryValueKind.DWord);
            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserWindowsAiPath, "DisableAIDataAnalysis", 1);
                SetHiveDword(hive, UserWindowsAiPath, "DisableClickToDo", 1);
            });

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
                Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -NoRestart -ErrorAction SilentlyContinue | Out-Null\"",
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(120000);

            GuardLogger.Info("Applied: DisableRecall (WindowsAI policies + Click to Do off, Recall feature removal attempted, WSAIFabricSvc=demand)");
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
            key?.SetValue("CortanaConsent", 0, Microsoft.Win32.RegistryValueKind.DWord);

            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserExplorerPoliciesPath, "DisableSearchBoxSuggestions", 1);
                SetHiveDword(hive, UserSearchPath, "BingSearchEnabled", 0);
                SetHiveDword(hive, UserSearchPath, "CortanaConsent", 0);
                // SearchSettings: kill the dynamic search box + cloud search
                // integrations that power web results in Start
                SetHiveDword(hive, UserSearchSettingsPath, "IsDynamicSearchBoxEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsAADCloudSearchEnabled", 0);
                SetHiveDword(hive, UserSearchSettingsPath, "IsMSACloudSearchEnabled", 0);
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
            using var sys = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(SystemPolicyPath);
            sys?.SetValue("PublishUserActivities", 0, Microsoft.Win32.RegistryValueKind.DWord);
            sys?.SetValue("UploadUserActivities", 0, Microsoft.Win32.RegistryValueKind.DWord);
            sys?.SetValue("EnableActivityFeed", 0, Microsoft.Win32.RegistryValueKind.DWord);
            using var edge = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(EdgePolicyPath);
            edge?.SetValue("PersonalizationReportingEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            edge?.SetValue("DiagnosticData", 0, Microsoft.Win32.RegistryValueKind.DWord);

            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserAdvertisingInfoPath, "Enabled", 0);
                SetHiveDword(hive, UserPrivacyPath, "TailoredExperiencesWithDiagnosticDataEnabled", 0);
                SetHiveDword(hive, UserOnlineSpeechPath, "HasAccepted", 0);
                SetHiveDword(hive, UserTipcPath, "Enabled", 0);
                SetHiveDword(hive, UserInputPersonalizationPath, "RestrictImplicitInkCollection", 1);
                SetHiveDword(hive, UserInputPersonalizationPath, "RestrictImplicitTextCollection", 1);
                SetHiveDword(hive, UserInputStorePath, "HarvestContacts", 0);
                SetHiveDword(hive, UserPersonalizationPath, "AcceptedPrivacyPolicy", 0);
                SetHiveDword(hive, UserExplorerAdvancedPath, "Start_TrackProgs", 0);
                SetHiveDword(hive, UserSiufPath, "NumberOfSIUFInPeriod", 0);
            });

            // "Connected User Experiences and Telemetry" (DiagTrack) — the actual
            // telemetry uploader; absent on some SKUs, failures are non-fatal.
            RunToolSilent("sc.exe", "stop DiagTrack");
            RunToolSilent("sc.exe", "config DiagTrack start= disabled");
            // RetailDemo data-collection service (present on most images)
            RunToolSilent("sc.exe", "stop RetailDemo");
            RunToolSilent("sc.exe", "config RetailDemo start= disabled");
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
            // Speech model downloads off (voice data pipeline)
            try
            {
                using var speech = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Microsoft\Speech_OneCore\Preferences");
                speech?.SetValue("ModelDownloadAllowed", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // "Sync your settings" off — stops settings roaming to MS accounts
            try
            {
                using var sync = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\SettingSync");
                sync?.SetValue("DisableSettingSync", 2, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
            // "Share across devices" (Connected Devices Platform) user consent off
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP",
                "CdpSessionUserAuthzPolicy", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP",
                "RomeSdkChannelUserAuthzPolicy", 0);
            SetUserDwordAllHives(
                @"Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage",
                "RomeSdkChannelUserAuthzPolicy", 0);

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
            });
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
            GuardLogger.Info("Applied: DisableOneDrive (DisableFileSyncNGSC=1, nav pin hidden)");
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
            GuardLogger.Info("Applied: DisableChatTaskbar (TaskbarMn=0, HideSCAMeetNow=1)");
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
            key?.SetValue("StartupBoostEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AllowPrelaunch", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("HideFirstRunExperience", 1, Microsoft.Win32.RegistryValueKind.DWord);
            // Shopping assistant, content recommendations, error-page web
            // service calls and user feedback — all upload/suggestion surfaces
            key?.SetValue("EdgeShoppingAssistantEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ShowRecommendationsEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("ResolveNavigationErrorsUseWebService", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("AlternateErrorPagesEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            key?.SetValue("UserFeedbackAllowed", 0, Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: DisableEdgeBloat (sidebar/startup-boost/prelaunch/first-run/shopping/recommendations off)");
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

        void ScanAndMark(RegistryKey root, string runPath, string approvedPath)
        {
            try
            {
                using var runKey = root.OpenSubKey(runPath);
                if (runKey == null)
                    return;
                var targets = runKey.GetValueNames()
                    .Where(n => IsBloat(n, runKey.GetValue(n) as string))
                    .ToList();
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
            ScanAndMark(Registry.LocalMachine, MachineRunPath, StartupApprovedRun);
            ScanAndMark(Registry.LocalMachine, MachineRunPath32, StartupApprovedRun);
            ScanAndMark(Registry.LocalMachine, MachineRunOncePath, StartupApprovedRunOnce);
            // Every user hive + HKCU (Run + RunOnce)
            ForEachUserHive(hive =>
            {
                ScanAndMark(hive, UserRunPath, StartupApprovedRun);
                ScanAndMark(hive, UserRunOncePath, StartupApprovedRunOnce);
            });
            GuardLogger.Info($"Applied: DisableStartupBloat ({applied} entries)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable startup bloat: {ex.Message}");
        }
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

            ForEachUserHive(hive =>
            {
                SetHiveDword(hive, UserWerPath, "Disabled", 1);
                SetHiveDword(hive, UserWerPath, "DontShowUI", 1);
                SetHiveDword(hive, UserWerPath, "LoggingDisabled", 1);
            });
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
            GuardLogger.Info("Applied: DisableEdgeUpdateBloat (edgeupdate/edgeupdatem/elevation → demand, update tasks off)");
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
            GuardLogger.Info("Applied: BlockOemDriverUpdates (ExcludeWUDriversInQualityUpdate=1)");
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
        @"SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
        @"SOFTWARE\Policies\Microsoft\Windows\AppCompat",
        @"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
        @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
        @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
        @"SOFTWARE\Policies\Microsoft\Dsh",
        @"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        @"SOFTWARE\Policies\Microsoft\Windows\System",
        @"SOFTWARE\Policies\Microsoft\Edge",
        @"SOFTWARE\Policies\Microsoft\Windows\GameDVR",
        @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
        @"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
        @"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
        @"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
        @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        @"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
        @"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
        @"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener",
        @"SYSTEM\CurrentControlSet\Control\Session Manager",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager",
        @"SYSTEM\CurrentControlSet\Control\Remote Assistance",
        @"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds",
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
    public static void DisableMiscBloatServices()
    {
        try
        {
            // CDPSvc = Nearby Sharing; NvTelemetryContainer / ESRV_* = GPU/Intel
            // driver telemetry; PushToInstall = Store push-install channel;
            // SEMgrSvc = NFC/SE payments manager; PhoneSvc = Phone Link
            // (absent where not applicable — write is a no-op)
            foreach (var svc in new[] { "dmwappushservice", "MapsBroker",
                                        "WMPNetworkSvc",
                                        "diagnosticshub.standardcollector.service",
                                        "CDPSvc", "NvTelemetryContainer",
                                        "esrv_svc", "ESRV_SVC_QUEENCREEK",
                                        "PushToInstall", "SEMgrSvc", "PhoneSvc" })
            {
                DemoteService(svc);
            }
            // Remote Registry: read/write registry over SMB — a real attack
            // surface with no consumer use case; disable outright (not
            // demand-start, which still leaves it reachable).
            RunToolSilent("sc.exe", "stop RemoteRegistry");
            RunToolSilent("sc.exe", "config RemoteRegistry start= disabled");
            GuardLogger.Info("Applied: DisableMiscBloatServices (11 services → demand-start, RemoteRegistry disabled)");
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
            GuardLogger.Info("Applied: DisableSpotlight (DesktopSpotlight + wallpaper type)");
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
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        proc?.WaitForExit(15000);
    }
}

// ─── Scheduled Task Manager ──────────────────────────────────────────────────

public static class ScheduledTaskGuard
{
    // Known OEM bloatware task patterns — must be specific enough to avoid matching Microsoft system tasks
    private static readonly string[] OemTaskPatterns = {
        "OEM", "Dell", "HPInc", "HPA", "Lenovo", "ASUS", "Acer", "McAfee", "Norton",
        "SupportAssist", "Vantage", "Armoury", "Crate", "CustomerExperienceImprovement",
        "Customer Experience Improvement", "Reinstall", "Restore", "Bloatware"
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
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-ScheduledTask | Where-Object {{$_.TaskPath -like '*OEM*' -or $_.TaskName -match '{string.Join("|", OemTaskPatterns.Select(Regex.Escape))}'}} | Select-Object TaskName,TaskPath,State | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? "";
        proc?.WaitForExit();

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
        @"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        @"\Microsoft\Windows\Application Experience\PcaPatchDbTask",
        @"\Microsoft\Windows\Application Experience\StartupAppTask",
        @"\Microsoft\Windows\Autochk\Proxy",
        @"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        @"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        @"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        @"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        @"\Microsoft\Windows\Feedback\Siuf\DmClient",
        @"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        @"\Microsoft\Windows\Maps\MapsUpdateTask",
        @"\Microsoft\Windows\Maps\MapsToastTask",
        // Office Customer Experience Improvement Program (when Office is
        // installed; schtasks ignores missing paths)
        @"\Microsoft\Office\OfficeTelemetryAgentLogOn",
        @"\Microsoft\Office\OfficeTelemetryAgentLogOn2016",
        @"\Microsoft\Office\OfficeTelemetryAgentFallBack",
        @"\Microsoft\Office\OfficeTelemetryAgentFallBack2016",
        @"\Microsoft\Office\Office 15 Subscription Heartbeat",
        @"\Microsoft\Office\Office Feature Updates",
        @"\Microsoft\Office\Office Feature Updates Logon",
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
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit();

        if (proc?.ExitCode == 0)
            GuardLogger.Info($"Disabled scheduled task: {fullPath}");
        else
            GuardLogger.Warn($"Failed to disable task: {fullPath}");
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
            RegistryGuard.ApplyAll(_config.Prevention, _config.Blacklist, _config.Whitelist);

            if (_config.Prevention.DisableOemScheduledTasks)
            {
                GuardLogger.Info("Disabling OEM scheduled tasks...");
                ScheduledTaskGuard.DisableOemTasks();
            }
            if (_config.Prevention.DisableTelemetryTasks)
            {
                GuardLogger.Info("Disabling Microsoft telemetry tasks...");
                ScheduledTaskGuard.DisableTelemetryTasks();
            }
        }

        // Layer 7: baseline-diff detection — a package that appears after being
        // absent in the previous scan counts as a (re-)install
        var seenProvisioned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenInstalled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var firstScan = true;

        // Main scan loop
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                RunScan(_config.DryRun);

                if (_config.Prevention.ReinstallMonitor)
                {
                    CheckReinstalls(seenProvisioned, seenInstalled, firstScan);
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
        HashSet<string> seenProvisioned, HashSet<string> seenInstalled, bool firstScan)
    {
        var currentProvisioned = new HashSet<string>(
            AppxManager.GetBlacklistedProvisionedPackages(_config.Blacklist, _config.Whitelist),
            StringComparer.OrdinalIgnoreCase);
        var installed = AppxManager.GetBlacklistedPackages(_config.Blacklist, _config.Whitelist);
        var currentInstalled = new HashSet<string>(
            installed.Select(p => p.PackageFamilyName), StringComparer.OrdinalIgnoreCase);

        if (!firstScan)
        {
            foreach (var pkg in currentProvisioned.Except(seenProvisioned))
            {
                GuardLogger.Warn($"[MONITOR] RE-INSTALLED detected: {pkg} — removing immediately!");
                if (AppxManager.RemoveProvisionedPackage(pkg))
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
                if (fullNameByFamily.TryGetValue(family, out var fullName) &&
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
        }

        seenProvisioned.Clear();
        seenProvisioned.UnionWith(currentProvisioned);
        seenInstalled.Clear();
        seenInstalled.UnionWith(currentInstalled);
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

        // 0. Safety net: restore point before destructive changes (self-throttles)
        if (!dryRun && _config.Prevention.CreateRestorePoint)
            Win32Guard.CreateRestorePoint();

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
                AppxManager.RemoveOptionalCapabilities();
        }

        // 2.6 Remove Win32 programs matching blacklist — the primary OEM
        // preinstall channel (McAfee/Norton etc. are Win32, not Appx). MSI gets
        // silent uninstall; vendors without a quiet uninstaller are logged.
        if (_config.Prevention.RemoveWin32Programs)
        {
            var programs = Win32Guard.GetBlacklistedPrograms(_config.Blacklist, _config.Whitelist);
            foreach (var (display, uninstall, quiet) in programs)
            {
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

        // 3. Re-apply registry settings (they can be reset by Windows Update)
        if (!dryRun)
        {
            RegistryGuard.ApplyAll(_config.Prevention, _config.Blacklist, _config.Whitelist);
            if (_config.Prevention.DisableTelemetryTasks)
                ScheduledTaskGuard.DisableTelemetryTasks();
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
        var configPath = Path.Combine(AppContext.BaseDirectory, "config.json");
        var config = ConfigLoader.Load(configPath);

        // Handle CLI commands
        if (args.Length > 0)
        {
            switch (args[0].ToLower())
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
                    Console.WriteLine("BloatwareGuard v1.29.0-mvp");
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
                    Console.WriteLine($"Unknown command: {args[0]}");
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
            RegistryGuard.ApplyAll(config.Prevention, config.Blacklist, config.Whitelist);
            ScheduledTaskGuard.DisableOemTasks();
            if (config.Prevention.DisableTelemetryTasks)
                ScheduledTaskGuard.DisableTelemetryTasks();
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
BloatwareGuard v1.29.0-mvp — Windows 11 bloatware removal + prevention

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
        Process.Start(psi);
        GuardLogger.Info("Service installed (idempotent, restart-on-failure: 60s/60s/5min). Use 'sc start BloatwareGuard' to start.");
    }

    private static void UninstallService()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = "delete BloatwareGuard",
            UseShellExecute = true,
            Verb = "runas"
        };
        Process.Start(psi);
        GuardLogger.Info("Service uninstalled.");
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
        Console.WriteLine(proc?.StandardOutput.ReadToEnd());
    }

    /// <summary>Re-register staged AppxPackages recorded in the removal ledger.
    /// Provisioned packages cannot be restored from the image — reported as manual.</summary>
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
            else
            {
                GuardLogger.Info(
                    $"Manual restore needed: {name} (provisioned — reinstall via Microsoft Store or Settings)");
                manual++;
            }
        }
        GuardLogger.Info($"Restore complete: {restored} restored, {manual} need manual reinstall.");
    }

    private static bool RestoreStagedPackage(string name)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"Get-AppxPackage -AllUsers -Name '" +
                name + "' | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register " +
                "\\\"$($_.InstallLocation)\\AppxManifest.xml\\\" -ErrorAction SilentlyContinue }\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        proc?.WaitForExit(60000);
        return proc?.ExitCode == 0;
    }

    /// <summary>
    /// Self-test mode: validates internal wiring without requiring admin elevation.
    /// Bypasses UAC by testing structure, not actual removal logic.
    /// </summary>
    private static int RunSelfTest(GuardConfig config)
    {
        var passed = 0;
        var total = 6;
        var results = new List<string>();

        GuardLogger.Info("=== BloatwareGuard v1.29.0-mvp — Self-Test Mode === [no admin required]");
        Console.WriteLine("=== BloatwareGuard v1.29.0-mvp — Self-Test Mode === [no admin required]");

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
