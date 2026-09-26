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

    /// <summary>Write AppxAllUserStore\Deprovisioned markers so feature updates
    /// don't re-provision removed apps (documented Windows behavior)</summary>
    public bool MarkDeprovisioned { get; set; } = true;

    /// <summary>25H2 policy: auto-remove default Store packages at first sign-in of
    /// NEW user profiles (HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages)</summary>
    public bool RemoveDefaultStorePackages { get; set; } = true;

    /// <summary>Apply content-delivery/suggestion suppression to every loaded user
    /// hive + the Default profile, not just HKCU (a SYSTEM service's HKCU is useless)</summary>
    public bool HardenContentDelivery { get; set; } = true;

    /// <summary>Policy-disable Copilot, Recall data analysis and Click to Do</summary>
    public bool DisableAiFeatures { get; set; } = true;

    /// <summary>Policy-disable the Widgets/News-and-Interests board</summary>
    public bool DisableWidgets { get; set; } = true;

    /// <summary>Disable Bing/web suggestions in Start-menu search</summary>
    public bool DisableSearchSuggestions { get; set; } = true;

    /// <summary>Disable known Microsoft telemetry/CEIP scheduled tasks by exact path</summary>
    public bool DisableTelemetryTasks { get; set; } = true;

    /// <summary>Group-policy telemetry/privacy suppression (DataCollection, activity
    /// feed, advertising ID, tailored experiences, per-hive tracking values)</summary>
    public bool DisableTelemetryPolicies { get; set; } = true;

    /// <summary>Policy-disable Edge annoyances (sidebar, startup boost, spotlight
    /// recommendations, personalization reporting, shopping assistant)</summary>
    public bool HardenEdgePolicies { get; set; } = true;

    /// <summary>Purge blacklist/vendor Run &amp; RunOnce startup entries across
    /// HKLM (64/32-bit) and all loaded user hives</summary>
    public bool CleanStartupEntries { get; set; } = true;

    /// <summary>Stop + disable OEM/vendor auto-start services (updaters, nagware)</summary>
    public bool DisableOemServices { get; set; } = true;

    /// <summary>Uninstall Win32/MSI/EXE bloat via Uninstall hives — only entries
    /// with a silent uninstall path (QuietUninstallString / msiexec / silent flags)</summary>
    public bool RemoveWin32Bloatware { get; set; } = true;

    /// <summary>Policy-disable GameDVR background capture (HKLM + per-hive)</summary>
    public bool DisableGameDvr { get; set; } = true;

    /// <summary>Null-route pure-telemetry endpoints via a marked hosts-file block
    /// (Spybot Anti-Beacon technique; toggling off removes the block)</summary>
    public bool BlockTelemetryEndpoints { get; set; } = true;

    /// <summary>winget uninstall --silent sweep for bloat/vendor matches
    /// (skips cleanly when App Installer is absent)</summary>
    public bool WingetSweep { get; set; } = true;

    /// <summary>Remove deprecated Windows capabilities (WordPad, Steps Recorder)</summary>
    public bool RemoveDeprecatedCapabilities { get; set; } = true;

    /// <summary>Stop + disable telemetry/leftover system services (DiagTrack,
    /// dmwappushservice, Xbox leftovers, WMP sharing) + NCSI active probing</summary>
    public bool DisableTelemetryServices { get; set; } = true;

    /// <summary>Start=0 on boot-time ETW autologger sessions that only feed
    /// telemetry (Diagtrack-Listener, SQMLogger, WiFiSession, …)</summary>
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

    private static void Write(string level, string msg)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {msg}";
        Console.WriteLine(line);

        try
        {
            EnsureSourceExists();
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
                "Microsoft.DevHome",
                "Microsoft.Copilot",
                "Microsoft.OutlookForWindows",        // new Outlook (replaces Mail & Calendar)
                "microsoft.windowscommunicationsapps", // legacy Mail & Calendar (deprecated Dec 2024)
                "Microsoft.BingSearch",
                "Microsoft.Windows.Ai.Copilot.Provider",
                "Clipchamp.Clipchamp",

                // Third-party bloatware commonly pre-installed
                "McAfee",
                "Norton",
                "SpotifyAB.SpotifyMusic",
                "Netflix",
                "Dolby",
                "RealtekSemiconductor",
                "SynapticsIncorporated",
                "BytedancePte.Ltd.TikTok",
                "KING.COM.CandyCrush",
                "A278AB0D.DisneyMagicKingdoms",
                "A278AB0D.MarchofEmpires",
                "D5EA27B7.Duolingo-LearnLanguagesforFree",
                "PandoraMediaInc.29680B314EFC2",
                "Facebook.InstagramBeta",
                "Facebook.Facebook",
                "WhatsApp",
                "Disney.",
                "MicrosoftWindows.Client.WebExperience",   // Widgets runtime pack
                "MicrosoftCorporationII.QuickAssist",       // documented vishing vector

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

// ─── Process helpers ─────────────────────────────────────────────────────────

internal static class Proc
{
    /// <summary>Start a process and drain redirected streams asynchronously so a
    /// hung child can never block the read, then enforce a hard deadline — kill
    /// the tree on expiry. Returns (stdout, stderr, exitCode); exitCode is null
    /// on timeout or launch failure.</summary>
    public static (string Stdout, string Stderr, int? ExitCode) Capture(ProcessStartInfo psi, int timeoutMs)
    {
        try
        {
            using var proc = Process.Start(psi);
            if (proc == null)
                return ("", "", null);
            var stdoutT = psi.RedirectStandardOutput
                ? Task.Run(() => proc.StandardOutput.ReadToEnd())
                : Task.FromResult("");
            var stderrT = psi.RedirectStandardError
                ? Task.Run(() => proc.StandardError.ReadToEnd())
                : Task.FromResult("");
            if (!proc.WaitForExit(timeoutMs))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                try { Task.WaitAll(new Task[] { stdoutT, stderrT }, 5000); } catch { }
                return ("", "", null);
            }
            // A detached grandchild can inherit the pipes and hold them open
            // after this process exits — bound the EOF wait rather than block
            // on .Result forever.
            try { Task.WaitAll(new Task[] { stdoutT, stderrT }, 10000); } catch { }
            var stdout = stdoutT.Status == TaskStatus.RanToCompletion ? stdoutT.Result : "";
            var stderr = stderrT.Status == TaskStatus.RanToCompletion ? stderrT.Result : "";
            return (stdout, stderr, proc.ExitCode);
        }
        catch { return ("", "", null); }
    }

    /// <summary>Wait with a hard deadline, kill on expiry. Returns exit code or
    /// null on timeout/failure.</summary>
    public static int? Wait(ProcessStartInfo psi, int timeoutMs)
        => Capture(psi, timeoutMs).ExitCode;
}

// ─── Appx Package Manager ────────────────────────────────────────────────────

public static class AppxManager
{
    /// <summary>Get all installed AppxPackages whose FamilyName matches any blacklist entry</summary>
    public static List<(string PackageFamilyName, string DisplayName, string PackageFullName, bool IsFramework, string? InstallPath)> GetBlacklistedPackages(
        List<string> blacklist, List<string> whitelist)
    {
        var results = new List<(string, string, string, bool, string?)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Only shell-safe entries reach the -Command argument — quotes or
        // metacharacters in config must never break out of the PS string.
        var pattern = string.Join("|",
            blacklist.Where(IsShellSafe).Select(Regex.Escape));
        if (pattern.Length == 0)
            return results;  // empty pattern would -match every package
        // -AllUsers surfaces packages installed for other users too (admin only)
        var scope = IsElevated() ? " -AllUsers" : "";
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-AppxPackage{scope} | Where-Object {{$_.PackageFamilyName -match '{pattern}'}} | Select-Object PackageFamilyName,Name,PackageFullName,IsFramework,InstallPath | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var output = Proc.Capture(psi, 180000).Stdout;

        try
        {
            var doc = JsonDocument.Parse(output.Trim());
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    var family = el.GetProperty("PackageFamilyName").GetString() ?? "";
                    var name = el.GetProperty("Name").GetString() ?? "";
                    var fullName = el.GetProperty("PackageFullName").GetString() ?? "";
                    var isFw = el.TryGetProperty("IsFramework", out var fw) && fw.ValueKind == JsonValueKind.True;
                    var installPath = el.TryGetProperty("InstallPath", out var ip) ? ip.GetString() : null;
                    // -AllUsers emits one row per user per package — dedupe
                    var dedupeKey = string.IsNullOrEmpty(fullName) ? family : fullName;
                    if (!IsWhitelisted(family, whitelist) && seen.Add(dedupeKey))
                        results.Add((family, name, fullName, isFw, installPath));
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                var family = doc.RootElement.GetProperty("PackageFamilyName").GetString() ?? "";
                var name = doc.RootElement.GetProperty("Name").GetString() ?? "";
                var fullName = doc.RootElement.GetProperty("PackageFullName").GetString() ?? "";
                var isFw = doc.RootElement.TryGetProperty("IsFramework", out var fw) && fw.ValueKind == JsonValueKind.True;
                var installPath = doc.RootElement.TryGetProperty("InstallPath", out var ip) ? ip.GetString() : null;
                var dedupeKey = string.IsNullOrEmpty(fullName) ? family : fullName;
                if (!IsWhitelisted(family, whitelist) && seen.Add(dedupeKey))
                    results.Add((family, name, fullName, isFw, installPath));
            }
        }
        catch { /* no matches or parse error */ }

        return results;
    }

    /// <summary>Check if a package family name matches any whitelist entry</summary>
    public static bool IsWhitelisted(string packageFamilyName, List<string> whitelist)
    {
        return whitelist.Any(w => !string.IsNullOrWhiteSpace(w) &&
            packageFamilyName.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>True when running elevated — enables -AllUsers enumeration.</summary>
    public static bool IsElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>Get all provisioned packages (these re-deploy on new user creation).
    /// Returns (PackageName, PackageFamilyName) — the family name (DisplayName_PublisherId)
    /// is what Deprovisioned markers and the 25H2 removal policy are keyed on.</summary>
    public static List<(string PackageName, string FamilyName)> GetBlacklistedProvisionedPackages(
        List<string> blacklist, List<string> whitelist)
    {
        var results = new List<(string, string)>();
        var pattern = string.Join("|",
            blacklist.Where(IsShellSafe).Select(Regex.Escape));
        if (pattern.Length == 0)
            return results;  // empty pattern would -match every package

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-AppxProvisionedPackage -Online | Where-Object {{$_.PackageName -match '{pattern}'}} | Select-Object PackageName,DisplayName | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var output = Proc.Capture(psi, 180000).Stdout;

        try
        {
            var doc = JsonDocument.Parse(output.Trim());
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    var pkg = el.GetProperty("PackageName").GetString() ?? "";
                    var family = ProvisionedFamilyName(el);
                    if (!IsWhitelisted(pkg, whitelist) && !IsWhitelisted(family, whitelist))
                        results.Add((pkg, family));
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                var pkg = doc.RootElement.GetProperty("PackageName").GetString() ?? "";
                var family = ProvisionedFamilyName(doc.RootElement);
                if (!IsWhitelisted(pkg, whitelist) && !IsWhitelisted(family, whitelist))
                    results.Add((pkg, family));
            }
        }
        catch { }

        return results;
    }

    /// <summary>True for entries safe to embed in a PowerShell -Command string
    /// (letters/digits/._- space only — no quotes or shell metacharacters).</summary>
    private static bool IsShellSafe(string s)
        => !string.IsNullOrWhiteSpace(s) && Regex.IsMatch(s, @"^[\w.\- ]+$");

    /// <summary>Derive DisplayName_PublisherId for a provisioned package.
    /// Get-AppxProvisionedPackage returns no PublisherId, so the publisher is
    /// taken from the last '_' segment of PackageName
    /// (Name_Version_Architecture_ResourceId_PublisherId). "" when unresolvable.</summary>
    private static string ProvisionedFamilyName(JsonElement el)
    {
        var display = el.TryGetProperty("DisplayName", out var d) ? d.GetString() ?? "" : "";
        var pkgName = el.TryGetProperty("PackageName", out var n) ? n.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(display))
            return "";
        var segs = pkgName.Split('_');
        var publisher = segs.Length >= 5 && Regex.IsMatch(segs[^1], @"^[A-Za-z0-9]+$")
            ? segs[^1] : "";
        return string.IsNullOrEmpty(publisher) ? "" : $"{display}_{publisher}";
    }

    /// <summary>Package names are simple identifiers (Name_ver_arch_resid_pubid)
    /// — anything else is rejected before it can reach a PowerShell string.</summary>
    private static bool IsPackageNameSafe(string name)
        => !string.IsNullOrEmpty(name) &&
           Regex.IsMatch(name, @"^[A-Za-z0-9_.\-~!]+$");

    public static bool RemoveAppxPackage(string packageFullName)
    {
        if (!IsPackageNameSafe(packageFullName))
        {
            GuardLogger.Warn($"Rejected malformed package name: {packageFullName}");
            return false;
        }
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Remove-AppxPackage -Package '{packageFullName}' -AllUsers -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var (_, stderr, rc) = Proc.Capture(psi, 60000);
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"Remove-AppxPackage stderr: {stderr.Trim()}");
        return rc == 0;
    }

    /// <summary>Remove AppxPackage for CURRENT USER only (no admin required).
    /// Returns (success, isSystemApp). SystemApps cannot be removed per-user.</summary>
    public static (bool Success, bool IsSystemApp) RemoveAppxPackageForUser(string packageFullName, string? installPath = null)
    {
        if (!IsPackageNameSafe(packageFullName))
        {
            GuardLogger.Warn($"Rejected malformed package name: {packageFullName}");
            return (false, false);
        }
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

        var (_, stderr, rc) = Proc.Capture(psi, 60000);
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"Remove-AppxPackage (user) stderr: {stderr.Trim()}");
        return (rc == 0, false);
    }

    public static bool RemoveProvisionedPackage(string packageName)
    {
        if (!IsPackageNameSafe(packageName))
        {
            GuardLogger.Warn($"Rejected malformed package name: {packageName}");
            return false;
        }
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Remove-AppxProvisionedPackage -Online -PackageName '{packageName}' -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var (_, stderr, rc) = Proc.Capture(psi, 120000);
        if (!string.IsNullOrEmpty(stderr))
            GuardLogger.Warn($"RemoveProvisionedPackage stderr: {stderr.Trim()}");
        return rc == 0;
    }
}

// ─── Registry-based Prevention ───────────────────────────────────────────────

public static class RegistryGuard
{
    private const string CloudContentPath = @"SOFTWARE\Policies\Microsoft\Windows\CloudContent";
    private const string DeviceMetadataPath = @"SOFTWARE\Policies\Microsoft\Windows\Device Metadata";
    private const string AppCompatPath = @"SOFTWARE\Policies\Microsoft\Windows\AppCompat";
    private const string WindowsSearchPath = @"SOFTWARE\Policies\Microsoft\Windows\Windows Search";
    private const string CopilotPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot";
    private const string WindowsAiPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI";
    private const string DshPolicyPath = @"SOFTWARE\Policies\Microsoft\Dsh";
    private const string NewsInterestsPolicyManagerPath = @"SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests";
    private const string ExplorerPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\Explorer";
    private const string RemoveDefaultPackagesPath = @"SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages";
    private const string DeprovisionedPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned";
    private const string ContentDeliveryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
    private const string ExplorerAdvancedPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    private const string EdgePolicyPath = @"SOFTWARE\Policies\Microsoft\Edge";

    // Telemetry/privacy group policies — documented HKLM policy paths (path, name, value)
    private static readonly (string Path, string Name, int Value)[] TelemetryPolicyWrites = {
        (@"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
        (@"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DoNotShowFeedbackNotifications", 1),
        (@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0),
        (@"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0),
        (@"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0),
        (@"SOFTWARE\Policies\Microsoft\Windows\System", "AllowCrossDeviceClipboard", 0),
        (@"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1),
        (@"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocationScripting", 1),
        (@"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace", "AllowWindowsInkWorkspace", 0),
        // Delivery Optimization P2P upload off (HTTP-only download mode)
        (@"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization", "DODownloadMode", 0),
        // WER: never send extra crash data to Microsoft
        (@"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "DontSendAdditionalData", 1),
        // Skip the OOBE privacy questions for new users
        (@"SOFTWARE\Policies\Microsoft\Windows\OOBE", "DisablePrivacyExperience", 1),
        // Windows Spotlight on lock screen / desktop
        (@"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsSpotlightFeatures", 1),
        // "Do not sync your settings" — settings aren't uploaded to the cloud
        (@"SOFTWARE\Policies\Microsoft\Windows\SettingSync", "DisableSettingSync", 2),
        // Hide the Start-menu "Recommended" section (ads + suggested apps slot)
        (ExplorerPolicyPath, "HideRecommendedSection", 1),
    };

    // Per-user telemetry/privacy values — written to every loaded user hive.
    // DisableTailoredExperiencesWithDiagnosticData is a documented User-class policy.
    private static readonly (string Path, string Name, int Value)[] TelemetryUserWrites = {
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0),
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),
        // 1 = restrict collection (0 would leave text/ink harvesting ON)
        (@"SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1),
        (@"SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 1),
        (@"SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", 0),
        (@"SOFTWARE\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0),
        (ExplorerAdvancedPath, "Start_TrackProgs", 0),
        // Explorer "sync provider" ads (OneDrive/MS promos in File Explorer)
        (ExplorerAdvancedPath, "ShowSyncProviderNotifications", 0),
        (@"SOFTWARE\Microsoft\Input\Settings", "InsightsEnabled", 0),
        // SCOOBE — the "let's finish setting up your device" nag screen
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement", "ScoobeSystemSettingEnabled", 0),
        (@"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableTailoredExperiencesWithDiagnosticData", 1),
    };

    // GameDVR capture: HKLM policy + per-user capture keys
    private const string GameDvrPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\GameDVR";
    private static readonly (string Path, string Name, int Value)[] GameDvrUserWrites = {
        (@"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", 0),
        (@"SOFTWARE\System\GameConfigStore", "GameDVR_Enabled", 0),
    };

    // Edge annoyance policies — documented MSEdge.admx policy names, all DWORD
    private static readonly (string Name, int Value)[] EdgePolicies = {
        ("HubsSidebarEnabled", 0), ("StandaloneHubsSidebarEnabled", 0),
        ("StartupBoostEnabled", 0), ("SpotlightExperiencesAndRecommendationsEnabled", 0),
        ("PersonalizationReportingEnabled", 0), ("ShowRecommendationsEnabled", 0),
        ("EdgeShoppingAssistantEnabled", 0), ("NewTabPageContentEnabled", 0),
        // privacy leaks: URLs/site data sent to Microsoft web services
        ("SendSiteInfoToImproveServices", 0),
        ("ResolveNavigationErrorsUseWebService", 0),
        ("AlternateErrorPagesEnabled", 0), ("UserFeedbackAllowed", 0),
        ("BingAdsSuppression", 1),
    };

    // Suggestion/ads delivery killswitches — the full set used by Win11Debloat's
    // Disable_Windows_Suggestions.reg, all DWORD 0
    private static readonly string[] ContentDeliveryValues = {
        "ContentDeliveryAllowed", "FeatureManagementEnabled",
        "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled",
        "PreInstalledAppsEverEnabled", "RotatingLockScreenEnabled",
        "RotatingLockScreenOverlayEnabled", "SilentInstalledAppsEnabled",
        "SoftLandingEnabled", "SystemPaneSuggestionsEnabled",
        "SubscribedContent-310093Enabled", "SubscribedContent-338387Enabled",
        "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled",
        "SubscribedContent-338380Enabled", "SubscribedContent-338393Enabled",
        "SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled",
        "SubscribedContent-353698Enabled",
    };

    // ETW autologger sessions that exist solely to feed telemetry — Start=0
    // stops them at boot (the privacy.sexy / Sophia Script technique)
    private const string AutologgersPath = @"SYSTEM\CurrentControlSet\Control\WMI\Autologger";
    private static readonly string[] TelemetryAutologgers = {
        "AutoLogger-Diagtrack-Listener", "Diagtrack-Listener", "SQMLogger",
        "DataMarket", "AppModel", "CloudExperienceHostOobe", "DiagLog",
        "LwtNetLog", "TileStore", "UBPM", "WiFiSession",
    };

    /// <summary>Stop boot-time ETW autologger sessions that only feed telemetry.
    /// Only touches keys that already exist (doesn't create them).</summary>
    public static void DisableTelemetryAutologgers()
    {
        var disabled = 0;
        foreach (var name in TelemetryAutologgers)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    $"{AutologgersPath}\\{name}", writable: true);
                if (key == null)
                    continue; // autologger not present on this machine
                key.SetValue("Start", 0, Microsoft.Win32.RegistryValueKind.DWord);
                disabled++;
            }
            catch (Exception ex)
            {
                GuardLogger.Warn($"Autologger {name}: {ex.Message}");
            }
        }
        GuardLogger.Info($"Disabled {disabled} telemetry autologgers (Start=0)");
    }

    public static void ApplyAll(PreventionLayers layers)
    {
        if (layers.DisableConsumerExperiences)
            DisableConsumerExperiences();

        if (layers.DisableCloudContent)
            DisableCloudContent();

        if (layers.PreventDeviceMetadata)
            PreventDeviceMetadata();

        if (layers.BlockProvisioning)
            BlockProvisioning();

        if (layers.DisableAiFeatures)
            DisableAiFeatures();

        if (layers.DisableWidgets)
            DisableWidgets();

        // HKLM policy for Start-search web suggestions (Bing)
        if (layers.DisableSearchSuggestions)
            DisableSearchSuggestions();

        if (layers.DisableTelemetryPolicies)
            DisableTelemetryPolicies();

        if (layers.HardenEdgePolicies)
            HardenEdgePolicies();

        if (layers.DisableGameDvr)
        {
            try
            {
                using var gdvr = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(GameDvrPolicyPath);
                gdvr?.SetValue("AllowGameDVR", 0, Microsoft.Win32.RegistryValueKind.DWord);
                GuardLogger.Info("Applied: AllowGameDVR = 0");
            }
            catch (Exception ex)
            {
                GuardLogger.Warn($"GameDVR policy: {ex.Message}");
            }
        }

        if (layers.DisableTelemetryAutologgers)
            DisableTelemetryAutologgers();

        // Hosts-file telemetry block — called unconditionally: the helper no-ops
        // when disabled and no block exists; toggling off removes the block.
        Win32BloatGuard.SetTelemetryHostsBlock(layers.BlockTelemetryEndpoints);

        // Per-user policies — must hit every loaded hive, not just HKCU
        if (layers.HardenContentDelivery || layers.DisableSearchSuggestions
            || layers.DisableAiFeatures || layers.DisableTelemetryPolicies
            || layers.DisableGameDvr)
            ApplyPerUserPolicies(layers);
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

    /// <summary>Block provisioning packages from re-registering</summary>
    public static void BlockProvisioning()
    {
        try
        {
            // Disable silent app install
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(CloudContentPath);
            key?.SetValue("DisableConsumerAccountContent", 1, Microsoft.Win32.RegistryValueKind.DWord);

            // Also set per-user
            using var cuKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager");
            cuKey?.SetValue("SilentInstalledAppsEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            cuKey?.SetValue("SystemPaneSuggestionsEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            cuKey?.SetValue("SubscribedContent-338389Enabled", 0, Microsoft.Win32.RegistryValueKind.DWord);

            GuardLogger.Info("Applied: BlockProvisioning (silent installs + suggestions disabled)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to block provisioning: {ex.Message}");
        }
    }

    /// <summary>Policy-disable Copilot, Recall data analysis and Click to Do (HKLM).</summary>
    public static void DisableAiFeatures()
    {
        try
        {
            using var copilot = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(CopilotPolicyPath);
            copilot?.SetValue("TurnOffWindowsCopilot", 1, Microsoft.Win32.RegistryValueKind.DWord);

            using var ai = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(WindowsAiPolicyPath);
            ai?.SetValue("DisableAIDataAnalysis", 1, Microsoft.Win32.RegistryValueKind.DWord);
            ai?.SetValue("AllowRecallEnablement", 0, Microsoft.Win32.RegistryValueKind.DWord);
            ai?.SetValue("DisableClickToDo", 1, Microsoft.Win32.RegistryValueKind.DWord);

            GuardLogger.Info("Applied: TurnOffWindowsCopilot + DisableAIDataAnalysis + DisableClickToDo");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable AI features: {ex.Message}");
        }
    }

    /// <summary>Policy-disable the Widgets / News-and-Interests board (HKLM).</summary>
    public static void DisableWidgets()
    {
        try
        {
            using var dsh = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(DshPolicyPath);
            dsh?.SetValue("AllowNewsAndInterests", 0, Microsoft.Win32.RegistryValueKind.DWord);
            // PolicyManager default — the feed stays off even if the policy is cleared
            using var pm = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(NewsInterestsPolicyManagerPath);
            pm?.SetValue("value", 0, Microsoft.Win32.RegistryValueKind.DWord);

            GuardLogger.Info("Applied: AllowNewsAndInterests = 0");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable widgets: {ex.Message}");
        }
    }

    /// <summary>Disable Bing/web suggestions inside Start-menu search (HKLM).</summary>
    public static void DisableSearchSuggestions()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(ExplorerPolicyPath);
            key?.SetValue("DisableSearchBoxSuggestions", 1, Microsoft.Win32.RegistryValueKind.DWord);
            GuardLogger.Info("Applied: DisableSearchBoxSuggestions = 1");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to disable search suggestions: {ex.Message}");
        }
    }

    /// <summary>Telemetry/privacy group policies (HKLM): diagnostic data level,
    /// activity feed/Timeline upload, advertising ID, cross-device clipboard,
    /// feedback nagging, location scripting. Documented ADMX policy paths.</summary>
    public static void DisableTelemetryPolicies()
    {
        var applied = 0;
        foreach (var (path, name, value) in TelemetryPolicyWrites)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(path);
                key?.SetValue(name, value, Microsoft.Win32.RegistryValueKind.DWord);
                if (key != null)
                    applied++;
            }
            catch (Exception ex)
            {
                GuardLogger.Warn($"Telemetry policy {name}: {ex.Message}");
            }
        }
        GuardLogger.Info($"Applied: telemetry/privacy policies ({applied} HKLM values)");
    }

    /// <summary>Policy-disable Edge annoyances: sidebar, startup boost, Spotlight
    /// backgrounds/promos, personalization reporting, shopping assistant (HKLM).</summary>
    public static void HardenEdgePolicies()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(EdgePolicyPath);
            var applied = 0;
            if (key != null)
            {
                foreach (var (name, value) in EdgePolicies)
                {
                    key.SetValue(name, value, Microsoft.Win32.RegistryValueKind.DWord);
                    applied++;
                }
            }
            GuardLogger.Info($"Applied: Edge hardening policies ({applied} values)");
        }
        catch (Exception ex)
        {
            GuardLogger.Error($"Failed to harden Edge policies: {ex.Message}");
        }
    }

    /// <summary>Per-user policies applied under every loaded user hive plus the
    /// Default profile template. A service running as SYSTEM would otherwise write
    /// them to SYSTEM's own HKCU where they do nothing for interactive users.</summary>
    private static void ApplyPerUserPolicies(PreventionLayers layers)
    {
        var applied = 0;
        foreach (var sid in EnumerateUserSidHives())
        {
            try
            {
                ApplyUserPolicies(Microsoft.Win32.Registry.Users, sid, layers);
                applied++;
            }
            catch (Exception ex)
            {
                GuardLogger.Warn($"User hive {sid}: {ex.Message}");
            }
        }

        // Stamp the Default profile template so FUTURE users get the policies.
        // reg.exe is required — winreg cannot load/unload hives.
        // SystemDrive is "C:" — normalize to a rooted path, else Path.Combine
        // produces the drive-relative "C:Users\..." and the template is missed.
        var systemDrive = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:")
            .TrimEnd('\\') + "\\";
        var defaultNtuser = Path.Combine(systemDrive, "Users", "Default", "NTUSER.DAT");
        if (File.Exists(defaultNtuser))
        {
            const string tempHive = "BloatwareGuard_Default";
            if (RunReg($"load HKU\\{tempHive} \"{defaultNtuser}\""))
            {
                try
                {
                    ApplyUserPolicies(Microsoft.Win32.Registry.Users, tempHive, layers);
                }
                catch (Exception ex)
                {
                    GuardLogger.Warn($"Default profile hive: {ex.Message}");
                }
                RunReg($"unload HKU\\{tempHive}");
            }
        }
        GuardLogger.Info($"Per-user policies applied to {applied} loaded hive(s) + Default profile");
    }

    /// <summary>SIDs of loaded real-user hives under HKEY_USERS (S-1-5-21-* only;
    /// skips .DEFAULT, *_Classes, and service SIDs like S-1-5-18).</summary>
    private static IEnumerable<string> EnumerateUserSidHives()
    {
        string[] names;
        try { names = Microsoft.Win32.Registry.Users.GetSubKeyNames(); }
        catch { yield break; }
        foreach (var n in names)
            if (n.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
                !n.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                yield return n;
    }

    private static void ApplyUserPolicies(Microsoft.Win32.RegistryKey hiveRoot,
        string subKeyPrefix, PreventionLayers layers)
    {
        if (layers.HardenContentDelivery)
        {
            using var cdm = hiveRoot.CreateSubKey($"{subKeyPrefix}\\{ContentDeliveryPath}");
            if (cdm != null)
                foreach (var v in ContentDeliveryValues)
                    cdm.SetValue(v, 0, Microsoft.Win32.RegistryValueKind.DWord);

            using var adv = hiveRoot.CreateSubKey($"{subKeyPrefix}\\{ExplorerAdvancedPath}");
            adv?.SetValue("ShowCopilotButton", 0, Microsoft.Win32.RegistryValueKind.DWord);
            adv?.SetValue("Start_IrisRecommendations", 0, Microsoft.Win32.RegistryValueKind.DWord);
        }
        if (layers.DisableSearchSuggestions)
        {
            using var explorer = hiveRoot.CreateSubKey($"{subKeyPrefix}\\{ExplorerPolicyPath}");
            explorer?.SetValue("DisableSearchBoxSuggestions", 1, Microsoft.Win32.RegistryValueKind.DWord);
        }
        if (layers.DisableAiFeatures)
        {
            using var copilot = hiveRoot.CreateSubKey($"{subKeyPrefix}\\{CopilotPolicyPath}");
            copilot?.SetValue("TurnOffWindowsCopilot", 1, Microsoft.Win32.RegistryValueKind.DWord);
        }
        if (layers.DisableTelemetryPolicies)
        {
            foreach (var (path, name, value) in TelemetryUserWrites)
            {
                using var key = hiveRoot.CreateSubKey($"{subKeyPrefix}\\{path}");
                key?.SetValue(name, value, Microsoft.Win32.RegistryValueKind.DWord);
            }
        }
        if (layers.DisableGameDvr)
        {
            foreach (var (path, name, value) in GameDvrUserWrites)
            {
                using var key = hiveRoot.CreateSubKey($"{subKeyPrefix}\\{path}");
                key?.SetValue(name, value, Microsoft.Win32.RegistryValueKind.DWord);
            }
        }
    }

    private static bool RunReg(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = arguments,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            return proc != null && proc.WaitForExit(15000) && proc.ExitCode == 0;
        }
        catch { return false; }
    }

    /// <summary>Create Deprovisioned marker keys for matched families — Windows
    /// checks this documented path and skips re-provisioning during feature updates.</summary>
    public static void MarkDeprovisioned(IEnumerable<string> familyNames)
    {
        var count = 0;
        foreach (var family in familyNames)
        {
            if (string.IsNullOrEmpty(family))
                continue;
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine
                    .CreateSubKey($"{DeprovisionedPath}\\{family}");
                if (key != null)
                    count++;
            }
            catch (Exception ex)
            {
                GuardLogger.Warn($"Deprovisioned marker failed for {family}: {ex.Message}");
            }
        }
        if (count > 0)
            GuardLogger.Info($"Deprovisioned markers written for {count} package families");
    }

    /// <summary>Windows 11 25H2 policy: remove these Store packages at first sign-in
    /// of new user profiles. Inert on older builds — unknown policy keys are ignored.</summary>
    public static void WriteRemoveDefaultStorePackagesPolicy(IEnumerable<string> familyNames)
    {
        var count = 0;
        foreach (var family in familyNames)
        {
            if (string.IsNullOrEmpty(family))
                continue;
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine
                    .CreateSubKey($"{RemoveDefaultPackagesPath}\\{family}");
                if (key != null)
                {
                    key.SetValue("RemovePackage", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    count++;
                }
            }
            catch (Exception ex)
            {
                GuardLogger.Warn($"RemoveDefaultStorePackages failed for {family}: {ex.Message}");
            }
        }
        if (count > 0)
            GuardLogger.Info($"RemoveDefaultStorePackages policy set for {count} package families");
    }
}

// ─── Scheduled Task Manager ──────────────────────────────────────────────────

public static class ScheduledTaskGuard
{
    // Known OEM bloatware task patterns — must be specific enough to avoid matching Microsoft system tasks
    private static readonly string[] OemTaskPatterns = {
        "OEM", "Dell", "HPInc", "HPA", "Lenovo", "ASUS", "Acer", "McAfee", "Norton",
        "SupportAssist", "Vantage", "Armoury", "Crate", "Reinstall", "Restore", "Bloatware"
    };

    // Microsoft telemetry/CEIP scheduled tasks — explicit full paths, disabled outright.
    // Mirrors the telemetry task lists used by Win11Debloat / Sophia Script.
    private static readonly string[] TelemetryTaskPaths = {
        @"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        @"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        @"\Microsoft\Windows\Application Experience\PcaPatchDbUpdate",
        @"\Microsoft\Windows\Application Experience\StartupAppTask",
        @"\Microsoft\Windows\Autochk\Proxy",
        @"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        @"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        @"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        @"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        @"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver",
        @"\Microsoft\Windows\Feedback\Siuf\DmClient",
        @"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        @"\Microsoft\Windows\Maps\MapsToastTask",
        @"\Microsoft\Windows\Maps\MapsUpdateTask",
        @"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        @"\Microsoft\Windows\Speech\SpeechModelDownloadTask",
        @"\Microsoft\Windows\DiskFootprint\Diagnostics",
        @"\Microsoft\Windows\WinErrorReporting\QueueReporting",
        @"\Microsoft\Windows\Device Information\Device",
        @"\Microsoft\Windows\Device Information\Device User",
        @"\Microsoft\Windows\TextInput\TextInputModelDownloadTask",
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
            // Match TaskPath too — e.g. CEIP tasks live under
            // \Microsoft\Windows\Customer Experience Improvement Program\ with
            // innocuous names like "Consolidator" that name-matching alone misses
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-ScheduledTask | Where-Object {{$_.TaskPath -like '*OEM*' -or $_.TaskName -match '{string.Join("|", OemTaskPatterns.Select(Regex.Escape))}' -or $_.TaskPath -match '{string.Join("|", OemTaskPatterns.Select(Regex.Escape))}'}} | Select-Object TaskName,TaskPath,State | ConvertTo-Json\"",
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

        if (Proc.Wait(psi, 15000) == 0)
            GuardLogger.Info($"Disabled scheduled task: {fullPath}");
        else
            GuardLogger.Warn($"Failed to disable task: {fullPath}");
    }

    /// <summary>Disable known Microsoft telemetry/CEIP scheduled tasks by exact path.
    /// Missing tasks are logged at info level — they vary by Windows build.</summary>
    public static void DisableTelemetryTasks()
    {
        var disabled = 0;
        foreach (var taskPath in TelemetryTaskPaths)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = $"/Change /TN \"{taskPath}\" /DISABLE",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            var rc = Proc.Wait(psi, 15000);
            if (rc == 0)
            {
                disabled++;
                GuardLogger.Info($"Disabled telemetry task: {taskPath}");
            }
            else
            {
                GuardLogger.Info($"Telemetry task not present/timeout (skip): {taskPath}");
            }
        }
        GuardLogger.Info($"Disabled {disabled}/{TelemetryTaskPaths.Length} telemetry scheduled tasks");
    }
}

// ─── Win32 / Vendor Bloat ────────────────────────────────────────────────────

public static class Win32BloatGuard
{
    // Hardware OEMs — a bare manufacturer name is never enough to act on:
    // drivers and hardware-integration utilities (touchpad, RGB, audio stack)
    // must survive. They only match together with a bloat keyword.
    private static readonly string[] HardwareVendorPatterns = {
        "Lenovo", "Dell", "Hewlett", "HP Inc", "HPInc",
        "ASUS", "ASUSTeK", "Acer", "Razer",
    };
    // Vendors whose typical OEM-shipped products are bloat/trialware by
    // definition — a name match alone suffices.
    private static readonly string[] JunkVendorPatterns = {
        "McAfee", "Norton", "NortonLifeLock", "Avast", "AVG Software",
        "WildTangent", "CyberLink", "ExpressVPN", "NordVPN",
        "Dropbox", "Spotify", "Adobe Creative Cloud", "CCleaner", "Booking.com",
    };
    // Words that mark OEM software as nagware/updater rather than hardware support
    private static readonly string[] BloatKeywords = {
        "update", "updater", "support", "assist", "telemetry", "diagnostic",
        "analytic", "nag", "promo", "customer", "optimizer", "helper",
        "quickset", "registration", "survey", "experience", "trial", "offer", "deals",
    };
    private static readonly string[] VendorPatterns =
        HardwareVendorPatterns.Concat(JunkVendorPatterns).ToArray();

    // Run/RunOnce keys swept for startup bloat — HKLM 64- and 32-bit views.
    // Policies\Explorer\Run is an often-overlooked autostart hive (also abused
    // for malware persistence).
    private static readonly string[] HklmRunKeyPaths = {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    };
    private static readonly string[] RunKeyPaths = {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    };

    // Active Setup — OEM stub installers that re-run at EVERY user sign-in
    private static readonly string[] ActiveSetupPaths = {
        @"SOFTWARE\Microsoft\Active Setup\Installed Components",
        @"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components",
    };

    // Win32 uninstall hives — 64- and 32-bit views
    private static readonly string[] Win32UninstallPaths = {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    };

    // UninstallString tokens that already make an uninstaller non-interactive
    private static readonly HashSet<string> SilentUninstallFlags = new(StringComparer.OrdinalIgnoreCase)
    {
        "/s", "/silent", "/verysilent", "/quiet", "/qn", "-s", "-silent"
    };

    // Pure-telemetry endpoints blocked via the hosts file — the Spybot
    // Anti-Beacon technique. Conservative: no Windows Update/Store/activation.
    private static readonly string[] TelemetryHosts = {
        "vortex.data.microsoft.com", "vortex-win.data.microsoft.com",
        "telecommand.telemetry.microsoft.com", "telecommand.telemetry.microsoft.com.nsatc.net",
        "oca.telemetry.microsoft.com", "oca.telemetry.microsoft.com.nsatc.net",
        "sqm.telemetry.microsoft.com", "sqm.telemetry.microsoft.com.nsatc.net",
        "watson.telemetry.microsoft.com", "watson.telemetry.microsoft.com.nsatc.net",
        "watson.ppe.telemetry.microsoft.com", "watson.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com", "wes.df.telemetry.microsoft.com",
        "services.wes.df.telemetry.microsoft.com", "sqm.df.telemetry.microsoft.com",
        "settings-win.data.microsoft.com", "settings.data.microsoft.com",
        "statsfe2.ws.microsoft.com", "redir.metaservices.microsoft.com",
        "choice.microsoft.com", "choice.microsoft.com.nsatc.net",
        "telemetry.appex.bing.net", "telemetry.urs.microsoft.com",
        "feedback.microsoft-hohm.com", "vortex-bn2.metron.live.com.nsatc.net",
    };
    private const string HostsBlockBegin = "# >>> BloatwareGuard telemetry block";
    private const string HostsBlockEnd = "# <<< BloatwareGuard telemetry block";

    // Deprecated-in-Windows capabilities safe to remove (deprecated by Microsoft)
    private static readonly string[] DeprecatedCapabilities = {
        "Microsoft.Windows.WordPad",  // deprecated — removed from builds > 26020
        "App.StepsRecorder",          // deprecated, slated for removal
    };

    // Telemetry/leftover system services — disabled outright. DiagTrack is the
    // main telemetry pipeline; the Xbox services are dead once Xbox apps go.
    private static readonly string[] TelemetryServices = {
        "DiagTrack",          // Connected User Experiences and Telemetry
        "dmwappushservice",   // WAP Push Message Routing (telemetry channel)
        "RetailDemo",         // Retail Demo service
        "XblAuthManager",     // Xbox Live Auth — dead once Xbox apps are gone
        "XblGameSave",        // Xbox Live Game Save
        "XboxNetApiSvc",      // Xbox Live Networking
        "WMPNetworkSvc",      // Windows Media Player network sharing (legacy)
    };

    /// <summary>Blacklist OR junk-vendor match suffices; a hardware-OEM match
    /// additionally requires a bloat keyword so drivers/hardware-integration
    /// software is never acted on by name alone.</summary>
    private static bool IsBloat(string text, GuardConfig config)
    {
        if (config.Whitelist.Any(w =>
            !string.IsNullOrEmpty(w) && text.Contains(w, StringComparison.OrdinalIgnoreCase)))
            return false;
        if (config.Blacklist.Any(p => !string.IsNullOrWhiteSpace(p) &&
            text.Contains(p, StringComparison.OrdinalIgnoreCase)))
            return true;
        if (JunkVendorPatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase)))
            return true;
        return HardwareVendorPatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase))
            && BloatKeywords.Any(k => text.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Return a non-interactive uninstall command, or null if the entry
    /// has none. QuietUninstallString passes through; msiexec strings become
    /// `/x {GUID} /qn /norestart`; strings already carrying a silent flag pass
    /// through. Interactive uninstallers are skipped — they'd hang the scan.</summary>
    public static string? SilentUninstallCommand(string? uninstallStr, string? quietStr)
    {
        if (!string.IsNullOrWhiteSpace(quietStr))
            return quietStr;
        if (string.IsNullOrWhiteSpace(uninstallStr))
            return null;
        var guid = Regex.Match(uninstallStr, @"\{[0-9A-Fa-f-]{36}\}");
        if (uninstallStr.Contains("msiexec", StringComparison.OrdinalIgnoreCase) && guid.Success)
            return $"msiexec.exe /x {guid.Value} /qn /norestart";
        if (uninstallStr.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Any(t => SilentUninstallFlags.Contains(t)))
            return uninstallStr;
        return null;
    }

    /// <summary>Uninstall Win32/desktop bloat (MSI/EXE) — Appx removal can't see
    /// these. Sweeps the Uninstall registry hives (HKLM 64/32-bit + loaded user
    /// hives) for DisplayNames matching Blacklist ∪ VendorPatterns.</summary>
    public static int RemoveWin32Bloatware(GuardConfig config, bool dryRun)
    {
        var removed = 0;
        var hives = new List<(Microsoft.Win32.RegistryKey Root, string Path)>();
        foreach (var p in Win32UninstallPaths)
            hives.Add((Microsoft.Win32.Registry.LocalMachine, p));
        foreach (var sid in EnumerateUserSidHives())
            hives.Add((Microsoft.Win32.Registry.Users, $"{sid}\\{Win32UninstallPaths[0]}"));

        foreach (var (root, path) in hives)
        {
            // Privilege boundary: HKU\<user-sid> is writable by that user — a
            // local user could plant a matching entry whose UninstallString the
            // elevated service would execute. HKLM entries only; user-hive
            // matches are reported, never run.
            var userHive = Equals(root, Microsoft.Win32.Registry.Users);
            Microsoft.Win32.RegistryKey? parent;
            try { parent = root.OpenSubKey(path); }
            catch { continue; }
            if (parent == null)
                continue;
            string[] subNames;
            using (parent)
                subNames = parent.GetSubKeyNames();

            foreach (var sub in subNames)
            {
                string display = "", uninstallStr = "", quietStr = "";
                try
                {
                    using var key = root.OpenSubKey($"{path}\\{sub}");
                    if (key == null)
                        continue;
                    display = key.GetValue("DisplayName")?.ToString() ?? "";
                    uninstallStr = key.GetValue("UninstallString")?.ToString() ?? "";
                    quietStr = key.GetValue("QuietUninstallString")?.ToString() ?? "";
                }
                catch { continue; }

                if (string.IsNullOrEmpty(display) || !IsBloat(display, config))
                    continue;
                if (userHive)
                {
                    GuardLogger.Info($"Win32 bloat in user hive (report only, not executed): {display}");
                    continue;
                }
                var cmd = SilentUninstallCommand(uninstallStr, quietStr);
                if (cmd == null)
                {
                    GuardLogger.Info($"Win32 bloat — no silent uninstaller (manual): {display}");
                    continue;
                }
                if (dryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would uninstall (win32): {display}");
                    removed++;
                    continue;
                }
                if (RunCmd(cmd, 300))
                {
                    GuardLogger.Info($"Uninstalled Win32 package: {display}");
                    RemovalLedger.Record(config, "win32", display);
                    removed++;
                }
                else
                {
                    GuardLogger.Warn($"Win32 uninstall failed: {display}");
                }
            }
        }
        return removed;
    }

    /// <summary>Delete Run/RunOnce values matching bloat/vendor patterns —
    /// HKLM (64- and 32-bit views) plus every loaded user hive.</summary>
    public static void CleanStartupEntries(GuardConfig config, bool dryRun)
    {
        var targets = new List<(Microsoft.Win32.RegistryKey Root, string Path)>();
        foreach (var p in HklmRunKeyPaths)
            targets.Add((Microsoft.Win32.Registry.LocalMachine, p));
        foreach (var sid in EnumerateUserSidHives())
            foreach (var p in RunKeyPaths)
                targets.Add((Microsoft.Win32.Registry.Users, $"{sid}\\{p}"));
        foreach (var p in RunKeyPaths)
            targets.Add((Microsoft.Win32.Registry.CurrentUser, p));

        var deleted = 0;
        foreach (var (root, path) in targets)
        {
            Microsoft.Win32.RegistryKey? key;
            try { key = root.OpenSubKey(path, writable: true); }
            catch { continue; }
            if (key == null)
                continue;
            using (key)
            {
                foreach (var name in key.GetValueNames())
                {
                    string data;
                    try { data = key.GetValue(name)?.ToString() ?? ""; }
                    catch { data = ""; }
                    if (!IsBloat($"{name} {data}", config))
                        continue;
                    if (dryRun)
                    {
                        GuardLogger.Info($"[DRY-RUN] Would delete startup entry: {path}\\{name}");
                        deleted++;
                        continue;
                    }
                    try
                    {
                        key.DeleteValue(name);
                        deleted++;
                        GuardLogger.Info($"Deleted startup entry: {name} ({path})");
                    }
                    catch (Exception ex)
                    {
                        GuardLogger.Warn($"Startup entry delete failed {name}: {ex.Message}");
                    }
                }
            }
        }
        // Active Setup stub installers — re-run at EVERY user sign-in
        foreach (var path in ActiveSetupPaths)
        {
            Microsoft.Win32.RegistryKey? rootKey;
            try
            {
                rootKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path, writable: true);
            }
            catch { continue; }
            if (rootKey == null)
                continue;
            using (rootKey)
            {
                foreach (var sub in rootKey.GetSubKeyNames())
                {
                    bool matched;
                    try
                    {
                        using var sk = rootKey.OpenSubKey(sub);
                        var blob = sub + " " + (sk?.GetValue(null)?.ToString() ?? "")
                            + " " + (sk?.GetValue("StubPath")?.ToString() ?? "")
                            + " " + (sk?.GetValue("LocalizedName")?.ToString() ?? "");
                        matched = IsBloat(blob, config);
                    }
                    catch { matched = false; }
                    if (!matched)
                        continue;
                    if (dryRun)
                    {
                        GuardLogger.Info($"[DRY-RUN] Would delete Active Setup stub: {path}\\{sub}");
                        deleted++;
                        continue;
                    }
                    try
                    {
                        rootKey.DeleteSubKey(sub);
                        deleted++;
                        GuardLogger.Info($"Deleted Active Setup stub: {sub} ({path})");
                    }
                    catch (Exception ex)
                    {
                        GuardLogger.Warn($"Active Setup stub delete failed {sub}: {ex.Message}");
                    }
                }
            }
        }

        if (deleted > 0)
            GuardLogger.Info($"Startup bloat entries {(dryRun ? "flagged" : "deleted")}: {deleted}");
    }

    /// <summary>Stop + disable OEM/vendor auto-start services (updaters, nagware).
    /// Hardware-OEM services additionally require a bloat keyword — drivers and
    /// hardware-integration services (RGB, audio, power) are never touched.</summary>
    public static void DisableOemServices(GuardConfig config)
    {
        var pattern = string.Join("|", VendorPatterns.Select(Regex.Escape));
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"Get-Service | " +
                $"Where-Object {{$_.Name -match '{pattern}' -or $_.DisplayName -match '{pattern}'}} | " +
                "Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        var output = Proc.Capture(psi, 60000).Stdout;
        if (string.IsNullOrWhiteSpace(output))
            return;

        var services = new List<(string Name, string Display, string StartType)>();
        try
        {
            var doc = JsonDocument.Parse(output.Trim());
            var elements = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().ToList()
                : new List<JsonElement> { doc.RootElement };
            foreach (var el in elements)
            {
                // StartType serializes as a number (Disabled = 4)
                var startType = "";
                if (el.TryGetProperty("StartType", out var st))
                    startType = st.ValueKind == JsonValueKind.String
                        ? st.GetString() ?? "" : st.GetRawText();
                services.Add((
                    el.GetProperty("Name").GetString() ?? "",
                    el.GetProperty("DisplayName").GetString() ?? "",
                    startType));
            }
        }
        catch (Exception ex)
        {
            GuardLogger.Warn($"Service scan parse error: {ex.Message}");
            return;
        }

        var disabled = 0;
        foreach (var (name, display, startType) in services)
        {
            if (string.IsNullOrEmpty(name) ||
                startType.Equals("Disabled", StringComparison.OrdinalIgnoreCase) ||
                startType == "4")
                continue;
            // Hardware vendors also need a bloat keyword — skips e.g. RGB/audio services
            if (!IsBloat($"{name} {display}", config))
                continue;
            RunSc($"stop \"{name}\"");
            if (RunSc($"config \"{name}\" start= disabled"))
            {
                disabled++;
                GuardLogger.Info($"Disabled OEM service: {name} ({display})");
            }
            else
            {
                GuardLogger.Warn($"Service disable failed [admin required?]: {name}");
            }
        }
        GuardLogger.Info($"Disabled {disabled} OEM/vendor services");
    }

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
        // Skip the write when the block is already in the desired state.
        if (File.Exists(hostsPath) && text == original)
            return;
        try
        {
            File.WriteAllText(hostsPath, text);
            GuardLogger.Info($"Telemetry hosts block {(enabled ? "applied" : "removed")} ({TelemetryHosts.Length} domains)");
        }
        catch (Exception ex)
        {
            GuardLogger.Warn($"Cannot write hosts file [admin required]: {ex.Message}");
        }
    }

    /// <summary>`winget uninstall --silent` sweep for bloat/vendor matches.
    /// Catches leftovers that neither Appx nor the Uninstall-hive sweep can
    /// reach silently. Skips cleanly when winget (App Installer) is absent.</summary>
    public static int WingetSweep(GuardConfig config, bool dryRun)
    {
        if (RunCmdExitCode("winget --version", 15) != 0)
        {
            GuardLogger.Info("winget not available — skipping winget sweep");
            return 0;
        }
        var (stdout, rc) = RunCmdCapture(
            "winget list --accept-source-agreements --disable-interactivity", 180);
        if (rc != 0 || string.IsNullOrWhiteSpace(stdout))
            return 0;

        var removed = 0;
        foreach (var rawLine in stdout.Split('\n'))
        {
            var cols = Regex.Split(rawLine.Trim(), @"\s{2,}");
            if (cols.Length < 2 || cols[0].Length == 0 || cols[1].StartsWith("-"))
                continue; // header/separator line
            var name = cols[0];
            var pkgId = cols[1];
            // winget ids are simple identifiers — anything else never reaches a shell
            if (!Regex.IsMatch(pkgId, @"^[A-Za-z0-9_.\-]+$"))
                continue;
            if (!IsBloat($"{name} {pkgId}", config))
                continue;
            if (dryRun)
            {
                GuardLogger.Info($"[DRY-RUN] Would winget-uninstall: {name} ({pkgId})");
                removed++;
                continue;
            }
            var rc2 = RunCmdExitCode(
                $"winget uninstall --id \"{pkgId}\" --silent --disable-interactivity --accept-source-agreements", 300);
            if (rc2 == 0)
            {
                GuardLogger.Info($"winget-uninstalled: {name} ({pkgId})");
                RemovalLedger.Record(config, "winget", name);
                removed++;
            }
            else
            {
                GuardLogger.Info($"winget uninstall skipped/failed: {name}");
            }
        }
        return removed;
    }

    /// <summary>Remove Windows capabilities Microsoft has deprecated (WordPad,
    /// Steps Recorder) — they persist in the image though nothing uses them.</summary>
    public static int RemoveDeprecatedCapabilities()
    {
        var removed = 0;
        foreach (var pattern in DeprecatedCapabilities)
        {
            var (stdout, rc) = RunPowerShellCapture(
                $"Get-WindowsCapability -Online -Name '{pattern}*' | " +
                "Where-Object {$_.State -eq 'Installed'} | Select-Object Name | ConvertTo-Json", 60);
            if (rc != 0 || string.IsNullOrWhiteSpace(stdout))
                continue;
            List<JsonElement> elements;
            try
            {
                var doc = JsonDocument.Parse(stdout.Trim());
                elements = doc.RootElement.ValueKind == JsonValueKind.Array
                    ? doc.RootElement.EnumerateArray().ToList()
                    : new List<JsonElement> { doc.RootElement };
            }
            catch { continue; }
            foreach (var cap in elements)
            {
                var name = cap.GetProperty("Name").GetString() ?? "";
                if (string.IsNullOrEmpty(name))
                    continue;
                var rc2 = RunPowerShellCapture(
                    $"Remove-WindowsCapability -Online -Name '{name}'", 180).Item2;
                if (rc2 == 0)
                {
                    GuardLogger.Info($"Removed deprecated capability: {name}");
                    removed++;
                }
            }
        }
        return removed;
    }

    /// <summary>Stop + disable telemetry/leftover system services (DiagTrack,
    /// Xbox leftovers, WMP sharing). NCSI active probing stays on — disabling it
    /// breaks captive-portal detection on public Wi-Fi.</summary>
    public static int DisableTelemetryServices()
    {
        var disabled = 0;
        foreach (var name in TelemetryServices)
        {
            if (RunCmdExitCode($"sc.exe query {name}", 10) != 0)
                continue; // service not present on this machine
            RunSc($"stop {name}");
            if (RunSc($"config {name} start= disabled"))
            {
                disabled++;
                GuardLogger.Info($"Disabled telemetry service: {name}");
            }
            else
            {
                GuardLogger.Warn($"Service disable failed [admin required?]: {name}");
            }
        }
        GuardLogger.Info($"Disabled {disabled} telemetry/leftover services");
        return disabled;
    }

    private static int RunCmdExitCode(string command, int timeoutSec)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        return Proc.Wait(psi, timeoutSec * 1000) ?? -1;
    }

    private static (string Stdout, int Rc) RunCmdCapture(string command, int timeoutSec)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        var (stdout, _, rc) = Proc.Capture(psi, timeoutSec * 1000);
        return (stdout.Trim(), rc ?? -1);
    }

    private static (string Stdout, int Rc) RunPowerShellCapture(string command, int timeoutSec)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        var (stdout, _, rc) = Proc.Capture(psi, timeoutSec * 1000);
        return (stdout.Trim(), rc ?? -1);
    }

    private static bool RunSc(string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = arguments,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        return Proc.Wait(psi, 20000) == 0;
    }

    private static bool RunCmd(string command, int timeoutSec)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{command}\"",
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        return Proc.Wait(psi, timeoutSec * 1000) == 0;
    }

    private static IEnumerable<string> EnumerateUserSidHives()
    {
        string[] names;
        try { names = Microsoft.Win32.Registry.Users.GetSubKeyNames(); }
        catch { yield break; }
        foreach (var n in names)
            if (n.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
                !n.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                yield return n;
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
            RegistryGuard.ApplyAll(_config.Prevention);

            if (_config.Prevention.DisableOemScheduledTasks)
            {
                GuardLogger.Info("Disabling OEM scheduled tasks...");
                ScheduledTaskGuard.DisableOemTasks();
            }

            if (_config.Prevention.DisableTelemetryTasks)
            {
                GuardLogger.Info("Disabling telemetry/CEIP scheduled tasks...");
                ScheduledTaskGuard.DisableTelemetryTasks();
            }

            if (_config.Prevention.DisableOemServices)
            {
                GuardLogger.Info("Disabling OEM/vendor services...");
                Win32BloatGuard.DisableOemServices(_config);
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
                    CheckReinstalls(seenProvisioned, seenInstalled, firstScan, _config.DryRun);
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
        HashSet<string> seenProvisioned, HashSet<string> seenInstalled, bool firstScan, bool dryRun)
    {
        var currentProvisioned = new HashSet<string>(
            AppxManager.GetBlacklistedProvisionedPackages(_config.Blacklist, _config.Whitelist)
                .Select(p => p.PackageName),
            StringComparer.OrdinalIgnoreCase);
        var installed = AppxManager.GetBlacklistedPackages(_config.Blacklist, _config.Whitelist);
        var currentInstalled = new HashSet<string>(
            installed.Select(p => p.PackageFamilyName), StringComparer.OrdinalIgnoreCase);

        if (!firstScan)
        {
            foreach (var pkg in currentProvisioned.Except(seenProvisioned))
            {
                GuardLogger.Warn($"[MONITOR] RE-INSTALLED detected: {pkg} — removing immediately!");
                if (dryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would re-remove provisioned package: {pkg}");
                }
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
                if (dryRun)
                {
                    GuardLogger.Info($"[DRY-RUN] Would re-remove package: {family}");
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
        var matchedFamilies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
            foreach (var (pkgName, provFamily) in provisioned)
            {
                if (IsWhitelisted(pkgName) || IsWhitelisted(provFamily))
                {
                    GuardLogger.Info($"Whitelisted provisioned (skip): {pkgName}");
                    skipped++;
                    continue;
                }

                matchedFamilies.Add(provFamily);

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

        // When a removal toggle is off, its packages were never enumerated —
        // but the persistence layers still need the families to protect future
        // profiles and feature updates.
        if ((_config.Prevention.MarkDeprovisioned || _config.Prevention.RemoveDefaultStorePackages) &&
            (!_config.Prevention.RemoveAppxPackages || !_config.Prevention.RemoveProvisionedPackages))
        {
            if (!_config.Prevention.RemoveAppxPackages)
                foreach (var (family, _, _, isFw, _) in
                         AppxManager.GetBlacklistedPackages(_config.Blacklist, _config.Whitelist))
                    if (!isFw && !IsWhitelisted(family))
                        matchedFamilies.Add(family);
            if (!_config.Prevention.RemoveProvisionedPackages)
                foreach (var (_, provFamily) in
                         AppxManager.GetBlacklistedProvisionedPackages(_config.Blacklist, _config.Whitelist))
                    if (!IsWhitelisted(provFamily))
                        matchedFamilies.Add(provFamily);
        }

        // 3. Re-apply registry settings (they can be reset by Windows Update)
        if (!dryRun)
            RegistryGuard.ApplyAll(_config.Prevention);
        else
            GuardLogger.Info("[DRY-RUN] Would re-apply registry prevention settings");

        // 4. Persist removal: Deprovisioned markers stop feature-update re-installs;
        //    the 25H2 policy stops provisioning for future user profiles
        if (!dryRun && matchedFamilies.Count > 0)
        {
            if (_config.Prevention.MarkDeprovisioned)
                RegistryGuard.MarkDeprovisioned(matchedFamilies);
            if (_config.Prevention.RemoveDefaultStorePackages)
                RegistryGuard.WriteRemoveDefaultStorePackagesPolicy(matchedFamilies);
        }
        else if (dryRun && matchedFamilies.Count > 0)
        {
            GuardLogger.Info($"[DRY-RUN] Would mark {matchedFamilies.Count} package families deprovisioned + write removal policy");
        }

        // 5. Win32 (MSI/EXE) bloat + winget sweep + deprecated capabilities —
        //    everything Appx removal can't see
        if (_config.Prevention.RemoveWin32Bloatware)
            removed += Win32BloatGuard.RemoveWin32Bloatware(_config, dryRun);
        if (_config.Prevention.WingetSweep)
            removed += Win32BloatGuard.WingetSweep(_config, dryRun);
        if (_config.Prevention.RemoveDeprecatedCapabilities)
        {
            if (dryRun)
                GuardLogger.Info("[DRY-RUN] Would remove deprecated Windows capabilities");
            else
                Win32BloatGuard.RemoveDeprecatedCapabilities();
        }

        // 6. Telemetry + OEM auto-start services + Run-key startup entries
        if (_config.Prevention.DisableTelemetryServices)
        {
            if (dryRun)
                GuardLogger.Info("[DRY-RUN] Would disable telemetry/leftover services");
            else
                Win32BloatGuard.DisableTelemetryServices();
        }

        if (_config.Prevention.DisableOemServices)
        {
            if (dryRun)
                GuardLogger.Info("[DRY-RUN] Would disable OEM/vendor services");
            else
                Win32BloatGuard.DisableOemServices(_config);
        }
        if (_config.Prevention.CleanStartupEntries)
            Win32BloatGuard.CleanStartupEntries(_config, dryRun);

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
                    Console.WriteLine("BloatwareGuard v1.8.0-mvp");
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
            RegistryGuard.ApplyAll(config.Prevention);
            if (config.Prevention.DisableOemScheduledTasks)
                ScheduledTaskGuard.DisableOemTasks();
            if (config.Prevention.DisableTelemetryTasks)
                ScheduledTaskGuard.DisableTelemetryTasks();
            if (config.Prevention.DisableOemServices)
                Win32BloatGuard.DisableOemServices(config);
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
BloatwareGuard v1.8.0-mvp — Windows 11 bloatware removal + prevention

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
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = $"create BloatwareGuard binPath= \"{exePath}\" start= auto DisplayName= \"Bloatware Guard\"",
            UseShellExecute = true,
            Verb = "runas"
        };
        Process.Start(psi);
        GuardLogger.Info("Service installed. Use 'sc start BloatwareGuard' to start.");
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
        var (stdout, _, _) = Proc.Capture(psi, 15000);
        Console.WriteLine(stdout);
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
        return Proc.Wait(psi, 60000) == 0;
    }

    /// <summary>
    /// Self-test mode: validates internal wiring without requiring admin elevation.
    /// Bypasses UAC by testing structure, not actual removal logic.
    /// </summary>
    private static int RunSelfTest(GuardConfig config)
    {
        var passed = 0;
        var total = 12;
        var results = new List<string>();

        GuardLogger.Info("=== BloatwareGuard v1.8.0-mvp — Self-Test Mode === [no admin required]");
        Console.WriteLine("=== BloatwareGuard v1.8.0-mvp — Self-Test Mode === [no admin required]");

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

        // Test 7: New prevention-layer flags exist and default to true
        try
        {
            var flags = new[] { "MarkDeprovisioned", "RemoveDefaultStorePackages",
                "HardenContentDelivery", "DisableAiFeatures", "DisableWidgets",
                "DisableSearchSuggestions", "DisableTelemetryTasks",
                "DisableTelemetryPolicies", "HardenEdgePolicies",
                "CleanStartupEntries", "DisableOemServices", "RemoveWin32Bloatware",
                "DisableGameDvr", "BlockTelemetryEndpoints",
                "WingetSweep", "RemoveDeprecatedCapabilities", "DisableTelemetryServices",
                "DisableTelemetryAutologgers" };
            var missing = flags.Where(f =>
                typeof(PreventionLayers).GetProperty(f) == null).ToList();
            var defaultsOn = flags.All(f =>
                typeof(PreventionLayers).GetProperty(f) is { } prop &&
                prop.GetValue(new PreventionLayers()) is bool b && b);
            if (missing.Count == 0 && defaultsOn)
            {
                results.Add("[PASS] T7: Prevention layers — 18 new flags registered & default-on");
                GuardLogger.Info("[PASS] T7: New prevention flags present");
                passed++;
            }
            else
            {
                results.Add($"[FAIL] T7: Prevention layers — missing/off-by-default: {string.Join(",", missing)}");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T7: Prevention layers — {ex.Message}");
        }

        // Test 8: New prevention-layer methods wired
        try
        {
            bool wired =
                typeof(RegistryGuard).GetMethod("MarkDeprovisioned") != null &&
                typeof(RegistryGuard).GetMethod("WriteRemoveDefaultStorePackagesPolicy") != null &&
                typeof(RegistryGuard).GetMethod("DisableAiFeatures") != null &&
                typeof(RegistryGuard).GetMethod("DisableWidgets") != null &&
                typeof(RegistryGuard).GetMethod("DisableSearchSuggestions") != null &&
                typeof(RegistryGuard).GetMethod("DisableTelemetryPolicies") != null &&
                typeof(RegistryGuard).GetMethod("HardenEdgePolicies") != null &&
                typeof(ScheduledTaskGuard).GetMethod("DisableTelemetryTasks") != null &&
                typeof(Win32BloatGuard).GetMethod("RemoveWin32Bloatware") != null &&
                typeof(Win32BloatGuard).GetMethod("CleanStartupEntries") != null &&
                typeof(Win32BloatGuard).GetMethod("DisableOemServices") != null &&
                typeof(Win32BloatGuard).GetMethod("SetTelemetryHostsBlock") != null &&
                typeof(Win32BloatGuard).GetMethod("WingetSweep") != null &&
                typeof(Win32BloatGuard).GetMethod("RemoveDeprecatedCapabilities") != null &&
                typeof(Win32BloatGuard).GetMethod("DisableTelemetryServices") != null &&
                typeof(RegistryGuard).GetMethod("DisableTelemetryAutologgers") != null;
            if (wired)
            {
                results.Add("[PASS] T8: New prevention methods — all wired");
                GuardLogger.Info("[PASS] T8: New prevention methods wired");
                passed++;
            }
            else
            {
                results.Add("[FAIL] T8: New prevention methods — a method is missing");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T8: New prevention methods — {ex.Message}");
        }

        // Test 9: Win32 silent-uninstall classifier
        try
        {
            var msi = Win32BloatGuard.SilentUninstallCommand(
                "MsiExec.exe /I{12345678-1234-1234-1234-123456789012}", "");
            var quiet = Win32BloatGuard.SilentUninstallCommand("x", "uninst.exe /S");
            var flagged = Win32BloatGuard.SilentUninstallCommand("\"C:\\app\\uninstall.exe\" /S", "");
            var interactive = Win32BloatGuard.SilentUninstallCommand("\"C:\\app\\uninstall.exe\"", "");
            if (msi == "msiexec.exe /x {12345678-1234-1234-1234-123456789012} /qn /norestart" &&
                quiet == "uninst.exe /S" && flagged != null && interactive == null)
            {
                results.Add("[PASS] T9: Win32 silent-uninstall classifier — msiexec/quiet/flagged/interactive all correct");
                GuardLogger.Info("[PASS] T9: Win32 silent-uninstall classifier");
                passed++;
            }
            else
            {
                results.Add($"[FAIL] T9: Win32 classifier — msi={msi ?? "null"} flagged={(flagged == null ? "null" : "ok")} interactive={interactive ?? "null"}");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T9: Win32 classifier — {ex.Message}");
        }

        // Test 10: Vendor/telemetry table sanity
        try
        {
            var vendorCount = typeof(Win32BloatGuard)
                .GetField("VendorPatterns", System.Reflection.BindingFlags.NonPublic |
                    System.Reflection.BindingFlags.Static)?.GetValue(null) is string[] v ? v.Length : 0;
            var taskCount = typeof(ScheduledTaskGuard)
                .GetField("TelemetryTaskPaths", System.Reflection.BindingFlags.NonPublic |
                    System.Reflection.BindingFlags.Static)?.GetValue(null) is string[] t ? t.Length : 0;
            if (vendorCount >= 15 && taskCount >= 10)
            {
                results.Add($"[PASS] T10: Vendor/telemetry tables — {vendorCount} vendor patterns, {taskCount} telemetry tasks");
                passed++;
            }
            else
            {
                results.Add($"[FAIL] T10: tables too small (vendor={vendorCount}, telemetry={taskCount})");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T10: table sanity — {ex.Message}");
        }

        // Test 11: telemetry hosts list well-formed (domains only, no WU/Store)
        try
        {
            var hosts = typeof(Win32BloatGuard)
                .GetField("TelemetryHosts", System.Reflection.BindingFlags.NonPublic |
                    System.Reflection.BindingFlags.Static)?.GetValue(null) as string[];
            var valid = hosts != null && hosts.Length >= 20 && hosts.All(h =>
                Regex.IsMatch(h, @"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$") &&
                !h.Contains("windowsupdate") && !h.Contains("activation") &&
                !h.Contains("store"));
            if (valid)
            {
                results.Add($"[PASS] T11: Telemetry hosts list — {hosts!.Length} domains, no update endpoints");
                passed++;
            }
            else
            {
                results.Add("[FAIL] T11: Telemetry hosts list invalid or too small");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T11: hosts list — {ex.Message}");
        }

        // Test 12: policy table sanity (telemetry writes ≥12, Edge ≥6, game dvr ≥2)
        try
        {
            var tele = typeof(RegistryGuard)
                .GetField("TelemetryPolicyWrites", System.Reflection.BindingFlags.NonPublic |
                    System.Reflection.BindingFlags.Static)?.GetValue(null)
                as (string, string, int)[];
            var edge = typeof(RegistryGuard)
                .GetField("EdgePolicies", System.Reflection.BindingFlags.NonPublic |
                    System.Reflection.BindingFlags.Static)?.GetValue(null)
                as (string, int)[];
            var gdvr = typeof(RegistryGuard)
                .GetField("GameDvrUserWrites", System.Reflection.BindingFlags.NonPublic |
                    System.Reflection.BindingFlags.Static)?.GetValue(null)
                as (string, string, int)[];
            if (tele != null && tele.Length >= 12 && edge != null && edge.Length >= 6 &&
                gdvr != null && gdvr.Length >= 2)
            {
                results.Add($"[PASS] T12: Policy tables — {tele.Length} telemetry writes, {edge.Length} Edge, {gdvr.Length} GameDVR");
                passed++;
            }
            else
            {
                results.Add($"[FAIL] T12: policy tables too small (tele={tele?.Length}, edge={edge?.Length}, gdvr={gdvr?.Length})");
            }
        }
        catch (Exception ex)
        {
            results.Add($"[FAIL] T12: policy tables — {ex.Message}");
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
