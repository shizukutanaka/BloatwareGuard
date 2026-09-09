// BloatwareGuard - Windows Service to block and remove bloatware automatically
// Requires admin rights (UAC manifest)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Text.Json;
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
        try
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "config.json");
            if (File.Exists(configPath))
            {
                var json = File.ReadAllText(configPath);
                var config = JsonSerializer.Deserialize<GuardConfig>(json);
                if (!string.IsNullOrEmpty(config?.LogFilePath))
                {
                    File.AppendAllText(config.LogFilePath, line + Environment.NewLine);
                }
            }
        }
        catch { /* ignore file log errors */ }
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
        var config = JsonSerializer.Deserialize<GuardConfig>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip
        });

        return config ?? CreateDefault();
    }

    public static void Save(string path, GuardConfig config)
    {
        var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
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

                // Third-party bloatware commonly pre-installed
                "McAfee",
                "Norton",
                "SpotifyAB.SpotifyMusic",
                "Netflix",
                "Dolby",
                "RealtekSemiconductor",
                "SynapticsIncorporated",

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
    public static List<(string PackageFamilyName, string DisplayName, string PackageFullName, bool IsFramework, string InstallPath)> GetBlacklistedPackages(
        List<string> blacklist, List<string> whitelist)
    {
        var results = new List<(string, string, string, bool, string)>();
        var pattern = string.Join("|", blacklist.Select(Regex.Escape));
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-AppxPackage | Where-Object {{$_.PackageFamilyName -match '{pattern}'}} | Select-Object PackageFamilyName,Name,PackageFullName,IsFramework,InstallPath | ConvertTo-Json\"",
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
                    var family = el.GetProperty("PackageFamilyName").GetString() ?? "";
                    var name = el.GetProperty("Name").GetString() ?? "";
                    var fullName = el.GetProperty("PackageFullName").GetString() ?? "";
                    var isFw = el.TryGetProperty("IsFramework", out var fw) && fw.ValueKind == JsonValueKind.True;
                    var installPath = el.TryGetProperty("InstallPath", out var ip) ? ip.GetString() : null;
                    if (!IsWhitelisted(family, whitelist))
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
                if (!IsWhitelisted(family, whitelist))
                    results.Add((family, name, fullName, isFw, installPath));
            }
        }
        catch { /* no matches or parse error */ }

        return results;
    }

    /// <summary>Check if a package family name matches any whitelist entry</summary>
    public static bool IsWhitelisted(string packageFamilyName, List<string> whitelist)
    {
        return whitelist.Any(w => packageFamilyName.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Get all provisioned packages (these re-deploy on new user creation)</summary>
    public static List<string> GetBlacklistedProvisionedPackages(List<string> blacklist, List<string> whitelist)
    {
        var results = new List<string>();
        var pattern = string.Join("|", blacklist.Select(Regex.Escape));

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
    public static (bool Success, bool IsSystemApp) RemoveAppxPackageForUser(string packageFullName, string installPath = null)
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

// ─── Registry-based Prevention ───────────────────────────────────────────────

public static class RegistryGuard
{
    private const string CloudContentPath = @"SOFTWARE\Policies\Microsoft\Windows\CloudContent";
    private const string DeviceMetadataPath = @"SOFTWARE\Policies\Microsoft\Windows\Device Metadata";
    private const string AppCompatPath = @"SOFTWARE\Policies\Microsoft\Windows\AppCompat";
    private const string WindowsSearchPath = @"SOFTWARE\Policies\Microsoft\Windows\Windows Search";

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
}

// ─── Scheduled Task Manager ──────────────────────────────────────────────────

public static class ScheduledTaskGuard
{
    // Known OEM bloatware task patterns — must be specific enough to avoid matching Microsoft system tasks
    private static readonly string[] OemTaskPatterns = {
        "OEM", "Dell", "HPInc", "HPA", "Lenovo", "ASUS", "Acer", "McAfee", "Norton",
        "SupportAssist", "Vantage", "Armoury", "Crate", "CustomerExperienceImprovement",
        "Customer Experience Improvement", "Reinstall", "Bloatware"
    };

    // Microsoft system tasks that MUST NEVER be disabled
    private static readonly string[] MicrosoftSystemPrefixes = {
        @"\\Microsoft\\Windows\\CloudRestore",
        @"\\Microsoft\\Windows\\InstallService",
        @"\\Microsoft\\Windows\\WindowsUpdate",
        @"\\Microsoft\\Windows\\UpdateOrchestrator",
        @"\\Microsoft\\Windows\\Defrag",
        @"\\Microsoft\\Windows\\Diagnosis",
        @"\\Microsoft\\Windows\\Maintenance",
        @"\\Microsoft\\Windows\\CloudExperienceHost",
        @"\\Microsoft\\Windows\\Feedback",
        @"\\Microsoft\\Windows\\Input",
        @"\\Microsoft\\Windows\\International",
        @"\\Microsoft\\Windows\\LanguageComponentsInstaller",
        @"\\Microsoft\\Windows\\MUI",
        @"\\Microsoft\\Windows\\PI",
        @"\\Microsoft\\Windows\\RecoveryEnvironment",
        @"\\Microsoft\\Windows\\Servicing",
        @"\\Microsoft\\Windows\\SettingSync",
        @"\\Microsoft\\Windows\\Shell",
        @"\\Microsoft\\Windows\\Sysmain",
        @"\\Microsoft\\Windows\\WDI",
        @"\\Microsoft\\Windows\\Wlan",
        @"\\Microsoft\\Windows\\Bluetooth",
        @"\\Microsoft\\Windows\\NetTrace",
        @"\\Microsoft\\Windows\\Security Center",
        @"\\Microsoft\\Windows\\SpaceAgent",
        @"\\Microsoft\\Windows\\Storage",
        @"\\Microsoft\\Windows\\SystemRestore",
        @"\\Microsoft\\Windows\\Task Manager",
        @"\\Microsoft\\Windows\\VerifiableFileIntegrity",
        @"\\Microsoft\\Windows\\WebAuth",
        @"\\Microsoft\\Windows\\WiFi",
        @"\\Microsoft\\Windows\\Windows Error Reporting",
        @"\\Microsoft\\Windows\\License Manager",
        @"\\Microsoft\\Windows\\Clip",
    };


    public static void DisableOemTasks()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"Get-ScheduledTask | Where-Object {$_.TaskPath -like '*OEM*' -or $_.TaskName -match 'SupportAssist|Vantage|Armoury|Crate|Dell|HPInc|Lenovo|ASUS|Acer|McAfee|Norton|CustomerExperience|Reinstall|Restore'} | Select-Object TaskName,TaskPath,State | ConvertTo-Json\"",
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

            foreach (var (name, path) in tasks)
            {
                DisableTask(name, path);
            }

            GuardLogger.Info($"Disabled {tasks.Count} OEM scheduled tasks");
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

        // Apply registry-based prevention once at startup
        GuardLogger.Info("Applying registry-based prevention layers...");
        RegistryGuard.ApplyAll(_config.Prevention);

        if (_config.Prevention.DisableOemScheduledTasks)
        {
            GuardLogger.Info("Disabling OEM scheduled tasks...");
            ScheduledTaskGuard.DisableOemTasks();
        }

        // Main scan loop
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                RunScan(_config.DryRun);
            }
            catch (Exception ex)
            {
                GuardLogger.Error($"Scan error: {ex.Message}");
            }

            await Task.Delay(TimeSpan.FromSeconds(_config.ScanIntervalSeconds), stoppingToken);
        }
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
                    removed++;
                }
                else if (dryRun)
                {
                    // already handled above
                }
                else
                {
                    GuardLogger.Warn($"Admin removal failed for {familyName}, trying user-level...");
                    var (success, isSystemApp) = AppxManager.RemoveAppxPackageForUser(fullName, installPath);
                    if (success)
                    {
                        GuardLogger.Info($"Removed AppxPackage (user-level): {familyName} ({displayName})");
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

            // 2. Remove provisioned packages (prevents re-deploy on new users)
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
                    GuardLogger.Info($"[DRY-RUN] Would remove provisioned: {pkgName}");
                    removed++;
                }
                else if (AppxManager.RemoveProvisionedPackage(pkgName))
                {
                    GuardLogger.Info($"Removed ProvisionedPackage: {pkgName}");
                    removed++;
                }
                else
                {
                    GuardLogger.Warn($"Failed to remove provisioned: {pkgName}");
                }
            }
        }

        // 3. Re-apply registry settings (they can be reset by Windows Update)
        if (!dryRun)
            RegistryGuard.ApplyAll(_config.Prevention);
        else
            GuardLogger.Info("[DRY-RUN] Would re-apply registry prevention settings");

        GuardLogger.Info($"Scan complete. {(dryRun ? "Would remove" : "Removed")} {removed} packages, skipped {skipped}, system apps skipped {systemAppsSkipped}, failed {failed}.");
    }

    private bool IsWhitelisted(string packageFamilyName)
    {
        var match = _config.Whitelist.FirstOrDefault(w =>
            packageFamilyName.StartsWith(w, StringComparison.OrdinalIgnoreCase));
        if (match != null)
            GuardLogger.Info($"  WHITELIST MATCH: '{packageFamilyName}' starts with '{match}'");
        return match != null;
    }

    private string GetPackageFullName(string packageFamilyName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"(Get-AppxPackage -PackageFamilyName '{packageFamilyName}').PackageFullName\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
        proc?.WaitForExit();

        // Validate: a real PackageFullName contains the family name
        if (!string.IsNullOrEmpty(output) && output.Contains(packageFamilyName) && !output.Contains("error"))
            return output.Split('\n').Last().Trim();
        return "";
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
                case "help":
                case "--help":
                case "-h":
                    ShowHelp();
                    return;
                case "--version":
                case "-v":
                    Console.WriteLine("BloatwareGuard v1.7.0");
                    return;
                case "--service-dry-run":
                    config.DryRun = true;
                    GuardLogger.Info("Service mode: DRY-RUN (no removal actions will execute)");
                    break;
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
            ScheduledTaskGuard.DisableOemTasks();
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
BloatwareGuard v1.7.0 — Windows 11 bloatware removal + prevention

Usage: BloatwareGuard.exe <command>

Commands:
  scan          Run one-time scan and remove bloatware
  dry-run       Show what WOULD be removed (no changes made)
  --service-dry-run  Run as service in dry-run mode (no removal actions)
  list-installed  List installed packages matching blacklist
  install       Install as Windows Service (requires admin)
  uninstall     Remove Windows Service (requires admin)
  status        Show Windows Service status
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
        using var proc = Process.Start(psi);
        Console.WriteLine(proc?.StandardOutput.ReadToEnd());
    }
}
