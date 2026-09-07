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

    /// <summary>Prevention layers</summary>
    public PreventionLayers Prevention { get; set; } = new();

    /// <summary>Log file path (optional, alongside Event Log)</summary>
    public string? LogFilePath { get; set; }
}

public class PreventionLayers
{
    /// <summary>Remove AppxPackage + ProvisionedPackage</summary>
    public bool RemoveAppxPackages { get; set; } = true;

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
}

// ─── Logger helper ───────────────────────────────────────────────────────────

public static class GuardLogger
{
    private const string EventSource = "BloatwareGuard";
    private const string EventLogName = "Application";

    public static void EnsureSourceExists()
    {
        if (!EventLog.SourceExists(EventSource))
        {
            EventLog.CreateEventSource(EventSource, EventLogName);
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
            }
        };
    }
}

// ─── Appx Package Manager ────────────────────────────────────────────────────

public static class AppxManager
{
    /// <summary>Get all installed AppxPackages whose FamilyName matches any blacklist entry</summary>
    public static List<(string PackageFamilyName, string DisplayName)> GetBlacklistedPackages(
        List<string> blacklist)
    {
        var results = new List<(string, string)>();

        // PowerShell: Get-AppxPackage | Where-Object {$_.PackageFamilyName -match "..."}
        var pattern = string.Join("|", blacklist.Select(Regex.Escape));
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -Command \"Get-AppxPackage | Where-Object {{$_.PackageFamilyName -match '{pattern}'}} | Select-Object PackageFamilyName,Name | ConvertTo-Json\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? "";
        proc?.WaitForExit();

        try
        {
            // Handle both single object and array JSON
            var doc = JsonDocument.Parse(output.Trim());
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    var family = el.GetProperty("PackageFamilyName").GetString() ?? "";
                    var name = el.GetProperty("Name").GetString() ?? "";
                    results.Add((family, name));
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                var family = doc.RootElement.GetProperty("PackageFamilyName").GetString() ?? "";
                var name = doc.RootElement.GetProperty("Name").GetString() ?? "";
                results.Add((family, name));
            }
        }
        catch { /* no matches or parse error */ }

        return results;
    }

    /// <summary>Get all provisioned packages (these re-deploy on new user creation)</summary>
    public static List<string> GetBlacklistedProvisionedPackages(List<string> blacklist)
    {
        var results = new List<string>();
        var pattern = string.Join("|", blacklist.Select(Regex.Escape));

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -Command \"Get-AppxProvisionedPackage -Online | Where-Object {{$_.DisplayName -match '{pattern}'}} | Select-Object DisplayName | ConvertTo-Json\"",
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
                    results.Add(el.GetProperty("DisplayName").GetString() ?? "");
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                results.Add(doc.RootElement.GetProperty("DisplayName").GetString() ?? "");
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
            Arguments = $"-NoProfile -Command \"Remove-AppxPackage -Package '{packageFullName}' -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit();
        return proc?.ExitCode == 0;
    }

    public static bool RemoveProvisionedPackage(string displayName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -Command \"Remove-AppxProvisionedPackage -Online -PackageName '{displayName}' -ErrorAction SilentlyContinue\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit();
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
    // Known OEM bloatware task patterns
    private static readonly string[] OemTaskPatterns = {
        "OEM", "Dell", "HP", "Lenovo", "ASUS", "Acer", "McAfee", "Norton",
        "Bloat", "Reinstall", "Restore", "SupportAssist", "Vantage",
        "Armoury", "Crate", "Update", "Telemetry", "CustomerExperience"
    };

    public static void DisableOemTasks()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -Command \"Get-ScheduledTask | Where-Object {$_.TaskPath -like '*OEM*' -or $_.TaskName -match 'SupportAssist|Vantage|Armoury|Crate|Dell|HPInc|Lenovo|ASUS|Acer|McAfee|Norton|CustomerExperience|Reinstall|Restore'} | Select-Object TaskName,TaskPath,State | ConvertTo-Json\"",
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

// ─── Main Service ────────────────────────────────────────────────────────────

public class GuardService : BackgroundService
{
    private readonly GuardConfig _config;

    public GuardService(GuardConfig config)
    {
        _config = config;
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
                RunScan();
            }
            catch (Exception ex)
            {
                GuardLogger.Error($"Scan error: {ex.Message}");
            }

            await Task.Delay(TimeSpan.FromSeconds(_config.ScanIntervalSeconds), stoppingToken);
        }
    }

    private void RunScan()
    {
        GuardLogger.Info("Starting bloatware scan...");

        int removed = 0;

        // 1. Remove installed AppxPackages matching blacklist
        if (_config.Prevention.RemoveAppxPackages)
        {
            var packages = AppxManager.GetBlacklistedPackages(_config.Blacklist);
            foreach (var (familyName, displayName) in packages)
            {
                // Get full package name for removal
                var fullName = GetPackageFullName(familyName);
                if (!string.IsNullOrEmpty(fullName))
                {
                    if (AppxManager.RemoveAppxPackage(fullName))
                    {
                        GuardLogger.Info($"Removed AppxPackage: {familyName} ({displayName})");
                        removed++;
                    }
                    else
                    {
                        GuardLogger.Warn($"Failed to remove: {familyName}");
                    }
                }
            }

            // 2. Remove provisioned packages (prevents re-deploy on new users)
            var provisioned = AppxManager.GetBlacklistedProvisionedPackages(_config.Blacklist);
            foreach (var displayName in provisioned)
            {
                if (AppxManager.RemoveProvisionedPackage(displayName))
                {
                    GuardLogger.Info($"Removed ProvisionedPackage: {displayName}");
                    removed++;
                }
                else
                {
                    GuardLogger.Warn($"Failed to remove provisioned: {displayName}");
                }
            }
        }

        // 3. Re-apply registry settings (they can be reset by Windows Update)
        RegistryGuard.ApplyAll(_config.Prevention);

        GuardLogger.Info($"Scan complete. Removed {removed} packages.");
    }

    private string GetPackageFullName(string packageFamilyName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -Command \"(Get-AppxPackage -PackageFamilyName '{packageFamilyName}').PackageFullName\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd().Trim() ?? "";
        proc?.WaitForExit();

        return string.IsNullOrEmpty(output) ? "" : output.Split('\n').Last().Trim();
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
                    RunOnce(config);
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
            }
        }

        // Run as Windows Service
        Host.CreateDefaultBuilder(args)
            .UseWindowsService()
            .ConfigureServices(services =>
            {
                services.AddHostedService<GuardService>(_ => new GuardService(config));
            })
            .Build()
            .Run();
    }

    private static void RunOnce(GuardConfig config)
    {
        GuardLogger.Info("Running one-time scan...");
        RegistryGuard.ApplyAll(config.Prevention);
        ScheduledTaskGuard.DisableOemTasks();

        var service = new GuardService(config);
        // Use reflection to call RunScan via a trick: just instantiate and call
        var method = service.GetType().GetMethod("RunScan",
            System.Reflection.BindingFlags.NonPublic |
            System.Reflection.BindingFlags.Instance);
        method?.Invoke(service, null);

        GuardLogger.Info("One-time scan complete.");
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
