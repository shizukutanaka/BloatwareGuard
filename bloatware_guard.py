#!/usr/bin/env python3
"""
BloatwareGuard v1.30.0-mvp - Python prototype
Windowsサービス化可能な常駐型bloatware自動削除ツール

使い方:
  python bloatware_guard.py            # 常駐モード（定期スキャン）
  python bloatware_guard.py --scan     # 1回だけスキャン
  python bloatware_guard.py --dry-run  # 削除対象を表示のみ（変更なし）
  python bloatware_guard.py --service-dry-run  # 常駐モード＋強制dry-run（監視のみ）
  python bloatware_guard.py --install  # Windowsサービスに登録（要管理者）
  python bloatware_guard.py --uninstall # サービス削除（要管理者）
  python bloatware_guard.py --status   # 状態確認
  python bloatware_guard.py --restore  # 削除したパッケージを復元
  python bloatware_guard.py --version  # バージョン表示

※ 管理者権限が必要です。
"""

import subprocess
import json
import os
import re
import sys
import time
import ctypes
import argparse
import logging
import tempfile
import shutil
from pathlib import Path
from typing import List, Tuple

# ─── Constants ───────────────────────────────────────────────────────────────

APP_NAME = "BloatwareGuard"
APP_VERSION = "1.30.0-mvp"
SERVICE_NAME = "BloatwareGuard"
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.json"
LOG_DIR = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "BloatwareGuard"
LOG_FILE = LOG_DIR / "bloatware-guard.log"


# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path) -> logging.Logger:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    try:
        fh = logging.FileHandler(str(log_file), encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except PermissionError:
        # Non-admin: fall back to console only
        pass

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


# ─── Config ──────────────────────────────────────────────────────────────────

DEFAULT_BLACKLIST = [
    # Microsoft bloatware
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
    "Microsoft.549981C3F5F10",       # Cortana
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.Todos",
    "Microsoft.Windows.Photos",
    "Microsoft.WindowsAlarms",
    "Microsoft.ScreenSketch",
    "Microsoft.Clipchamp",
    "MicrosoftTeams",
    "Microsoft.MicrosoftEdge.Stable",
    "Microsoft.Windows.DevHome",       # Dev Home (+ GitHub extension)
    "Microsoft.Copilot",
    "Clipchamp.Clipchamp",
    "MSTeams",                          # New Teams (Work/School), provisioned via AppX push
    "Microsoft.OutlookForWindows",      # New Outlook, preinstalled since 23H2
    "Microsoft.WindowsCommunicationsApps",  # Mail & Calendar (discontinued Dec 2024)
    "MicrosoftCorporationII.MicrosoftFamily",
    "MicrosoftCorporationII.QuickAssist",
    "Microsoft.BingSearch",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.Edge.GameAssist",
    # Third-party
    "McAfee",
    "Norton",
    "SpotifyAB.SpotifyMusic",
    "Netflix",
    "Dolby",
    "RealtekSemiconductor",
    "SynapticsIncorporated",
    "BytedancePte.Ltd.TikTok",
    "KING.COM.",                       # CandyCrush + all King.com promo games
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "PandoraMediaInc.29680B314EFC2",
    "Facebook.InstagramBeta",
    "Facebook.Facebook",
    "WhatsApp",
    "A278AB0D.DisneyMagicKingdoms",
    "A278AB0D.MarchofEmpires",
    "Disney",                          # Disney+ etc.
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
]


def load_config(path: Path) -> dict:
    if not path.exists():
        config = {
            "ScanIntervalSeconds": 300,
            "LogFilePath": str(LOG_FILE),
            "Blacklist": DEFAULT_BLACKLIST,
            "Whitelist": [
                "Microsoft.WindowsStore",
                "Microsoft.WindowsCalculator",
                "Microsoft.WindowsNotepad",
                "Microsoft.WindowsTerminal",
                "Microsoft.Windows.ShellExperienceHost",
                "Microsoft.Windows.Cortana",
                "Microsoft.Windows.SecHealthUI",
                "Microsoft.Windows.Apprep.ChxApp",
            ],
            "Prevention": {
                "RemoveAppxPackages": True,
                "RemoveProvisionedPackages": True,
                "DisableConsumerExperiences": True,
                "DisableCloudContent": True,
                "PreventDeviceMetadata": True,
                "DisableOemScheduledTasks": True,
                "BlockProvisioning": True,
                "ReinstallMonitor": True,
                "DisableCopilot": True,
                "DisableRecall": True,
                "DisableSearchSuggestions": True,
                "DisableWidgets": True,
                "DisableTelemetry": True,
                "DisableGameDvr": True,
                "DisableDeliveryOptimization": True,
                "DisableOneDrive": False,
                "DisableChatTaskbar": True,
                "DisableEdgeBloat": True,
                "RemoveOptionalCapabilities": True,
                "RemoveWin32Programs": True,
                "CreateRestorePoint": True,
                "DisableTelemetryTasks": True,
                "DisableStartupBloat": True,
                "DisableErrorReporting": True,
                "DisableEdgeUpdateBloat": True,
                "BlockOemDriverUpdates": True,
                "DisableAppPermissions": True,
                "DisableXboxServices": True,
                "BackupRegistry": True,
                "DisablePrintSpooler": False,
                "BlockOemWpbtExecution": True,
                "DisableReservedStorage": True,
                "DisableCloudClipboard": True,
                "DisableRemoteAssistance": True,
                "BlockInsiderPreview": True,
                "DisableMiscBloatServices": True,
                "DisableSpotlight": True,
                "DisableAutoplay": True,
                "NoForcedReboot": True,
                "HideStartRecommendations": True,
            },
            "DryRun": False,
        }
        path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
        return config

    # utf-8-sig tolerates a BOM (Notepad saves UTF-8 with BOM by default)
    return json.loads(path.read_text(encoding="utf-8-sig"))


# ─── Helpers ─────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_powershell(cmd: str, timeout: int = 60) -> Tuple[str, str, int]:
    """Run a PowerShell command and return (stdout, stderr, exit_code)."""
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True, timeout=timeout
    )
    # Windows console output is often CP932/Shift-JIS — use errors="replace" to avoid crashes
    stdout = proc.stdout.decode("cp932", errors="replace") if proc.stdout else ""
    stderr = proc.stderr.decode("cp932", errors="replace") if proc.stderr else ""
    return stdout.strip(), stderr.strip(), proc.returncode


def run_cmd(args: List[str], timeout: int = 30) -> Tuple[str, int]:
    proc = subprocess.run(args, capture_output=True, timeout=timeout)
    out = proc.stdout.decode("cp932", errors="replace") if proc.stdout else ""
    return out.strip(), proc.returncode


# ─── Appx Package Manager ────────────────────────────────────────────────────

def is_target_package(pkg_name: str, blacklist: List[str], whitelist: List[str]) -> bool:
    """True if pkg_name matches any blacklist entry and no whitelist entry."""
    name = pkg_name.lower()
    if any(w and w.lower() in name for w in whitelist):
        return False
    # empty entries would substring-match every package
    return any(entry and entry.strip() and entry.lower() in name for entry in blacklist)


def get_blacklisted_packages(blacklist: List[str], whitelist: List[str]) -> List[Tuple[str, str, str]]:
    """Return (PackageFamilyName, Name, InstallPath) for packages matching blacklist.
    InstallPath is None for SystemApps (cannot be removed per-user).
    Whitelisted packages are never returned, and IsFramework packages (dependency
    DLLs for other apps) are skipped. Enumerates -AllUsers when admin so packages
    installed for other profiles are caught too."""
    if not blacklist:
        return []

    scope = " -AllUsers" if is_admin() else ""
    ps_cmd = ("Get-AppxPackage" + scope +
              " | Select-Object PackageFamilyName,Name,InstallPath,IsFramework | ConvertTo-Json")
    stdout, stderr, rc = run_powershell(ps_cmd, timeout=120)

    if rc != 0 or not stdout:
        return []

    # -AllUsers returns one row per user — dedupe by family
    seen = set()
    results = []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        for pkg in data:
            family = pkg.get("PackageFamilyName", "")
            name = pkg.get("Name", "")
            install_path = pkg.get("InstallPath", "")  # None for SystemApps
            if bool(pkg.get("IsFramework")) or family in seen:
                continue
            if is_target_package(family, blacklist, whitelist):
                seen.add(family)
                results.append((family, name, install_path))
    except (json.JSONDecodeError, TypeError):
        pass

    return results


def get_blacklisted_provisioned(blacklist: List[str], whitelist: List[str]) -> List[Tuple[str, str]]:
    """Return (DisplayName, PackageName) for provisioned packages matching blacklist.
    PackageName removes directly — no second lookup like DisplayName requires.
    Whitelisted packages are never returned."""
    results = []
    ps_cmd = "Get-AppxProvisionedPackage -Online | Select-Object DisplayName,PackageName | ConvertTo-Json"
    stdout, stderr, rc = run_powershell(ps_cmd, timeout=120)

    if rc != 0 or not stdout:
        return []

    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        for pkg in data:
            display = pkg.get("DisplayName", "")
            package_name = pkg.get("PackageName", "")
            if package_name and is_target_package(display, blacklist, whitelist):
                results.append((display, package_name))
    except (json.JSONDecodeError, TypeError):
        pass

    return results


def get_package_full_names() -> dict:
    """Map PackageFamilyName -> PackageFullName in one PowerShell call.
    Avoids spawning a process per package inside scan loops."""
    scope = " -AllUsers" if is_admin() else ""
    ps_cmd = ("Get-AppxPackage" + scope +
              " | Select-Object PackageFamilyName,PackageFullName | ConvertTo-Json")
    stdout, _, rc = run_powershell(ps_cmd, timeout=120)
    mapping = {}
    if rc != 0 or not stdout:
        return mapping
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        for pkg in data:
            family = pkg.get("PackageFamilyName", "")
            full = pkg.get("PackageFullName", "")
            if family:
                mapping[family] = full
    except (json.JSONDecodeError, TypeError):
        pass
    return mapping


def remove_appx_package(package_full_name: str) -> bool:
    # Admin: remove for all users first (mirrors C# admin→user fallback)
    if is_admin():
        _, _, rc = run_powershell(
            f"Remove-AppxPackage -Package '{package_full_name}' -AllUsers "
            f"-ErrorAction SilentlyContinue", timeout=60)
        if rc == 0:
            return True
    _, _, rc = run_powershell(
        f"Remove-AppxPackage -Package '{package_full_name}' -ErrorAction SilentlyContinue",
        timeout=60)
    return rc == 0


# ─── Removal Ledger (restore support) ────────────────────────────────────────

def record_removal(config: dict, entry: dict):
    """Append a removal record to the ledger for later `--restore`."""
    backup_dir = Path(config.get("BackupDirectory") or (LOG_DIR / "Backups"))
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **entry}
        with open(backup_dir / "removed-packages.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def run_restore(config: dict, logger: logging.Logger) -> int:
    """Re-register staged AppxPackages recorded in the removal ledger.
    Provisioned packages cannot be restored from the image — reported as manual."""
    ledger = Path(config.get("BackupDirectory") or (LOG_DIR / "Backups")) / "removed-packages.jsonl"
    if not ledger.exists():
        logger.info("No removal ledger found — nothing to restore.")
        return 0

    restored = 0
    manual = 0
    for line in ledger.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = entry.get("name", "")
        if entry.get("kind") == "appx" and name:
            ps_cmd = (
                f"Get-AppxPackage -AllUsers -Name '{name}' | "
                f"ForEach-Object {{ Add-AppxPackage -DisableDevelopmentMode "
                f"-Register \"$($_.InstallLocation)\\AppxManifest.xml\" "
                f"-ErrorAction SilentlyContinue }}"
            )
            _, _, rc = run_powershell(ps_cmd, timeout=60)
            if rc == 0:
                logger.info(f"Restored (re-registered): {name}")
                restored += 1
            else:
                logger.warning(f"Restore failed: {name} — reinstall via Microsoft Store")
                manual += 1
        else:
            logger.info(
                f"Manual restore needed: {name or entry.get('family', '?')} "
                f"(provisioned — reinstall via Microsoft Store or Settings)")
            manual += 1

    logger.info(f"Restore complete: {restored} restored, {manual} need manual reinstall.")
    return 0


def remove_provisioned_package(package_name: str) -> bool:
    # Caller supplies the exact PackageName — no second PowerShell lookup needed
    ps_cmd = (
        f"Remove-AppxProvisionedPackage -Online "
        f"-PackageName '{package_name}' -ErrorAction SilentlyContinue"
    )
    _, _, rc = run_powershell(ps_cmd, timeout=60)
    return rc == 0


def remove_optional_capabilities(logger: logging.Logger) -> bool:
    """Remove deprecated/legacy optional capabilities (IE mode, Steps Recorder,
    WordPad). Requires admin; non-present entries are skipped by PowerShell."""
    pattern = ("Browser.InternetExplorer|App.StepsRecorder|"
               "Microsoft.Windows.WordPad|XPS.Viewer|Print.Fax.Scan|"
               "App.WirelessDisplay.Connect")
    _, _, rc = run_powershell(
        "Get-WindowsCapability -Online | Where-Object "
        f"{{$_.Name -match '{pattern}' -and $_.State -eq 'Installed'}} | "
        "Remove-WindowsCapability -Online -ErrorAction SilentlyContinue | Out-Null",
        timeout=180)
    if rc == 0:
        logger.info("Applied: RemoveOptionalCapabilities (IE/StepsRecorder/WordPad)")
    else:
        logger.warning("RemoveOptionalCapabilities: no capabilities removed "
                       "(absent or admin required)")
    return rc == 0


# ─── Win32 program removal (non-Appx OEM bloatware) ──────────────────────────

_UNINSTALL_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_UNINSTALL_PATH32 = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
_USER_UNINSTALL_PATH = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
_MSI_GUID_RE = re.compile(r"\{[0-9A-Fa-f\-]{36}\}")


def get_blacklisted_win32(blacklist, whitelist):
    """Enumerate installed Win32 programs (HKLM 64/32, HKCU + loaded user hives)
    whose DisplayName matches the blacklist. Returns (display, uninstall, quiet)."""
    import winreg  # Windows-only

    results, seen = [], set()

    def _scan(root, path):
        try:
            key = winreg.OpenKey(root, path)
        except OSError:
            return
        try:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    i += 1
                except OSError:
                    break
                try:
                    sk = winreg.OpenKey(key, sub)
                    display = winreg.QueryValueEx(sk, "DisplayName")[0]
                    uninstall = winreg.QueryValueEx(sk, "UninstallString")[0]
                    if not display or not uninstall:
                        continue
                    try:
                        if winreg.QueryValueEx(sk, "SystemComponent")[0] == 1:
                            continue
                    except OSError:
                        pass
                    try:
                        quiet = winreg.QueryValueEx(sk, "QuietUninstallString")[0] or ""
                    except OSError:
                        quiet = ""
                    if not is_target_package(display, blacklist, whitelist):
                        continue
                    if display.lower() not in seen:
                        seen.add(display.lower())
                        results.append((display, uninstall, quiet))
                except OSError:
                    continue
        finally:
            key.Close()

    _scan(winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_PATH)
    _scan(winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_PATH32)
    _scan(winreg.HKEY_CURRENT_USER, _USER_UNINSTALL_PATH)
    try:
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(winreg.HKEY_USERS, i)
                i += 1
            except OSError:
                break
            if re.match(r"^S-1-5-21-\d+-\d+-\d+-\d+$", sid):
                _scan(winreg.HKEY_USERS, sid + "\\" + _USER_UNINSTALL_PATH)
    except OSError:
        pass
    return results


def _split_command_line(command_line):
    """Split 'cmd args...' or '"path" args...' into (cmd, args)."""
    command_line = command_line.strip()
    if command_line.startswith('"'):
        end = command_line.find('"', 1)
        if end > 0:
            return command_line[1:end], command_line[end + 1:].strip()
    parts = command_line.split(" ", 1)
    return (parts[0], parts[1].strip() if len(parts) > 1 else "")


def remove_win32_program(display, uninstall, quiet, logger):
    """Silent-uninstall one Win32 program: vendor QuietUninstallString when present,
    MSI via `msiexec /x {guid} /qn /norestart`; others are logged, not executed."""
    if quiet:
        cmd, args = _split_command_line(quiet)
        argv = [cmd] + (args.split() if args else [])
    elif "msiexec" in uninstall.lower():
        m = _MSI_GUID_RE.search(uninstall)
        if not m:
            return False
        argv = ["msiexec.exe", "/x", m.group(0), "/qn", "/norestart"]
    else:
        logger.info(f"Win32 program needs manual removal (no silent uninstaller): {display}")
        return False
    out, rc = run_cmd(argv, timeout=300)
    if rc == 0:
        return True
    logger.warning(f"Win32 uninstall failed for {display} (rc={rc}): {out[:200]}")
    return False


def create_restore_point(logger):
    """Create a system restore point before destructive changes. Windows throttles
    checkpoints to ~1 per 24h; failure is non-fatal."""
    _, rc = run_cmd(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
         "Enable-ComputerRestore -Drive 'C:\\' -ErrorAction SilentlyContinue | Out-Null; "
         "Checkpoint-Computer -Description 'BloatwareGuard pre-scan' "
         "-RestorePointType 'MODIFY_SETTINGS' -ErrorAction SilentlyContinue | Out-Null"],
        timeout=120)
    if rc == 0:
        logger.info("Applied: CreateRestorePoint (created or throttled)")
    else:
        logger.warning("CreateRestorePoint: skipped (admin required or System Restore disabled)")


# ─── Registry Prevention ─────────────────────────────────────────────────────

def set_registry_dword(hive, path: str, name: str, value: int) -> bool:
    """Set a DWORD value in the registry. hive = 'HKLM' or 'HKCU'."""
    try:
        import winreg
        root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
        key = winreg.CreateKeyEx(root, path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def demote_service(name: str) -> bool:
    """Set a service to demand-start. Opens — never creates — the service
    key, so vendor services absent from the machine don't get phantom
    Services\\X entries."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Services\{name}", 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)
        winreg.CloseKey(key)
        return True
    except OSError:
        return False


# Per-user registry paths (relative to a user hive root — HKCU or HKEY_USERS\<SID>)
_USER_CDM = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
_USER_EXPLORER_ADV = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
_USER_EXPLORER_POLICIES = r"Software\Policies\Microsoft\Windows\Explorer"
_USER_COPILOT = r"Software\Policies\Microsoft\Windows\WindowsCopilot"
_USER_WINDOWS_AI = r"Software\Policies\Microsoft\Windows\WindowsAI"
_USER_SEARCH = r"Software\Microsoft\Windows\CurrentVersion\Search"
_USER_SEARCH_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\SearchSettings"
_USER_PROFILE_ENGAGEMENT = r"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"
_USER_ACCOUNT_NOTIFICATIONS = r"Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications"
_USER_SUGGESTED_TOAST = (r"Software\Microsoft\Windows\CurrentVersion"
                         r"\Notifications\Settings\Windows.SystemToast.Suggested")
_USER_MOBILITY = r"Software\Microsoft\Windows\CurrentVersion\Mobility"
_USER_ADVERTISING_INFO = r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
_USER_PRIVACY = r"Software\Microsoft\Windows\CurrentVersion\Privacy"
_USER_ONLINE_SPEECH = r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"
_USER_TIPC = r"Software\Microsoft\Input\TIPC"
_USER_INPUT_PERSONALIZATION = r"Software\Microsoft\InputPersonalization"
_USER_INPUT_STORE = r"Software\Microsoft\InputPersonalization\TrainedDataStore"
_USER_PERSONALIZATION = r"Software\Microsoft\Personalization\Settings"
_USER_SIUF = r"Software\Microsoft\Siuf\Rules"
_USER_GAME_CONFIG_STORE = r"System\GameConfigStore"
_USER_GAME_DVR = r"Software\Microsoft\Windows\CurrentVersion\GameDVR"
_USER_DELIVERY_OPT = (r"Software\Microsoft\Windows\CurrentVersion"
                      r"\DeliveryOptimization\Settings")
_USER_POLICIES_EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
_USER_ONEDRIVE_CLSID = r"Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
_USER_WER = r"Software\Microsoft\Windows\Windows Error Reporting"

# Startup value names worth disabling even outside the package blacklist
# (OEM updaters, adware helpers). OneDrive stays out — DisableOneDrive is opt-in.
_STARTUP_BLOAT_NAMES = (
    "Skype", "Cortana", "MicrosoftEdgeAutoLaunch", "GameAssist",
    "McAfee", "Norton", "WebAdvisor", "CCleaner", "Dell", "Lenovo",
    "SupportAssist", "Acer", "ASUS", "HP",
)
# 0x03 = disabled in StartupApproved (value kept — re-enableable via Task Manager)
_STARTUP_DISABLED_MARKER = b"\x03" + b"\x00" * 11

# HKLM subkey used to temporarily mount the Default-profile template hive
_DEFAULT_HIVE_MOUNT = "BloatwareGuard_DefaultProfile"

# Real user profile SIDs only — excludes .DEFAULT, service accounts
# (S-1-5-18/19/20) and *_Classes virtual hives
_USER_SID_RE = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$")


def _default_profile_dat() -> str:
    """Path of the default-profile NTUSER.DAT template (usually C:\\Users\\Default)."""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
        default_dir, _ = winreg.QueryValueEx(key, "Default")
        winreg.CloseKey(key)
        default_dir = os.path.expandvars(default_dir)
    except Exception:
        default_dir = r"C:\Users\Default"
    dat = os.path.join(default_dir, "NTUSER.DAT")
    return dat if os.path.exists(dat) else ""


def for_each_user_hive(apply, logger: logging.Logger):
    """Call apply(root, prefix) for every writable user hive: each loaded
    interactive profile under HKEY_USERS, the default-profile template (mounted
    temporarily so future users inherit the settings), and HKCU. A service
    running as SYSTEM writes only to the SYSTEM hive without this — the per-user
    settings never reach real users."""
    import winreg
    applied = 0
    try:
        count = winreg.QueryInfoKey(winreg.HKEY_USERS)[0]
        sids = [winreg.EnumKey(winreg.HKEY_USERS, i) for i in range(count)]
    except Exception:
        sids = []
    for sid in sids:
        if not _USER_SID_RE.match(sid):
            continue
        try:
            apply(winreg.HKEY_USERS, sid)
            applied += 1
        except Exception as e:
            logger.warning(f"Registry: could not write hive {sid}: {e}")

    dat = _default_profile_dat()
    if dat:
        _, rc = run_cmd(["reg.exe", "load", f"HKLM\\{_DEFAULT_HIVE_MOUNT}", dat])
        if rc == 0:
            try:
                apply(winreg.HKEY_LOCAL_MACHINE, _DEFAULT_HIVE_MOUNT)
                applied += 1
            except Exception as e:
                logger.warning(f"Registry: default profile hive skipped: {e}")
            finally:
                run_cmd(["reg.exe", "unload", f"HKLM\\{_DEFAULT_HIVE_MOUNT}"])

    try:
        apply(winreg.HKEY_CURRENT_USER, "")
        applied += 1
    except Exception:
        pass
    if applied == 0:
        logger.warning("Registry: no writable user hive found")


def set_user_dword_all_hives(path: str, name: str, value: int, logger: logging.Logger):
    """Set a DWORD under `path` in every user hive (loaded profiles + default
    template + HKCU)."""
    import winreg

    def apply(root, prefix):
        key_path = f"{prefix}\\{path}" if prefix else path
        key = winreg.CreateKeyEx(root, key_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)

    for_each_user_hive(apply, logger)


# HKLM keys this tool writes to — exported to .reg before first apply so every
# change is restorable with a double-click.
_BACKUP_KEY_PATHS = (
    r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
    r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
    r"SOFTWARE\Policies\Microsoft\Windows\AppCompat",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
    r"SOFTWARE\Policies\Microsoft\Dsh",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    r"SOFTWARE\Policies\Microsoft\Windows\System",
    r"SOFTWARE\Policies\Microsoft\Edge",
    r"SOFTWARE\Policies\Microsoft\Windows\GameDVR",
    r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
    r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
    r"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
    r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
    r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
    r"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener",
    r"SYSTEM\CurrentControlSet\Control\Session Manager",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager",
    r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
    r"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds",
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
    r"SOFTWARE\Microsoft\PolicyManager\current\device\System",
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
    r"SOFTWARE\Policies\Microsoft\MRT",
    r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
    r"SOFTWARE\Microsoft\Speech_OneCore\Preferences",
    r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
    r"SOFTWARE\Policies\Microsoft\FindMyDevice",
    r"SOFTWARE\Policies\Microsoft\Windows\SettingSync",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
)
_registry_backup_done = False


def backup_registry_keys(logger: logging.Logger):
    """reg-export every HKLM key this tool touches into
    %ProgramData%\\BloatwareGuard\\backup\\ — once per process."""
    global _registry_backup_done
    if _registry_backup_done:
        return
    _registry_backup_done = True
    try:
        base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        backup_dir = os.path.join(base, "BloatwareGuard", "backup")
        os.makedirs(backup_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        for i, path in enumerate(_BACKUP_KEY_PATHS):
            # reg.exe export fails for non-existent keys — expected, non-fatal
            run_cmd(["reg.exe", "export", f"HKLM\\{path}",
                     os.path.join(backup_dir, f"{stamp}-{i}.reg"), "/y"])
        logger.info(f"Applied: BackupRegistry ({len(_BACKUP_KEY_PATHS)} keys → {backup_dir})")
    except OSError as e:
        logger.warning(f"BackupRegistry skipped: {e}")


def apply_registry_prevention(config: dict, logger: logging.Logger):
    import winreg
    prev = config.get("Prevention", {})

    if prev.get("BackupRegistry", True):
        backup_registry_keys(logger)

    cloud_content = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"

    if prev.get("DisableConsumerExperiences", True):
        if set_registry_dword("HKLM", cloud_content, "DisableWindowsConsumerFeatures", 1):
            logger.info("Applied: DisableWindowsConsumerFeatures = 1")

    if prev.get("DisableCloudContent", True):
        set_registry_dword("HKLM", cloud_content, "DisableSoftLanding", 1)
        set_registry_dword("HKLM", cloud_content, "DisableCloudOptimizedContent", 1)
        logger.info("Applied: DisableSoftLanding + DisableCloudOptimizedContent = 1")

    if prev.get("PreventDeviceMetadata", True):
        if set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
                              "PreventDeviceMetadataFromNetwork", 1):
            logger.info("Applied: PreventDeviceMetadataFromNetwork = 1")

    if prev.get("BlockProvisioning", True):
        set_registry_dword("HKLM", cloud_content, "DisableConsumerAccountContent", 1)

        # ContentDeliveryManager — silent installs + every SubscribedContent surface
        # (key set mirrors Win11Debloat Disable_Windows_Suggestions.reg)
        cdm_zeros = (
            "SilentInstalledAppsEnabled",        # silent app installs
            "SystemPaneSuggestionsEnabled",      # system pane suggestions
            "SoftLandingEnabled",                # soft landing tips
            "SubscribedContent-310093Enabled",   # Windows welcome experience
            "SubscribedContent-338387Enabled",   # lock-screen spotlight ads
            "SubscribedContent-338388Enabled",   # Start suggestions
            "SubscribedContent-338389Enabled",   # tips while using Windows
            "SubscribedContent-338393Enabled",   # Settings suggestions
            "SubscribedContent-353694Enabled",   # Settings suggestions (2)
            "SubscribedContent-353696Enabled",   # Settings suggestions (3)
            "SubscribedContent-353698Enabled",   # Settings suggestions (4)
            "RotatingLockScreenEnabled",         # lock-screen spotlight
            "RotatingLockScreenOverlayEnabled",  # lock-screen overlay ads
        )

        def _apply_suggestions(root, prefix):
            def w(path, name, value):
                key_path = f"{prefix}\\{path}" if prefix else path
                key = winreg.CreateKeyEx(root, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
            for n in cdm_zeros:
                w(_USER_CDM, n, 0)
            w(_USER_EXPLORER_ADV, "Start_IrisRecommendations", 0)
            w(_USER_EXPLORER_ADV, "ShowSyncProviderNotifications", 0)
            w(_USER_PROFILE_ENGAGEMENT, "ScoobeSystemSettingEnabled", 0)
            w(_USER_ACCOUNT_NOTIFICATIONS, "EnableAccountNotifications", 0)
            w(_USER_SUGGESTED_TOAST, "Enabled", 0)
            w(_USER_MOBILITY, "OptedIn", 0)

        for_each_user_hive(_apply_suggestions, logger)
        logger.info("Applied: BlockProvisioning (silent installs + all suggestion surfaces, all hives)")

    if prev.get("DisableCopilot", True):
        copilot_pol = r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        set_registry_dword("HKLM", copilot_pol, "TurnOffWindowsCopilot", 1)
        set_user_dword_all_hives(_USER_COPILOT, "TurnOffWindowsCopilot", 1, logger)
        logger.info("Applied: DisableCopilot (TurnOffWindowsCopilot = 1, HKLM + user hives)")

    if prev.get("DisableRecall", True):
        ai_pol = r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        set_registry_dword("HKLM", ai_pol, "DisableAIDataAnalysis", 1)
        set_registry_dword("HKLM", ai_pol, "TurnOffSavingSnapshots", 1)
        set_registry_dword("HKLM", ai_pol, "AllowRecallEnablement", 0)
        set_registry_dword("HKLM", ai_pol, "DisableClickToDo", 1)
        set_user_dword_all_hives(_USER_WINDOWS_AI, "DisableAIDataAnalysis", 1, logger)
        set_user_dword_all_hives(_USER_WINDOWS_AI, "DisableClickToDo", 1, logger)
        if is_admin():
            # Remove the optional feature where present — absent on most hardware
            run_powershell(
                "Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' "
                "-NoRestart -ErrorAction SilentlyContinue | Out-Null", timeout=120)
        # AI fabric service: 2=auto, 3=demand. Absent without NPU/Copilot+ hardware.
        demote_service("WSAIFabricSvc")
        logger.info("Applied: DisableRecall (WindowsAI policies + Click to Do off, "
                    "Recall feature removal attempted, WSAIFabricSvc=demand)")

    if prev.get("DisableSearchSuggestions", True):
        search_pol = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        set_registry_dword("HKLM", search_pol, "AllowCortana", 0)
        set_registry_dword("HKLM", search_pol, "CortanaConsent", 0)
        set_user_dword_all_hives(_USER_EXPLORER_POLICIES, "DisableSearchBoxSuggestions", 1, logger)
        set_user_dword_all_hives(_USER_SEARCH, "BingSearchEnabled", 0, logger)
        # SearchSettings: dynamic search box + cloud search integrations
        set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsDynamicSearchBoxEnabled", 0, logger)
        set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsAADCloudSearchEnabled", 0, logger)
        set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsMSACloudSearchEnabled", 0, logger)
        set_user_dword_all_hives(_USER_SEARCH, "CortanaConsent", 0, logger)
        logger.info("Applied: DisableSearchSuggestions (Bing/search suggestions + Cortana off, all hives)")

    if prev.get("DisableWidgets", True):
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests", 0)
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
                           "EnableFeeds", 0)
        set_user_dword_all_hives(_USER_EXPLORER_ADV, "TaskbarDa", 0, logger)
        logger.info("Applied: DisableWidgets (AllowNewsAndInterests = 0, TaskbarDa = 0)")

    if prev.get("DisableTelemetry", True):
        # Key set mirrors Win11Debloat Disable_Telemetry.reg
        set_registry_dword(
            "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
            "AllowTelemetry", 0)
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                           "PublishUserActivities", 0)
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                           "EnableActivityFeed", 0)
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                           "UploadUserActivities", 0)
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Edge",
                           "PersonalizationReportingEnabled", 0)
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Edge",
                           "DiagnosticData", 0)

        def _apply_telemetry(root, prefix):
            def w(path, name, value):
                key_path = f"{prefix}\\{path}" if prefix else path
                key = winreg.CreateKeyEx(root, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
            w(_USER_ADVERTISING_INFO, "Enabled", 0)
            w(_USER_PRIVACY, "TailoredExperiencesWithDiagnosticDataEnabled", 0)
            w(_USER_ONLINE_SPEECH, "HasAccepted", 0)
            w(_USER_TIPC, "Enabled", 0)
            w(_USER_INPUT_PERSONALIZATION, "RestrictImplicitInkCollection", 1)
            w(_USER_INPUT_PERSONALIZATION, "RestrictImplicitTextCollection", 1)
            w(_USER_INPUT_STORE, "HarvestContacts", 0)
            w(_USER_PERSONALIZATION, "AcceptedPrivacyPolicy", 0)
            w(_USER_EXPLORER_ADV, "Start_TrackProgs", 0)
            w(_USER_SIUF, "NumberOfSIUFInPeriod", 0)

        for_each_user_hive(_apply_telemetry, logger)

        # "Connected User Experiences and Telemetry" (DiagTrack) — the actual
        # telemetry uploader; absent on some SKUs, failures are non-fatal.
        run_cmd(["sc.exe", "stop", "DiagTrack"])
        run_cmd(["sc.exe", "config", "DiagTrack", "start=", "disabled"])
        # RetailDemo data-collection service (present on most images)
        run_cmd(["sc.exe", "stop", "RetailDemo"])
        run_cmd(["sc.exe", "config", "RetailDemo", "start=", "disabled"])
        # ETW AutoLogger feeding DiagTrack — Start=0 kills the boot-time trace
        set_registry_dword(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener",
            "Start", 0)
        # Ink Workspace suggestion surface (ads inside the pen menu)
        set_registry_dword("HKLM",
                           r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
                           "AllowWindowsInkWorkspace", 0)
        # Defender SpyNet — no sample uploads to Microsoft
        spynet = r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        set_registry_dword("HKLM", spynet, "SpynetReporting", 0)
        set_registry_dword("HKLM", spynet, "SubmitSamplesConsent", 0)
        # Microsoft feature experimentation (A/B flighting) off
        set_registry_dword(
            "HKLM",
            r"SOFTWARE\Microsoft\PolicyManager\current\device\System",
            "AllowExperimentation", 0)
        # Cap diagnostic log/dump collection + enhanced analytics
        data_collection = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")
        for name in ("LimitDiagnosticLogCollection", "LimitDumpCollection",
                     "LimitEnhancedDiagnosticDataWindowsAnalytics"):
            set_registry_dword("HKLM", data_collection, name, 1)
        # MRT infection reports off
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\MRT",
                           "DontReportInfectionInformation", 1)
        # Speech model downloads off (voice data pipeline)
        set_registry_dword("HKLM",
                           r"SOFTWARE\Microsoft\Speech_OneCore\Preferences",
                           "ModelDownloadAllowed", 0)
        # "Sync your settings" off — stops settings roaming to MS accounts
        set_registry_dword("HKLM",
                           r"SOFTWARE\Policies\Microsoft\Windows\SettingSync",
                           "DisableSettingSync", 2)
        # "Share across devices" (Connected Devices Platform) consent off
        cdp = r"Software\Microsoft\Windows\CurrentVersion\CDP"
        set_user_dword_all_hives(cdp, "CdpSessionUserAuthzPolicy", 0, logger)
        set_user_dword_all_hives(cdp, "RomeSdkChannelUserAuthzPolicy", 0, logger)
        set_user_dword_all_hives(cdp + r"\SettingsPage",
                                 "RomeSdkChannelUserAuthzPolicy", 0, logger)
        logger.info("Applied: DisableTelemetry (AllowTelemetry=0, DiagTrack off, "
                    "privacy surfaces set)")

    if prev.get("DisableGameDvr", True):
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\GameDVR",
                           "AllowGameDVR", 0)
        set_user_dword_all_hives(_USER_GAME_CONFIG_STORE, "GameDVR_Enabled", 0, logger)
        set_user_dword_all_hives(_USER_GAME_DVR, "AppCaptureEnabled", 0, logger)
        logger.info("Applied: DisableGameDvr (AllowGameDVR=0, GameDVR_Enabled=0, "
                    "AppCaptureEnabled=0)")

    if prev.get("DisableDeliveryOptimization", True):
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
                           "DODownloadMode", 0)
        set_user_dword_all_hives(_USER_DELIVERY_OPT, "DownloadMode", 0, logger)
        # The Delivery Optimization service reads the NETWORK SERVICE hive (S-1-5-20)
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_USERS, "S-1-5-20\\" + _USER_DELIVERY_OPT, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "DownloadMode", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except Exception:
            pass
        logger.info("Applied: DisableDeliveryOptimization (DODownloadMode=0)")

    if prev.get("DisableOneDrive", False):
        set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
                           "DisableFileSyncNGSC", 1)
        # Hide the OneDrive pin in Explorer's navigation pane for every user
        set_user_dword_all_hives(_USER_ONEDRIVE_CLSID, "System.IsPinnedToNameSpaceTree", 0, logger)
        logger.info("Applied: DisableOneDrive (DisableFileSyncNGSC=1, nav pin hidden)")

    if prev.get("DisableChatTaskbar", True):
        set_user_dword_all_hives(_USER_EXPLORER_ADV, "TaskbarMn", 0, logger)
        set_user_dword_all_hives(_USER_POLICIES_EXPLORER, "HideSCAMeetNow", 1, logger)
        logger.info("Applied: DisableChatTaskbar (TaskbarMn=0, HideSCAMeetNow=1)")

    if prev.get("DisableEdgeBloat", True):
        edge_pol = r"SOFTWARE\Policies\Microsoft\Edge"
        set_registry_dword("HKLM", edge_pol, "HubsSidebarEnabled", 0)
        set_registry_dword("HKLM", edge_pol, "StartupBoostEnabled", 0)
        set_registry_dword("HKLM", edge_pol, "AllowPrelaunch", 0)
        set_registry_dword("HKLM", edge_pol, "HideFirstRunExperience", 1)
        # Shopping assistant, recommendations, error-page web service,
        # user feedback — all upload/suggestion surfaces
        for name in ("EdgeShoppingAssistantEnabled",
                     "ShowRecommendationsEnabled",
                     "ResolveNavigationErrorsUseWebService",
                     "AlternateErrorPagesEnabled",
                     "UserFeedbackAllowed"):
            set_registry_dword("HKLM", edge_pol, name, 0)
        logger.info("Applied: DisableEdgeBloat (sidebar/startup-boost/"
                    "prelaunch/first-run/shopping/recommendations off)")

    if prev.get("DisableStartupBloat", True):
        disable_startup_bloat(config, logger)

    if prev.get("DisableErrorReporting", True):
        wer = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting"
        wer_policy = r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
        set_registry_dword("HKLM", wer, "Disabled", 1)
        set_registry_dword("HKLM", wer, "DontSendAdditionalData", 1)
        set_registry_dword("HKLM", wer_policy, "Disabled", 1)
        set_registry_dword("HKLM", wer_policy, "AutoApproveOSDumps", 0)
        set_user_dword_all_hives(_USER_WER, "Disabled", 1, logger)
        set_user_dword_all_hives(_USER_WER, "DontShowUI", 1, logger)
        set_user_dword_all_hives(_USER_WER, "LoggingDisabled", 1, logger)
        logger.info("Applied: DisableErrorReporting (WER uploads + UI + logging off)")

    if prev.get("DisableEdgeUpdateBloat", True):
        for svc in ("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService"):
            demote_service(svc)
        # Scheduled tasks re-arm the services — disable them too
        for task in ("MicrosoftEdgeUpdateTaskMachineCore",
                     "MicrosoftEdgeUpdateTaskMachineUA",
                     "MicrosoftEdgeUpdateBrowserReplacementTask"):
            run_cmd(["schtasks.exe", "/Change", "/TN", task, "/DISABLE"])
        logger.info("Applied: DisableEdgeUpdateBloat "
                    "(edgeupdate/edgeupdatem/elevation → demand, update tasks off)")

    if prev.get("BlockOemDriverUpdates", True):
        set_registry_dword("HKLM",
                           r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                           "ExcludeWUDriversInQualityUpdate", 1)
        # Device Metadata channel off — OEM companion apps ship through it
        set_registry_dword("HKLM",
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
                           "PreventDeviceMetadataFromNetwork", 1)
        logger.info("Applied: BlockOemDriverUpdates "
                    "(ExcludeWUDriversInQualityUpdate=1)")

    if prev.get("DisableAppPermissions", True):
        # Force-deny (2) a conservative AppPrivacy set — camera/mic/location left
        # alone since legitimate apps need them.
        app_privacy = (
            "LetAppsRunInBackground", "LetAppsAccessAccountInfo",
            "LetAppsAccessCallHistory", "LetAppsAccessContacts",
            "LetAppsAccessEmail", "LetAppsAccessMessaging",
            "LetAppsAccessMotion", "LetAppsAccessNotifications",
            "LetAppsAccessPhone", "LetAppsAccessRadios",
            "LetAppsAccessTasks", "LetAppsAccessTrustedDevices",
            "LetAppsSyncWithDevices", "LetAppsGetDiagnosticInfo",
            "LetAppsActivateWithVoice", "LetAppsActivateWithVoiceAboveLock",
        )
        for name in app_privacy:
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
                               name, 2)
        # HKLM ad-ID + Find My Device policies
        set_registry_dword("HKLM",
                           r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
                           "DisabledByGroupPolicy", 1)
        set_registry_dword("HKLM",
                           r"SOFTWARE\Policies\Microsoft\FindMyDevice",
                           "AllowFindMyDevice", 0)
        logger.info(f"Applied: DisableAppPermissions ({len(app_privacy)} "
                    "force-denied + ad-ID/FindMyDevice policies)")

    if prev.get("DisablePrintSpooler", False):
        # Opt-in — kills the PrintNightmare surface but breaks printing
        run_cmd(["sc.exe", "stop", "Spooler"])
        run_cmd(["sc.exe", "config", "Spooler", "start=", "disabled"])
        logger.info("Applied: DisablePrintSpooler (Spooler stopped + disabled)")

    if prev.get("BlockOemWpbtExecution", True):
        # WPBT: OEMs inject executables into the boot chain via UEFI
        # (abused e.g. by ASUS Live Update) — DisableWpbtExecution makes
        # Windows ignore the table
        set_registry_dword("HKLM",
                           r"SYSTEM\CurrentControlSet\Control\Session Manager",
                           "DisableWpbtExecution", 1)
        logger.info("Applied: BlockOemWpbtExecution (WPBT disabled)")

    if prev.get("DisableReservedStorage", True):
        # Free the ~7GB reserved for updates (they use free space pre-1903 style)
        reserve = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager"
        for name, val in (("ShippedWithReserves", 0),
                          ("MiscPolicyInfo", 2), ("PassedPolicy", 0)):
            set_registry_dword("HKLM", reserve, name, val)
        logger.info("Applied: DisableReservedStorage (ReserveManager)")

    if prev.get("DisableCloudClipboard", True):
        # Local history stays usable; stop the cloud sync of copied content
        set_registry_dword("HKLM",
                           r"SOFTWARE\Policies\Microsoft\Windows\System",
                           "AllowCrossDeviceClipboard", 0)
        set_user_dword_all_hives(
            r"Software\Microsoft\Clipboard",
            "EnableClipboardHistory", 0, logger)
        logger.info("Applied: DisableCloudClipboard")

    if prev.get("DisableRemoteAssistance", True):
        # Inbound help-request offers off
        for name in ("fAllowToGetHelp", "fAllowFullControl"):
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
                name, 0)
        logger.info("Applied: DisableRemoteAssistance")

    if prev.get("BlockInsiderPreview", True):
        # Preview builds ship heavier telemetry + instability
        set_registry_dword("HKLM",
                           r"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds",
                           "AllowBuildPreview", 0)
        set_registry_dword("HKLM",
                           r"SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility",
                           "HideInsiderPage", 1)
        logger.info("Applied: BlockInsiderPreview")

    if prev.get("DisableXboxServices", True):
        # Demand-start (Start=3) — Game Bar/Xbox sign-in still work on demand
        for svc in ("XblAuthManager", "XblGameSave",
                    "XboxNetApiSvc", "XboxGipSvc"):
            demote_service(svc)
        logger.info("Applied: DisableXboxServices (4 services → demand-start)")

    if prev.get("DisableMiscBloatServices", True):
        # Demand-start (Start=3) — all stay usable when actually invoked.
        # Vendor services absent from the machine are skipped (open, not create).
        for svc in ("dmwappushservice", "MapsBroker", "WMPNetworkSvc",
                    "diagnosticshub.standardcollector.service",
                    "CDPSvc", "NvTelemetryContainer",
                    "esrv_svc", "ESRV_SVC_QUEENCREEK",
                    "PushToInstall", "SEMgrSvc", "PhoneSvc"):
            demote_service(svc)
        # Remote Registry: remote registry read/write over SMB — disabled
        # outright (demand-start would still leave the surface reachable)
        run_cmd(["sc.exe", "stop", "RemoteRegistry"])
        run_cmd(["sc.exe", "config", "RemoteRegistry", "start=", "disabled"])
        logger.info("Applied: DisableMiscBloatServices "
                    "(11 services → demand-start, RemoteRegistry disabled)")

    if prev.get("DisableSpotlight", True):
        # Desktop Spotlight = content-delivery channel (wallpaper promos)
        set_user_dword_all_hives(
            r"Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings",
            "Enabled", 0, logger)
        set_user_dword_all_hives(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers",
            "BackgroundType", 0, logger)
        logger.info("Applied: DisableSpotlight")

    if prev.get("DisableAutoplay", True):
        # NoDriveTypeAutoRun=255 + NoAutorun=1 — media auto-execute off
        pol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        set_registry_dword("HKLM", pol, "NoDriveTypeAutoRun", 255)
        set_registry_dword("HKLM", pol, "NoAutorun", 1)
        set_user_dword_all_hives(
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun", 255, logger)
        logger.info("Applied: DisableAutoplay")

    if prev.get("NoForcedReboot", True):
        # Never force-reboot while a user is logged on
        au = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        set_registry_dword("HKLM", au, "NoAutoRebootWithLoggedOnUsers", 1)
        set_registry_dword("HKLM", au, "AlwaysAutoRebootAtScheduledTime", 0)
        logger.info("Applied: NoForcedReboot (WU reboot policy)")

    if prev.get("HideStartRecommendations", True):
        # Start "Recommended" section — promoted apps surface (22H2+)
        set_registry_dword("HKLM",
                           r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
                           "HideRecommendedSection", 1)
        logger.info("Applied: HideStartRecommendations")


def disable_startup_bloat(config: dict, logger: logging.Logger):
    """Disable bloatware autostart entries via the StartupApproved\\Run marker
    (0x03...) — the entry stays listed in Task Manager and is re-enableable,
    the same mechanism the UI uses. HKLM 64/32-bit + every user hive."""
    import winreg

    machine_run = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    machine_run32 = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    machine_runonce = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    user_run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    user_runonce = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    approved = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
    approved_once = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\RunOnce"

    needles = [s for s in list(config.get("Blacklist", [])) + list(_STARTUP_BLOAT_NAMES)
               if s and s.strip()]
    whitelist = config.get("Whitelist", [])
    applied = 0

    def _is_bloat(name, data):
        haystack = f"{name} {data or ''}".lower()
        if any(w and w.strip().lower() in haystack for w in whitelist):
            return False
        return any(n.lower() in haystack for n in needles)

    def _scan(root, run_path, approved_path):
        nonlocal applied
        try:
            run_key = winreg.OpenKey(root, run_path)
        except OSError:
            return
        try:
            targets = []
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(run_key, i)
                    i += 1
                    if _is_bloat(name, data):
                        targets.append(name)
                except OSError:
                    break
            if not targets:
                return
            ap_key = winreg.CreateKeyEx(root, approved_path, 0, winreg.KEY_WRITE)
            for name in targets:
                winreg.SetValueEx(ap_key, name, 0, winreg.REG_BINARY,
                                  _STARTUP_DISABLED_MARKER)
                applied += 1
                logger.info(f"Disabled startup entry: {name}")
            ap_key.Close()
        finally:
            run_key.Close()

    _scan(winreg.HKEY_LOCAL_MACHINE, machine_run, approved)
    _scan(winreg.HKEY_LOCAL_MACHINE, machine_run32, approved)
    _scan(winreg.HKEY_LOCAL_MACHINE, machine_runonce, approved_once)

    def _scan_user(root, prefix):
        p = (prefix + "\\") if prefix else ""
        _scan(root, p + user_run, p + approved)
        _scan(root, p + user_runonce, p + approved_once)

    for_each_user_hive(_scan_user, logger)
    logger.info(f"Applied: DisableStartupBloat ({applied} entries)")


# ─── Scheduled Task Prevention ───────────────────────────────────────────────

# Microsoft system tasks that MUST NEVER be disabled (TaskPath prefixes) —
# kept in parity with C# ScheduledTaskGuard.MicrosoftSystemPrefixes
MICROSOFT_SYSTEM_TASK_PREFIXES = (
    "\\Microsoft\\Windows\\CloudRestore", "\\Microsoft\\Windows\\InstallService",
    "\\Microsoft\\Windows\\WindowsUpdate", "\\Microsoft\\Windows\\UpdateOrchestrator",
    "\\Microsoft\\Windows\\Defrag", "\\Microsoft\\Windows\\Diagnosis",
    "\\Microsoft\\Windows\\Maintenance", "\\Microsoft\\Windows\\CloudExperienceHost",
    "\\Microsoft\\Windows\\Feedback", "\\Microsoft\\Windows\\Input",
    "\\Microsoft\\Windows\\International", "\\Microsoft\\Windows\\LanguageComponentsInstaller",
    "\\Microsoft\\Windows\\MUI", "\\Microsoft\\Windows\\PI",
    "\\Microsoft\\Windows\\RecoveryEnvironment", "\\Microsoft\\Windows\\Servicing",
    "\\Microsoft\\Windows\\SettingSync", "\\Microsoft\\Windows\\Shell",
    "\\Microsoft\\Windows\\Sysmain", "\\Microsoft\\Windows\\WDI",
    "\\Microsoft\\Windows\\Wlan", "\\Microsoft\\Windows\\Bluetooth",
    "\\Microsoft\\Windows\\NetTrace", "\\Microsoft\\Windows\\Security Center",
    "\\Microsoft\\Windows\\SpaceAgent", "\\Microsoft\\Windows\\Storage",
    "\\Microsoft\\Windows\\SystemRestore", "\\Microsoft\\Windows\\Task Manager",
    "\\Microsoft\\Windows\\VerifiableFileIntegrity", "\\Microsoft\\Windows\\WebAuth",
    "\\Microsoft\\Windows\\WiFi", "\\Microsoft\\Windows\\Windows Error Reporting",
    "\\Microsoft\\Windows\\License Manager", "\\Microsoft\\Windows\\Clip",
)


def disable_oem_scheduled_tasks(logger: logging.Logger):
    """Disable known OEM scheduled tasks that reinstall bloatware."""
    patterns = (
        "OEM|Dell|HPInc|HPA|Lenovo|ASUS|Acer|McAfee|Norton|"
        "SupportAssist|Vantage|Armoury|Crate|CustomerExperienceImprovement|"
        "Customer Experience Improvement|Reinstall|Restore|Bloatware"
    )
    ps_cmd = (
        f"Get-ScheduledTask | "
        f"Where-Object {{$_.TaskPath -like '*OEM*' -or $_.TaskName -match '{patterns}'}} | "
        f"Select-Object TaskName,TaskPath,State | ConvertTo-Json"
    )
    stdout, _, rc = run_powershell(ps_cmd, timeout=60)

    if rc != 0 or not stdout:
        return

    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]

        skipped = 0
        for task in data:
            name = task.get("TaskName", "")
            path = task.get("TaskPath", "\\")
            if not name:
                continue
            full_path = path.rstrip("\\") + "\\" + name
            if any(full_path.lower().startswith(p.lower() + "\\")
                   for p in MICROSOFT_SYSTEM_TASK_PREFIXES):
                logger.warning(f"Skipping protected system task: {full_path}")
                skipped += 1
                continue
            out, ret = run_cmd(["schtasks", "/Change", "/TN", full_path, "/DISABLE"])
            if ret == 0:
                logger.info(f"Disabled scheduled task: {full_path}")
            else:
                logger.warning(f"Failed to disable task: {full_path} ({out})")

        logger.info(f"Processed {len(data) - skipped} OEM scheduled tasks "
                    f"({skipped} protected skipped)")
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"Scheduled task scan error: {e}")


# Microsoft's own data-collection tasks — exact names, not patterns, so nothing
# else is touched. CompatTelRunner is a notorious CPU/IO hog.
TELEMETRY_TASK_PATHS = (
    "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
    "\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
    "\\Microsoft\\Windows\\Application Experience\\PcaPatchDbTask",
    "\\Microsoft\\Windows\\Application Experience\\StartupAppTask",
    "\\Microsoft\\Windows\\Autochk\\Proxy",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
    "\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\\Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
    "\\Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
    "\\Microsoft\\Windows\\Maps\\MapsUpdateTask",
    "\\Microsoft\\Windows\\Maps\\MapsToastTask",
    # Office Customer Experience Improvement Program (when Office is
    # installed; schtasks ignores missing paths)
    "\\Microsoft\\Office\\OfficeTelemetryAgentLogOn",
    "\\Microsoft\\Office\\OfficeTelemetryAgentLogOn2016",
    "\\Microsoft\\Office\\OfficeTelemetryAgentFallBack",
    "\\Microsoft\\Office\\OfficeTelemetryAgentFallBack2016",
    "\\Microsoft\\Office\\Office 15 Subscription Heartbeat",
    "\\Microsoft\\Office\\Office Feature Updates",
    "\\Microsoft\\Office\\Office Feature Updates Logon",
    # Retail demo + Insider flighting data collection + Insider feedback app
    "\\Microsoft\\Windows\\RetailDemo\\RetailDemoCleanupOnContent",
    "\\Microsoft\\Windows\\Flighting\\FeatureConfig\\ReconcileFeatures",
    "\\Microsoft\\Windows\\Flighting\\FeatureConfig\\UsageDataFlushed",
    "\\Microsoft\\Windows\\Flighting\\FeatureConfig\\UsageDataReporting",
    "\\Microsoft\\Windows\\Feedback\\WipAppUsageClient",
)


def disable_telemetry_tasks(logger: logging.Logger):
    """Disable the known Microsoft telemetry/CEIP scheduled tasks."""
    for full_path in TELEMETRY_TASK_PATHS:
        out, ret = run_cmd(["schtasks", "/Change", "/TN", full_path, "/DISABLE"])
        if ret == 0:
            logger.info(f"Disabled scheduled task: {full_path}")
        else:
            logger.warning(f"Failed to disable task: {full_path} ({out[:120]})")
    logger.info(f"Applied: DisableTelemetryTasks ({len(TELEMETRY_TASK_PATHS)} tasks)")


# ─── Main Scan Logic ─────────────────────────────────────────────────────────

def run_scan(config: dict, logger: logging.Logger, dry_run: bool = False) -> int:
    """Run one scan cycle. Returns number of packages removed."""
    if dry_run:
        logger.info("=== DRY-RUN MODE — no changes will be made ===")
    blacklist = config.get("Blacklist", [])
    whitelist = config.get("Whitelist", [])
    prev = config.get("Prevention", {})
    removed = 0
    matched = 0

    # 0. Safety net: restore point before destructive changes (self-throttles)
    if prev.get("CreateRestorePoint", True):
        if dry_run:
            logger.info("[DRY-RUN] Would create system restore point")
        else:
            create_restore_point(logger)

    # 1. Remove installed packages
    if prev.get("RemoveAppxPackages", True):
        packages = get_blacklisted_packages(blacklist, whitelist)
        matched += len(packages)
        full_names = get_package_full_names() if packages else {}
        for family_name, display_name, install_path in packages:
            full_name = full_names.get(family_name)
            is_system_app = not install_path or install_path.strip() == ""
            if dry_run:
                note = "[SystemApp: requires admin]" if is_system_app else ""
                if full_name:
                    logger.info(
                        f"[DRY-RUN] Would remove AppxPackage: {family_name} ({full_name}) {note}")
                else:
                    logger.info(
                        f"[DRY-RUN] Would remove AppxPackage: {family_name} "
                        f"(non-admin: full name not resolvable) {note}")
            else:
                if is_system_app:
                    logger.info(f"SystemApp skipped (requires admin): {family_name}")
                elif full_name and remove_appx_package(full_name):
                    logger.info(f"Removed AppxPackage: {family_name} ({display_name})")
                    record_removal(config, {
                        "kind": "appx", "name": display_name,
                        "family": family_name, "full_name": full_name,
                    })
                    removed += 1
                else:
                    logger.warning(f"Failed to remove AppxPackage: {family_name}")

    # 2. Remove provisioned packages (independent toggle — prevents re-deploy on new users)
    if prev.get("RemoveProvisionedPackages", True):
        provisioned = get_blacklisted_provisioned(blacklist, whitelist)
        matched += len(provisioned)
        for display_name, package_name in provisioned:
            if dry_run:
                logger.info(f"[DRY-RUN] Would remove ProvisionedPackage: {display_name} [requires admin]")
            else:
                if remove_provisioned_package(package_name):
                    logger.info(f"Removed ProvisionedPackage: {display_name}")
                    record_removal(config, {"kind": "provisioned", "name": display_name})
                    removed += 1
                else:
                    logger.warning(f"Failed to remove ProvisionedPackage: {display_name} [admin required]")

    # 2.5 Remove optional Windows capabilities (IE mode, Steps Recorder, WordPad)
    if prev.get("RemoveOptionalCapabilities", True):
        if dry_run:
            logger.info("[DRY-RUN] Would remove optional capabilities (IE/StepsRecorder/WordPad) [requires admin]")
        else:
            remove_optional_capabilities(logger)

    # 2.6 Remove Win32 programs matching blacklist — primary OEM preinstall
    # channel (McAfee/Norton are Win32, not Appx). MSI silent only.
    if prev.get("RemoveWin32Programs", True):
        for display, uninstall, quiet in get_blacklisted_win32(blacklist, whitelist):
            matched += 1
            if dry_run:
                logger.info(f"[DRY-RUN] Would uninstall Win32 program: {display} [requires admin]")
            else:
                if remove_win32_program(display, uninstall, quiet, logger):
                    logger.info(f"Removed Win32 program: {display}")
                    record_removal(config, {"kind": "win32", "name": display})
                    removed += 1
                else:
                    logger.warning(f"Failed/manual: {display} [admin required or no silent uninstaller]")

    # 3. Re-apply registry (idempotent, Windows Update may reset)
    if dry_run:
        logger.info("[DRY-RUN] Would apply registry prevention")
    else:
        apply_registry_prevention(config, logger)

    # 4. Disable OEM tasks
    if prev.get("DisableOemScheduledTasks", True):
        if dry_run:
            logger.info("[DRY-RUN] Would disable OEM scheduled tasks")
        else:
            disable_oem_scheduled_tasks(logger)

    # 4.5 Disable Microsoft telemetry/CEIP tasks (CompatTelRunner etc.)
    if prev.get("DisableTelemetryTasks", True):
        if dry_run:
            logger.info("[DRY-RUN] Would disable Microsoft telemetry tasks")
        else:
            disable_telemetry_tasks(logger)

    logger.info(f"Scan complete. {matched} packages matched blacklist; removed {removed}.")
    return removed


# ─── Service Mode ────────────────────────────────────────────────────────────

def run_service(config: dict, logger: logging.Logger):
    """Run as a persistent background process."""
    interval = config.get("ScanIntervalSeconds", 300)
    prev = config.get("Prevention", {})
    blacklist = config.get("Blacklist", [])
    whitelist = config.get("Whitelist", [])

    logger.info(f"=== {APP_NAME} Service Started ===")
    logger.info(f"Scan interval: {interval}s")
    logger.info(f"Blacklist entries: {len(blacklist)}")
    logger.info(f"Whitelist entries: {len(whitelist)}")

    # Layer 7: baseline-diff detection — a package that appears after being
    # absent in the previous scan counts as a (re-)install
    seen_provisioned: set = set()
    seen_installed: set = set()
    first_scan = True

    # Apply prevention once at startup — skipped entirely in dry-run mode
    if config.get("DryRun", False):
        logger.info("[DRY-RUN] Startup prevention changes skipped")
    else:
        if not is_admin():
            logger.warning("Running without admin rights — some prevention may fail.")
        apply_registry_prevention(config, logger)
        if prev.get("DisableOemScheduledTasks", True):
            disable_oem_scheduled_tasks(logger)
        if prev.get("DisableTelemetryTasks", True):
            disable_telemetry_tasks(logger)

    while True:
        try:
            # Standard scan (dry-run mode if configured)
            run_scan(config, logger, dry_run=config.get("DryRun", False))

            # Layer 7: Re-install Monitor
            if prev.get("ReinstallMonitor", True):
                # Keyed by DisplayName (stable across versions) → PackageName for removal
                prov_map = dict(
                    (display, pkg_name)
                    for display, pkg_name in get_blacklisted_provisioned(blacklist, whitelist)
                )
                current_provisioned = set(prov_map)
                current_installed = {
                    family for family, _, _ in get_blacklisted_packages(blacklist, whitelist)
                }

                if not first_scan:
                    for display_name in current_provisioned - seen_provisioned:
                        logger.warning(
                            f"[MONITOR] RE-INSTALLED detected: {display_name} — removing immediately!")
                        if remove_provisioned_package(prov_map[display_name]):
                            logger.info(f"[MONITOR] Re-removal complete: {display_name}")
                        else:
                            logger.warning(f"[MONITOR] Re-removal failed: {display_name}")

                    reinstalled = current_installed - seen_installed
                    full_names = get_package_full_names() if reinstalled else {}
                    for family_name in reinstalled:
                        logger.warning(
                            f"[MONITOR] RE-INSTALLED AppxPackage: {family_name} — removing!")
                        full_name = full_names.get(family_name)
                        if full_name and remove_appx_package(full_name):
                            logger.info(f"[MONITOR] Re-removal complete: {family_name}")
                        else:
                            logger.warning(f"[MONITOR] Re-removal failed: {family_name}")

                seen_provisioned = current_provisioned
                seen_installed = current_installed
                first_scan = False

        except Exception as e:
            logger.error(f"Scan error: {e}")
        time.sleep(interval)


# ─── Windows Service Registration ────────────────────────────────────────────

def install_service():
    """Register as a Windows service via NSSM.

    A pythonw.exe process is not SCM-aware, so plain `sc create` produces a
    service that always fails to start (error 1053). NSSM wraps the script
    and answers the service control dispatcher correctly. Prefer the C#
    implementation (`BloatwareGuard.exe install`) which is SCM-native."""
    script_path = Path(__file__).resolve()
    python_path = Path(sys.executable).resolve()

    # Use pythonw.exe for no-console window
    pythonw = python_path.parent / "pythonw.exe"
    if not pythonw.exists():
        pythonw = python_path

    nssm = shutil.which("nssm") or shutil.which("nssm", path=str(script_path.parent))
    if not nssm:
        print("ERROR: NSSM not found — a Python process cannot be a Windows service")
        print("       without a service wrapper. Options:")
        print("  1. Install NSSM (https://nssm.cc) and retry")
        print("  2. Use the C# build instead: BloatwareGuard.exe install")
        print("  3. Register a scheduled task:")
        print(f'     schtasks /Create /TN "{SERVICE_NAME}" /SC ONSTART /RU SYSTEM '
              f'/RL HIGHEST /TR "\\"{pythonw}\\" \\"{script_path}\\" --service"')
        return False

    subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True)
    subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True)
    subprocess.run([nssm, "remove", SERVICE_NAME, "confirm"], capture_output=True)
    time.sleep(2)

    result = subprocess.run(
        [nssm, "install", SERVICE_NAME, str(pythonw), str(script_path), "--service"],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False

    subprocess.run([nssm, "set", SERVICE_NAME, "Start", "SERVICE_AUTO_START"],
                   capture_output=True)
    subprocess.run(
        [nssm, "set", SERVICE_NAME, "AppStdout", str(LOG_DIR / "service-stdout.log")],
        capture_output=True)
    print(f"Service '{SERVICE_NAME}' installed via NSSM. "
          f"Use 'sc start {SERVICE_NAME}' to start.")
    return True


def uninstall_service():
    subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True)
    result = subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True, text=True)
    print(result.stdout)


# ─── Self-Test ───────────────────────────────────────────────────────────────

def run_self_test() -> int:
    """Real wiring checks — no admin required. Returns 0 if all pass, 1 otherwise."""
    print(f"{APP_NAME} v{APP_VERSION} — Self-Test Mode")
    results: List[Tuple[str, bool, str]] = []

    def check(name: str, fn):
        try:
            fn()
            results.append((name, True, ""))
        except Exception as e:
            results.append((name, False, str(e)))

    def t_config_roundtrip():
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "config.json"
            created = load_config(path)
            assert created["Blacklist"], "default blacklist empty"
            reloaded = load_config(path)
            assert reloaded["Blacklist"] == created["Blacklist"], "round-trip mismatch"

    def t_matching():
        bl = ["Microsoft.Xbox", "McAfee"]
        wl = ["Microsoft.XboxGameCallableUI"]
        assert is_target_package("Microsoft.XboxGamingOverlay_abc", bl, wl)
        assert is_target_package("McAfee.TotalProtection_xyz", bl, wl)
        assert not is_target_package("Microsoft.XboxGameCallableUI_abc", bl, wl)
        assert not is_target_package("Microsoft.WindowsStore_abc", bl, wl)

    def t_get_packages_parse():
        fake_json = json.dumps([
            {"PackageFamilyName": "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe",
             "Name": "Microsoft.XboxGamingOverlay",
             "InstallPath": "C:\\Program Files\\WindowsApps\\xbox"},
            {"PackageFamilyName": "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
             "Name": "Microsoft.WindowsCalculator",
             "InstallPath": "C:\\Program Files\\WindowsApps\\calc"},
        ])
        orig = run_powershell
        globals()["run_powershell"] = lambda cmd, timeout=60: (fake_json, "", 0)
        try:
            pkgs = get_blacklisted_packages(["Microsoft.Xbox"], ["Calculator"])
            assert len(pkgs) == 1 and pkgs[0][1] == "Microsoft.XboxGamingOverlay", \
                f"unexpected result: {pkgs}"
        finally:
            globals()["run_powershell"] = orig

    def t_full_name_map():
        fake_json = json.dumps([
            {"PackageFamilyName": "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe",
             "PackageFullName": "Microsoft.XboxGamingOverlay_1.0_x64__8wekyb3d8bbwe"},
        ])
        orig = run_powershell
        globals()["run_powershell"] = lambda cmd, timeout=60: (fake_json, "", 0)
        try:
            m = get_package_full_names()
            assert m.get("Microsoft.XboxGamingOverlay_8wekyb3d8bbwe") == \
                "Microsoft.XboxGamingOverlay_1.0_x64__8wekyb3d8bbwe"
        finally:
            globals()["run_powershell"] = orig

    def t_logging():
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "test.log"
            lg = setup_logging(log)
            try:
                lg.info("self-test marker")
                for h in lg.handlers:
                    h.flush()
                assert "self-test marker" in log.read_text(encoding="utf-8")
            finally:
                # Windows: FileHandler must be closed before TemporaryDirectory
                # cleanup (WinError 32)
                for h in list(lg.handlers):
                    h.close()
                    lg.removeHandler(h)

    def t_is_admin():
        result = is_admin()
        assert isinstance(result, bool), f"is_admin returned {type(result)}"

    def t_prevention_layers():
        prev = load_config(DEFAULT_CONFIG_PATH).get("Prevention", {})
        required = ["RemoveAppxPackages", "RemoveProvisionedPackages",
                    "DisableConsumerExperiences", "DisableCloudContent",
                    "PreventDeviceMetadata", "DisableOemScheduledTasks",
                    "BlockProvisioning", "ReinstallMonitor",
                    "DisableCopilot", "DisableRecall",
                    "DisableSearchSuggestions", "DisableWidgets",
                    "DisableTelemetry", "DisableGameDvr",
                    "DisableDeliveryOptimization", "DisableOneDrive",
                    "DisableChatTaskbar", "DisableEdgeBloat",
                    "RemoveOptionalCapabilities", "RemoveWin32Programs",
                    "CreateRestorePoint", "DisableTelemetryTasks",
                    "DisableStartupBloat", "DisableErrorReporting",
                    "DisableEdgeUpdateBloat", "BlockOemDriverUpdates",
                    "DisableAppPermissions", "DisableXboxServices",
                    "BackupRegistry", "DisablePrintSpooler",
                    "BlockOemWpbtExecution", "DisableReservedStorage",
                    "DisableCloudClipboard", "DisableRemoteAssistance",
                    "BlockInsiderPreview", "DisableMiscBloatServices",
                    "DisableSpotlight", "DisableAutoplay",
                    "NoForcedReboot", "HideStartRecommendations"]
        missing = [k for k in required if k not in prev]
        assert not missing, f"missing prevention keys: {missing}"

    def t_removal_ledger():
        with tempfile.TemporaryDirectory() as td:
            cfg = {"BackupDirectory": td}
            record_removal(cfg, {"kind": "appx", "name": "Microsoft.XboxGamingOverlay",
                                 "family": "fam", "full_name": "full"})
            ledger = Path(td) / "removed-packages.jsonl"
            entries = [
                json.loads(line)
                for line in ledger.read_text(encoding="utf-8").splitlines()
            ]
            assert len(entries) == 1 and entries[0]["name"] == "Microsoft.XboxGamingOverlay"
            assert "ts" in entries[0]

    check("T1: Config default-create + reload", t_config_roundtrip)
    check("T2: Blacklist/whitelist matching", t_matching)
    check("T3: Get-AppxPackage JSON parsing", t_get_packages_parse)
    check("T4: Logger file + console wiring", t_logging)
    check("T5: is_admin() callable", t_is_admin)
    check("T6: Prevention layers — 40 registered", t_prevention_layers)
    check("T7: Removal ledger write/read", t_removal_ledger)
    check("T8: Full-name batch map", t_full_name_map)

    print()
    passed = 0
    for name, ok, err in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {err}" if err else ""))
        passed += ok
    total = len(results)
    print(f"=== Self-Test Results: {passed}/{total} PASSED ===")
    if passed == total:
        print("Self-test PASSED — structure verified. Runtime requires admin Windows 11.")
        return 0
    print("Self-test FAILED — see failures above.")
    return 1


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BloatwareGuard - Auto-remove Windows bloatware")
    parser.add_argument("--scan", action="store_true", help="Run one scan and exit")
    parser.add_argument("--dry-run", action="store_true", help="Scan and log planned actions WITHOUT executing removal")
    parser.add_argument("--service", action="store_true", help="Run in service mode (background loop)")
    parser.add_argument("--service-dry-run", action="store_true",
                        help="Service mode with forced dry-run (monitoring only, mirrors C# --service-dry-run)")
    parser.add_argument("--install", action="store_true", help="Install as Windows service")
    parser.add_argument("--uninstall", action="store_true", help="Remove Windows service")
    parser.add_argument("--status", action="store_true", help="Show service status")
    parser.add_argument("--restore", action="store_true",
                        help="Restore staged packages recorded in the removal ledger")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Config file path")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument("--self-test", action="store_true", help="Run internal wiring self-test (no admin required)")
    args = parser.parse_args()

    if args.version:
        print(f"{APP_NAME} v{APP_VERSION}")
        return

    if args.self_test:
        sys.exit(run_self_test())

    if args.status:
        result = subprocess.run(["sc", "query", SERVICE_NAME], capture_output=True, text=True)
        print(result.stdout)
        return

    if args.install:
        if not is_admin():
            print("ERROR: Administrator rights required. Run as admin.")
            sys.exit(1)
        install_service()
        return

    if args.uninstall:
        if not is_admin():
            print("ERROR: Administrator rights required.")
            sys.exit(1)
        uninstall_service()
        return

    # Load config
    config = load_config(args.config)

    # Setup logging
    log_path = Path(config.get("LogFilePath", str(LOG_FILE)))
    logger = setup_logging(log_path)

    if not is_admin():
        logger.warning("Running without admin rights — registry changes and package removal may fail.")

    if args.restore:
        run_restore(config, logger)
        return

    if args.scan:
        run_scan(config, logger, dry_run=False)
        return

    if args.dry_run:
        run_scan(config, logger, dry_run=True)
        return

    # Default: service mode — honors config "DryRun" (set true for a
    # monitoring-only service); --service-dry-run forces it (C# parity).
    if args.service_dry_run:
        config["DryRun"] = True
        logger.info("SERVICE MODE IN DRY-RUN — no removal actions will execute")
    run_service(config, logger)


if __name__ == "__main__":
    main()
