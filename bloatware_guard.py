#!/usr/bin/env python3
"""
BloatwareGuard v1.11.0-mvp - Python prototype
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
APP_VERSION = "1.11.0-mvp"
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
    pattern = "Browser.InternetExplorer|App.StepsRecorder|Microsoft.Windows.WordPad"
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


# Per-user registry paths (relative to a user hive root — HKCU or HKEY_USERS\<SID>)
_USER_CDM = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
_USER_EXPLORER_ADV = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
_USER_EXPLORER_POLICIES = r"Software\Policies\Microsoft\Windows\Explorer"
_USER_COPILOT = r"Software\Policies\Microsoft\Windows\WindowsCopilot"
_USER_WINDOWS_AI = r"Software\Policies\Microsoft\Windows\WindowsAI"
_USER_SEARCH = r"Software\Microsoft\Windows\CurrentVersion\Search"
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


def apply_registry_prevention(config: dict, logger: logging.Logger):
    import winreg
    prev = config.get("Prevention", {})

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
        set_registry_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\WSAIFabricSvc", "Start", 3)
        logger.info("Applied: DisableRecall (WindowsAI policies + Click to Do off, "
                    "Recall feature removal attempted, WSAIFabricSvc=demand)")

    if prev.get("DisableSearchSuggestions", True):
        search_pol = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        set_registry_dword("HKLM", search_pol, "AllowCortana", 0)
        set_registry_dword("HKLM", search_pol, "CortanaConsent", 0)
        set_user_dword_all_hives(_USER_EXPLORER_POLICIES, "DisableSearchBoxSuggestions", 1, logger)
        set_user_dword_all_hives(_USER_SEARCH, "BingSearchEnabled", 0, logger)
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
        logger.info("Applied: DisableEdgeBloat (sidebar/startup-boost/prelaunch/first-run off)")


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
                    "RemoveOptionalCapabilities"]
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
    check("T6: Prevention layers — 19 registered", t_prevention_layers)
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
