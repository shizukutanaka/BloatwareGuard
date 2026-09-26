#!/usr/bin/env python3
"""
BloatwareGuard v1.8.0-mvp - Python prototype
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
import sys
import time
import ctypes
import argparse
import logging
import tempfile
import shutil
import re
from pathlib import Path
from typing import List, Optional, Tuple

# ─── Constants ───────────────────────────────────────────────────────────────

APP_NAME = "BloatwareGuard"
APP_VERSION = "1.8.0-mvp"
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
    "Microsoft.DevHome",
    "Microsoft.Copilot",
    "Microsoft.OutlookForWindows",        # new Outlook (replaces Mail & Calendar)
    "microsoft.windowscommunicationsapps",  # legacy Mail & Calendar (deprecated Dec 2024)
    "Microsoft.BingSearch",
    "Microsoft.Windows.Ai.Copilot.Provider",
    "Clipchamp.Clipchamp",
    # Third-party
    "McAfee",
    "Norton",
    "SpotifyAB.SpotifyMusic",
    "Netflix",
    "Dolby",
    "RealtekSemiconductor",
    "SynapticsIncorporated",
    "BytedancePte.Ltd.TikTok",
    "KING.COM.CandyCrush",
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "PandoraMediaInc.29680B314EFC2",
    "Facebook.InstagramBeta",
    "Facebook.Facebook",
    "WhatsApp",
    "Disney.",
    "A278AB0D.DisneyMagicKingdoms",
    "A278AB0D.MarchofEmpires",
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
                "MarkDeprovisioned": True,
                "RemoveDefaultStorePackages": True,
                "HardenContentDelivery": True,
                "DisableAiFeatures": True,
                "DisableWidgets": True,
                "DisableSearchSuggestions": True,
                "DisableTelemetryTasks": True,
                "DisableTelemetryPolicies": True,
                "HardenEdgePolicies": True,
                "CleanStartupEntries": True,
                "DisableOemServices": True,
                "RemoveWin32Bloatware": True,
                "DisableGameDvr": True,
                "BlockTelemetryEndpoints": True,
                "WingetSweep": True,
                "RemoveDeprecatedCapabilities": True,
                "DisableTelemetryServices": True,
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
    Whitelisted and IsFramework packages are never returned (framework parity with C#).
    Enumerates all users when elevated (-AllUsers)."""
    if not blacklist:
        return []

    # -AllUsers surfaces packages installed for other users too (admin only)
    scope = " -AllUsers" if is_admin() else ""
    results = []
    seen = set()
    ps_cmd = (f"Get-AppxPackage{scope} | "
              "Select-Object PackageFamilyName,Name,InstallPath,IsFramework | ConvertTo-Json")
    stdout, stderr, rc = run_powershell(ps_cmd, timeout=120)

    if rc != 0 or not stdout:
        return []

    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        for pkg in data:
            if pkg.get("IsFramework"):
                continue  # never remove framework packages
            family = pkg.get("PackageFamilyName", "")
            name = pkg.get("Name", "")
            install_path = pkg.get("InstallPath", "")  # None for SystemApps
            # -AllUsers emits one row per user per package — dedupe by family
            if family in seen:
                continue
            seen.add(family)
            if is_target_package(family, blacklist, whitelist):
                results.append((family, name, install_path))
    except (json.JSONDecodeError, TypeError):
        pass

    return results


def get_blacklisted_provisioned(blacklist: List[str], whitelist: List[str]) -> List[Tuple[str, str, str]]:
    """Return (DisplayName, PackageName, PackageFamilyName) for provisioned packages
    matching blacklist. Whitelisted packages are never returned. PackageFamilyName
    is derived as DisplayName_PublisherId — the key Deprovisioned markers and the
    25H2 removal policy are written under."""
    results = []
    ps_cmd = ("Get-AppxProvisionedPackage -Online | "
              "Select-Object DisplayName,PackageName,PublisherId | ConvertTo-Json")
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
            publisher = pkg.get("PublisherId", "")
            family = f"{display}_{publisher}" if display else ""
            if (is_target_package(display, blacklist, whitelist)
                    and not _is_whitelisted(package_name, whitelist)
                    and not _is_whitelisted(family, whitelist)):
                results.append((display, package_name, family))
    except (json.JSONDecodeError, TypeError):
        pass

    return results


def _is_whitelisted(name: str, whitelist: List[str]) -> bool:
    lname = name.lower()
    return any(w and w.lower() in lname for w in whitelist)


def get_package_full_names() -> dict:
    """Map PackageFamilyName -> PackageFullName in one PowerShell call.
    Avoids spawning a process per package inside scan loops."""
    ps_cmd = "Get-AppxPackage | Select-Object PackageFamilyName,PackageFullName | ConvertTo-Json"
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
    # -AllUsers removes for every user at once (admin); falls back to per-user
    scope = " -AllUsers" if is_admin() else ""
    ps_cmd = f"Remove-AppxPackage -Package '{package_full_name}'{scope} -ErrorAction SilentlyContinue"
    _, _, rc = run_powershell(ps_cmd, timeout=60)
    if rc != 0 and scope:
        ps_cmd = f"Remove-AppxPackage -Package '{package_full_name}' -ErrorAction SilentlyContinue"
        _, _, rc = run_powershell(ps_cmd, timeout=60)
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
    # PackageName is supplied by get_blacklisted_provisioned — no lookup respawn
    ps_cmd = (f"Remove-AppxProvisionedPackage -Online -PackageName '{package_name}' "
              f"-ErrorAction SilentlyContinue")
    _, _, rc = run_powershell(ps_cmd, timeout=60)
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


# Registry paths used by the prevention layers
DEPROVISIONED_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned"
REMOVE_DEFAULT_PACKAGES_PATH = r"SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages"
COPILOT_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
WINDOWS_AI_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
DSH_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Dsh"
NEWS_INTERESTS_PM_PATH = r"SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests"
EXPLORER_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\Explorer"
CDM_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
EXPLORER_ADVANCED_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
DEFAULT_HIVE_NAME = "BloatwareGuard_Default"

# Suggestion/ads delivery killswitches — the full set used by Win11Debloat's
# Disable_Windows_Suggestions.reg, all written as DWORD 0
CONTENT_DELIVERY_VALUES = (
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
)


def set_hive_dword(root, prefix: str, path: str, name: str, value: int) -> bool:
    """Set a DWORD under a given registry root + subkey prefix (e.g. an HKEY_USERS SID)."""
    try:
        import winreg
        full_path = f"{prefix}\\{path}" if prefix else path
        key = winreg.CreateKeyEx(root, full_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def _loaded_user_sids() -> List[str]:
    """SIDs of loaded real-user hives under HKEY_USERS (S-1-5-21-* only).
    Skips .DEFAULT, *_Classes, and service SIDs like S-1-5-18."""
    try:
        import winreg
        sids = []
        key = winreg.OpenKey(winreg.HKEY_USERS, "")
        i = 0
        while True:
            try:
                name = winreg.EnumKey(key, i)
            except OSError:
                break
            if name.upper().startswith("S-1-5-21-") and not name.endswith("_Classes"):
                sids.append(name)
            i += 1
        winreg.CloseKey(key)
        return sids
    except Exception:
        return []


def _apply_user_policies(root, prefix: str, prev: dict) -> int:
    """Write per-user policy values under one hive (prefix = SID or loaded hive name).
    Returns the number of values written."""
    written = 0
    if prev.get("HardenContentDelivery", True):
        for v in CONTENT_DELIVERY_VALUES:
            written += set_hive_dword(root, prefix, CDM_PATH, v, 0)
        written += set_hive_dword(root, prefix, EXPLORER_ADVANCED_PATH, "ShowCopilotButton", 0)
        written += set_hive_dword(root, prefix, EXPLORER_ADVANCED_PATH, "Start_IrisRecommendations", 0)
    if prev.get("DisableSearchSuggestions", True):
        written += set_hive_dword(root, prefix, EXPLORER_POLICY_PATH, "DisableSearchBoxSuggestions", 1)
    if prev.get("DisableAiFeatures", True):
        written += set_hive_dword(root, prefix, COPILOT_POLICY_PATH, "TurnOffWindowsCopilot", 1)
    if prev.get("DisableTelemetryPolicies", True):
        for path, name, value in TELEMETRY_USER_WRITES:
            written += set_hive_dword(root, prefix, path, name, value)
    if prev.get("DisableGameDvr", True):
        for path, name, value in GAMEDVR_USER_WRITES:
            written += set_hive_dword(root, prefix, path, name, value)
    return written


def apply_per_user_policies(prev: dict, logger: logging.Logger):
    """Apply per-user policies under every loaded user hive plus the Default
    profile template. A service running as SYSTEM would otherwise write them
    to SYSTEM's own HKCU where they do nothing for interactive users."""
    try:
        import winreg
    except ImportError:
        return  # non-Windows
    applied = 0
    for sid in _loaded_user_sids():
        applied += _apply_user_policies(winreg.HKEY_USERS, sid, prev)
    # Interactive run: current user's hive (usually also a loaded SID — idempotent)
    applied += _apply_user_policies(winreg.HKEY_CURRENT_USER, "", prev)

    # Stamp the Default profile template so FUTURE users get the policies.
    # reg.exe is required — winreg cannot load/unload hives.
    ntuser = Path(os.environ.get("SystemDrive", "C:")) / "Users" / "Default" / "NTUSER.DAT"
    if ntuser.exists():
        _, rc = run_cmd(["reg.exe", "load", f"HKU\\{DEFAULT_HIVE_NAME}", str(ntuser)], timeout=15)
        if rc == 0:
            applied += _apply_user_policies(winreg.HKEY_USERS, DEFAULT_HIVE_NAME, prev)
            run_cmd(["reg.exe", "unload", f"HKU\\{DEFAULT_HIVE_NAME}"], timeout=15)
    logger.info(f"Per-user policies applied ({applied} values across loaded hives + Default profile)")


def mark_deprovisioned(families, logger: logging.Logger):
    """Create Deprovisioned marker keys for matched families — Windows checks this
    documented path and skips re-provisioning during feature updates."""
    try:
        import winreg
    except ImportError:
        return
    count = 0
    for family in families:
        if not family:
            continue
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                f"{DEPROVISIONED_PATH}\\{family}", 0, winreg.KEY_WRITE)
            winreg.CloseKey(key)
            count += 1
        except Exception as e:
            logger.warning(f"Deprovisioned marker failed for {family}: {e}")
    if count:
        logger.info(f"Deprovisioned markers written for {count} package families")


def write_default_store_packages_policy(families, logger: logging.Logger):
    """Windows 11 25H2 policy: remove these Store packages at first sign-in of new
    user profiles. Inert on older builds — unknown policy keys are ignored."""
    try:
        import winreg
    except ImportError:
        return
    count = 0
    for family in families:
        if not family:
            continue
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                f"{REMOVE_DEFAULT_PACKAGES_PATH}\\{family}", 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "RemovePackage", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            count += 1
        except Exception as e:
            logger.warning(f"RemoveDefaultStorePackages failed for {family}: {e}")
    if count:
        logger.info(f"RemoveDefaultStorePackages policy set for {count} package families")


# Telemetry/privacy group policies — documented HKLM policy paths
TELEMETRY_POLICY_WRITES = (
    (r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
    (r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DoNotShowFeedbackNotifications", 1),
    (r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0),
    (r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0),
    (r"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0),
    (r"SOFTWARE\Policies\Microsoft\Windows\System", "AllowCrossDeviceClipboard", 0),
    (r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1),
    (r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocationScripting", 1),
    (r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace", "AllowWindowsInkWorkspace", 0),
    # Delivery Optimization P2P upload off (HTTP-only download mode)
    (r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization", "DODownloadMode", 0),
    # WER: never send extra crash data to Microsoft
    (r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "DontSendAdditionalData", 1),
    # Skip the OOBE privacy questions for new users
    (r"SOFTWARE\Policies\Microsoft\Windows\OOBE", "DisablePrivacyExperience", 1),
    # Windows Spotlight on lock screen / desktop
    (r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsSpotlightFeatures", 1),
    # Hide the Start-menu "Recommended" section (ads + suggested apps slot)
    (EXPLORER_POLICY_PATH, "HideRecommendedSection", 1),
)

# Per-user telemetry/privacy values — written to every loaded user hive.
# DisableTailoredExperiencesWithDiagnosticData is a documented User-class policy.
TELEMETRY_USER_WRITES = (
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy",
     "TailoredExperiencesWithDiagnosticDataEnabled", 0),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),
    (r"SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 0),
    (r"SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 0),
    (r"SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", 0),
    (r"SOFTWARE\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackProgs", 0),
    # Explorer "sync provider" ads (OneDrive/MS promos in File Explorer)
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowSyncProviderNotifications", 0),
    (r"SOFTWARE\Microsoft\Input\Settings", "InsightsEnabled", 0),
    (r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
     "DisableTailoredExperiencesWithDiagnosticData", 1),
)

EDGE_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Edge"

# Edge annoyance policies — documented MSEdge.admx policy names, all DWORD
EDGE_POLICIES = (
    ("HubsSidebarEnabled", 0), ("StandaloneHubsSidebarEnabled", 0),
    ("StartupBoostEnabled", 0), ("SpotlightExperiencesAndRecommendationsEnabled", 0),
    ("PersonalizationReportingEnabled", 0), ("ShowRecommendationsEnabled", 0),
    ("EdgeShoppingAssistantEnabled", 0), ("NewTabPageContentEnabled", 0),
)

# OEM/vendor name substrings — used for Win32 uninstallers, auto-start services,
# and Run/RunOnce startup entries (matched case-insensitively)
VENDOR_PATTERNS = (
    "McAfee", "Norton", "NortonLifeLock", "Avast", "AVG Software",
    "WildTangent", "CyberLink", "Lenovo", "Dell", "Hewlett", "HP Inc",
    "HPInc", "ASUS", "ASUSTeK", "Acer", "Razer", "ExpressVPN", "NordVPN",
    "Dropbox", "Spotify", "Adobe Creative Cloud", "CCleaner", "Booking.com",
)

# Run/RunOnce keys swept for startup bloat
RUN_KEY_PATHS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    # often-overlooked autostart hive (also abused by malware persistence)
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
)
HKLM_RUN_KEY_PATHS = RUN_KEY_PATHS + tuple(
    "SOFTWARE\\WOW6432Node\\" + p[len("SOFTWARE\\"):] for p in RUN_KEY_PATHS)

# Win32 uninstall hives — 64- and 32-bit views
WIN32_UNINSTALL_PATHS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)

# UninstallString tokens that already make an uninstaller non-interactive
SILENT_UNINSTALL_FLAGS = {
    "/s", "/silent", "/verysilent", "/quiet", "/qn", "-s", "-silent"
}

# Pure-telemetry endpoints blocked via the hosts file — the Spybot Anti-Beacon
# technique. Conservative: no Windows Update / Store / activation endpoints.
TELEMETRY_HOSTS = (
    "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "telecommand.telemetry.microsoft.com.nsatc.net",
    "oca.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com.nsatc.net",
    "sqm.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com.nsatc.net",
    "watson.telemetry.microsoft.com",
    "watson.telemetry.microsoft.com.nsatc.net",
    "watson.ppe.telemetry.microsoft.com",
    "watson.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com",
    "wes.df.telemetry.microsoft.com",
    "services.wes.df.telemetry.microsoft.com",
    "sqm.df.telemetry.microsoft.com",
    "settings-win.data.microsoft.com",
    "settings.data.microsoft.com",
    "statsfe2.ws.microsoft.com",
    "redir.metaservices.microsoft.com",
    "choice.microsoft.com",
    "choice.microsoft.com.nsatc.net",
    "telemetry.appex.bing.net",
    "telemetry.urs.microsoft.com",
    "feedback.microsoft-hohm.com",
    "vortex-bn2.metron.live.com.nsatc.net",
)
HOSTS_BLOCK_BEGIN = "# >>> BloatwareGuard telemetry block"
HOSTS_BLOCK_END = "# <<< BloatwareGuard telemetry block"

# Deprecated-in-Windows capabilities safe to remove (both deprecated by Microsoft)
DEPRECATED_CAPABILITIES = (
    "Microsoft.Windows.WordPad",       # deprecated — removed from builds > 26020
    "App.StepsRecorder",               # deprecated, slated for removal
)

# GameDVR policy + per-user capture keys
GAMEDVR_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\GameDVR"
GAMEDVR_USER_WRITES = (
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", 0),
    (r"SOFTWARE\System\GameConfigStore", "GameDVR_Enabled", 0),
)

# Telemetry/leftover system services — disabled outright. DiagTrack is the main
# telemetry pipeline; the Xbox services are dead once the Xbox apps are gone.
TELEMETRY_SERVICES = (
    "DiagTrack",          # Connected User Experiences and Telemetry
    "dmwappushservice",   # WAP Push Message Routing (telemetry channel)
    "RetailDemo",         # Retail Demo service
    "XblAuthManager",     # Xbox Live Auth — dead once Xbox apps are gone
    "XblGameSave",        # Xbox Live Game Save
    "XboxNetApiSvc",      # Xbox Live Networking
    "WMPNetworkSvc",      # Windows Media Player network sharing (legacy)
)

# NCSI active probing phones home to msftconnecttest.com on every reconnect
NCSI_PATH = r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"


# Microsoft telemetry/CEIP scheduled tasks — explicit full paths, disabled outright.
# Mirrors the telemetry task lists used by Win11Debloat / Sophia Script.
TELEMETRY_TASK_PATHS = (
    r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    r"\Microsoft\Windows\Application Experience\PcaPatchDbUpdate",
    r"\Microsoft\Windows\Application Experience\StartupAppTask",
    r"\Microsoft\Windows\Autochk\Proxy",
    r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    r"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver",
    r"\Microsoft\Windows\Feedback\Siuf\DmClient",
    r"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
    r"\Microsoft\Windows\Maps\MapsToastTask",
    r"\Microsoft\Windows\Maps\MapsUpdateTask",
    r"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
    r"\Microsoft\Windows\Speech\SpeechModelDownloadTask",
)


def disable_telemetry_tasks(logger: logging.Logger):
    """Disable known Microsoft telemetry/CEIP scheduled tasks by exact path.
    Missing tasks are logged at info level — they vary by Windows build."""
    disabled = 0
    for task_path in TELEMETRY_TASK_PATHS:
        _, rc = run_cmd(["schtasks", "/Change", "/TN", task_path, "/DISABLE"], timeout=15)
        if rc == 0:
            disabled += 1
            logger.info(f"Disabled telemetry task: {task_path}")
        else:
            logger.info(f"Telemetry task not present (skip): {task_path}")
    logger.info(f"Disabled {disabled}/{len(TELEMETRY_TASK_PATHS)} telemetry scheduled tasks")


# ─── Win32 / Vendor Bloat ────────────────────────────────────────────────────

def _read_uninstall_entry(root, path: str):
    """Return (DisplayName, UninstallString, QuietUninstallString) or ("","","")."""
    try:
        import winreg
        key = winreg.OpenKey(root, path, 0, winreg.KEY_READ)

        def _val(name):
            try:
                v, _ = winreg.QueryValueEx(key, name)
                return str(v)
            except OSError:
                return ""
        result = _val("DisplayName"), _val("UninstallString"), _val("QuietUninstallString")
        winreg.CloseKey(key)
        return result
    except Exception:
        return "", "", ""


def _win32_silent_uninstall_cmd(uninstall_str: str, quiet_str: str) -> Optional[str]:
    """Return a non-interactive uninstall command, or None if the entry has none.

    - QuietUninstallString is used verbatim
    - msiexec strings are converted to `msiexec /x {GUID} /qn /norestart`
    - UninstallStrings already carrying a known silent flag are used verbatim
    Anything else is skipped — an interactive uninstaller would hang the scan."""
    if quiet_str:
        return quiet_str
    if not uninstall_str:
        return None
    guid = re.search(r"\{[0-9A-Fa-f-]{36}\}", uninstall_str)
    if "msiexec" in uninstall_str.lower() and guid:
        return f"msiexec.exe /x {guid.group(0)} /qn /norestart"
    if any(t.lower() in SILENT_UNINSTALL_FLAGS for t in uninstall_str.split()):
        return uninstall_str
    return None


def remove_win32_bloatware(config: dict, dry_run: bool, logger: logging.Logger) -> int:
    """Uninstall Win32/desktop bloat (MSI/EXE) — Appx removal can't see these.
    Sweeps the Uninstall registry hives (HKLM 64/32-bit + loaded user hives) for
    DisplayNames matching Blacklist ∪ VENDOR_PATTERNS, excluding Whitelist.
    Only entries with a silent uninstall path are touched."""
    try:
        import winreg
    except ImportError:
        return 0
    blacklist = config.get("Blacklist", [])
    whitelist = config.get("Whitelist", [])
    patterns = [p for p in list(blacklist) + list(VENDOR_PATTERNS) if p.strip()]

    hives = [(winreg.HKEY_LOCAL_MACHINE, p) for p in WIN32_UNINSTALL_PATHS]
    hives += [(winreg.HKEY_USERS, f"{sid}\\{WIN32_UNINSTALL_PATHS[0]}")
              for sid in _loaded_user_sids()]
    removed = 0
    for root, path in hives:
        try:
            parent = winreg.OpenKey(root, path, 0, winreg.KEY_READ)
        except OSError:
            continue
        sub_names = []
        i = 0
        while True:
            try:
                sub_names.append(winreg.EnumKey(parent, i))
            except OSError:
                break
            i += 1
        winreg.CloseKey(parent)
        for sub in sub_names:
            display, uninstall_str, quiet_str = _read_uninstall_entry(
                root, f"{path}\\{sub}")
            if not display or not is_target_package(display, patterns, whitelist):
                continue
            cmd = _win32_silent_uninstall_cmd(uninstall_str, quiet_str)
            if cmd is None:
                logger.info(f"Win32 bloat — no silent uninstaller (manual): {display}")
                continue
            if dry_run:
                logger.info(f"[DRY-RUN] Would uninstall (win32): {display}")
                removed += 1
                continue
            _, rc = run_cmd(["cmd.exe", "/c", cmd], timeout=300)
            if rc == 0:
                logger.info(f"Uninstalled Win32 package: {display}")
                record_removal(config, {"kind": "win32", "name": display})
                removed += 1
            else:
                logger.warning(f"Win32 uninstall failed (rc={rc}): {display}")
    return removed


def clean_startup_entries(config: dict, dry_run: bool, logger: logging.Logger):
    """Delete Run/RunOnce values matching bloat/vendor patterns — HKLM (64- and
    32-bit views) plus every loaded user hive. Whitelist still applies."""
    try:
        import winreg
    except ImportError:
        return
    blacklist = config.get("Blacklist", [])
    whitelist = config.get("Whitelist", [])
    patterns = [p for p in list(blacklist) + list(VENDOR_PATTERNS) if p.strip()]

    targets = [(winreg.HKEY_LOCAL_MACHINE, p) for p in HKLM_RUN_KEY_PATHS]
    targets += [(winreg.HKEY_USERS, f"{sid}\\{p}")
                for sid in _loaded_user_sids() for p in RUN_KEY_PATHS]
    targets += [(winreg.HKEY_CURRENT_USER, p) for p in RUN_KEY_PATHS]

    deleted = 0
    for root, path in targets:
        try:
            key = winreg.OpenKey(root, path, 0,
                                 winreg.KEY_READ | winreg.KEY_SET_VALUE)
        except OSError:
            continue
        values = []  # collect first — deleting while enumerating skips entries
        i = 0
        while True:
            try:
                values.append(winreg.EnumValue(key, i))
            except OSError:
                break
            i += 1
        for name, data, _kind in values:
            if not is_target_package(f"{name} {data}", patterns, whitelist):
                continue
            if dry_run:
                logger.info(f"[DRY-RUN] Would delete startup entry: {path}\\{name}")
                deleted += 1
                continue
            try:
                winreg.DeleteValue(key, name)
                deleted += 1
                logger.info(f"Deleted startup entry: {name} ({path})")
            except OSError as e:
                logger.warning(f"Startup entry delete failed {name}: {e}")
        winreg.CloseKey(key)
    if deleted:
        logger.info(f"Startup bloat entries {'flagged' if dry_run else 'deleted'}: {deleted}")


def disable_oem_services(logger: logging.Logger):
    """Stop + disable OEM/vendor auto-start services (updaters, trial nagware)."""
    pattern = "|".join(re.escape(p) for p in VENDOR_PATTERNS)
    ps_cmd = ("Get-Service | Where-Object {$_.Name -match '" + pattern +
              "' -or $_.DisplayName -match '" + pattern + "'} | "
              "Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json")
    stdout, _, rc = run_powershell(ps_cmd, timeout=60)
    if rc != 0 or not stdout:
        return
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
    except (json.JSONDecodeError, TypeError):
        return
    disabled = 0
    for svc in data:
        name = svc.get("Name", "")
        # StartType serializes as a number in ConvertTo-Json (Disabled = 4)
        start_type = svc.get("StartType")
        if not name or start_type == "Disabled" or start_type == 4:
            continue
        run_cmd(["sc.exe", "stop", name], timeout=20)
        _, rc2 = run_cmd(["sc.exe", "config", name, "start=", "disabled"],
                         timeout=20)
        if rc2 == 0:
            disabled += 1
            logger.info(f"Disabled OEM service: {name} ({svc.get('DisplayName', '')})")
        else:
            logger.warning(f"Service disable failed [admin required?]: {name}")
    logger.info(f"Disabled {disabled} OEM/vendor services")


def disable_telemetry_services(logger: logging.Logger) -> int:
    """Stop + disable telemetry/leftover system services (DiagTrack, Xbox
    leftovers, WMP sharing) and kill NCSI active-probing connectivity checks."""
    disabled = 0
    for name in TELEMETRY_SERVICES:
        _, rc = run_cmd(["sc.exe", "query", name], timeout=10)
        if rc != 0:
            continue  # service not present on this machine
        run_cmd(["sc.exe", "stop", name], timeout=20)
        _, rc2 = run_cmd(["sc.exe", "config", name, "start=", "disabled"], timeout=15)
        if rc2 == 0:
            disabled += 1
            logger.info(f"Disabled telemetry service: {name}")
        else:
            logger.warning(f"Service disable failed [admin required?]: {name}")
    # NCSI active probing — stops msftconnecttest.com connectivity checks
    if set_registry_dword("HKLM", NCSI_PATH, "EnableActiveProbing", 0):
        logger.info("Applied: NCSI EnableActiveProbing = 0")
    logger.info(f"Disabled {disabled} telemetry/leftover services")
    return disabled


def _hosts_file_path() -> Path:
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    return Path(windir) / "System32" / "drivers" / "etc" / "hosts"


def set_telemetry_hosts_block(enabled: bool, logger: logging.Logger):
    """Add/remove a marked hosts-file block that null-routes pure-telemetry
    endpoints (the Spybot Anti-Beacon technique). Toggle-off removes the block —
    fully reversible. Conservative list: no Windows Update/Store/activation."""
    hosts = _hosts_file_path()
    try:
        text = hosts.read_text(encoding="utf-8", errors="replace") if hosts.exists() else ""
    except OSError as e:
        logger.warning(f"Cannot read hosts file: {e}")
        return

    begin_idx = text.find(HOSTS_BLOCK_BEGIN)
    end_idx = text.find(HOSTS_BLOCK_END)
    if begin_idx != -1 and end_idx != -1:
        text = text[:begin_idx].rstrip("\n") + "\n" + text[end_idx + len(HOSTS_BLOCK_END):].lstrip("\n")
    if enabled:
        block = "\n".join(f"0.0.0.0 {d}" for d in TELEMETRY_HOSTS)
        text = text.rstrip("\n") + f"\n\n{HOSTS_BLOCK_BEGIN}\n{block}\n{HOSTS_BLOCK_END}\n"
    if begin_idx == -1 and not enabled:
        return  # nothing to do — don't touch the file
    try:
        hosts.write_text(text, encoding="utf-8")
        logger.info(f"Telemetry hosts block {'applied' if enabled else 'removed'} "
                    f"({len(TELEMETRY_HOSTS)} domains)")
    except OSError as e:
        logger.warning(f"Cannot write hosts file [admin required]: {e}")


def disable_game_dvr(logger: logging.Logger):
    """Policy-disable Game Bar background capture (GameDVR) — removes the
    background recording overhead once Xbox apps are gone."""
    if set_registry_dword("HKLM", GAMEDVR_POLICY_PATH, "AllowGameDVR", 0):
        logger.info("Applied: AllowGameDVR = 0")


def winget_sweep(config: dict, dry_run: bool, logger: logging.Logger) -> int:
    """`winget uninstall --silent` sweep for bloat/vendor matches. Catches the
    leftovers that neither Appx nor the Uninstall-hive sweep can reach silently.
    Skips cleanly when winget (App Installer) is absent."""
    _, rc = run_cmd(["winget", "--version"], timeout=15)
    if rc != 0:
        logger.info("winget not available — skipping winget sweep")
        return 0
    stdout, rc = run_cmd(
        ["winget", "list", "--accept-source-agreements", "--disable-interactivity"],
        timeout=180)
    if rc != 0 or not stdout:
        return 0
    blacklist = config.get("Blacklist", [])
    whitelist = config.get("Whitelist", [])
    patterns = [p for p in list(blacklist) + list(VENDOR_PATTERNS) if p.strip()]

    removed = 0
    for line in stdout.splitlines():
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) < 2 or not cols[0] or cols[1].startswith("-"):
            continue  # header/separator line
        name, pkg_id = cols[0], cols[1]
        if not is_target_package(f"{name} {pkg_id}", patterns, whitelist):
            continue
        if dry_run:
            logger.info(f"[DRY-RUN] Would winget-uninstall: {name} ({pkg_id})")
            removed += 1
            continue
        _, rc = run_cmd(["winget", "uninstall", "--id", pkg_id, "--silent",
                         "--disable-interactivity", "--accept-source-agreements"],
                        timeout=300)
        if rc == 0:
            logger.info(f"winget-uninstalled: {name} ({pkg_id})")
            record_removal(config, {"kind": "winget", "name": name})
            removed += 1
        else:
            logger.info(f"winget uninstall skipped/failed: {name}")
    return removed


def remove_deprecated_capabilities(logger: logging.Logger) -> int:
    """Remove Windows capabilities Microsoft has deprecated (WordPad, Steps
    Recorder) — they persist in the image even though nothing uses them."""
    removed = 0
    for pattern in DEPRECATED_CAPABILITIES:
        ps_cmd = (f"Get-WindowsCapability -Online -Name '{pattern}*' | "
                  "Where-Object {$_.State -eq 'Installed'} | "
                  "Select-Object Name | ConvertTo-Json")
        stdout, _, rc = run_powershell(ps_cmd, timeout=60)
        if rc != 0 or not stdout:
            continue
        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                data = [data]
        except (json.JSONDecodeError, TypeError):
            continue
        for cap in data:
            name = cap.get("Name", "")
            if not name:
                continue
            _, rc2 = run_powershell(
                f"Remove-WindowsCapability -Online -Name '{name}'", timeout=180)
            if rc2 == 0:
                logger.info(f"Removed deprecated capability: {name}")
                removed += 1
    return removed


def apply_registry_prevention(config: dict, logger: logging.Logger):
    prev = config.get("Prevention", {})

    cloud_content = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    cdm = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

    if prev.get("DisableConsumerExperiences", True):
        if set_registry_dword("HKLM", cloud_content, "DisableWindowsConsumerFeatures", 1):
            logger.info("Applied: DisableWindowsConsumerFeatures = 1")

    if prev.get("DisableCloudContent", True):
        set_registry_dword("HKLM", cloud_content, "DisableSoftLanding", 1)
        set_registry_dword("HKLM", cloud_content, "DisableCloudOptimizedContent", 1)
        set_registry_dword("HKLM", cloud_content, "DisableWindowsSpotlightFeatures", 1)
        logger.info("Applied: DisableSoftLanding + DisableCloudOptimizedContent"
                    " + DisableWindowsSpotlightFeatures = 1")

    if prev.get("PreventDeviceMetadata", True):
        if set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
                              "PreventDeviceMetadataFromNetwork", 1):
            logger.info("Applied: PreventDeviceMetadataFromNetwork = 1")

    if prev.get("BlockProvisioning", True):
        set_registry_dword("HKLM", cloud_content, "DisableConsumerAccountContent", 1)
        set_registry_dword("HKCU", cdm, "SilentInstalledAppsEnabled", 0)
        set_registry_dword("HKCU", cdm, "SystemPaneSuggestionsEnabled", 0)
        set_registry_dword("HKCU", cdm, "SubscribedContent-338389Enabled", 0)
        logger.info("Applied: BlockProvisioning (silent installs + suggestions disabled)")

    if prev.get("DisableAiFeatures", True):
        set_registry_dword("HKLM", COPILOT_POLICY_PATH, "TurnOffWindowsCopilot", 1)
        set_registry_dword("HKLM", WINDOWS_AI_POLICY_PATH, "DisableAIDataAnalysis", 1)
        set_registry_dword("HKLM", WINDOWS_AI_POLICY_PATH, "AllowRecallEnablement", 0)
        set_registry_dword("HKLM", WINDOWS_AI_POLICY_PATH, "DisableClickToDo", 1)
        logger.info("Applied: TurnOffWindowsCopilot + DisableAIDataAnalysis + DisableClickToDo")

    if prev.get("DisableWidgets", True):
        set_registry_dword("HKLM", DSH_POLICY_PATH, "AllowNewsAndInterests", 0)
        # PolicyManager default — the feed stays off even if the policy is cleared
        set_registry_dword("HKLM", NEWS_INTERESTS_PM_PATH, "value", 0)
        logger.info("Applied: AllowNewsAndInterests = 0")

    if prev.get("DisableSearchSuggestions", True):
        set_registry_dword("HKLM", EXPLORER_POLICY_PATH, "DisableSearchBoxSuggestions", 1)
        logger.info("Applied: DisableSearchBoxSuggestions = 1")

    if prev.get("DisableTelemetryPolicies", True):
        applied = sum(set_registry_dword("HKLM", path, name, value)
                      for path, name, value in TELEMETRY_POLICY_WRITES)
        logger.info(f"Applied: telemetry/privacy policies ({applied} HKLM values)")

    if prev.get("HardenEdgePolicies", True):
        applied = sum(set_registry_dword("HKLM", EDGE_POLICY_PATH, name, value)
                      for name, value in EDGE_POLICIES)
        logger.info(f"Applied: Edge hardening policies ({applied} values)")

    if prev.get("DisableGameDvr", True):
        disable_game_dvr(logger)

    # Hosts-file telemetry blocking — toggle-off removes the marked block.
    # Unconditional call: the helper no-ops when disabled and no block exists.
    set_telemetry_hosts_block(prev.get("BlockTelemetryEndpoints", True), logger)

    # Per-user policies — must hit every loaded hive, not just HKCU
    if (prev.get("HardenContentDelivery", True) or prev.get("DisableSearchSuggestions", True)
            or prev.get("DisableAiFeatures", True) or prev.get("DisableTelemetryPolicies", True)
            or prev.get("DisableGameDvr", True)):
        apply_per_user_policies(prev, logger)


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
        "SupportAssist|Vantage|Armoury|Crate|Reinstall|Restore|Bloatware"
    )
    # Match TaskPath too — e.g. CEIP tasks live under
    # \Microsoft\Windows\Customer Experience Improvement Program\ with
    # innocuous names like "Consolidator" that name-matching alone misses
    ps_cmd = (
        f"Get-ScheduledTask | "
        f"Where-Object {{$_.TaskPath -like '*OEM*' -or $_.TaskName -match '{patterns}' "
        f"-or $_.TaskPath -match '{patterns}'}} | "
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
    matched_families = set()

    # 1. Remove installed packages
    if prev.get("RemoveAppxPackages", True):
        packages = get_blacklisted_packages(blacklist, whitelist)
        matched += len(packages)
        full_names = get_package_full_names() if packages else {}
        for family_name, display_name, install_path in packages:
            matched_families.add(family_name)
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
        for display_name, package_name, family in provisioned:
            matched_families.add(family)
            if dry_run:
                logger.info(f"[DRY-RUN] Would remove ProvisionedPackage: {display_name} [requires admin]")
            else:
                if remove_provisioned_package(package_name):
                    logger.info(f"Removed ProvisionedPackage: {display_name}")
                    record_removal(config, {"kind": "provisioned", "name": display_name})
                    removed += 1
                else:
                    logger.warning(f"Failed to remove ProvisionedPackage: {display_name} [admin required]")

    # 3. Re-apply registry (idempotent, Windows Update may reset)
    if dry_run:
        logger.info("[DRY-RUN] Would apply registry prevention")
    else:
        apply_registry_prevention(config, logger)

    # Persist removal: Deprovisioned markers stop feature-update re-installs;
    # the 25H2 policy stops provisioning for future user profiles
    if prev.get("MarkDeprovisioned", True) or prev.get("RemoveDefaultStorePackages", True):
        if dry_run:
            if matched_families:
                logger.info(f"[DRY-RUN] Would mark {len(matched_families)} package families "
                            "deprovisioned + write removal policy")
        else:
            if prev.get("MarkDeprovisioned", True):
                mark_deprovisioned(matched_families, logger)
            if prev.get("RemoveDefaultStorePackages", True):
                write_default_store_packages_policy(matched_families, logger)

    # 4. Disable OEM tasks
    if prev.get("DisableOemScheduledTasks", True):
        if dry_run:
            logger.info("[DRY-RUN] Would disable OEM scheduled tasks")
        else:
            disable_oem_scheduled_tasks(logger)

    # 5. Disable Microsoft telemetry/CEIP tasks
    if prev.get("DisableTelemetryTasks", True):
        if dry_run:
            logger.info("[DRY-RUN] Would disable telemetry scheduled tasks")
        else:
            disable_telemetry_tasks(logger)

    # 6. Win32 (MSI/EXE) bloat + winget sweep + deprecated capabilities —
    #    everything Appx removal can't see
    if prev.get("RemoveWin32Bloatware", True):
        removed += remove_win32_bloatware(config, dry_run, logger)
    if prev.get("WingetSweep", True):
        removed += winget_sweep(config, dry_run, logger)
    if prev.get("RemoveDeprecatedCapabilities", True):
        if dry_run:
            logger.info("[DRY-RUN] Would remove deprecated Windows capabilities")
        else:
            remove_deprecated_capabilities(logger)

    # 7. Telemetry + OEM auto-start services + Run-key startup entries
    if prev.get("DisableTelemetryServices", True):
        if dry_run:
            logger.info(f"[DRY-RUN] Would disable {len(TELEMETRY_SERVICES)} telemetry services")
        else:
            disable_telemetry_services(logger)

    if prev.get("DisableOemServices", True):
        if dry_run:
            logger.info("[DRY-RUN] Would disable OEM/vendor services")
        else:
            disable_oem_services(logger)
    if prev.get("CleanStartupEntries", True):
        clean_startup_entries(config, dry_run, logger)

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
                current_provisioned = {
                    pkg_name
                    for _, pkg_name, _ in get_blacklisted_provisioned(blacklist, whitelist)
                }
                current_installed = {
                    family for family, _, _ in get_blacklisted_packages(blacklist, whitelist)
                }

                if not first_scan:
                    for package_name in current_provisioned - seen_provisioned:
                        logger.warning(
                            f"[MONITOR] RE-INSTALLED detected: {package_name} — removing immediately!")
                        if remove_provisioned_package(package_name):
                            logger.info(f"[MONITOR] Re-removal complete: {package_name}")
                        else:
                            logger.warning(f"[MONITOR] Re-removal failed: {package_name}")

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
            assert len(created["Whitelist"]) == 8, "default whitelist not aligned with C#"
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
             "InstallPath": "C:\\Program Files\\WindowsApps\\xbox",
             "IsFramework": False},
            {"PackageFamilyName": "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
             "Name": "Microsoft.WindowsCalculator",
             "InstallPath": "C:\\Program Files\\WindowsApps\\calc",
             "IsFramework": False},
            # Framework packages must never be returned even when blacklisted
            {"PackageFamilyName": "Microsoft.XboxFramework_8wekyb3d8bbwe",
             "Name": "Microsoft.XboxFramework",
             "InstallPath": "C:\\Program Files\\WindowsApps\\xbfw",
             "IsFramework": True},
            # -AllUsers emits one row per user — duplicates must be deduped
            {"PackageFamilyName": "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe",
             "Name": "Microsoft.XboxGamingOverlay",
             "InstallPath": "C:\\Program Files\\WindowsApps\\xbox",
             "IsFramework": False},
        ])
        orig = run_powershell
        globals()["run_powershell"] = lambda cmd, timeout=60: (fake_json, "", 0)
        try:
            pkgs = get_blacklisted_packages(["Microsoft.Xbox"], ["Calculator"])
            assert len(pkgs) == 1 and pkgs[0][1] == "Microsoft.XboxGamingOverlay", \
                f"unexpected result: {pkgs}"
        finally:
            globals()["run_powershell"] = orig

    def t_get_provisioned_parse():
        fake_json = json.dumps([
            {"DisplayName": "Microsoft.BingNews",
             "PackageName": "Microsoft.BingNews_4.6.32001.0_neutral_~_8wekyb3d8bbwe",
             "PublisherId": "8wekyb3d8bbwe"},
            {"DisplayName": "Microsoft.WindowsCalculator",
             "PackageName": "Microsoft.WindowsCalculator_11.0_x64__8wekyb3d8bbwe",
             "PublisherId": "8wekyb3d8bbwe"},
        ])
        orig = run_powershell
        globals()["run_powershell"] = lambda cmd, timeout=60: (fake_json, "", 0)
        try:
            provs = get_blacklisted_provisioned(["Microsoft.BingNews"], ["Calculator"])
            assert len(provs) == 1, f"unexpected result: {provs}"
            display, package_name, family = provs[0]
            assert package_name == "Microsoft.BingNews_4.6.32001.0_neutral_~_8wekyb3d8bbwe"
            assert family == "Microsoft.BingNews_8wekyb3d8bbwe"
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
                    "MarkDeprovisioned", "RemoveDefaultStorePackages",
                    "HardenContentDelivery", "DisableAiFeatures",
                    "DisableWidgets", "DisableSearchSuggestions",
                    "DisableTelemetryTasks", "DisableTelemetryPolicies",
                    "HardenEdgePolicies", "CleanStartupEntries",
                    "DisableOemServices", "RemoveWin32Bloatware",
                    "DisableGameDvr", "BlockTelemetryEndpoints",
                    "WingetSweep", "RemoveDeprecatedCapabilities",
                    "DisableTelemetryServices"]
        missing = [k for k in required if k not in prev]
        assert not missing, f"missing prevention keys: {missing}"

    def t_telemetry_task_paths():
        assert len(TELEMETRY_TASK_PATHS) >= 10, "telemetry task list unexpectedly small"
        for p in TELEMETRY_TASK_PATHS:
            assert p.startswith("\\Microsoft\\Windows\\"), f"non-Microsoft task path: {p}"
        assert any("Customer Experience Improvement Program" in p for p in TELEMETRY_TASK_PATHS)

    def t_content_delivery_values():
        assert len(CONTENT_DELIVERY_VALUES) >= 15, "CDM killswitch set too small"
        assert "SilentInstalledAppsEnabled" in CONTENT_DELIVERY_VALUES

    def t_win32_silent_uninstall():
        # msiexec strings get converted to silent /x
        cmd = _win32_silent_uninstall_cmd("MsiExec.exe /I{12345678-1234-1234-1234-123456789012}", "")
        assert cmd == "msiexec.exe /x {12345678-1234-1234-1234-123456789012} /qn /norestart"
        # QuietUninstallString passes through verbatim
        assert _win32_silent_uninstall_cmd("x", "uninst.exe /S") == "uninst.exe /S"
        # already-silent flags pass through
        assert _win32_silent_uninstall_cmd('"C:\\app\\uninstall.exe" /S', "") is not None
        # interactive uninstallers are skipped — they'd hang the scan
        assert _win32_silent_uninstall_cmd('"C:\\app\\uninstall.exe"', "") is None

    def t_vendor_patterns():
        assert len(VENDOR_PATTERNS) >= 15, "vendor pattern list too small"
        for p in VENDOR_PATTERNS:
            assert p.strip(), "empty vendor pattern would match everything"
        # 'hp' alone would match 'Photoshop' — require word-ish patterns
        assert "HP" not in VENDOR_PATTERNS

    def t_policy_tables():
        assert len(TELEMETRY_POLICY_WRITES) >= 10
        assert len(TELEMETRY_USER_WRITES) >= 8
        assert len(EDGE_POLICIES) >= 5
        for path, name, value in TELEMETRY_POLICY_WRITES:
            assert path.startswith("SOFTWARE\\Policies\\Microsoft\\"), path
            assert name and isinstance(value, int)
        for name, value in EDGE_POLICIES:
            assert name and isinstance(value, int)

    def t_telemetry_hosts():
        assert len(TELEMETRY_HOSTS) >= 20
        for d in TELEMETRY_HOSTS:
            assert re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", d), d
        # never block update/activation endpoints
        assert not any("windowsupdate" in d or "activation" in d
                       or "store" in d for d in TELEMETRY_HOSTS)

    def t_deprecated_capabilities():
        assert len(DEPRECATED_CAPABILITIES) >= 2
        assert all("*" not in c and c.strip() for c in DEPRECATED_CAPABILITIES)
        assert len(TELEMETRY_SERVICES) >= 5 and "DiagTrack" in TELEMETRY_SERVICES

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
    check("T3: Get-AppxPackage JSON parsing (+framework/dedupe)", t_get_packages_parse)
    check("T4: Logger file + console wiring", t_logging)
    check("T5: is_admin() callable", t_is_admin)
    check("T6: Prevention layers — 25 registered", t_prevention_layers)
    check("T7: Removal ledger write/read", t_removal_ledger)
    check("T8: Full-name batch map", t_full_name_map)
    check("T9: ProvisionedPackage parse (name + family)", t_get_provisioned_parse)
    check("T10: Telemetry task paths well-formed", t_telemetry_task_paths)
    check("T11: ContentDelivery killswitch set", t_content_delivery_values)
    check("T12: Win32 silent-uninstall classifier", t_win32_silent_uninstall)
    check("T13: Vendor patterns sane", t_vendor_patterns)
    check("T14: Telemetry/Edge policy tables well-formed", t_policy_tables)
    check("T15: Telemetry hosts list well-formed", t_telemetry_hosts)
    check("T16: Deprecated capabilities list", t_deprecated_capabilities)

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
