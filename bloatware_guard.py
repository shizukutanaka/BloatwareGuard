#!/usr/bin/env python3
"""
BloatwareGuard v1.7.0 - Python prototype
Windowsサービス化可能な常駐型bloatware自動削除ツール

使い方:
  python bloatware_guard.py            # 常駐モード（定期スキャン）
  python bloatware_guard.py --scan     # 1回だけスキャン
  python bloatware_guard.py --dry-run  # 削除対象を表示のみ（変更なし）
  python bloatware_guard.py --install  # Windowsサービスに登録（要管理者）
  python bloatware_guard.py --uninstall # サービス削除（要管理者）
  python bloatware_guard.py --status   # 状態確認
  python bloatware_guard.py --version  # バージョン表示

※ 管理者権限が必要です。
"""

import subprocess
import json
import os
import sys
import time
import re
import ctypes
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Optional

# ─── Constants ───────────────────────────────────────────────────────────────

APP_NAME = "BloatwareGuard"
APP_VERSION = "1.7.0"
SERVICE_NAME = "BloatwareGuard"
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.json"
YAML_CONFIG_PATH = Path(__file__).parent / "config.yaml"
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
    "Microsoft.DevHome",
    "Microsoft.Copilot",
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
    "A278AB0D.DisneyMagicKingdoms",
    "A278AB0D.MarchofEmpires",
]


def load_config(path: Path) -> dict:
    if not path.exists():
        config = {
            "ScanIntervalSeconds": 300,
            "LogFilePath": str(LOG_FILE),
            "Blacklist": DEFAULT_BLACKLIST,
            "Prevention": {
                "RemoveAppxPackages": True,
                "RemoveProvisionedPackages": True,
                "DisableConsumerExperiences": True,
                "DisableCloudContent": True,
                "PreventDeviceMetadata": True,
                "DisableOemScheduledTasks": True,
                "BlockProvisioning": True,
                "ReinstallMonitor": True,
            }
        }
        path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
        return config

    return json.loads(path.read_text(encoding="utf-8"))


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

def get_blacklisted_packages(blacklist: List[str]) -> List[Tuple[str, str, str]]:
    """Return (PackageFamilyName, Name, InstallPath) for packages matching blacklist.
    InstallPath is None for SystemApps (cannot be removed per-user)."""
    if not blacklist:
        return []

    # Build regex: match if any blacklist entry is a substring of PackageFamilyName
    results = []
    ps_cmd = "Get-AppxPackage | Select-Object PackageFamilyName,Name,InstallPath | ConvertTo-Json"
    stdout, stderr, rc = run_powershell(ps_cmd, timeout=120)

    if rc != 0 or not stdout:
        return []

    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        for pkg in data:
            family = pkg.get("PackageFamilyName", "")
            name = pkg.get("Name", "")
            install_path = pkg.get("InstallPath", "")  # None for SystemApps
            if any(entry.lower() in family.lower() for entry in blacklist):
                results.append((family, name, install_path))
    except (json.JSONDecodeError, TypeError):
        pass

    return results


def get_blacklisted_provisioned(blacklist: List[str]) -> List[str]:
    """Return DisplayName of provisioned packages matching blacklist."""
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
            if any(entry.lower() in display.lower() for entry in blacklist):
                results.append(display)
    except (json.JSONDecodeError, TypeError):
        pass

    return results


def get_package_full_name(package_family_name: str) -> Optional[str]:
    ps_cmd = f"(Get-AppxPackage -PackageFamilyName '{package_family_name}').PackageFullName"
    stdout, _, rc = run_powershell(ps_cmd)
    if rc == 0 and stdout:
        return stdout.strip().split("\n")[-1].strip()
    return None


def remove_appx_package(package_full_name: str) -> bool:
    ps_cmd = f"Remove-AppxPackage -Package '{package_full_name}' -ErrorAction SilentlyContinue"
    _, _, rc = run_powershell(ps_cmd, timeout=60)
    return rc == 0


def remove_provisioned_package(display_name: str) -> bool:
    # Need the exact package name for removal
    ps_cmd = (
        f"$pkg = Get-AppxProvisionedPackage -Online | "
        f"Where-Object {{$_.DisplayName -eq '{display_name}'}}; "
        f"if ($pkg) {{ Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction SilentlyContinue }}"
    )
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


def apply_registry_prevention(config: dict, logger: logging.Logger):
    prev = config.get("Prevention", {})

    if prev.get("DisableConsumerExperiences", True):
        if set_registry_dword("HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            "DisableWindowsConsumerFeatures", 1):
            logger.info("Applied: DisableWindowsConsumerFeatures = 1")

    if prev.get("DisableCloudContent", True):
        set_registry_dword("HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            "DisableSoftLanding", 1)
        set_registry_dword("HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            "DisableCloudOptimizedContent", 1)
        logger.info("Applied: DisableSoftLanding + DisableCloudOptimizedContent = 1")

    if prev.get("PreventDeviceMetadata", True):
        if set_registry_dword("HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
            "PreventDeviceMetadataFromNetwork", 1):
            logger.info("Applied: PreventDeviceMetadataFromNetwork = 1")

    if prev.get("BlockProvisioning", True):
        set_registry_dword("HKLM",
            r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            "DisableConsumerAccountContent", 1)
        set_registry_dword("HKCU",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SilentInstalledAppsEnabled", 0)
        set_registry_dword("HKCU",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SystemPaneSuggestionsEnabled", 0)
        set_registry_dword("HKCU",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SubscribedContent-338389Enabled", 0)
        logger.info("Applied: BlockProvisioning (silent installs + suggestions disabled)")


# ─── Scheduled Task Prevention ───────────────────────────────────────────────

def disable_oem_scheduled_tasks(logger: logging.Logger):
    """Disable known OEM scheduled tasks that reinstall bloatware."""
    patterns = "SupportAssist|Vantage|Armoury|Crate|Dell|HPInc|Lenovo|ASUS|Acer|McAfee|Norton|CustomerExperience|Reinstall|Restore|OEM"
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

        for task in data:
            name = task.get("TaskName", "")
            path = task.get("TaskPath", "\\")
            if not name:
                continue
            full_path = path.rstrip("\\") + "\\" + name
            out, ret = run_cmd(["schtasks", "/Change", "/TN", full_path, "/DISABLE"])
            if ret == 0:
                logger.info(f"Disabled scheduled task: {full_path}")
            else:
                logger.warning(f"Failed to disable task: {full_path} ({out})")

        logger.info(f"Processed {len(data)} OEM scheduled tasks")
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"Scheduled task scan error: {e}")


# ─── Main Scan Logic ─────────────────────────────────────────────────────────

def run_scan(config: dict, logger: logging.Logger, dry_run: bool = False) -> int:
    """Run one scan cycle. Returns number of packages removed."""
    if dry_run:
        logger.info("=== DRY-RUN MODE — no changes will be made ===")
    blacklist = config.get("Blacklist", [])
    prev = config.get("Prevention", {})
    removed = 0

    # 1. Remove installed packages
    if prev.get("RemoveAppxPackages", True):
        packages = get_blacklisted_packages(blacklist)
        for family_name, display_name, install_path in packages:
            full_name = get_package_full_name(family_name)
            is_system_app = not install_path or install_path.strip() == ""
            if dry_run:
                note = "[SystemApp: requires admin]" if is_system_app else ""
                if full_name:
                    logger.info(f"[DRY-RUN] Would remove AppxPackage: {family_name} ({full_name}) {note}")
                else:
                    logger.info(f"[DRY-RUN] Would remove AppxPackage: {family_name} (non-admin: full name not resolvable) {note}")
            else:
                if is_system_app:
                    logger.info(f"SystemApp skipped (requires admin): {family_name}")
                elif remove_appx_package(full_name):
                    logger.info(f"Removed AppxPackage: {family_name} ({display_name})")
                    removed += 1
                else:
                    logger.warning(f"Failed to remove AppxPackage: {family_name}")

        # 2. Remove provisioned packages
        if prev.get("RemoveProvisionedPackages", True):
            provisioned = get_blacklisted_provisioned(blacklist)
            for display_name in provisioned:
                if dry_run:
                    logger.info(f"[DRY-RUN] Would remove ProvisionedPackage: {display_name}")
                else:
                    if remove_provisioned_package(display_name):
                        logger.info(f"Removed ProvisionedPackage: {display_name}")
                        removed += 1
                    else:
                        logger.warning(f"Failed to remove ProvisionedPackage: {display_name}")

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

    logger.info(f"Scan complete. Removed {removed} packages.")
    return removed


# ─── Service Mode ────────────────────────────────────────────────────────────

def run_service(config: dict, logger: logging.Logger):
    """Run as a persistent background process."""
    interval = config.get("ScanIntervalSeconds", 300)
    prev = config.get("Prevention", {})
    blacklist = config.get("Blacklist", [])
    
    logger.info(f"=== {APP_NAME} Service Started ===")
    logger.info(f"Scan interval: {interval}s")
    logger.info(f"Blacklist entries: {len(blacklist)}")
    
    # Layer 7: Track previously removed provisioned packages to detect re-installation
    known_removed = set()

    # Apply prevention once at startup
    if not is_admin():
        logger.warning("Running without admin rights — some prevention may fail.")
    apply_registry_prevention(config, logger)
    disable_oem_scheduled_tasks(logger)

    while True:
        try:
            # Standard scan (dry-run mode if configured)
            removed = run_scan(config, logger, dry_run=config.get("DryRun", False))
            
            # Layer 7: Re-install Monitor
            if prev.get("ReinstallMonitor", True):
                current_provisioned = get_blacklisted_provisioned(blacklist)
                for display_name in current_provisioned:
                    if display_name in known_removed:
                        logger.warning(f"[MONITOR] RE-INSTALLED detected: {display_name} — removing immediately!")
                        remove_provisioned_package(display_name)
                        logger.info(f"[MONITOR] Re-removal complete: {display_name}")
                    else:
                        known_removed.add(display_name)
            
            # Also check installed packages for re-appearance
            current_installed = get_blacklisted_packages(blacklist)
            for family_name, display_name, install_path in current_installed:
                if family_name in known_removed:
                    logger.warning(f"[MONITOR] RE-INSTALLED AppxPackage: {family_name} — removing!")
                    full_name = get_package_full_name(family_name)
                    if full_name:
                        remove_appx_package(full_name)

        except Exception as e:
            logger.error(f"Scan error: {e}")
        time.sleep(interval)


# ─── Windows Service Registration ────────────────────────────────────────────

def install_service():
    """Register as a Windows service using NSSM or sc.exe."""
    script_path = Path(__file__).resolve()
    python_path = Path(sys.executable).resolve()

    # Use pythonw.exe for no-console window
    pythonw = python_path.parent / "pythonw.exe"
    if not pythonw.exists():
        pythonw = python_path

    bin_path = f'"{pythonw}" "{script_path}" --service'

    # Stop and delete existing
    subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True)
    subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True)
    time.sleep(2)

    # Create
    result = subprocess.run(
        ["sc", "create", SERVICE_NAME, f"binPath= {bin_path}",
         "start= " "auto", f"DisplayName= " f'"{APP_NAME}"'],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False

    print(f"Service '{SERVICE_NAME}' installed. Use 'sc start {SERVICE_NAME}' to start.")
    return True


def uninstall_service():
    subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True)
    result = subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True, text=True)
    print(result.stdout)


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BloatwareGuard - Auto-remove Windows bloatware")
    parser.add_argument("--scan", action="store_true", help="Run one scan and exit")
    parser.add_argument("--dry-run", action="store_true", help="Scan and log planned actions WITHOUT executing removal")
    parser.add_argument("--service", action="store_true", help="Run in service mode (background loop)")
    parser.add_argument("--install", action="store_true", help="Install as Windows service")
    parser.add_argument("--uninstall", action="store_true", help="Remove Windows service")
    parser.add_argument("--status", action="store_true", help="Show service status")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Config file path")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"{APP_NAME} v{APP_VERSION}")
        return

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

    if args.scan:
        run_scan(config, logger, dry_run=False)
        return

    if args.dry_run:
        run_scan(config, logger, dry_run=True)
        return

    # Default: service mode
    if args.service:
        config["DryRun"] = True
        logger.info("SERVICE MODE IN DRY-RUN — no removal actions will execute")
    run_service(config, logger)


if __name__ == "__main__":
    main()
