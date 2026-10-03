#!/usr/bin/env python3
"""
BloatwareGuard v1.61.2 - Python prototype
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
import ast
import json
import os
import re
import sys
import time
import ctypes
import argparse
import logging
import logging.handlers
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Set, Tuple

# ─── Constants ───────────────────────────────────────────────────────────────

APP_NAME = "BloatwareGuard"
APP_VERSION = "1.61.2"
SERVICE_NAME = "BloatwareGuard"
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.json"
LOG_DIR = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "BloatwareGuard"
LOG_FILE = LOG_DIR / "bloatware-guard.log"


# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # A resident service appends forever — rotate at 1 MB, keep one backup
        fh = logging.handlers.RotatingFileHandler(
            str(log_file), maxBytes=1_000_000, backupCount=1,
            encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError:
        # Non-admin or unwritable path: fall back to console only
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
    "Flipgrid",                      # Flip education stub (ReviOS appx.yml)
    "Microsoft.FrenchRiviera",       # scenic/spotlight stub (TronScript)
    "Microsoft.Lucille",             # inbox demo stub (TronScript)
    "Microsoft.SeaofThieves",        # game stub (TronScript)
    # zoicware RemoveWindowsAI 2026 diff — AI component packages
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
    "Microsoft.MicrosoftJournal",
    "MicrosoftWindows.Client.WebExperience",  # Widgets host
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
    "Microsoft.USNationalParks",        # theme/content pack stub (VDOT appx)
    "Microsoft.WindowsAlarms",
    "Microsoft.ScreenSketch",
    "Microsoft.Clipchamp",
    "MicrosoftTeams", "Microsoft.Teams",
    "Microsoft.MicrosoftEdge.Stable",
    "Microsoft.Windows.DevHome",       # Dev Home (+ GitHub extension)
    "Microsoft.Copilot",
    # OS-inboxed Copilot package (distinct from Store Microsoft.Copilot —
    # itsnileshhere/windows-iso-debloater)
    "Microsoft.Windows.Copilot",
    "Microsoft.Windows.Ai.Copilot.Provider",  # Copilot provider package
    "MicrosoftWindows.Client.CoPilot",  # Copilot client (distinct from Microsoft.Copilot)
    "MicrosoftWindows.Client.CoreAI",   # Windows AI platform — Recall/ClickToDo runtime
    "MicrosoftWindows.Client.AIX",      # AI experience shell (Copilot+)
    "aimgr",                            # AI Manager package
    "Clipchamp.Clipchamp",
    "MSTeams",                          # New Teams (Work/School), provisioned via AppX push
    "Microsoft.Windows.Teams",          # inbox Teams integration stub (iso-debloater)
    "Microsoft.OutlookForWindows",      # New Outlook, preinstalled since 23H2
    "Microsoft.WindowsCommunicationsApps",  # Mail & Calendar (discontinued Dec 2024)
    "MicrosoftCorporationII.MicrosoftFamily",
    "MicrosoftCorporationII.QuickAssist",
    "Microsoft.BingSearch",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.Edge.GameAssist",
    "Microsoft.3DBuilder",               # discontinued
    "Microsoft.BingFinance",             # discontinued Bing consumer apps
    "Microsoft.BingFoodAndDrink",
    "Microsoft.BingHealthAndFitness",
    "Microsoft.BingSports",
    "Microsoft.BingTranslator",
    "Microsoft.BingTravel",
    "Microsoft.News",                    # News feed app
    "Microsoft.PCManager",               # pushed via 24H2+ provisioning
    "Microsoft.Windows.AIHub",           # Store AI promotions hub
    # Third-party
    "McAfee",
    "Norton",
    "SpotifyAB.SpotifyMusic",
    "Netflix",
    "Dolby",
    # Intel Management & Security Status (IMSS) — OEM support stub
    # (tiny11builder removal list)
    "AppUp.IntelManagementandSecurityStatus",
    "RealtekSemiconductor",
    "SynapticsIncorporated",
    "BytedancePte.Ltd.TikTok",
    "KING.COM.",                       # CandyCrush + all King.com promo games
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "PandoraMediaInc.29680B314EFC2",
    "Facebook.InstagramBeta",
    "Facebook.Facebook",
    "WhatsApp",
    "A278AB0D.",  # Lenovo apps + MarchofEmpires/DisneyMagicKingdoms
    "9E2F88E3.",   # Twitter stub apps
    "613EBCEA.",   # Polarr photo stubs
    "89006A2E.",   # Autodesk stubs
    "D52A8D61.",   # FarmVille stubs
    "DB6EA5DB.",   # CyberLink stubs
    "NORDCURRENT.",  # CookingFever-family stubs,
    # Win-Debloat-Tools list — Samsung store stubs + RandomSalad game stubs
    "RandomSaladGamesLLC.", "SAMSUNGELECTRONICSCO.LTD.",
    "Playtika.",      # casino-game stubs (Caesars Slots)
    "ThumbmunkeysLtd.",  # Phototastic Collage stub
    "DolbyAccess",    # Dolby Atmos trial console (OEM push)
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
    # Dead/deprecated stock apps and promo stubs (24H2 image still ships them)
    "Microsoft.3DViewer",                # 3D Viewer — deprecated, no updates
    "Microsoft.Print3D",
    "Microsoft.Whiteboard",
    "Microsoft.Wallet",                  # Microsoft Pay UI — service retired
    "Microsoft.Messaging",               # dead legacy SMS app
    "Microsoft.OneConnect",              # Mobile Plans (cellular add-on promos)
    "Microsoft.CommsPhone",              # legacy phone-call component
    "Microsoft.Appconnector",            # legacy connector, no UI
    "Microsoft.NetworkSpeedTest",
    "Microsoft.Office.Sway",
    "Microsoft.Office.Desktop",          # Office Hub launcher / promo stub
    "MSTranslatorBeta",
    "MicrosoftWindows.CrossDevice",      # Cross-Device Experience stub (Phone Link)
    "Microsoft.ECApp",                   # Edge app-maker stub
    "SystweakSoftware",                  # optimizer ads
    "PricerunnerAB",
    # OEM/promo third-party (Win11Debloat default-removal parity)
    "ACGMediaPlayer",
    "ActiproSoftwareLLC",
    "AdobeSystemsIncorporated.AdobePhotoshopExpress",
    "AutodeskSketchBook",
    "CaesarsSlotsFreeCasino",
    "DrawboardPDF",
    "FarmVille2CountryEscape",
    "HULULLC.HULUPLUS",
    "HiddenCity",
    "NYTCrossword",
    "OneCalendar",
    "PhototasticCollage",
    "PolarrPhotoEditorAcademicEdition",
    "Sidia.LiveWallpaper",
    "SlingTV",
    # winlite batchfile diff — promoted stubs still shipping on 25H2
    # consumer images (Priceline travel, GroupMe social, Tips content)
    "PricelineCom.", "GroupMe", "Microsoft.Tips",
    "TuneInRadio",
    "WinZipUniversal",
    "flaregamesGmbH.RoyalRevolt",
    "CandyCrush",
    "MarchofEmpires",
    "Plex",
    "Viber",
    "iHeartRadio",
    # OEM vendor appx bundles — entire publisher prefixes: all 21 HP apps
    # (SupportAssistant, JumpStarts, QuickDrop, PowerManager, Welcome,
    # myHP, SureShieldAI, ...), all three Dell apps, both Lenovo entries
    # (Win11Debloat "optional" removals — consumer promo/support-ware)
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
    # Debloat-Win11 diff — remaining OEM utility suites (audio/RGB/
    # control-center promo ware) + Widgets platform runtime + the Start
    # 'experiences' companion feed host
    "WavesAudio", "DragonCenter", "MysticLight", "MSIAfterburner",
    "ROGLiveService", "ArmouryCrate", "MyASUS", "ASUSPCAssistant",
    "Razer", "LenovoUtility",
    "Microsoft.WidgetsPlatformRuntime", "Microsoft.StartExperiencesApp",
    # M365 companion suite promo (24H2) + stable Instagram (only the Beta
    # family was listed before)
    "Microsoft.M365Companions",
    "Facebook.Instagram",
    # TronScript Metro diff — dead/promo/game-demo Microsoft appx
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
    # Dead Microsoft products still shipped by images (Windows10Debloater
    # diff): Office Lens retired Jan 2021, Office.Todo.List folded into
    # Microsoft To Do, Wunderlist killed 2020 (6Wunderkinder publisher)
    "Microsoft.Office.Lens", "Microsoft.Office.Todo.List", "Wunderlist",
    # simeononsecurity diff: dead Windows Phone companion + promo
    # preinstalls (Fitbit Coach upsell, Keeper PM promo, Shazam, Xing).
    # Skipped: MicrosoftPowerBIForWindows (business tool), CAF9E577.Plex
    # (functional app, only that list removes it)
    "Microsoft.WindowsPhone", "Fitbit.FitbitCoach",
    "KeeperSecurityInc.Keeper", "ShazamEntertainmentLtd.Shazam",
    "XINGAG.XING",
    # ReviOS playbook diff: Take-a-Test secure browser, People host,
    # Surface Hub mail, and the New Outlook PWA package name (the
    # Microsoft.OutlookForWindows entry covers the other family name)
    "Microsoft.Windows.SecureAssessmentBrowser",
    "Microsoft.Windows.PeopleExperienceHost",
    "MicrosoftCorporationII.MailforSurfaceHub", "OutlookPWA",
    # W4RH4WK leftovers: Yandex preinstall, legacy Win10 feedback app,
    # dead Reading List, Paint 3D (deprecated UWP paint — classic
    # paint.exe is a different binary and unaffected)
    "A025C540.Yandex.Music", "Microsoft.WindowsFeedback",
    "Microsoft.MicrosoftReadingList", "Microsoft.MSPaint",
    # xd-AntiSpy DebloaterPlugin diff: OEM promo/collection stubs and
    # third-party promo preinstalls (publisher-needle form — family names
    # embed the vendor id so substring needles stay safe)
    "HPJumpStart", "ASUSGiftBox", "AcerCollection",
    "DellDigitalDelivery", "DellSupportAssist",
    "GAMELOFTSA", "KhanAcademy", "AsanaInc.Asana", "Luminar",
    "DropboxInc.Dropbox", "TripAdvisor", "Uber",
    "WildTangent", "SaferVPN", "SymantecCorporation",
    "BethesdaSoftworks.FalloutShelter",
    "Microsoft.Advertising",
]


def _atomic_write_text(path: Path, text: str) -> None:
    """Write `text` to `path` via a same-dir temp file + os.replace — a
    crash mid-write can't leave a truncated/corrupt destination."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


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
                # Xbox/Troubleshooter framework packages the broad
                # "Microsoft.Xbox"/"Microsoft.GetHelp" blacklist prefixes
                # would otherwise hit — removing them breaks the Store,
                # Photos, some games, and speech-to-text overlay
                # (Win11Debloat "unsafe" list)
                "Microsoft.Xbox.TCUI",
                "Microsoft.XboxIdentityProvider",
                "Microsoft.XboxSpeechToTextOverlay",
                "Microsoft.GetHelp",
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
                "DisableModernStandbyNetworking": False,
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
                # Layers added post-merge — keep defaults in parity with
                # config.json so a fresh install (no file) runs them too
                "MarkDeprovisioned": True,
                "RemoveDefaultStorePackages": True,
                "BlockTelemetryEndpoints": True,
                "WingetSweep": True,
                "DisableTelemetryAutologgers": True,
            },
            "DryRun": False,
        }
        _atomic_write_text(path, json.dumps(config, indent=2, ensure_ascii=False))
        return config

    # utf-8-sig tolerates a BOM (Notepad saves UTF-8 with BOM by default)
    return json.loads(path.read_text(encoding="utf-8-sig"))


# ─── Helpers ─────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _relaunch_elevated(flag: str) -> None:
    """Re-run this script with `flag` elevated via UAC (C# `Verb="runas"`
    parity: install/uninstall self-elevate instead of failing outright)."""
    params = f'"{Path(__file__).resolve()}" {flag}'
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", str(Path(sys.executable).resolve()), params, None, 1)
    if rc <= 32:
        print(f"ERROR: elevation declined or failed (ShellExecute rc={rc}).")
        sys.exit(1)
    print(f"Elevation requested — '{flag}' is running in an elevated window.")


def run_powershell(cmd: str, timeout: int = 60) -> Tuple[str, str, int]:
    """Run a PowerShell command and return (stdout, stderr, exit_code).
    Missing binaries/hangs return rc=-1 instead of propagating."""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return "", str(e), -1
    # Windows console output is often CP932/Shift-JIS — use errors="replace" to avoid crashes
    stdout = proc.stdout.decode("cp932", errors="replace") if proc.stdout else ""
    stderr = proc.stderr.decode("cp932", errors="replace") if proc.stderr else ""
    return stdout.strip(), stderr.strip(), proc.returncode


def run_cmd(args, timeout: int = 30) -> Tuple[str, int]:
    # args may be a list (argv) or a raw command-line string — on Windows a
    # string is passed verbatim to CreateProcess, preserving vendor quoting.
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return str(e), -1
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
    """Public 3-tuple view (PackageFamilyName, Name, InstallPath) — kept for
    external callers (CI verification snippet unpacks 3 fields). The scan path
    uses _enum_blacklisted_packages which also carries PackageFullName."""
    return [(f, n, p) for f, n, p, _full in _enum_blacklisted_packages(blacklist, whitelist)]


def _enum_blacklisted_packages(blacklist: List[str], whitelist: List[str]) -> List[Tuple[str, str, str, str]]:
    """Return (PackageFamilyName, Name, InstallPath, PackageFullName) for
    packages matching blacklist. InstallPath is None for SystemApps (cannot be
    removed per-user); PackageFullName comes from the same query — no second
    PowerShell call per scan (C# GetBlacklistedPackages parity).
    Whitelisted packages are never returned, and IsFramework packages (dependency
    DLLs for other apps) are skipped. Enumerates -AllUsers when admin so packages
    installed for other profiles are caught too."""
    if not blacklist:
        return []

    scope = " -AllUsers" if is_admin() else ""
    ps_cmd = ("Get-AppxPackage" + scope +
              " | Select-Object PackageFamilyName,Name,InstallPath,IsFramework,PackageFullName | ConvertTo-Json")
    stdout, stderr, rc = run_powershell(ps_cmd, timeout=120)

    if rc != 0 or not stdout:
        return []

    # -AllUsers returns one row per user — dedupe by PackageFullName so two
    # coexisting versions of the same family both get removed (C# parity:
    # keyed on fullName; fall back to family when full_name is empty).
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
            full_name = pkg.get("PackageFullName", "")
            key = full_name or family
            if bool(pkg.get("IsFramework")) or key in seen:
                continue
            if is_target_package(family, blacklist, whitelist):
                seen.add(key)
                results.append((family, name, install_path, full_name))
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


def remove_appx_package(package_full_name: str) -> bool:
    if not _safe_pkg_name(package_full_name):
        return False
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
            # Interpolated into a PowerShell string — reject anything outside
            # the package-name charset before it can break the quoting.
            if not _safe_pkg_name(name):
                logger.warning(f"Ledger entry with unsafe name skipped: {name!r}")
                manual += 1
                continue
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
        elif entry.get("kind") == "winget" and name:
            if (not _WINGET_ID_RE.fullmatch(name)
                    or shutil.which("winget") is None):
                manual += 1
                continue
            _, rc = run_cmd(
                ["winget", "install", "-e", "--id", name, "--silent",
                 "--disable-interactivity", "--accept-source-agreements",
                 "--accept-package-agreements"], timeout=300)
            if rc == 0:
                logger.info(f"Restored via winget: {name}")
                restored += 1
            else:
                logger.warning(f"winget restore failed: {name}")
                manual += 1
        elif entry.get("kind") == "capability" and name:
            if not _safe_pkg_name(name):
                logger.warning(f"Ledger entry with unsafe name skipped: {name!r}")
                manual += 1
                continue
            _, _, rc = run_powershell(
                f"Add-WindowsCapability -Online -Name '{name}' "
                "-ErrorAction SilentlyContinue | Out-Null", timeout=180)
            if rc == 0:
                logger.info(f"Restored capability: {name}")
                restored += 1
            else:
                logger.warning(f"Capability restore failed: {name} "
                               "(Settings → Optional features)")
                manual += 1
        elif entry.get("kind") == "provisioned" and name:
            # The provisioned payload may still exist for another user —
            # try the same re-register path before declaring it manual.
            if not _safe_pkg_name(name):
                logger.warning(f"Ledger entry with unsafe name skipped: {name!r}")
                manual += 1
                continue
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
                logger.info(
                    f"Manual restore needed: {name or entry.get('family', '?')} "
                    f"(provisioned — reinstall via Microsoft Store or Settings)")
                manual += 1
        else:
            logger.info(
                f"Manual restore needed: {name or entry.get('family', '?')} "
                f"(kind={entry.get('kind', '?')} — reinstall via the app vendor or Settings)")
            manual += 1

    logger.info(f"Restore complete: {restored} restored, {manual} need manual reinstall.")
    return 0


def remove_provisioned_package(package_name: str) -> bool:
    if not _safe_pkg_name(package_name):
        return False
    # Caller supplies the exact PackageName — no second PowerShell lookup needed
    ps_cmd = (
        f"Remove-AppxProvisionedPackage -Online "
        f"-PackageName '{package_name}' -ErrorAction SilentlyContinue"
    )
    # 120s — provisioned removal is a servicing op (parity: C# 120000ms)
    _, _, rc = run_powershell(ps_cmd, timeout=120)
    return rc == 0


def remove_optional_capabilities(logger: logging.Logger,
                                 config: dict = None) -> bool:
    """Remove deprecated/legacy optional capabilities (IE mode, Steps Recorder,
    WordPad). Requires admin; non-present entries are skipped by PowerShell.
    Removed names go to the removal ledger — `--restore` reinstalls them via
    Add-WindowsCapability."""
    pattern = ("Browser.InternetExplorer|App.StepsRecorder|"
               "Microsoft.Windows.WordPad|XPS.Viewer|Print.Fax.Scan|"
               "App.WirelessDisplay.Connect")
    query = ("Get-WindowsCapability -Online | Where-Object "
             f"{{$_.Name -match '{pattern}' -and $_.State -eq 'Installed'}}")
    out, _, _ = run_powershell(
        f"{query} | Select-Object -ExpandProperty Name", timeout=60)
    names = [n.strip() for n in (out or "").splitlines()
             if _safe_pkg_name(n.strip())]
    _, _, rc = run_powershell(
        f"{query} | Remove-WindowsCapability -Online "
        "-ErrorAction SilentlyContinue | Out-Null", timeout=180)
    if rc == 0:
        # Remove-WindowsCapability may fail per-item even with rc=0 — re-query
        # and only ledger capabilities that are actually gone so restore
        # does not reinstall ones never removed (Devin Review)
        out2, _, _ = run_powershell(
            f"{query} | Select-Object -ExpandProperty Name", timeout=60)
        remaining = {n.strip() for n in (out2 or "").splitlines()}
        removed = [n for n in names if n not in remaining]
        if config is not None:
            for n in removed:
                record_removal(config, {"kind": "capability", "name": n})
        logger.info("Applied: RemoveOptionalCapabilities "
                    f"({len(removed)}/{len(names)} capabilities removed)")
    else:
        logger.warning("RemoveOptionalCapabilities: no capabilities removed "
                       "(absent or admin required)")
    return rc == 0


# ─── Win32 program removal (non-Appx OEM bloatware) ──────────────────────────

# DisplayName needles checked alongside the blacklist in the Win32 uninstall
# scan — appx-style publisher prefixes (DellInc., AD2F1837.) never appear in
# DisplayName strings, so OEM support-ware and PUA optimizers need their own
# product names. Sources: TronScript programs_to_target_by_name (PUA/adware
# canon), winutil, Win11Debloat. Vendor-bare names (HP, Dell, Lenovo) are
# deliberately absent — substrings would false-positive on utilities
# ("HP" is inside "Touchpad").
_WIN32_BLOAT_NAMES = (
    # OEM support-ware / promo updaters still shipping today
    "SupportAssist", "HP Support Assistant", "HP JumpStart", "MyASUS",
    "Acer Collection", "MSI Center", "Dragon Center", "Armoury Crate",
    "ArmouryCrate", "Nahimic", "Killer Intelligence", "BlueStacks",
    "Wondershare",
    # HP serviceware channel (Spiceworks HP-debloat canon): connection
    # optimizer, docs/notifications pushers, update/resilience services.
    # HP Wolf Security (real AV) deliberately excluded.
    "HP Connection Optimizer", "HP Documentation", "HP Notifications",
    "HP Security Update Service", "HP Sure Recover", "HP Sure Run Module",
    # PUA "optimizer"/driver-updater tier pushed via ads
    "IObit", "Advanced SystemCare", "Driver Booster", "DriverBooster",
    "Driver Easy", "DriverEasy", "DriverUpdate", "Driver Tonic",
    "Win Tonic", "PCVARK", "Systweak", "RegClean", "SlimWare",
    "SlimCleaner", "Outbyte", "Restoro", "PCRepair", "PC Repair",
    "PC Cleaner", "SpeedUpMyPC", "OneSafe", "WinZip Driver",
    "DriverDoc", "TotalAV", "ScanGuard", "PCProtect", "PC Health",
    "McAfee Security Scan",
    # Legacy adware/toolbar canon — dead weight where still installed
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
)


_UNINSTALL_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_UNINSTALL_PATH32 = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
_USER_UNINSTALL_PATH = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
_MSI_GUID_RE = re.compile(r"\{[0-9A-Fa-f\-]{36}\}")


def get_blacklisted_win32(blacklist, whitelist):
    """Enumerate installed Win32 programs (HKLM 64/32, HKCU + loaded user hives)
    whose DisplayName matches the blacklist. Returns (display, uninstall,
    quiet, user_hive). user_hive entries are report-only: HKU\\<sid> is
    user-writable, so an elevated service must never execute strings a
    non-admin user could plant there."""
    import winreg  # Windows-only

    results, seen = [], set()

    def _scan(root, path, user_hive=False):
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
                    with winreg.OpenKey(key, sub) as sk:
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
                        if not is_target_package(
                                display, blacklist + list(_WIN32_BLOAT_NAMES),
                                whitelist):
                            continue
                        if display.lower() not in seen:
                            seen.add(display.lower())
                            results.append((display, uninstall, quiet, user_hive))
                except OSError:
                    continue
        finally:
            key.Close()

    _scan(winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_PATH)
    _scan(winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_PATH32)
    # HKCU maps to the *caller's* hive: under an elevated interactive run
    # that's the invoking (non-admin-origin) user — a user-writable hive
    # whose uninstall strings must never execute with our admin token.
    # Report-only, same rule as HKU\<sid>.
    _scan(winreg.HKEY_CURRENT_USER, _USER_UNINSTALL_PATH, user_hive=True)
    try:
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(winreg.HKEY_USERS, i)
                i += 1
            except OSError:
                break
            if re.match(r"^S-1-5-21-\d+-\d+-\d+-\d+$", sid):
                _scan(winreg.HKEY_USERS, sid + "\\" + _USER_UNINSTALL_PATH,
                      user_hive=True)
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
        # Raw command line — whitespace-splitting args would mangle quoted
        # paths (C# hands the args string to CreateProcess verbatim).
        argv = f'"{cmd}" {args}'.rstrip()
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
         "Enable-ComputerRestore -Drive \"$env:SystemDrive\\\" -ErrorAction SilentlyContinue | Out-Null; "
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


def set_registry_string(hive, path: str, name: str, value: str) -> bool:
    """Set a REG_SZ value in the registry. hive = 'HKLM' or 'HKCU'."""
    try:
        import winreg
        root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
        key = winreg.CreateKeyEx(root, path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
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
# Machine-wide Explorer policies hive (HKLM side of _USER_EXPLORER_POLICIES)
_EXPLORER_POLICIES_HKLM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
# Language-list leak to websites (documented in Sophia Script)
_USER_INTL_PROFILE = r"Control Panel\International\User Profile"
_USER_COPILOT = r"Software\Policies\Microsoft\Windows\WindowsCopilot"
_USER_WINDOWS_AI = r"Software\Policies\Microsoft\Windows\WindowsAI"
_USER_COPILOT_KEYBOARD = r"Software\Policies\Microsoft\CopilotKeyboard"
_USER_SHELL_COPILOT = r"Software\Microsoft\Windows\Shell\Copilot"
_USER_SHELL_COPILOT_BINGCHAT = r"Software\Microsoft\Windows\Shell\Copilot\BingChat"
_USER_VOICE_ACTIVATION = (r"Software\Microsoft\Speech_OneCore\Settings"
                          + r"\VoiceActivation\UserPreferenceForAllApps")
_USER_CLICK_TO_DO = r"Software\Microsoft\Windows\Shell\ClickToDo"
_USER_RECALL = r"Software\Microsoft\Windows\CurrentVersion\Recall"
# Feature-management velocity overrides (community-verified IDs — e.g.
# zoicware/RemoveWindowsAI). EnabledState: 0=default, 1=disabled, 2=enabled.
_VELOCITY_PATH = r"SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\8"
_VELOCITY_COPILOT_IDS = (
    # Copilot nudges + taskbar + systray
    ("1546588812", 1), ("203105932", 1), ("2381287564", 1),
    ("3389499533", 1), ("4027803789", 1),
)
_VELOCITY_AI_IDS = (
    # AI Actions in Explorer; 1646260367 hides the entry when no action exists
    ("1853569164", 1), ("4098520719", 1), ("929719951", 1), ("1646260367", 2),
    # Additional AI velocity IDs (DebloatAndSecurizeW11 / phantomofearth
    # velocity feature lists)
    ("3189581453", 1), ("3552646797", 1), ("450471565", 1),
    # FeatureId 58375086 -> regID 1561856655 via zoicware's
    # ObfuscateFeatureId — disables the Explorer-side feature that
    # depends on AIFabric (zoicware #236/#238 Explorer-ribbon fix)
    ("1561856655", 1),
)
_USER_SEARCH = r"Software\Microsoft\Windows\CurrentVersion\Search"
_USER_SEARCH_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\SearchSettings"
_USER_PROFILE_ENGAGEMENT = r"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"
_USER_ACCOUNT_NOTIFICATIONS = r"Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications"
_USER_SUGGESTED_TOAST = (r"Software\Microsoft\Windows\CurrentVersion"
                         r"\Notifications\Settings\Windows.SystemToast.Suggested")
_USER_MOBILITY = r"Software\Microsoft\Windows\CurrentVersion\Mobility"
_USER_OUTLOOK_MIGRATION = (r"Software\Policies\Microsoft\Office\16.0"
                           r"\Outlook\Options\General")
_USER_OUTLOOK_PREFERENCES = (r"Software\Policies\Microsoft\Office\16.0"
                             r"\Outlook\Preferences")
_USER_NOTIFICATION_SETTINGS = (r"Software\Microsoft\Windows\CurrentVersion"
                               r"\Notifications\Settings")
_USER_ADVERTISING_INFO = r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
_USER_PRIVACY = r"Software\Microsoft\Windows\CurrentVersion\Privacy"
_USER_PRIVACY_POLICIES = r"Software\Policies\Microsoft\Windows\Privacy"
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
    # First-party promo suites + OEM utilities that re-register autostart
    "Teams", "YourPhone", "PhoneLink", "Xbox", "EdgeUpdate",
    "Armoury", "Nahimic",
    # Promo-installed third parties (markers are re-enableable, so a
    # deliberate install can re-enable from Task Manager)
    "Spotify", "Opera", "Adobe", "iTunes",
    # PUA-tier "optimizers"/driver updaters commonly pushed by OEMs/ads
    "IObit", "DriverBooster", "DriverEasy", "SlimWare", "Outbyte",
    "Restoro", "Wondershare", "PCHealth",
    # Razer utilities (Debloat-Win11 OEM purge) — "Synapse" is not a
    # substring of "Synaptics", so pointing-device entries stay safe
    "Razer", "Synapse", "Cortex",
    # Peripheral-vendor control suites — same class as Armoury/Nahimic
    # (WinOpt startup audit); marker-based disable is reversible
    "Corsair", "SteelSeries", "Logitech",
    # Browser-hijacker/adware PUPs + PUA optimizers (et-optimizer Run-purge
    # list); functional tools (TeamViewer) and system-name lookalikes
    # (searchapp.exe) are left out
    "ASCTray", "BabylonToolbar", "CoolWebSearch", "Crossrider",
    "DriverMax", "FunWebProducts", "MediaNewTab", "MyWebSearch",
    "PCOptimizerPro", "RelevantKnowledge", "SAntivirus", "Segurazo",
    "ShopperPro", "SlimDrivers", "SuperOptimizer", "SweetPacks",
    "UpdatePPShortCut", "Vosteran", "WebCompanion",
    "WinZipDriverUpdater",
)
# 0x03 = disabled in StartupApproved (value kept — re-enableable via Task Manager)
_STARTUP_DISABLED_MARKER = b"\x03" + b"\x00" * 11

# HKLM subkey used to temporarily mount the Default-profile template hive
_DEFAULT_HIVE_MOUNT = "BloatwareGuard_DefaultProfile"

# Real user profile SIDs only — excludes .DEFAULT, service accounts
# (S-1-5-18/19/20) and *_Classes virtual hives
_USER_SID_RE = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$")

# Package names are simple identifiers (Name_ver_arch_resid_pubid) — anything
# else is rejected before it can reach a PowerShell string.
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-~!]+$")

# winget package ids: Publisher.Name only
_WINGET_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _safe_pkg_name(name: str) -> bool:
    return bool(name) and bool(_PKG_NAME_RE.fullmatch(name))


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
        _, rc = run_cmd(["reg.exe", "load", f"HKLM\\{_DEFAULT_HIVE_MOUNT}", dat], timeout=15)
        if rc == 0:
            try:
                apply(winreg.HKEY_LOCAL_MACHINE, _DEFAULT_HIVE_MOUNT)
                applied += 1
            except Exception as e:
                logger.warning(f"Registry: default profile hive skipped: {e}")
            finally:
                run_cmd(["reg.exe", "unload", f"HKLM\\{_DEFAULT_HIVE_MOUNT}"], timeout=15)

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
    r"SOFTWARE\AMD\CN",
    r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
    r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
    r"SOFTWARE\Policies\Microsoft\Windows\AppCompat",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
    r"SOFTWARE\Policies\Microsoft\Dsh",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    r"SOFTWARE\Policies\Microsoft\Windows\System",
    r"SOFTWARE\Microsoft\SQMClient",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
    r"SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy",
    r"SOFTWARE\Policies\Microsoft\Windows\CredUI",
    r"SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics",
    r"SOFTWARE\Policies\Microsoft\Windows\Troubleshooting\AllowRecommendations",
    r"SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy",
    r"SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
    r"SOFTWARE\Policies\Microsoft\Assistance\Client\1.0",
    r"SOFTWARE\Policies\Microsoft\Edge",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry",
    r"SOFTWARE\Microsoft\WindowsMitigation",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\DevDrive",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss",
    r"SOFTWARE\Policies\Microsoft\FVE",
    r"SOFTWARE\Policies\Microsoft\Windows\GameDVR",
    r"SOFTWARE\Policies\Microsoft\InputPersonalization",
    r"SOFTWARE\Policies\Microsoft\PenTraining",
    r"SOFTWARE\Policies\Microsoft\TabletPC",
    r"SOFTWARE\Policies\Microsoft\Internet Explorer",
    r"SOFTWARE\Policies\Microsoft\Windows\ShareSheet",
    r"SOFTWARE\Policies\Microsoft\Windows\TextInput",
    r"SOFTWARE\Policies\Microsoft\Windows\IME",
    r"SOFTWARE\Policies\Microsoft\Windows\AI\Copilot",
    r"SOFTWARE\Policies\Microsoft\Windows\LanguageOptions",
    r"SYSTEM\CurrentControlSet\Control\CrashControl",
    r"SOFTWARE\Policies\Microsoft\Windows\SpellingAndTyping",
    r"SOFTWARE\Policies\Microsoft\Windows\SuperFetch",
    r"SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics",
    r"SOFTWARE\Policies\Microsoft\Windows\MachineLearning",
    r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
    r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
    r"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
    r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
    r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife",
    r"SOFTWARE\Microsoft\OneDrive",
    r"SOFTWARE\Microsoft\Windows\Shell\Copilot",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
    r"SOFTWARE\NVIDIA Corporation\Global\FTS",
    r"SOFTWARE\Policies\Microsoft\Copilot",
    r"SOFTWARE\Policies\Microsoft\EdgeUpdate",
    r"SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup",
    r"SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\Global\Startup",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\systemAIModels",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\generativeAI",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunNotification",
    r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes",
    r"SOFTWARE\Policies\Microsoft\Peernet",
    r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation",
    r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
    r"SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config",
    r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars",
    r"SOFTWARE\Policies\Microsoft\Windows\Appx",
    r"SOFTWARE\Policies\Microsoft\Windows\Appx"
    r"\RemoveDefaultMicrosoftStorePackages",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass",
    r"SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService",
    r"SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting",
    r"SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc",
    r"SOFTWARE\Policies\Microsoft\Speech",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
    r"SOFTWARE\Policies\Microsoft\Windows\Bowser",
    r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings",
    r"SOFTWARE\Policies\Microsoft\Windows\LLTD",
    r"SOFTWARE\Policies\Microsoft\Windows\Messaging",
    r"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider",
    r"SOFTWARE\Policies\Microsoft\Windows\WDI\{9C5A40DA-B965-4FC3-8781-88DD50A6299D}",
    r"SOFTWARE\Policies\WindowsNotepad",
    r"SYSTEM\CurrentControlSet\Control\Diagnostics\Performance",
    r"SYSTEM\CurrentControlSet\Control\Lsa",
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",
    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    r"SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput",
    r"SOFTWARE\Microsoft\Input\Settings",
    r"SOFTWARE\Microsoft\Input\TIPC",
    r"SOFTWARE\Microsoft\WcmSvc",
    r"SOFTWARE\Microsoft\PolicyManager\default\WiFi",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    r"SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS",
    r"SOFTWARE\Policies\Microsoft\Internet Explorer\SQM",
    r"SOFTWARE\Policies\Microsoft\Internet Explorer\Main",
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Chat",
    r"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener",
    r"SYSTEM\CurrentControlSet\Control\Session Manager",
    r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
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
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsBackup",
    r"SOFTWARE\Policies\Microsoft\Windows\Backup",
    r"SOFTWARE\Policies\Microsoft\Windows\BITS",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
    r"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
    # --- coverage completion (audit: every HKLM write path backed up) ---
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient",
    r"SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId",
    r"SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility",
    r"SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate",
    r"SOFTWARE\Microsoft\WindowsUpdate\Orchestrator",
    r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
    r"SYSTEM\Setup\UpgradeNotification",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Communications",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
    r"SOFTWARE\Policies\Microsoft\Windows\DriverSearching",
    r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate",
    r"SOFTWARE\Microsoft\Windows\Shell",
    r"SOFTWARE\Policies\Microsoft\AppV\CEIP",
    r"SOFTWARE\Policies\Microsoft\EventViewer",
    r"SOFTWARE\Policies\Microsoft\Messenger\Client",
    r"SOFTWARE\Policies\Microsoft\Power\PowerSettings",
    r"SOFTWARE\Policies\Microsoft\PushToInstall",
    r"SOFTWARE\Policies\Microsoft\SQMClient\Windows",
    r"SOFTWARE\Policies\Microsoft\Teams",
    r"SOFTWARE\Policies\Microsoft\Windows NT\Printers",
    r"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer",
    r"SOFTWARE\Policies\Microsoft\WindowsStore",
    r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
    r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    r"SOFTWARE\Policies\Microsoft\Windows\EdgeUI",
    r"SOFTWARE\Policies\Microsoft\OneDrive",
    r"SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin",
    r"SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports",
    r"SOFTWARE\Policies\Microsoft\Windows\Maps",
    r"SOFTWARE\Policies\Microsoft\Windows\OneSettings",
    r"SOFTWARE\Policies\Microsoft\Windows\TabletPC",
    r"SOFTWARE\Policies\Microsoft\WindowsNotepad",
    r"SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\8",
    r"SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume",
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
    r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
    r"SOFTWARE\Policies\Microsoft\Notepad",
    r"SOFTWARE\Policies\Microsoft\Windows\OOBE",
)
_registry_backup_done = False

# Demand-start (Start=3) — all stay usable when actually invoked.
_MISC_DEMOTE_SERVICES = (
    "dmwappushservice", "MapsBroker", "WMPNetworkSvc",
    "diagnosticshub.standardcollector.service",
    "CDPSvc", "NvTelemetryContainer",
    "esrv_svc", "ESRV_SVC_QUEENCREEK",
    # Intel Dynamic Tuning telemetry + Innovation Platform Framework
    # service (vendor telemetry — coolvitto 25H2 service list)
    "dptftcs", "ipfsvc",
    # Intel DAL host (jhi) / Local Mgmt Service (LMS) / Graphics Command
    # Center + control-panel services (vendor background — WindowsMize)
    "jhi_service", "LMS", "igccservice", "igfxCUIService2.0.0.0",
    "cplspcon", "cphs",
    # Copilot Elevation Service — lets the Copilot app request elevated
    # operations (zoicware/RemoveWindowsAI; demoted, not deleted)
    "MicrosoftCopilotElevationService",
    # Agent Activation Runtime — Copilot/voice-agent activation host
    # (zoicware removes it; demote keeps the service restorable)
    "AarSvc",
    # Cloud-clipboard sync service + Windows Push Notification user
    # service (privacy.sexy per-user service kills — cloud sync and WNS
    # push channel); Manual keeps on-demand starts working
    "cbdhsvc", "WpnUserService",
    # AMD logging service + SSDP network-discovery service (vendor
    # telemetry / discovery attack surface — nova + titanium lists)
    "amdlog", "SsdpDiscovery",
    # Waves MaxxAudio service — OEM audio suite background daemon
    # (SysAdminDoc/Debloat-Win11 OEM module)
    "WavesSvc64",

    "PushToInstall", "SEMgrSvc", "PhoneSvc",
    "utcsvc",                 # Connected User Experiences and Telemetry
                              # (DiagTrack companion — registry demote works
                              # where sc config is refused)
    "SysMain", "TabletInputService",
    "WSearch",                # indexer — resident file scan
    "AssignedAccessManagerSvc",  # kiosk assigned-access
    "DusmSvc",                # data-usage metering
    # Per-user service templates for Mail/People/contacts sync — dead
    # weight once those apps are removed
    "CDPUserSvc", "OneSyncSvc", "UnistoreSvc",
    "UserDataSvc", "PimIndexMaintenanceSvc",
    # OneDrive FileSyncHelper — companion sync service to OneSyncSvc
    # (WinOpt) — demoted, not disabled
    "FileSyncHelper",
    # Diagnostic Service Host pair — WDI diagnostics sessions
    "WdiSystemHost", "WdiServiceHost",
    # Diagnostic Policy Service + Diagnostic Execution Service — both
    # Automatic by default; Manual keeps on-demand diagnostics working
    "DPS", "diagsvc",
    # Data Collection and Publishing Service — feeds the diagnostic
    # ingest pipeline
    "DcpSvc",
    "PcaSvc",                 # Program Compatibility Assistant
    # Microsoft Pay (dead), Windows Insider, Mixed Reality, AllJoyn,
    # smart card triad
    "WalletService", "wisvc",
    "SharedRealitySvc", "perceptionsimulation", "Spectrum",
    # Mixed Reality OpenXR runtime — dead stack once VR/MR unused
    # (Trachti/windows-debloat Balanced tier)
    "MixedRealityOpenXRSvc",
    # Legacy Fax service — fax feature already in the capability
    # kill list (Trachti/windows-debloat)
    "Fax",
    "AJRouter", "SCardSvr", "ScDeviceEnum", "CertPropSvc",
    # Location tracking + sensor monitoring stack — SensorDataService
    # aggregates sensor feeds for apps (Win-Debloat7 services.json)
    "lfsvc", "SensorService", "sensrsvc", "SensorDataService",
    # SNMP traps (dead), recommended-troubleshooting runner, cellular WWAN
    # (demand-start keeps LTE working)
    "SNMPTRAP", "TroubleshootingSvc", "WwanSvc", "WwanAuthSvc",
    # Storage settings service + Offline Files (Client Side Caching —
    # legacy enterprise sync, dead weight on consumer installs)
    "StorSvc", "CscService",
    # Windows AI Fabric service — feeds Copilot+ AI APIs; demand-start
    # keeps apps working without the resident listener (Win11Debloat
    # DisableAISvcAutoStart / winutil)
    "WSAIFabricSvc",
    # Win-Debloat services.json diff: AI-fabric user-side listeners —
    # model catalog, semantic-search orchestration, Recall narrative
    # flow, OneSettings pull client
    "AIFabricUserSvc", "ModelCatalogUserSvc",
    "SemanticSearchUserSvc", "NarrativeFlows",
    "OneSettingsClientUserSvc",
    # Windows Health and Optimized Experiences — ships the PC-health /
    # optimizer suggestion feed (coolvitto 25H2 service list)
    "whesvc",
    # Distributed Link Tracking — NTFS cross-volume link chasing,
    # Microsoft 'OK to disable' per IoT/VDI guidance (Atlas services.yml)
    "TrkWks",
    # VDOT services.json diff: GameDVR broadcast per-user template,
    # cellular time sync, SMS router, Internet Connection Sharing —
    # demand-start keeps invocation working
    "BcastDVRUserService", "autotimesvc", "SmsRouter", "icssvc",
    "SharedAccess",
    # WER control-panel support — companion to the disabled WerSvc
    # (Atlas services.yml; the error-report pipeline is already off)
    "wercplsupport",
    # Desktop Activity Moderator (user-activity monitoring driver),
    # Intel telemetry driver, Event Collector — all disabled by ReviOS
    "dam", "Telemetry", "Wecsvc",
    # NetBIOS-over-TCP/IP — legacy LAN name protocol; pairs with the
    # LLMNR kill in DisableTelemetry (Atlas services.yml)
    "NetBT", "lmhosts",
    # Debloat-Win11 services diff — app-inventory appraisal (same
    # AppCompat pipeline as the killed policies), parental-controls
    # monitor (pairs with the FamilySafety task kills), Phone-Link
    # messaging backend (app is blacklisted), Game Pass runtime pair
    "InventorySvc", "WpcMonSvc", "MessagingService",
    "GamingServices", "GamingServicesNet",
    # Agent-isolation broker — hosts experimental agentic-AI sandboxed
    # runs (zoicware/RemoveWindowsAI); demand-start keeps invocation
    # working without the resident service
    "IsoEnvBroker",
)


_EXTRA_BACKUP_SERVICES = (
    # Services demoted/disabled by name outside _MISC_DEMOTE_SERVICES —
    # their Services\<name> keys are exported too so the original
    # Start/config survives in the backup net.
    "DiagTrack", "RetailDemo", "WerSvc", "Spooler", "RemoteRegistry",
    "DoSvc", "edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService",
    "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc",
)


_USER_BACKUP_KEY_PATHS = (
    # Per-user key paths written through for_each_user_hive /
    # set_user_dword_all_hives — exported under every loaded
    # interactive SID (and HKCU) by backup_registry_keys.
    r"Control Panel\International\User Profile",
    r"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer",
    r"Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
    r"Software\Microsoft\Clipboard",
    r"Software\Microsoft\GameBar",
    r"Software\Microsoft\Input\Settings",
    r"Software\Microsoft\Input\TIPC",
    r"Software\Microsoft\InputPersonalization",
    r"Software\Microsoft\InputMethod\Settings\CHS",
    r"Software\Microsoft\InputPersonalization\TrainedDataStore",
    r"Software\Microsoft\Narrator\NoRoam",
    r"Software\Microsoft\Personalization\Settings",
    r"Software\Microsoft\Siuf\Rules",
    r"Software\Microsoft\Speech_OneCore\Preferences",
    r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy",
    r"Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps",
    r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
    r"Software\Microsoft\Windows\CurrentVersion\CDP",
    r"Software\Microsoft\Windows\CurrentVersion\M365Copilot",
    r"Software\Policies\Microsoft\Windows\CopilotKey",
    r"Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage",
    r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
    r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Context\CloudExperienceHostIntent\Wireless",
    r"Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings",
    r"Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings",
    r"Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers",
    r"Software\Microsoft\Windows\CurrentVersion\Feeds",
    r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
    r"Software\Microsoft\Windows\CurrentVersion\Mobility",
    r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
    r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    r"Software\Microsoft\Windows\CurrentVersion\Privacy",
    r"Software\Microsoft\Windows\CurrentVersion\PublishUserActivities",
    r"Software\Microsoft\Windows\CurrentVersion\Recall",
    r"Software\Microsoft\Windows\CurrentVersion\Search",
    r"Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization",
    r"Software\Microsoft\Windows\CurrentVersion\UploadUserActivities",
    r"Software\Microsoft\Windows\CurrentVersion\SearchSettings",
    r"Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchPro",
    r"Software\Microsoft\Windows\CurrentVersion\A9\SnapshotCapture",
    r"Software\Microsoft\Windows\CurrentVersion\WindowsCopilot",
    r"Software\Microsoft\Windows\CurrentVersion\WindowsBackup",
    r"Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs",
    r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
    r"Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel",
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",
    r"Software\Microsoft\Notepad",
    r"Software\Microsoft\Paint",
    r"Software\Microsoft\Windows\CurrentVersion\Photos",
    r"Software\Microsoft\Windows\CurrentVersion\SettingSync",
    r"Software\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers",
    r"Software\Microsoft\Windows\CurrentVersion\Start\Companions\Microsoft.YourPhone_8wekyb3d8bbwe",
    r"Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications",
    r"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement",
    r"Software\Microsoft\Windows\Shell\ClickToDo",
    r"Software\Microsoft\Windows\Shell\Copilot",
    r"Software\Microsoft\Windows\Shell\Copilot\BingChat",
    r"Software\Microsoft\Windows\Windows Error Reporting",
    r"Software\NVIDIA Corporation\NVControlPanel2\Client",
    r"Software\Policies\Microsoft\Assistance\Client\1.0",
    r"Software\Policies\Microsoft\Office\16.0\Outlook\Options\General",
    r"Software\Policies\Microsoft\Office\16.0\Outlook\Preferences",
    r"Software\Policies\Microsoft\Windows\CloudContent",
    r"Software\Policies\Microsoft\Windows\EdgeUI",
    r"Software\Policies\Microsoft\InputPersonalization",
    r"Software\Policies\Microsoft\TabletPC",
    r"Software\Policies\Microsoft\PenTraining",
    r"Software\Policies\Microsoft\Internet Explorer",
    r"Software\Policies\Microsoft\Control Panel\International",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    r"Software\Policies\Microsoft\Windows\Windows Error Reporting",
    r"Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
    r"Software\Policies\Microsoft\Windows\Explorer",
    r"Software\Policies\Microsoft\Windows\Privacy",
    r"Software\Policies\Microsoft\Windows\WindowsAI",
    r"Software\Policies\Microsoft\Windows\WindowsCopilot",
    r"Software\Policies\Microsoft\CopilotKeyboard",
    r"Software\Policies\Microsoft\OneDrive",
    r"Software\Policies\Microsoft\Windows\WorkplaceJoin",
    r"System\GameConfigStore",
    r"Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration",
    r"Software\Policies\Microsoft\Windows\WindowsNotepad",
)


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
                     os.path.join(backup_dir, f"{stamp}-{i}.reg"), "/y"],
                    timeout=15)
        # Per-user keys — export under each loaded interactive SID and HKCU so
        # the same safety net covers user-scope writes (the bulk of the knobs).
        roots = ["HKCU"]
        try:
            import winreg
            sids = [winreg.EnumKey(winreg.HKEY_USERS, i)
                    for i in range(winreg.QueryInfoKey(winreg.HKEY_USERS)[0])]
            roots += [f"HKU\\{sid}" for sid in sids if _USER_SID_RE.match(sid)]
        except Exception:
            pass
        for svc in _MISC_DEMOTE_SERVICES + _EXTRA_BACKUP_SERVICES:
            run_cmd(["reg.exe", "export",
                     f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc}",
                     os.path.join(backup_dir, f"{stamp}-s{i}.reg"), "/y"],
                    timeout=15)
            i += 1
        j = 0
        for root in roots:
            for path in _USER_BACKUP_KEY_PATHS:
                run_cmd(["reg.exe", "export", f"{root}\\{path}",
                         os.path.join(backup_dir, f"{stamp}-u{j}.reg"), "/y"],
                        timeout=15)
                j += 1
        logger.info(f"Applied: BackupRegistry ({len(_BACKUP_KEY_PATHS)} HKLM + "
                    f"{len(_USER_BACKUP_KEY_PATHS)}x{len(roots)} user keys -> {backup_dir})")
    except OSError as e:
        logger.warning(f"BackupRegistry skipped: {e}")


def apply_registry_prevention(config: dict, logger: logging.Logger):
    import winreg
    prev = config.get("Prevention", {})

    if prev.get("BackupRegistry", True):
        try:
            backup_registry_keys(logger)

        except Exception as e:
            logger.warning(f"BackupRegistry layer failed: {e}")
    cloud_content = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"

    if prev.get("DisableConsumerExperiences", True):
        try:
            if set_registry_dword("HKLM", cloud_content, "DisableWindowsConsumerFeatures", 1):
                logger.info("Applied: DisableWindowsConsumerFeatures = 1")
            # "Edit with Clipchamp" context-menu entry — CLSID block
            # (CrapFixer): Clipchamp is blacklisted, drop its shell
            # integration remnant too
            set_registry_string(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\Shell Extensions\Blocked",
                "{8AB635F8-9A67-4698-AB99-784AD929F3B4}",
                "RemoveClipchampContext")

        except Exception as e:
            logger.warning(f"DisableConsumerExperiences layer failed: {e}")
    if prev.get("DisableCloudContent", True):
        try:
            set_registry_dword("HKLM", cloud_content, "DisableSoftLanding", 1)
            set_registry_dword("HKLM", cloud_content, "DisableCloudOptimizedContent", 1)
            # Microsoft 365 / consumer-account content (Settings Home Copilot ads)
            set_registry_dword("HKLM", cloud_content,
                               "DisableConsumerAccountStateContent", 1)
            # Settings "Home" page — the Microsoft 365 / account promo card
            set_registry_string("HKLM", _EXPLORER_POLICIES_HKLM,
                                "SettingsPageVisibility",
                                "hide:home;aicomponents;appactions")
            # Third-party content suggestions surface (sponsored tiles/ads)
            set_registry_dword("HKLM", cloud_content, "DisableThirdPartySuggestions", 1)
            # Share-sheet app promotions off (25H2 ADMX ShareSheet —
            # Machine class only)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\ShareSheet",
                "DisableShareAppPromotions", 1)
            # App notifications must not show on the lock screen
            # (WinOpt) — documented CloudContent policy
            set_registry_dword("HKLM", cloud_content,
                               "DisableLockScreenAppNotifications", 1)
            # Machine-wide Windows Spotlight kill (documented policy
            # twin of the per-user CloudContent spotlight switches)
            set_registry_dword("HKLM", cloud_content,
                               "ConfigureWindowsSpotlight", 0)
            # Camera trigger removed from the lock screen (WinOpt) —
            # prevents unauthenticated camera activation; app camera
            # permissions untouched
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
                "NoLockScreenCamera", 1)
            logger.info("Applied: DisableSoftLanding + DisableCloudOptimizedContent = 1 "
                        "+ Settings Home promo page hidden")

        except Exception as e:
            logger.warning(f"DisableCloudContent layer failed: {e}")
    if prev.get("PreventDeviceMetadata", True):
        try:
            if set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
                                  "PreventDeviceMetadataFromNetwork", 1):
                logger.info("Applied: PreventDeviceMetadataFromNetwork = 1")

        except Exception as e:
            logger.warning(f"PreventDeviceMetadata layer failed: {e}")
    if prev.get("BlockProvisioning", True):
        try:
            set_registry_dword("HKLM", cloud_content, "DisableConsumerAccountContent", 1)
            # Open-With store nags: "Look for an app in the Store" + the
            # "new apps can open this file type" toast (HKLM Explorer policies)
            set_registry_dword("HKLM", _EXPLORER_POLICIES_HKLM, "NoUseStoreOpenWith", 1)
            set_registry_dword("HKLM", _EXPLORER_POLICIES_HKLM, "NoNewAppAlert", 1)
            # Open-With internet lookup + Settings-app online tips (content fetch)
            set_registry_dword("HKLM", _EXPLORER_POLICIES_HKLM, "NoInternetOpenWith", 1)
            set_registry_dword("HKLM", _EXPLORER_POLICIES_HKLM, "AllowOnlineTips", 0)

            # ContentDeliveryManager — silent installs + every SubscribedContent surface
            # (key set mirrors Win11Debloat Disable_Windows_Suggestions.reg)
            cdm_zeros = (
                "ContentDeliveryAllowed",            # master CDM switch
                "SilentInstalledAppsEnabled",        # silent app installs
                "SystemPaneSuggestionsEnabled",      # system pane suggestions
                "SoftLandingEnabled",                # soft landing tips
                "SubscribedContent-310093Enabled",   # Windows welcome experience
                "SubscribedContent-338387Enabled",   # lock-screen spotlight ads
                "SubscribedContent-410400Enabled",   # additional sponsored feed
                "SubscribedContent-338388Enabled",   # Start suggestions
                "SubscribedContent-338389Enabled",   # tips while using Windows
                "SubscribedContent-338393Enabled",   # Settings suggestions
                "SubscribedContent-353694Enabled",   # Settings suggestions (2)
                "SubscribedContent-353696Enabled",   # Settings suggestions (3)
                "SubscribedContent-353698Enabled",   # Settings suggestions (4)
                "SubscribedContent-338380Enabled",   # Settings app content ads
                "SubscribedContent-314563Enabled",   # My People suggestions
                "SubscribedContent-314559Enabled",   # OneDrive promotions (ReviOS)
                "SubscribedContent-280815Enabled",   # OneDrive suggestions (ReviOS)
                "SubscribedContent-310091Enabled",   # promo tile (RegiLattice MsStore)
                "SubscribedContent-202914Enabled",   # Start ads (ReviOS)
                "SubscribedContent-280810Enabled",   # OneDrive SyncProviders ad
                "SubscribedContent-280811Enabled",   # OneDrive upsell
                "SubscribedContent-88000326Enabled",  # Edge/app promotions (Optimizer diff)
                "RotatingLockScreenEnabled",         # lock-screen spotlight
                "RotatingLockScreenOverlayEnabled",  # lock-screen overlay ads
                "ShowWindowsWelcomeExperience",      # post-update welcome
                # (experience promos)
                "PreInstalledAppsEnabled",           # OEM app seeding
                "PreInstalledAppsEverEnabled",       # OEM app seeding (sticky)
                "OemPreInstalledAppsEnabled",        # OEM app seeding (OEM channel)
                "RemediationRequired",               # CDM remediation re-offers
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
                # Account-notification promos in Start (Raphire/Win11Debloat)
                w(_USER_EXPLORER_ADV, "Start_AccountNotifications", 0)
                w(_USER_EXPLORER_ADV, "ShowSyncProviderNotifications", 0)
                w(_USER_PROFILE_ENGAGEMENT, "ScoobeSystemSettingEnabled", 0)
                # "Let's finish setting up" second-chance OOBE — mark done
                # (ReviOS notifications.yml)
                w(_USER_CDM + r"\Context\CloudExperienceHostIntent\Wireless",
                  "ScoobeCheckCompleted", 1)
                # Tray balloon feature ads + auto tray nags (ReviOS)
                w(r"Software\Policies\Microsoft\Windows\Explorer",
                  "NoBalloonFeatureAdvertisements", 1)
                w(r"Software\Policies\Microsoft\Windows\Explorer",
                  "NoAutoTrayNotify", 1)
                w(_USER_ACCOUNT_NOTIFICATIONS, "EnableAccountNotifications", 0)
                w(_USER_SUGGESTED_TOAST, "Enabled", 0)
                # Sibling promo toasts: startup-impact, account-health,
                # OneDrive desktop nags (Windows-Utility/winutil)
                for _toast in ("Windows.SystemToast.StartupApp",
                               "Windows.SystemToast.AccountHealth",
                               "Microsoft.SkyDrive.Desktop"):
                    w(_USER_NOTIFICATION_SETTINGS + "\\" + _toast,
                      "Enabled", 0)
                w(_USER_MOBILITY, "OptedIn", 0)
                w(_USER_MOBILITY, "PhoneLinkEnabled", 0)
                # Mail/Calendar -> "new Outlook" forced migration nudge (winutil)
                w(_USER_OUTLOOK_MIGRATION, "DoNewOutlookAutoMigration", 0)
                # Classic-Outlook "try new Outlook" toggle + migration prompt
                # off (privacy.sexy; same migration surface, Office-side)
                w(_USER_OUTLOOK_MIGRATION, "HideNewOutlookToggle", 1)
                w(_USER_OUTLOOK_PREFERENCES, "NewOutlookMigrationUserSetting", 0)
                # Cross-device experiences consent (Phone Link channel) +
                # Search highlights/dynamic content (privacy.sexy)
                w(_USER_MOBILITY, "CrossDeviceEnabled", 0)
                w(_USER_SEARCH_SETTINGS, "SafeSearchMode", 0)
                w(_USER_SEARCH_SETTINGS, "ShowDynamicContent", 0)
            # Block Chat/Teams consumer auto-install at the documented
            # channel (Atlas appx.yml — complements Teams DisableInstallation)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Communications",
                "ConfigureChatAutoInstall", 0)
            # "Get the latest updates as soon as they're available" opt-in off —
            # continuous-innovation drops ship unannounced feature/bloat updates
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                               "IsContinuousInnovationOptedIn", 0)
            # Push-to-install: block remote/mobile-driven Store installs
            # (tiny11builder; complements the demoted PushToInstall service
            # and disabled LoginCheck task — third anchor on the channel)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\PushToInstall",
                               "DisablePushToInstall", 1)
            # Block automatic Teams (personal & consumer) install/reinstall
            # (tiny11builder — the package keeps coming back via Store)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Teams",
                               "DisableInstallation", 1)
            # Cloud app notifications (promo toasts) — ReviOS notifications.yml
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
                "NoCloudApplicationNotification", 1)
            # BITS download-status toasts off (RegiLattice v6.35.0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\BITS",
                "DisableBITSNotification", 1)
            # Mark forced new-Outlook/DevHome pushes as already delivered so
            # Windows Update does not re-ship them (tiny11builder)
            for sched in ("UScheduler", "UScheduler_Oobe"):
                for upd in ("OutlookUpdate", "DevHomeUpdate", "WindowsUpdate"):
                    set_registry_dword(
                        "HKLM",
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
                        rf"\Orchestrator\{sched}\{upd}",
                        "workCompleted", 1)

            for_each_user_hive(_apply_suggestions, logger)
            logger.info("Applied: BlockProvisioning (silent installs + all suggestion surfaces, all hives)")

        except Exception as e:
            logger.warning(f"BlockProvisioning layer failed: {e}")
    if prev.get("DisableCopilot", True):
        try:
            copilot_pol = r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
            set_registry_dword("HKLM", copilot_pol, "TurnOffWindowsCopilot", 1)
            set_user_dword_all_hives(_USER_COPILOT, "TurnOffWindowsCopilot", 1, logger)
            # Copilot taskbar button
            set_user_dword_all_hives(_USER_EXPLORER_ADV, "ShowCopilotButton", 0, logger)
            # Shell eligibility suppression (HKLM + user hives — same pattern as
            # zoicware/RemoveWindowsAI): app removed via blacklist, shell too
            shell_copilot = r"SOFTWARE\Microsoft\Windows\Shell\Copilot"
            set_registry_dword("HKLM", shell_copilot, "IsCopilotAvailable", 0)
            set_registry_dword("HKLM", shell_copilot + r"\BingChat", "IsUserEligible", 0)
            # Region-availability trick (winscript): report the geographic
            # eligibility check as failed so the feature never surfaces
            set_registry_string("HKLM", shell_copilot, "CopilotDisabledReason",
                                "IsEnabledForGeographicRegionFailed")
            # "Ask Copilot" Explorer context-menu entry — CLSID block
            # (CrapFixer): HKLM applies to all users incl. new profiles
            set_registry_string(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\Shell Extensions\Blocked",
                "{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}",
                "RemoveCopilotContext")
            # Per-user Copilot runtime kill (winscript)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\WindowsCopilot",
                "AllowCopilotRuntime", 0, logger)
            # Copilot app ADMX (CopilotApp.admx, v146+): kill in-app web
            # browsing + Cowork agentic actions. ComponentUpdatesEnabled left
            # alone — disabling it can block security fixes per doc.
            copilot_app = r"SOFTWARE\Policies\Microsoft\Copilot"
            set_registry_dword("HKLM", copilot_app, "BrowsingEnabled", 0)
            set_registry_dword("HKLM", copilot_app,
                               "CopilotCoworkToolActionsEnabled", 0)
            # Edge Update Copilot-distribution guard: block the updater from
            # installing/updating Copilot and from Copilot unification.
            edgeupd_pol = r"SOFTWARE\Policies\Microsoft\EdgeUpdate"
            set_registry_dword(
                "HKLM", edgeupd_pol,
                "Install{C50565E9-CCCF-44B4-BA15-5AC5C6569197}", 0)
            set_registry_dword(
                "HKLM", edgeupd_pol,
                "Update{C50565E9-CCCF-44B4-BA15-5AC5C6569197}", 0)
            set_registry_dword(
                "HKLM", edgeupd_pol,
                "CopilotUnificationAllowed{C50565E9-CCCF-44B4-BA15-5AC5C6569197}", 0)
            # zoicware RemoveWindowsAI re-diff — per-user Copilot surface kills:
            # taskbar pins, companion entry, background-app disable, PWA flag
            _pins = (r"Software\Microsoft\Windows\CurrentVersion"
                     r"\Explorer\Taskband\AuxilliaryPins")
            set_user_dword_all_hives(_pins, "CopilotPWAPin", 0, logger)
            set_user_dword_all_hives(_pins, "RecallPin", 0, logger)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                "TaskbarCompanion", 0, logger)
            # "Ask Copilot" Explorer context-menu entry — CLSID block
            # (CrapFixer): HKLM applies to all users incl. new profiles
            set_registry_string(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\Shell Extensions\Blocked",
                "{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}",
                "RemoveCopilotContext")
            for _pkg in ("Microsoft.Copilot_8wekyb3d8bbwe",
                         "Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe"):
                _bga = (r"Software\Microsoft\Windows\CurrentVersion"
                        r"\BackgroundAccessApplications" + "\\" + _pkg)
                set_user_dword_all_hives(_bga, "DisabledByUser", 1, logger)
                set_user_dword_all_hives(_bga, "SleepDisabled", 1, logger)
            _pwa = (r"Software\Microsoft\Windows\CurrentVersion"
                    r"\Explorer\AutoInstalledPWAs")
            set_user_dword_all_hives(_pwa, "CopilotPWAPreinstallCompleted", 1, logger)
            # noverse.dev copilot page: sibling marker for the Copilot
            # hardware-key choice prompt — same fake-completed mechanism
            set_user_dword_all_hives(_pwa, "CopilotHWKeyChoiceSet", 1, logger)
            set_user_dword_all_hives(
                _pwa, "Microsoft.Copilot_8wekyb3d8bbwe", 1, logger)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\SettingSync"
                r"\WindowsSettingHandlers",
                "A9HomeContentEnabled", 0, logger)
            # NVIDIA telemetry opt-out RIDs (winscript)
            _nv_fts = r"SOFTWARE\NVIDIA Corporation\Global\FTS"
            for _rid in ("EnableRID44231", "EnableRID64640", "EnableRID66610"):
                set_registry_dword("HKLM", _nv_fts, _rid, 0)
            # NVIDIA driver telemetry upload off (winscript)
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup",
                "SendTelemetryData", 0)
            # default-value form under Parameters\Global\Startup
            set_registry_string(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\Global\Startup",
                "SendTelemetryData", "0")
            set_user_dword_all_hives(_USER_SHELL_COPILOT, "IsCopilotAvailable", 0, logger)
            # Copilot nudge prompts off (Winhance)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                "ShowCopilotNudges", 0, logger)
            set_user_dword_all_hives(_USER_SHELL_COPILOT_BINGCHAT, "IsUserEligible", 0, logger)
            # Copilot voice-agent activation off (all user hives)
            set_user_dword_all_hives(_USER_VOICE_ACTIVATION, "AgentActivationEnabled", 0, logger)
            set_user_dword_all_hives(
                _USER_VOICE_ACTIVATION,
                "AgentActivationOnLockScreenEnabled", 0, logger)
            set_user_dword_all_hives(
                _USER_VOICE_ACTIVATION,
                "AgentActivationLastUsed", 0, logger)
            # Wake-word/voice activation off (RegiLattice Cortana)
            set_user_dword_all_hives(
                r"Software\Microsoft\Speech_OneCore\Preferences",
                "VoiceActivationOn", 0, logger)
            # Default/master voice-activation toggle (privacy.sexy) — the
            # always-on "Hey Cortana"-class listening preference; same key as
            # VoiceActivationOn but a distinct value honoured by SpeechRuntime
            set_user_dword_all_hives(
                r"Software\Microsoft\Speech_OneCore\Preferences",
                "VoiceActivationDefaultOn", 0, logger)
            # Voice activation above the lock screen (parity with C#
            # VoiceActivationEnableAboveLockscreen write)
            set_user_dword_all_hives(
                r"Software\Microsoft\Speech_OneCore\Preferences",
                "VoiceActivationEnableAboveLockscreen", 0, logger)
            # IME cloud AI suggestions off (RegiLattice CopilotPlus —
            # per-user InputMethod settings)
            set_user_dword_all_hives(
                r"Software\Microsoft\InputMethod\Settings\CHS",
                "UseAISuggestions", 0, logger)
            # Copilot hardware-key remap (WindowsCopilot ADMX, zoicware)
            _copilot_key = (r"Software\Policies\Microsoft\Windows"
                            r"\CopilotKey")
            set_user_dword_all_hives(_copilot_key,
                                     "SetCopilotHardwareKey", 0, logger)
            # M365 Copilot auto-start delay + companion window (zoicware)
            _m365 = (r"Software\Microsoft\Windows\CurrentVersion"
                     r"\M365Copilot")
            set_user_dword_all_hives(_m365, "AutoStartDelayEnabled", 0, logger)
            set_user_dword_all_hives(_m365,
                                     "IsCompanionWindowAvailable", 0, logger)
            # Copilot auto-launch on startup (RunNotification entry)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                               r"\RunNotification",
                               "MicrosoftCopilotAutoLaunch", 0)
            # generativeAI consent store: deny prompt-level access + stop
            # usage recording at the Capabilities layer (zoicware)
            _consent = (r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                        r"\CapabilityAccessManager\ConsentStore")
            set_registry_string("HKLM",
                                _consent + r"\generativeAI",
                                "Value", "Deny")
            set_registry_string("HKLM",
                                _consent + r"\systemAIModels",
                                "Value", "Deny")
            _caps = (r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                     r"\CapabilityAccessManager\Capabilities")
            set_registry_dword("HKLM",
                               _caps + r"\generativeAI",
                               "RecordUsageData", 0)
            set_registry_dword("HKLM",
                               _caps + r"\systemAIModels",
                               "RecordUsageData", 0)
            # Copilot auto-open on large screens (notification channel,
            # privacy.sexy) — per-user
            set_user_dword_all_hives(_USER_NOTIFICATION_SETTINGS, "AutoOpenCopilotLargeScreens", 0, logger)
            # Toast content must not render above the lock screen
            # (Debloat-Win11) — standard + critical channels
            set_user_dword_all_hives(
                _USER_NOTIFICATION_SETTINGS,
                "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK", 0, logger)
            set_user_dword_all_hives(
                _USER_NOTIFICATION_SETTINGS,
                "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK", 0, logger)
            # Narrator online voices download off (Winnow ExtendedAIPurge)
            set_user_dword_all_hives(
                r"Software\Microsoft\Narrator\NoRoam",
                "OnlineVoicesEnabled", 0, logger)
            for vid, state in _VELOCITY_COPILOT_IDS:
                set_registry_dword("HKLM", _VELOCITY_PATH + "\\" + vid,
                                   "EnabledState", state)
            logger.info("Applied: DisableCopilot (policy + shell eligibility + "
                        "voice agent + nudge/taskbar/systray overrides, HKLM + user hives)")

        except Exception as e:
            logger.warning(f"DisableCopilot layer failed: {e}")
    if prev.get("DisableRecall", True):
        try:
            ai_pol = r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
            set_registry_dword("HKLM", ai_pol, "DisableAIDataAnalysis", 1)
            set_registry_dword("HKLM", ai_pol, "TurnOffSavingSnapshots", 1)
            # Win11Debloater: sibling snapshotting kill switch (same CSP key)
            set_registry_dword("HKLM", ai_pol, "AllowSnapshotting", 0)
            set_registry_dword("HKLM", ai_pol, "AllowRecallEnablement", 0)
            # On-device screen semantic analysis off (25H2 WindowsAI CSP —
            # Win-Debloat7 Privacy module)
            set_registry_dword("HKLM", ai_pol, "DisableScreenSemanticAnalysis", 1)
            set_registry_dword("HKLM", ai_pol, "DisableClickToDo", 1)
            # 25H2 "Agent in Settings" (Settings AI agent)
            set_registry_dword("HKLM", ai_pol, "DisableSettingsAgent", 1)
            # WindowsAI model management — block on-device AI model
            # downloads and background updates (win-debloat Security module)
            mm = ai_pol + r"\ModelManagement"
            set_registry_dword("HKLM", mm, "DisableModelDownload", 1)
            set_registry_dword("HKLM", mm, "DisableBackgroundModelUpdates", 1)
            # Recall export + app/URI deny-lists (noid-privacy AntiAI —
            # documented 25H2 WindowsCopilot ADMX values)
            set_registry_dword("HKLM", ai_pol, "AllowRecallExport", 0)
            # Sibling snapshot-export kill — same semantics, alternate
            # value name used by dvandenburgh/Disable-Win11AI
            set_registry_dword("HKLM", ai_pol, "AllowSnapshotExport", 0)
            set_registry_dword("HKLM", ai_pol, "SetDenyAppListForRecall", 1)
            set_registry_string(
                "HKLM", ai_pol, "DenyAppListForRecall",
                "msedge.exe;chrome.exe;firefox.exe;WindowsTerminal.exe;"
                "KeePassXC.exe;KeePass.exe;1Password.exe;mstsc.exe;msrdc.exe")
            set_registry_dword("HKLM", ai_pol, "SetDenyUriListForRecall", 1)
            set_registry_string(
                "HKLM", ai_pol, "DenyUriListForRecall",
                "https://account.microsoft.com;https://login.live.com;"
                "https://outlook.live.com;https://accounts.google.com;"
                "https://mail.google.com;https://www.paypal.com")
            # Copilot agent connector/workspace kills (25H2 agent
            # framework — noid-privacy AntiAI)
            for name in ("DisableAgentConnectors", "ConfigureAgentConnectors",
                         "DisableAgentWorkspaces", "DisableRemoteAgentConnectors"):
                set_registry_dword("HKLM", ai_pol, name, 2)
            set_registry_dword("HKLM", ai_pol, "AgentConnectorMinimumPolicy", 1)
            set_registry_dword("HKLM", ai_pol, "AgentConsentDuration", 1)
            # April 2026 RemoveMicrosoftCopilotApp also exists at Device scope
            # (./Device/.../WindowsAI per KB5083769 doc)
            set_registry_dword("HKLM", ai_pol, "RemoveMicrosoftCopilotApp", 1)
            set_user_dword_all_hives(_USER_WINDOWS_AI, "DisableAIDataAnalysis", 1, logger)
            set_user_dword_all_hives(_USER_WINDOWS_AI, "DisableClickToDo", 1, logger)
            set_user_dword_all_hives(_USER_WINDOWS_AI, "DisableSettingsAgent", 1, logger)
            set_user_dword_all_hives(_USER_WINDOWS_AI, "DisableRecallDataProviders", 1, logger)
            # April 2026 update "Remove Microsoft Copilot app" policy —
            # Copilot + Microsoft 365 Copilot auto-removed when not
            # user-installed and unused >28 days (windowslatest.com)
            set_user_dword_all_hives(_USER_WINDOWS_AI,
                                     "RemoveMicrosoftCopilotApp", 1, logger)
            # Copilot Keyboard admin policies (Microsoft Japan blog,
            # June 2026): usage-data upload, cloud conversion
            # candidates, internet integration (Bing search via IME,
            # desktop character, update nudges). 'Telementry' is
            # Microsoft's literal (misspelled) value name.
            set_user_dword_all_hives(_USER_COPILOT_KEYBOARD,
                                     "TurnOffSendTelementryData", 1, logger)
            set_user_dword_all_hives(_USER_COPILOT_KEYBOARD,
                                     "TurnOffCloudCandidate", 1, logger)
            set_user_dword_all_hives(_USER_COPILOT_KEYBOARD,
                                     "TurnOffInternetIntegration", 1, logger)
            # ClickToDo user preference (policy alone still leaves the shell entry)
            set_user_dword_all_hives(_USER_CLICK_TO_DO, "DisableClickToDo", 1, logger)
            # App-level AI toggles (WinRice): Notepad cowriter, Paint
            # cocreator/image-creator, Photos AI features
            set_user_dword_all_hives(
                r"Software\Microsoft\Notepad", "EnableCowriter", 0, logger)
            # Notepad "Rewrite" AI opt-out + Photos super-resolution
            # (tomytate/Win-Debloat Privacy) — per-user app preferences
            set_user_dword_all_hives(
                r"Software\Microsoft\Notepad", "DisableAIRewrite", 1, logger)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Photos",
                "DisableSuperResolution", 1, logger)
            _paint_user = r"Software\Microsoft\Paint"
            for _v in ("EnableCocreator", "EnableImageCreator",
                       "CocreatorEnabled", "ImageCreatorEnabled",
                       "GenerativeFillEnabled", "GenerativeEraseEnabled"):
                set_user_dword_all_hives(_paint_user, _v, 0, logger)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Photos",
                "EnableAIFeatures", 0, logger)
            # User-level Recall toggle (Debloat-Win11) — policy kills
            # alone leave the per-user shell preference on
            set_user_dword_all_hives(
                _USER_EXPLORER_ADV, "EnableRecall", 0, logger)
            # Per-user Recall opt-out toggle + Click-to-Do shell pref
            # (win-debloat/Debloat-Win11) — complementary to the policies
            set_user_dword_all_hives(_USER_RECALL, "IsRecallAllowed", 0, logger)
            set_user_dword_all_hives(
                _USER_EXPLORER_ADV, "ClickToDoEnabled", 0, logger)
            # Per-app AI features: Paint (image creator/cocreator/fill/erase/
            # background) and Notepad (Rewrite) — documented policy keys
            paint_pol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint"
            for name in ("DisableImageCreator", "DisableCocreator",
                         "DisableGenerativeFill", "DisableGenerativeErase",
                         "DisableRemoveBackground"):
                set_registry_dword("HKLM", paint_pol, name, 1)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\WindowsNotepad",
                               "DisableAIFeatures", 1)
            # Secondary Notepad policy namespace + per-user variant
            # (0Ai-Windows-Hardening): some Store builds honor these
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Notepad",
                               "DisableAIFeatures", 1)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\Windows\WindowsNotepad",
                "DisableAIFeatures", 1, logger)
            for vid, state in _VELOCITY_AI_IDS:
                set_registry_dword("HKLM", _VELOCITY_PATH + "\\" + vid,
                                   "EnabledState", state)
            if is_admin():
                # Remove the optional feature where present — absent on most hardware
                run_powershell(
                    "Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' "
                    "-NoRestart -ErrorAction SilentlyContinue | Out-Null", timeout=120)
            # AI fabric service: 2=auto, 3=demand. Absent without NPU/Copilot+ hardware.
            demote_service("WSAIFabricSvc")
            # 25H2 AI platform event-log channels off (RemoveWindowsAI —
            # ModelContextProtocol + AI-Platform admin/operational logs)
            for chan in ("Microsoft-Windows-AI-ModelContextProtocol/Admin",
                         "Microsoft-Windows-AI-ModelContextProtocol/Operational",
                         "Microsoft-Windows-AI-Platform/Admin",
                         "Microsoft-Windows-AI-Platform/Operational"):
                run_cmd(["wevtutil", "sl", chan, "/e:false"], timeout=15)
            logger.info("Applied: DisableRecall (WindowsAI+SettingsAgent policies, "
                        "Paint/Notepad AI off, Click to Do off, Recall feature "
                        "removal attempted, WSAIFabricSvc=demand, AI event-log "
                        "channels off)")

        except Exception as e:
            logger.warning(f"DisableRecall layer failed: {e}")
    if prev.get("DisableSearchSuggestions", True):
        try:
            search_pol = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            set_registry_dword("HKLM", search_pol, "AllowCortana", 0)
            set_registry_dword("HKLM", search_pol, "CortanaConsent", 0)
            # Cortana/voice access above the lock screen (TronScript)
            set_registry_dword(
                "HKLM", search_pol, "AllowCortanaAboveLock", 0)
            # Connected-search privacy=disabled + no web results on
            # metered links (winscript)
            set_registry_dword("HKLM", search_pol, "ConnectedSearchPrivacy", 3)
            set_registry_dword(
                "HKLM", search_pol,
                "ConnectedSearchUseWebOverMeteredConnections", 0)
            # Legacy Cortana master kill + policy-level search-history off
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
                "CortanaEnabled", 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
                "DisableSearchHistory", 1)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Search",
                "DeviceHistoryEnabled", 0, logger)
            # Per-user search voice shortcut (winscript)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Search",
                "VoiceShortcut", 0, logger)
            # Block remote query results entering the index (winscript)
            set_registry_dword(
                "HKLM", search_pol, "PreventRemoteQueries", 1)
            # Location-aware search results leak the device location to Bing
            set_registry_dword("HKLM", search_pol, "AllowSearchToUseLocation", 0)
            # AAD work/school-account Cortana + OOBE-path variants
            # (ReviOS search.yml)
            for v in ("AllowCortanaInAAD", "AllowCortanaInAADPathOOBE"):
                set_registry_dword("HKLM", search_pol, v, 0)
            # WinRT activation class for the Store-driven search task —
            # same neuter as the GamingAI host (ReviOS search.yml)
            wst = (r"SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId"
                   r"\WinStore.Tasks.WindowsSearchTask")
            set_registry_dword("HKLM", wst, "ActivationType", 0xFFFFFFFF)
            set_registry_string("HKLM", wst, "Server", "")
            # Explorer-search web lookups off too (separate nag surface)
            set_registry_dword("HKLM", _EXPLORER_POLICIES_HKLM, "NoSearchInternet", 1)
            set_user_dword_all_hives(_USER_EXPLORER_POLICIES, "DisableSearchBoxSuggestions", 1, logger)
            # HKLM policy too — covers hive-creation edge cases
            set_registry_dword("HKLM", _EXPLORER_POLICIES_HKLM, "DisableSearchBoxSuggestions", 1)
            # Windows Search cloud results master switch (hellzerg/Optimizer)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
                               "AllowCloudSearch", 0)
            set_user_dword_all_hives(_USER_SEARCH, "BingSearchEnabled", 0, logger)
            # SearchSettings: dynamic search box + cloud search integrations
            set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsDynamicSearchBoxEnabled", 0, logger)
            set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsAADCloudSearchEnabled", 0, logger)
            set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsMSACloudSearchEnabled", 0, logger)
            set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsDeviceSearchHistoryEnabled", 0, logger)
            set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsStoreSuggestionsEnabled", 0, logger)
            set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsGlobalFileSearchProviderToggleEnabled", 0, logger)
            set_user_dword_all_hives(_USER_SEARCH_SETTINGS, "IsWebSuggestionsEnabled", 0, logger)
            # Background-apps master toggle + Iris Start recommendations
            set_user_dword_all_hives(_USER_SEARCH, "BackgroundAppGlobalToggle", 0, logger)
            set_user_dword_all_hives(_USER_EXPLORER_ADV, "Start_IrisRecommendationEnabled", 0, logger)
            # Voice activation above the lock screen off (speech surface)
            set_user_dword_all_hives(
                r"Software\Microsoft\Speech_OneCore\Preferences",
                "VoiceActivationEnableAboveLockscreen", 0, logger)
            # DeliveryOptimization for system settings off
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization",
                "SystemSettingsDownloadMode", 0, logger)
            # On-device search history view (HST Windows Utility) — the
            # Settings "Search history" toggle surface
            set_user_dword_all_hives(_USER_SEARCH, "HistoryViewEnabled", 0, logger)
            set_user_dword_all_hives(_USER_SEARCH, "CortanaConsent", 0, logger)
            # Policy kill for web results in Start (Optimizer diff — same spirit
            # as the Bing/suggestion switches above, one level deeper)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
                               "DisableWebSearch", 1)
            # Dynamic web content inside the search box itself (Atlas)
            set_registry_dword("HKLM", search_pol, "EnableDynamicContentInWSB", 0)
            # Hard kill for web results in search (RegiLattice v6.35.0)
            set_registry_dword("HKLM", search_pol, "DoNotUseWebResults", 1)
            # Shell web-service integration + "search online" open-with
            # lookup promo (mxk — hard kill below the search policies)
            xpol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            set_registry_dword("HKLM", xpol, "NoWebServices", 1)
            set_registry_dword("HKLM", xpol, "NoInternetOpenWith", 1)
            # Connected-search web results + global web-search provider
            # toggle + Bing-as-provider registration (noid-privacy)
            set_registry_dword("HKLM", search_pol, "ConnectedSearchUseWeb", 0)
            set_user_dword_all_hives(
                _USER_SEARCH_SETTINGS,
                "IsGlobalWebSearchProviderToggleEnabled", 0, logger)
            set_user_dword_all_hives(
                _USER_SEARCH_SETTINGS + r"\WebSearchPro",
                "Microsoft.BingSearch_8wekyb3d8bbwe!App", 0, logger)
            logger.info("Applied: DisableSearchSuggestions (Bing/search suggestions + Cortana off, all hives)")

        except Exception as e:
            logger.warning(f"DisableSearchSuggestions layer failed: {e}")
    if prev.get("DisableWidgets", True):
        try:
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
                               "EnableFeeds", 0)
            set_user_dword_all_hives(_USER_EXPLORER_ADV, "TaskbarDa", 0, logger)
            # 2 = Feeds view hidden entirely (news/interests flyout off)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Feeds",
                "ShellFeedsTaskbarViewMode", 2, logger)
            # Taskbar feeds open-on-hover off (ledr)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Feeds",
                "ShellFeedsTaskbarOpenOnHover", 0, logger)
            logger.info("Applied: DisableWidgets (AllowNewsAndInterests = 0, TaskbarDa = 0)")

        except Exception as e:
            logger.warning(f"DisableWidgets layer failed: {e}")
    if prev.get("DisableTelemetry", True):
        try:
            # Key set mirrors Win11Debloat Disable_Telemetry.reg
            set_registry_dword(
                "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
                "AllowTelemetry", 0)
            # Opt-in notification/UX suppression (documented
            # DataCollection policies)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                "ConfigureTelemetryOptInChangeNotification", 1)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                "ConfigureTelemetryOptInSettingsUx", 2)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "PublishUserActivities", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "EnableActivityFeed", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "UploadUserActivities", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "PublishUserActivitiesOnUserConsent", 0)
            # Per-user activity-history recording kill (CrapFixer) —
            # policy flags alone leave Timeline recording on at user level
            set_user_dword_all_hives(_USER_PRIVACY, "ActivityHistoryEnabled", 0, logger)
            # User-level publish/upload toggles (gdid-guard) — the Settings
            # activity-history switches the policies don't reach
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\PublishUserActivities",
                "PublishUserActivities", 0, logger)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\UploadUserActivities",
                "UploadUserActivities", 0, logger)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "AllowClipboardHistory", 0)
            # Smart Clipboard (Copilot+ AI clipboard suggestions) —
            # documented System policy (Debloat-Win11)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "EnableSmartClipboard", 0)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Assistance\Client\1.0",
                "NoActiveHelp", 1)
            # Recommended troubleshooting off (WindowsMitigation — auto-run
            # troubleshooters upload diagnostics; LeDragoX)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\WindowsMitigation",
                               "UserPreference", 3)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Edge",
                               "PersonalizationReportingEnabled", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Edge",
                               "TextPredictionEnabled", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Edge",
                               "MicrosoftEditorProofingEnabled", 0)
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
                w(_USER_PRIVACY, "PersonalizedOffersEnabled", 0)
                w(r"Software\Microsoft\Windows\CurrentVersion\A9\SnapshotCapture",
                  "IsFilteringTelemetryEnabled", 0)
                # Suggested content surface (HST) — app suggestions in the
                # shell/Start feed off this privacy toggle
                w(_USER_PRIVACY, "AppSuggestions", 0)
                w(_USER_ONLINE_SPEECH, "HasAccepted", 0)
                w(_USER_TIPC, "Enabled", 0)
                w(_USER_INPUT_PERSONALIZATION, "RestrictImplicitInkCollection", 1)
                w(_USER_INPUT_PERSONALIZATION, "RestrictImplicitTextCollection", 1)
                w(_USER_INPUT_STORE, "HarvestContacts", 0)
                w(_USER_PERSONALIZATION, "AcceptedPrivacyPolicy", 0)
                w(_USER_EXPLORER_ADV, "Start_TrackProgs", 0)
                w(_USER_SIUF, "NumberOfSIUFInPeriod", 0)
                w(_USER_INTL_PROFILE, "HttpAcceptLanguageOptOut", 1)
                # Tailored-experiences policy (policy-level, not just the value)
                w(_USER_PRIVACY_POLICIES, "TailoredExperiencesWithDiagnosticDataEnabled", 0)
                # Mark the diagnostic-level toast as shown — silences the
                # "your data settings changed" prompt after telemetry is cut
                w(r"Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
                  "ShowedToastAtLevel", 1)

            for_each_user_hive(_apply_telemetry, logger)

            # "Connected User Experiences and Telemetry" (DiagTrack) — the actual
            # telemetry uploader; absent on some SKUs, failures are non-fatal.
            run_cmd(["sc.exe", "stop", "DiagTrack"], timeout=15)
            run_cmd(["sc.exe", "config", "DiagTrack", "start=", "disabled"], timeout=15)
            # RetailDemo data-collection service (present on most images)
            run_cmd(["sc.exe", "stop", "RetailDemo"], timeout=15)
            run_cmd(["sc.exe", "config", "RetailDemo", "start=", "disabled"], timeout=15)
            # Windows Error Reporting — upload path for crash dumps (QueueReporting
            # task and WER hosts are already covered elsewhere)
            run_cmd(["sc.exe", "stop", "WerSvc"], timeout=15)
            run_cmd(["sc.exe", "config", "WerSvc", "start=", "disabled"], timeout=15)
            # Block the outbound firewall rules for the telemetry/error-report
            # services — neither can upload even if something re-enables them.
            run_powershell(
                "'DiagTrack','WerSvc' | % { Get-NetFirewallRule -Group $_ "
                "-ErrorAction Ignore | Set-NetFirewallRule -Enabled True "
                "-Action Block }", timeout=60)
            # ETW AutoLogger feeding DiagTrack — Start=0 kills the boot-time trace
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener",
                "Start", 0)
            # CEIP collection under-layer: census upload + task-run gate
            # (HushWin — AppCompatFlags telemetry suppression)
            for _ct in ("IsCensusDisabled", "DontRetryOnError",
                        "TaskEnableRun"):
                set_registry_dword(
                    "HKLM",
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry",
                    _ct, 1)
            # Ink Workspace suggestion surface (ads inside the pen menu)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
                               "AllowWindowsInkWorkspace", 0)
            # ... and the suggested-apps surface inside it (belt for re-enable)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
                               "AllowSuggestedAppsInWindowsInkWorkspace", 0)
            # Defender SpyNet — no sample uploads to Microsoft
            spynet = r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
            set_registry_dword("HKLM", spynet, "SpynetReporting", 0)
            set_registry_dword("HKLM", spynet, "SubmitSamplesConsent", 0)
            # Offline-maps auto-download channel (MapsBroker service is demoted;
            # kill the data push too)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Maps",
                               "AutoDownloadAndUpdateMapData", 0)
            # AppCompat: Application Inventory Telemetry + Program Compatibility
            # Assistant (PcaSvc is already demoted)
            appc = r"SOFTWARE\Policies\Microsoft\Windows\AppCompat"
            set_registry_dword("HKLM", appc, "AITEnable", 0)
            set_registry_dword("HKLM", appc, "DisablePCA", 1)
            # Application Compatibility Inventory collector (app inventory
            # telemetry) — classic Win10-Initial-Setup hardening
            set_registry_dword("HKLM", appc, "DisableInventory", 1)
            # AppCompat engine + User-Access-Reporting off (ReviOS app-compat.yml)
            set_registry_dword("HKLM", appc, "DisableEngine", 1)
            set_registry_dword("HKLM", appc, "DisableUAR", 1)
            # AppCompat UA-automation + property-page shim off (RegiLattice)
            set_registry_dword("HKLM", appc, "DisableUACompleteAutomation", 1)
            set_registry_dword("HKLM", appc, "DisablePropPageShim", 1)
            # AppCompat install-activity tracing collector (mxk
            # windows-secure-group-policy)
            set_registry_dword("HKLM", appc, "DisableInstallTracing", 1)
            # Legacy name-resolution/discovery broadcast surfaces — policy
            # kills matching the demoted NetBT service + LLMNR block (mxk):
            # NetBIOS at the DNS client, mailslots, LLTD responder + mapper
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "EnableNetbios", 0)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Bowser",
                "EnableMailslots", 0)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider",
                "EnableMailslots", 0)
            lltd = r"SOFTWARE\Policies\Microsoft\Windows\LLTD"
            set_registry_dword("HKLM", lltd, "AllowLLTDIOOnPublicNet", 0)
            set_registry_dword("HKLM", lltd, "ProhibitLLTDIOOnPrivateNet", 1)
            set_registry_dword("HKLM", lltd, "AllowRspndrOnPublicNet", 0)
            set_registry_dword("HKLM", lltd, "ProhibitRspndrOnPrivateNet", 1)
            # WPAD off at the WinHTTP layer too — user-level AutoDetect=0
            # does not reach the machine WinHTTP proxy resolver
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
                "DisableWpad", 1)
            # Legacy Edge telemetry opt-in + OneDrive pre-sign-in traffic
            # off (mxk — the OneDrive value restricts traffic, not sync)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
                "MicrosoftEdgeDataOptIn", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Microsoft\OneDrive",
                               "PreventNetworkTrafficPreUserSignIn", 1)
            # Device Census hardware/software inventory task off via policy
            # + OneDrive sync diagnostics off (RegiLattice DataCollection)
            dcol = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            set_registry_dword("HKLM", dcol, "DisableDeviceCensus", 1)
            set_registry_dword("HKLM", dcol, "DisableOneDriveSyncDiagnostics", 1)
            # OneSettings sync diagnostics collection off (RegiLattice
            # v6.9.0 Privacy)
            set_registry_dword("HKLM", dcol, "DisableOneSettingsSyncDiag", 1)
            # Handwriting/input personalization upload surfaces
            # (RegiLattice Privacy/Input — policy kills only)
            ipz = r"SOFTWARE\Policies\Microsoft\InputPersonalization"
            for v in ("AllowHandwritingErrorReports", "AllowInputDataUpload",
                      "AllowInkRecognitionLearning",
                      "AllowInkingAndTypingPersonalization"):
                set_registry_dword("HKLM", ipz, v, 0)
            # Implicit ink/typing collection off (25H2 ADMX
            # InputPersonalization — Machine+User classes)
            set_registry_dword("HKLM", ipz, "ImplicitDataCollectionOff", 1)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\InputPersonalization",
                "ImplicitDataCollectionOff", 1, logger)
            tip = r"SOFTWARE\Policies\Microsoft\Windows\TextInput"
            for v in ("AllowHandwritingLMUpdate",
                      "AllowHandwritingPersonalizationUpload",
                      "AllowIMENetworkAccess",
                      "AllowHardwareKeyboardTextSuggestions"):
                set_registry_dword("HKLM", tip, v, 0)
            ime = r"SOFTWARE\Policies\Microsoft\Windows\IME"
            set_registry_dword("HKLM", ime, "AllowIMETelemetry", 0)
            set_registry_dword("HKLM", ime, "AllowCloudCandidates", 0)
            # Clipboard AI suggested-actions + Copilot clipboard/screen
            # access off (RegiLattice PolicyCloudClipboard/PolicyAI)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "AllowClipboardSuggestedActions", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "AllowCopilotClipboardAccess", 0)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\AI\Copilot",
                "AllowCopilotScreenAccess", 0)
            # Copilot first-run nag + history cloud-sync off (RegiLattice
            # CopilotSidebar — WindowsCopilot policy key)
            wcp = r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
            set_registry_dword("HKLM", wcp, "SuppressCopilotFirstRun", 1)
            set_registry_dword("HKLM", wcp, "BlockCopilotHistorySync", 1)
            # Speech-recognition language telemetry off (RegiLattice
            # LanguageOptions)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\LanguageOptions",
                "SpeechRecognitionTelemetryEnabled", 0)
            # Crash-dump storage telemetry off (RegiLattice)
            set_registry_dword(
                "HKLM", r"SYSTEM\CurrentControlSet\Control\CrashControl",
                "StorageTelemetryEnabled", 0)
            # Typing-pattern telemetry upload off (RegiLattice
            # SpellingAndTyping policy)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\SpellingAndTyping",
                "TypingDataCollectionEnabled", 0)
            # SysMain memory-usage telemetry reports off (RegiLattice —
            # service stays demand-start, telemetry path only)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\SuperFetch",
                "SuperFetchDisableTelemetry", 1)
            # AI data-analysis kill (TurnOff* sibling of DisableAIDataAnalysis)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
                "TurnOffAIDataAnalysis", 1)
            # Scripted diagnostics upload off (RegiLattice)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics",
                "AllowDiagnosticDataUpload", 0)
            # Troubleshooter online-content access off (documented
            # policy — Microsoft-server troubleshooting content)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics",
                "EnableDiagnostics", 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows"
                r"\ScriptedDiagnosticsProvider\Policy",
                "EnableQueryRemoteServer", 0)
            # Recommended-troubleshooting suggestions off (documented)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows"
                r"\Troubleshooting\AllowRecommendations",
                "TroubleshootingAllowRecommendations", 0)
            # Windows ML inference telemetry off (RegiLattice
            # MachineLearning policy — kill flag polarity is 1)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\MachineLearning",
                "WinMLTelemetryEnabled", 1)
            # GameDVR achievement-sharing + streaming-upload surfaces
            # (RegiLattice — capture policies untouched)
            dvr = r"SOFTWARE\Policies\Microsoft\Windows\GameDVR"
            set_registry_dword("HKLM", dvr, "AllowAchievementSharing", 0)
            set_registry_dword("HKLM", dvr, "AllowGameStreamingUpload", 0)
            # SMS/message cloud backup off (RegiLattice — Messaging policy)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Messaging",
                "AllowMessageBackup", 0)
            # 24H2 app-inventory collectors: API sampling / app footprint /
            # Win32 backup scan (Qiita 24H2 new-policy list; DisableAPISamping
            # is Microsoft's literal ADMX spelling)
            set_registry_dword("HKLM", appc, "DisableAPISamping", 1)
            set_registry_dword("HKLM", appc, "DisableApplicationFootprint", 1)
            set_registry_dword("HKLM", appc, "DisableWin32AppBackup", 1)
            # CEIP stragglers: App-V, Messenger client, unattend SQM
            # (ReviOS ceip.yml)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\AppV\CEIP",
                               "CEIPEnable", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Messenger\Client",
                               "CEIP", 2)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient",
                               "CEIPEnabled", 0)
            # Event Viewer "more information online" links (ReviOS ceip.yml)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\EventViewer",
                               "MicrosoftEventVwrDisableLinks", 1)
            # Help-sticker hand raises + EdgeUI tracking (ReviOS privacy.yml)
            edgeui = r"SOFTWARE\Policies\Microsoft\Windows\EdgeUI"
            set_registry_dword("HKLM", edgeui, "DisableHelpSticker", 1)
            # Handwriting error reports + data sharing (ReviOS privacy.yml)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports",
                               "PreventHandwritingErrorReports", 1)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\TabletPC",
                               "PreventHandwritingDataSharing", 1)
            # Pen feedback + pen-recognition training uploads off
            # (25H2 ADMX TabletPC/PenTraining — Machine+User)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\TabletPC",
                "TurnOffPenFeedback", 1)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\TabletPC",
                "TurnOffPenFeedback", 1, logger)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\PenTraining",
                "DisablePenTraining", 1)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\PenTraining",
                "DisablePenTraining", 1, logger)
            # Web printing channels (ReviOS privacy.yml)
            printers = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers"
            set_registry_dword("HKLM", printers, "DisableHTTPPrinting", 1)
            set_registry_dword("HKLM", printers, "DisableWebPnPDownload", 1)
            # UPnP device registrar kill — legacy network-device discovery
            # surface (soswod/Windows-On-Reins)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars",
                "DisableUPnPRegistrar", 0)
            # Peer-to-peer networking service kill, credential-delegation
            # lock-down and cert padding check (DebloatAndSecurizeW11)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Peernet",
                "Disabled", 1)
            cred_del = r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
            set_registry_dword(
                "HKLM", cred_del, "AllowDefaultCredentials", 0)
            set_registry_dword(
                "HKLM", cred_del, "AllowProtectedCreds", 1)
            for root in (r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
                         r"SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"):
                set_registry_dword(
                    "HKLM", root, "EnableCertPaddingCheck", 1)
            # Explorer online wizards (ReviOS privacy.yml; HKLM + per-user below)
            exp_pol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            for v in ("NoOnlinePrintsWizard", "NoPublishingWizard",
                      "NoWebServices"):
                set_registry_dword("HKLM", exp_pol, v, 1)
            # Skip the OOBE privacy pages — every policy they gate is denied
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE",
                               "DisablePrivacyExperience", 1)
            # Microsoft feature experimentation (A/B flighting) off
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\PolicyManager\current\device\System",
                "AllowExperimentation", 0)
            # Cap diagnostic log/dump collection + enhanced analytics
            data_collection = (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")
            for name in ("LimitDiagnosticLogCollection", "LimitDumpCollection",
                         "LimitEnhancedDiagnosticDataWindowsAnalytics",
                         # Limit optional-diagnostic configuration set (WGO)
                         "LimitDiagnosticDataConfigurationSet"):
                set_registry_dword("HKLM", data_collection, name, 1)
            # Microsoft 365 analytics commercial telemetry off (25H2
            # ADMX — Machine+User under the non-Policies-hive path)
            set_registry_dword(
                "HKLM", data_collection,
                "ConfigureTelemetryForMicrosoft365Analytics", 0)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion"
                r"\Policies\DataCollection",
                "ConfigureTelemetryForMicrosoft365Analytics", 0, logger)
            # MRT infection reports off
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\MRT",
                               "DontReportInfectionInformation", 1)
            # ReviOS telemetry.yml deep coverage: 32-bit policy mirror,
            # PolicyManager default-provider node, CPSS device/store
            # overrides (survive CSP re-sync), authenticated-proxy
            # telemetry block, IE CEIP
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
                "AllowTelemetry", 0)
            # NTVDM kill policy (same layer as legacy-feature off)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\AppCompat",
                               "VDMDisallowed", 1)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry",
                "value", 0)
            for sub, name in (("DevicePolicy", "DefaultValue"),
                              ("Store", "Value")):
                set_registry_dword(
                    "HKLM",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS"
                    + "\\" + sub + r"\AllowTelemetry", name, 0)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                "DisableEnterpriseAuthProxy", 1)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Internet Explorer\SQM",
                "DisableCustomerImprovementProgram", 1)
            # MS Security Baseline: block legacy IE COM automation
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Internet Explorer\Main",
                "DisableInternetExplorerLaunchViaCOM", 1)
            # IE service-powered quick-search suggestions off (25H2
            # ADMX Internet Explorer policy — Machine+User)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Internet Explorer",
                "AllowServicePoweredQSA", 0)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\Internet Explorer",
                "AllowServicePoweredQSA", 0, logger)
            # Speech model downloads off (voice data pipeline)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Speech_OneCore\Preferences",
                               "ModelDownloadAllowed", 0)
            # Always-on voice-listening master default off (privacy.sexy —
            # machine-wide default complementing the per-user writes)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Speech_OneCore\Preferences",
                               "VoiceActivationDefaultOn", 0)
            # "Sync your settings" off — stops settings roaming to MS accounts
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\SettingSync",
                               "DisableSettingSync", 2)
            # Dev-tool telemetry opt-outs — machine-wide env vars
            # (PowerShell + .NET CLI send diagnostics unless these are set)
            env_key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
            set_registry_string("HKLM", env_key, "POWERSHELL_TELEMETRY_OPTOUT", "1")
            set_registry_string("HKLM", env_key, "DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            # .NET strong crypto (TLS 1.2+) + strong-name bypass off
            for dn_root in (r"SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
                            r"SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"):
                set_registry_dword("HKLM", dn_root, "SchUseStrongCrypto", 1)
                set_registry_dword("HKLM", dn_root, "AllowStrongNameBypass", 0)
            # .NET v2.0.50727 sibling mirror — legacy runtime TLS opt-in
            # (milgradesec/windows-settings)
            for dn2 in (r"SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
                        r"SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"):
                set_registry_dword("HKLM", dn2, "SchUseStrongCrypto", 1)
            # Attack/diagnostics surface hardening (Atlas playbook): LLMNR off
            # (mDNS-spoofing vector), anonymous SAM/null-session enumeration off,
            # perf-scenario + RSOP + DiagTrack event-transcript data off
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                               "EnableMulticast", 0)
            # Smart name-resolution fallback off — same DNSClient policy
            # bucket (windows-hardening-scripts)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                               "DisableSmartNameResolution", 1)
            # IP source-routing + ICMP-redirect attack surface off
            # (windows-hardening-scripts)
            for tcp_root in (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                             r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"):
                set_registry_dword(
                    "HKLM", tcp_root, "DisableIPSourceRouting", 2)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                               "EnableICMPRedirect", 0)
            # Lock-screen network-picker off (windows-hardening-scripts)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "DontDisplayNetworkSelectionUI", 1)
            # LSASS access auditing on (windows-hardening-scripts)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
                               "AuditLevel", 8)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Lsa",
                               "RestrictAnonymous", 1)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Lsa",
                               "RestrictAnonymousSAM", 1)
            # Credential/protocol hardening (milgradesec/windows-settings):
            # no LM hashes stored, NTLMv2-only, DMA-under-lock off
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Lsa",
                               "NoLMHash", 1)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Lsa",
                               "LmCompatibilityLevel", 5)
            # Lsa anonymous-access + blank-password hardening (RegiLattice)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Lsa",
                               "EveryoneIncludesAnonymous", 0)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Lsa",
                               "NoDefaultAdminOwner", 1)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Lsa",
                               "LimitBlankPasswordUse", 1)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Lsa",
                               "SCENoApplyLegacyAuditPolicy", 1)
            # NTLM traffic restrict + audit (MSV1_0)
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
                "RestrictSendingNTLMTraffic", 2)
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
                "AuditReceivingNTLMTraffic", 2)
            # Command line in process-creation audit events
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
                "ProcessCreationIncludeCmdLine_Enabled", 1)
            # ARD off: no auto sign-in of last user after update restart
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "DisableAutomaticRestartSignOn", 1)
            # Hide last signed-in user name on the lock screen
            # (documented interactive-logon setting)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "DontDisplayLastUserName", 1)
            # Hide the user name entirely on the sign-in screen
            # (noverse.dev hide-last-logged-in-user)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "DontDisplayUserName", 1)
            # Account details hidden on the sign-in screen
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\System",
                "BlockUserFromShowingAccountDetailsOnSignin", 1)
            # Classic SQMClient upload kill (pre-policy CEIP channel)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\SQMClient",
                "UploadDisableFlag", 1)
            # License/activation telemetry — SPP generic ticket off
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
                "NoGenTicket", 1)
            # Per-app tagged-energy collection off (battery-usage
            # telemetry pipeline)
            for _v in ("TelemetryMaxApplication",
                       "TelemetryMaxTagPerApplication"):
                set_registry_dword(
                    "HKLM",
                    r"SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy",
                    _v, 0)
            # Local-account security questions off (documented GPO)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\System",
                "NoLocalPasswordResetQuestions", 1)
            # Password reveal button off on all credential dialogs
            # (documented GPO — MS security baseline)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\CredUI",
                "DisablePasswordReveal", 1)
            # Print Spooler remote-RPC endpoint off (PrintNightmare
            # class remote attack surface; local printing unaffected)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows NT\Printers",
                "RegisterSpoolerRemoteRpcEndPoint", 0)
            # Scheduled Diagnostics engine off (documented policy)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics",
                "EnabledExecution", 0)
            # Game Bar broadcast channel off (documented policy —
            # upload path, not recording)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\GameDVR",
                "AllowBroadcasting", 0)
            # App sharing of user name/picture/domain info off (GPO twin)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\System",
                "AllowUserInfoAccess", 2)
            # MRT infection-report suppression (scan still runs; kills
            # the diagnostic report back-channel — WindowsMize)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\MRT",
                "DontReportInfectionInformation", 1)
            # Diagnostic log + dump collection ceilings off
            for _v in ("LimitDiagnosticLogCollection",
                       "LimitDumpCollection"):
                set_registry_dword(
                    "HKLM",
                    r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                    _v, 1)
            # AppCompat: install-tracing + PCA assistant off
            for _v in ("DisableInstallTracing", "DisablePCA"):
                set_registry_dword(
                    "HKLM",
                    r"SOFTWARE\Policies\Microsoft\Windows\AppCompat",
                    _v, 1)
            # NT kernel diagnostic tracing off (documented value)
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Diagnostics\Performance",
                "DisableDiagnosticTracing", 1)
            # NVIDIA driver-level telemetry opt-out (NvTelemetryContainer
            # service is already demoted; these cover the driver knobs)
            for _v in ("SendTelemetryData", "SendNonNvDisplayDetails"):
                set_registry_dword(
                    "HKLM",
                    r"SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup",
                    _v, 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client",
                "OptInOrOutPreference", 0)
            # .NET CLI + PowerShell 7 telemetry opt-out (machine env
            # vars live in Session Manager\Environment — REG_SZ)
            for _v in ("DOTNET_CLI_TELEMETRY_OPTOUT",
                       "POWERSHELL_TELEMETRY_OPTOUT"):
                set_registry_string(
                    "HKLM",
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    _v, "1")
            # LMHOSTS lookup off (NetBT name-resolution side-channel)
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
                "EnableLMHOSTS", 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\FVE",
                "DisableExternalDMAUnderLock", 1)
            # RegiLattice diff: Dev Drive + WSL + cloud-TTS telemetry off,
            # no telemetry cache, no auto app archiving
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\DevDrive",
                "DisableTelemetry", 1)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss",
                "EnableTelemetry", 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Speech",
                "AllowCloudTTS", 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                "MaxTelemetryCacheSize", 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\Appx",
                "AllowAutomaticAppArchiving", 0)
            # SEHOP (structured-exception chain validation) + safe DLL
            # search order (session-manager kernel hardening)
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel",
                "DisableExceptionChainValidation", 0)
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                "SafeDllSearchMode", 1)
            # WDigest plaintext-credential caching off + WPAD auto-discovery
            # off (proxy-poisoning vector) — WinRice hardening
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest",
                "UseLogonCredential", 0)
            # RPC authenticated endpoint resolution, external DMA-device
            # enumeration block, encrypted memory dumps (Win-Debloat7
            # Security module — documented policies)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
                "EnableAuthEpResolution", 1)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
                "RestrictRemoteClients", 1)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection",
                "DeviceEnumerationPolicy", 1)
            set_registry_dword(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                "EnableDumpEncryption", 1)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
                               "RestrictNullSessAccess", 1)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}",
                               "ScenarioExecutionEnabled", 0)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "RSoPLogging", 0)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey",
                               "EnableEventTranscript", 0)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey",
                               "MiniTraceSlotEnabled", 0)
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Diagnostics\Performance",
                               "DisableDiagnosticTracing", 1)
            # Device Health Attestation + speech-model auto-download +
            # cloud message-sync channels off
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService",
                               "EnableDeviceHealthAttestationService", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Speech",
                               "AllowSpeechModelUpdate", 0)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\Messaging",
                               "AllowMessageSync", 0)
            # Maps: no background network traffic for Settings-page
            # content (winscript)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Maps",
                "AllowUntriggeredNetworkTrafficOnSettingsPage", 0)
            # SettingSync extras — deeper kills on the same toggle
            ss = r"SOFTWARE\Policies\Microsoft\Windows\SettingSync"
            set_registry_dword("HKLM", ss, "DisableSettingSyncUserOverride", 1)
            set_registry_dword("HKLM", ss, "DisableSyncOnPaidNetwork", 1)
            set_registry_dword("HKLM", ss, "DisableWindowsSettingSync", 2)
            # Per-category sync kills — app settings + credentials never roam
            # to the Microsoft account (hellzerg/Optimizer privacy diff)
            for n, v in (("DisableApplicationSettingSync", 2),
                         ("DisableApplicationSettingSyncUserOverride", 1),
                         ("DisableCredentialsSettingSync", 2),
                         ("DisableCredentialsSettingSyncUserOverride", 1),
                         ("DisableWebBrowserSettingSync", 2),
                         ("DisableWebBrowserSettingSyncUserOverride", 1),
                         ("DisableStartLayoutSettingSync", 2),
                         ("DisableStartLayoutSettingSyncUserOverride", 1),
                         ("DisablePersonalizationSettingSync", 2),
                         ("DisablePersonalizationSettingSyncUserOverride", 1),
                         ("DisableDesktopThemeSettingSync", 2),
                         ("DisableDesktopThemeSettingSyncUserOverride", 1),
                         ("DisableAppSyncSettingSync", 2),
                         ("DisableAppSyncSettingSyncUserOverride", 1),
                         ("DisableWindowsSettingSyncUserOverride", 1)):
                set_registry_dword("HKLM", ss, n, v)
            # Device-level sync override kill (RegiLattice v6.35.0)
            set_registry_dword("HKLM", ss, "DisableSettingSyncDeviceOverride", 1)
            # Text-input linguistic data collection + Bluetooth device
            # advertising off (hellzerg/Optimizer privacy diff)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput",
                "AllowLinguisticDataCollection", 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth",
                "AllowAdvertising", 0)
            # Machine-side typing-insight + handwriting prediction kills
            # (per-user copies already covered) + WiFi Sense hotspot
            # reporting/auto-connect family (ReviOS privacy/misc)
            ins = r"SOFTWARE\Microsoft\Input\Settings"
            for v in ("InsightsEnabled", "EnableHwkbTextPrediction"):
                set_registry_dword("HKLM", ins, v, 0)
            set_registry_dword("HKLM", r"SOFTWARE\Microsoft\Input\TIPC",
                               "Enabled", 0)
            wcm = r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager"
            for v in ("PaidWifi", "WiFiSenseOpen"):
                set_registry_dword("HKLM", wcm + r"\features", v, 0)
            # Wi-Fi Sense credential sharing (soswod/Windows-On-Reins)
            set_registry_dword(
                "HKLM", wcm + r"\features", "WiFiSenseCredShared", 0)
            set_registry_dword("HKLM", wcm + r"\config",
                               "AutoConnectAllowedOEM", 0)
            # Wi-Fi profile sync to MS cloud off + hotspot sharing off
            # (RegiLattice wificonn)
            set_registry_dword("HKLM", wcm + r"\config",
                               "WiFiConfigSyncDisabled", 1)
            set_registry_dword("HKLM", wcm + r"\config",
                               "WiFiSharingEnabled", 0)
            wifi = r"SOFTWARE\Microsoft\PolicyManager\default\WiFi"
            for p in ("AllowAutoConnectToWiFiSenseHotspots",
                      "AllowWiFiHotSpotReporting"):
                set_registry_dword("HKLM", wifi + "\\" + p, "value", 0)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\SettingSync",
                "SyncPolicy", 5, logger)
            # Per-user stragglers: CDM master switches + usage instrumentation +
            # handwriting/typing insight collection
            cdm = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            set_user_dword_all_hives(cdm, "FeatureManagementEnabled", 0, logger)
            set_user_dword_all_hives(cdm, "SubscribedContentEnabled", 0, logger)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoInstrumentation", 1, logger)
            set_user_dword_all_hives(
                r"Software\Microsoft\Input\Settings",
                "InsightsEnabled", 0, logger)
            # CEIP policy + feedback nag prompts
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\SQMClient\Windows",
                               "CEIPEnable", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                               "DoNotShowFeedbackNotifications", 1)
            # OneSettings download kill at the DataCollection alias path,
            # recent-items graph off (noid-privacy)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                               "DisableOneSettingsDownloads", 1)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
                               "DisableGraphRecentItems", 1)
            # Per-user policy-level tailored-experiences lock (stronger
            # than the setting-level kill — locks the toggle)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\Windows\CloudContent",
                "DisableTailoredExperiencesWithDiagnosticData", 1, logger)
            # CDP master + Windows Backup cloud-sync kills (noid-privacy)
            sys_pol = r"SOFTWARE\Policies\Microsoft\Windows\System"
            set_registry_dword("HKLM", sys_pol, "EnableCdp", 0)
            # Phone Link (MMX) + apps-for-websites URI handoff off
            # (documented System policies — noverse.dev)
            set_registry_dword("HKLM", sys_pol, "EnableMmx", 0)
            set_registry_dword("HKLM", sys_pol, "EnableAppUriHandlers", 0)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\SettingSync",
                "EnableWindowsBackup", 0)
            # Windows Backup shell UI suppression (Debloat-Win11)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsBackup",
                "DisableBackupUI", 1)
            # Cloud-backup + nag-notification policy kills (RegiLattice v6.35.0)
            bkup = r"SOFTWARE\Policies\Microsoft\Windows\Backup"
            set_registry_dword("HKLM", bkup, "DisableCloudBackup", 1)
            set_registry_dword("HKLM", bkup, "DisableBackupNotifications", 1)
            # Windows Backup nag notifications off per user (SysAdminDoc)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\WindowsBackup",
                "NotificationDisabled", 1, logger)
            # Smart Clipboard per-user kill (Debloat-Win11)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard",
                "Disabled", 1, logger)
            # OneDrive: feedback/sync-health reporting + pre-sign-in
            # traffic (policy kills only — OneDrive itself untouched)
            od_pol = r"SOFTWARE\Policies\Microsoft\OneDrive"
            set_registry_dword("HKLM", od_pol, "EnableSyncAdminReports", 0)
            set_registry_dword("HKLM", od_pol, "EnableFeedbackAndSupport", 0)
            set_registry_dword("HKLM", od_pol, "PreventNetworkTrafficPreUserSignIn", 1)
            # Suppress the "your telemetry setting changed" nag + hide the
            # telemetry level picker UX entirely (ReviOS parity)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                               "DisableTelemetryOptInChangeNotification", 1)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                               "DisableTelemetryOptInSettingsUx", 1)
            # Commercial data pipeline, device name in telemetry, Edge data
            # opt-in — ReviOS privacy/telemetry.yml parity
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                               "AllowCommercialDataPipeline", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                               "AllowDeviceNameInTelemetry", 0)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                               "MicrosoftEdgeDataOptIn", 0)
            # Documented Policy-CSP-System DataCollection kills
            # (hateblo/coolvitto list): analytics-processing + device-
            # name-in-diag + managed-desktop + update-compliance + WUfB
            # cloud processing off, diagnostic-data-viewer surface off,
            # OneSettings auditing off, enhanced-diag-data limited
            dc = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            for dn, dv in (("AllowDesktopAnalyticsProcessing", 0),
                           ("AllowDeviceNameInDiagnosticData", 0),
                           ("AllowMicrosoftManagedDesktopProcessing", 0),
                           ("AllowUpdateComplianceProcessing", 0),
                           ("AllowWUfBCloudProcessing", 0),
                           ("DisableDiagnosticDataViewer", 1),
                           ("EnableOneSettingsAuditing", 0),
                           ("LimitEnhancedDiagnosticDataWindowsAnalytics", 1)):
                set_registry_dword("HKLM", dc, dn, dv)
            # Online font-provider downloads off (Policy CSP - System)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "EnableFontProviders", 0)
            # OOBE in-setup update pulls off (Policy CSP - System)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\OOBE",
                               "AllowOOBEUpdates", 0)
            # Cap the diagnostic level at Security/Basic even if a component
            # or update re-raises AllowTelemetry later (Sophia Script parity)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                               "MaxTelemetryAllowed", 1)
            # OneSettings periodic config download (recommendations channel)
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\OneSettings",
                               "DisableOneSettingsFileDownloads", 1)
            # Store: never auto-update apps + no OS-upgrade offers via Store
            # (ReviOS updates/ms-store.yml)
            store = r"SOFTWARE\Policies\Microsoft\WindowsStore"
            set_registry_dword("HKLM", store, "AutoDownload", 4)
            set_registry_dword("HKLM", store, "DisableOSUpgrade", 1)
            # Legacy (non-policy) sibling for pre-policy hosts (speedup-windows10)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate",
                "AutoDownload", 2)
            # Block the OOBE updater that pushes "New Outlook" via WU
            # (ReviOS updates.yml)
            set_registry_string(
                "HKLM",
                r"SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe",
                "BlockedOobeUpdaters", '["MS_Outlook"]')
            # Media Creation Tool promo link in Windows Update settings
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                               "HideMCTLink", 1)
            # Feature-upgrade offer nag (ReviOS updates.yml)
            set_registry_dword("HKLM",
                               r"SYSTEM\Setup\UpgradeNotification",
                               "UpgradeAvailable", 0)
            # WMP legacy auto-update channel (dead on modern builds)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer",
                               "DisableAutoUpdate", 1)
            # WMP online metadata lookups (windowsmedia.com) — per-user policy
            # (Disassembler Win10-Initial-Setup-Script)
            wmp = r"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
            for _v in ("PreventCDDVDMetadataRetrieval",
                       "PreventMusicFileMetadataRetrieval",
                       "PreventRadioPresetsRetrieval"):
                set_user_dword_all_hives(wmp, _v, 1, logger)
            # "Share across devices" (Connected Devices Platform) consent off
            cdp = r"Software\Microsoft\Windows\CurrentVersion\CDP"
            set_user_dword_all_hives(cdp, "CdpSessionUserAuthzPolicy", 0, logger)
            # CDP session-user override off — same auth family
            # (Titanium-OS-Suite)
            set_user_dword_all_hives(cdp, "CdpSessionUserOverride", 0, logger)
            # Share drag tray off (Raphire 2026.06): suppresses the CDP
            # share surface that appears while dragging files
            set_user_dword_all_hives(cdp, "DragTrayEnabled", 0, logger)
            # Remote-launch toast off — same per-user CDP surface
            # (noverse.dev cross-device-experiences)
            set_user_dword_all_hives(cdp, "EnableRemoteLaunchToast", 0, logger)
            set_user_dword_all_hives(cdp, "RomeSdkChannelUserAuthzPolicy", 0, logger)
            set_user_dword_all_hives(cdp + r"\SettingsPage",
                                     "RomeSdkChannelUserAuthzPolicy", 0, logger)
            # Nearby Share consent — same CDP auth-policy family
            set_user_dword_all_hives(cdp + r"\SettingsPage",
                                     "NearShareChannelUserAuthzPolicy", 0, logger)
            # Cross-Device Resume off (unslop-windows): MDM PolicyManager
            # gate stops sihost spawning CrossDeviceResumeHost at logon
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume",
                               "value", 1)
            resume = (r"Software\Microsoft\Windows\CurrentVersion"
                      r"\CrossDeviceResume\Configuration")
            set_user_dword_all_hives(resume, "IsResumeAllowed", 0, logger)
            set_user_dword_all_hives(resume, "IsOneDriveResumeAllowed", 0, logger)
            # Per-user policy stragglers (ReviOS privacy.yml): Explorer online
            # wizards, Help & Support feedback channel, EdgeUI MFU tracking,
            # NVIDIA CEIP opt-out
            user_exp = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            for v in ("NoOnlinePrintsWizard", "NoPublishingWizard",
                      "NoWebServices"):
                set_user_dword_all_hives(user_exp, v, 1, logger)
            assist = r"Software\Policies\Microsoft\Assistance\Client\1.0"
            for v in ("NoExplicitFeedback", "NoImplicitFeedback",
                      "NoOnlineAssist"):
                set_user_dword_all_hives(assist, v, 1, logger)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\Windows\EdgeUI",
                "DisableMFUTracking", 1, logger)
            set_user_dword_all_hives(
                r"Software\NVIDIA Corporation\NVControlPanel2\Client",
                "OptInOrOutPreference", 0, logger)
            # AMD Customer Experience Program opt-out (Reclaim vendor
            # telemetry): HKLM AMD CN hive
            set_registry_dword("HKLM", r"SOFTWARE\AMD\CN",
                               "UserExperienceProgram", 0)
            logger.info("Applied: DisableTelemetry (AllowTelemetry=0, DiagTrack off, "
                        "privacy surfaces set)")
            # Deprecated TLS 1.0/1.1 protocols off (Winnow/BSI guidance):
            # weak-protocol surface removal — Enabled=0 + DisabledByDefault=1
            for _tls in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
                for _end in ("Client", "Server"):
                    _p = (r"SYSTEM\CurrentControlSet\Control\SecurityProviders"
                          r"\SCHANNEL\Protocols" + "\\" + _tls + "\\" + _end)
                    set_registry_dword("HKLM", _p, "Enabled", 0)
                    set_registry_dword("HKLM", _p, "DisabledByDefault", 1)

        except Exception as e:
            logger.warning(f"DisableTelemetry layer failed: {e}")
    if prev.get("DisableGameDvr", True):
        try:
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\GameDVR",
                               "AllowGameDVR", 0)
            set_user_dword_all_hives(_USER_GAME_CONFIG_STORE, "GameDVR_Enabled", 0, logger)
            set_user_dword_all_hives(_USER_GAME_DVR, "AppCaptureEnabled", 0, logger)
            # Game Bar nags: Nexus overlay hook + startup panel
            set_user_dword_all_hives(r"Software\Microsoft\GameBar", "UseNexusForGameBarEnabled", 0, logger)
            set_user_dword_all_hives(r"Software\Microsoft\GameBar", "ShowStartupPanel", 0, logger)
            set_user_dword_all_hives(r"Software\Microsoft\GameBar", "GamePanelStartupTipIndex", 3, logger)
            # ms-gamebar/ms-gamebarservices protocol hijack (Win11Debloat):
            # NoOpenWith + a dead handler command kills the "get Game Bar"
            # popup that games trigger when the app is removed
            for proto in ("ms-gamebar", "ms-gamebarservices"):
                base = rf"SOFTWARE\Classes\{proto}"
                set_registry_string("HKLM", base, "", f"URL:{proto}")
                set_registry_string("HKLM", base, "URL Protocol", "")
                set_registry_string("HKLM", base, "NoOpenWith", "")
                set_registry_string("HKLM", base + r"\shell\open\command",
                                    "", r"%SystemRoot%/System32/systray.exe")
            logger.info("Applied: DisableGameDvr (AllowGameDVR=0, GameDVR_Enabled=0, "
                        "AppCaptureEnabled=0)")

        except Exception as e:
            logger.warning(f"DisableGameDvr layer failed: {e}")
    if prev.get("DisableDeliveryOptimization", True):
        try:
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
                               "DODownloadMode", 0)
            set_user_dword_all_hives(_USER_DELIVERY_OPT, "DownloadMode", 0, logger)
            # The DoSvc service still auto-starts for CDN fetches — demote it too
            demote_service("DoSvc")
            # The Delivery Optimization service reads the NETWORK SERVICE hive (S-1-5-20)
            try:
                key = winreg.CreateKeyEx(
                    winreg.HKEY_USERS, "S-1-5-20\\" + _USER_DELIVERY_OPT, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "DownloadMode", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
            except Exception:
                pass
            logger.info("Applied: DisableDeliveryOptimization (DODownloadMode=0)")

        except Exception as e:
            logger.warning(f"DisableDeliveryOptimization layer failed: {e}")
    if prev.get("DisableOneDrive", False):
        try:
            set_registry_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
                               "DisableFileSyncNGSC", 1)
            # Hide the OneDrive pin in Explorer's navigation pane for every user
            set_user_dword_all_hives(_USER_ONEDRIVE_CLSID, "System.IsPinnedToNameSpaceTree", 0, logger)
            # OneDrive's own standalone updaters — stop them alongside the sync
            for t in ("OneDrive Standalone Update Task",
                      "OneDrive Per-Machine Standalone Update Task"):
                run_cmd(["schtasks", "/Change", "/TN", t, "/Disable"], timeout=15)
            logger.info("Applied: DisableOneDrive (DisableFileSyncNGSC=1, nav pin hidden, update tasks off)")

        except Exception as e:
            logger.warning(f"DisableOneDrive layer failed: {e}")
    if prev.get("DisableChatTaskbar", True):
        try:
            set_user_dword_all_hives(_USER_EXPLORER_ADV, "TaskbarMn", 0, logger)
            set_user_dword_all_hives(_USER_POLICIES_EXPLORER, "HideSCAMeetNow", 1, logger)
            # "My People" taskbar button (contact-promo surface)
            set_user_dword_all_hives(_USER_EXPLORER_ADV, "PeopleBand", 0, logger)
            # Machine policy kills the Chat integration itself (icon toggle
            # only hides it) — tiny11builder Windows Chat policy
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Windows Chat",
                "ChatIcon", 3)
            logger.info("Applied: DisableChatTaskbar (TaskbarMn=0, HideSCAMeetNow=1, PeopleBand=0, ChatIcon=3)")

        except Exception as e:
            logger.warning(f"DisableChatTaskbar layer failed: {e}")
    if prev.get("DisableEdgeBloat", True):
        try:
            edge_pol = r"SOFTWARE\Policies\Microsoft\Edge"
            set_registry_dword("HKLM", edge_pol, "HubsSidebarEnabled", 0)
            # Copilot surfaces inside Edge — chat icon, address-bar/NTP
            # suggestions, browse-with-Copilot, M365 link interception,
            # visual search (noid-privacy AntiAI edge group)
            for name in ("Microsoft365CopilotChatIconEnabled",
                         "CopilotAddressBarSuggestionsEnabled",
                         "CopilotNewTabPageEnabled",
                         "AllowBrowsingWithCopilot",
                         "M365LinksAutoOpenCopilotEnabled",
                         "VisualSearchEnabled",
                         # Address-bar trending suggestions + reading-mode
                         # cloud extraction upload (noid-privacy EdgePolicies)
                         "AddressBarTrendingSuggestEnabled",
                         "EdgeReadingModeServiceBasedExtractionEnabled",
                         # URL-keyed "anonymized" browsing-data uploads
                         # (winutil tweaks.json Edge group)
                         "UrlKeyedAnonymizedDataCollectionEnabled",
                         "LocalBrowserDataShareEnabled", "GuidSwitchEnabled",
                         "CredentialProviderPromoEnabled",
                         "OutlookHubMenuEnabled",
                         "MicrosoftOfficeMenuEnabled",
                         # first-run taskbar-pin wizard suppression (Reclaim)
                         "EnableUnsafeSwiftShader", "PinningWizardAllowed",
                         "AllowSurfGame",
                         # Edge desktop-analytics telemetry (WGO)
                         "ConfigureTelemetryForDesktop",
                         # Cloud management enrollment + shopping assistant +
                         # Workspaces collaboration surface (Edge policy docs)
                         "EdgeManagementEnabled",
                         "ShoppingInEdgeEnabled",
                         "EdgeWorkspaceEnabled",
                         # M365 Copilot inline-compose (Rewrite) surface
                         # (MS Learn Edge policy docs; eplord Win-Debloat7)
                         "ComposeInlineEnabled"):
                set_registry_dword("HKLM", edge_pol, name, 0)
            # NTP background restricted to off/theme-only (3 = no custom
            # imagery feeds; Reclaim Edge catalog)
            set_registry_dword("HKLM", edge_pol,
                               "NewTabPageAllowedBackgroundTypes", 3)
            # Edge search-provider suggestions upload (soswod SearchScopes)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes",
                "ShowSearchSuggestionsGlobal", 0)
            set_registry_dword("HKLM", edge_pol, "StartupBoostEnabled", 0)
            set_registry_dword("HKLM", edge_pol, "AllowPrelaunch", 0)
            set_registry_dword("HKLM", edge_pol, "HideFirstRunExperience", 1)
            # Background-mode keep-alive, startup autolaunch and per-URL
            # diagnostic upload (W1X-Debloat)
            set_registry_dword("HKLM", edge_pol, "BackgroundModeEnabled", 0)
            set_registry_dword(
                "HKLM", edge_pol, "LaunchEdgeOnWindowsStartupEnabled", 0)
            set_registry_dword("HKLM", edge_pol, "UrlDiagnosticDataEnabled", 0)
            # Shopping assistant, recommendations, error-page web service,
            # user feedback — all upload/suggestion surfaces
            for name in ("EdgeShoppingAssistantEnabled",
                         "ShowRecommendationsEnabled",
                         "ResolveNavigationErrorsUseWebService",
                         "AlternateErrorPagesEnabled",
                         "UserFeedbackAllowed",
                         # URL-leak surfaces: omnibox suggestions + nav-error web
                         # services + site-safety look-ups all send URLs to MS
                         "SearchSuggestEnabled",
                         "AddressBarMicrosoftSearchInBingProviderEnabled",
                         "SiteSafetyServicesEnabled",
                         # Cross-device collection/Follow feeds
                         "EdgeCollectionsEnabled",
                         "EdgeFollowEnabled",
                         # privacy.sexy Edge-policy diff — promo/feed/telemetry
                         # surfaces: ads suppression, Discover/enhance feeds,
                         # metrics reporting, site-info upload (deprecated but
                         # still read), rewards/sign-in nags, NTP spotlight,
                         # sidebar variant, games menu, in-app support,
                         # Acrobat promo, web widget autostart, searchbar,
                         # ECS experimentation
                         "DiscoverPageContextEnabled",
                         "EdgeDiscoverEnabled", "EdgeEnhanceImagesEnabled",
                         # Discover hub kill (CoPilot-Cleaner)
                         "DiscoverHubEnabled",
                         "MetricsReportingEnabled",
                         "RelatedMatchesCloudServiceEnabled",
                         "SendSiteInfoToImproveServices",
                         "ShowMicrosoftRewards", "SignInCtaOnNtpEnabled",
                         "SpotlightExperiencesAndRecommendationsEnabled",
                         "StandaloneHubsSidebarEnabled", "AllowGamesMenu",
                         "InAppSupportEnabled", "ShowAcrobatSubscriptionButton",
                         "WebWidgetIsEnabledOnStartup", "SearchbarAllowed",
                         "SearchbarIsEnabledOnStartup",
                         "ExperimentationAndConfigurationServiceControl",
                         # Debloat-Win11 Edge diff — Copilot master + NTP AI
                         # prompt + crash uploads + Wallet/gamer/travel
                         # promo surfaces + migration nag + Office
                         # favorites-bar shortcut + mini search menu
                         "EdgeCopilotEnabled", "NewTabPageBingAIPromptEnabled",
                         "CrashReportingMode",
                         "EdgeWalletEnabled", "EdgeWalletCheckoutEnabled",
                         "GamerModeEnabled", "TravelAssistanceEnabled",
                         "ShowBrowserMigrationPrompt",
                         "ShowOfficeShortcutInFavoritesBar",
                         "QuickSearchShowMiniMenu"):
                set_registry_dword("HKLM", edge_pol, name, 0)
            # Documented policy suppresses Bing ads when ENABLED (=1)
            set_registry_dword("HKLM", edge_pol, "BingAdsSuppressionEnabled", 1)
            # 2 = never predict/pre-resolve via Microsoft web service
            set_registry_dword("HKLM", edge_pol, "NetworkPredictionOptions", 2)
            # Promo tabs + desktop web widget (feature/promo surfaces)
            set_registry_dword("HKLM", edge_pol, "PromotionalTabsEnabled", 0)
            set_registry_dword("HKLM", edge_pol, "WebWidgetAllowed", 0)
            # xd-AntiSpy diff: launch-time browser-data import, default-browser
            # nag, NTP sponsored quick links
            for name in ("ImportOnEachLaunch", "DefaultBrowserSettingEnabled",
                         "NewTabPageQuickLinksEnabled",
                         # NTP prerender off — stops background feed prefetch
                         # (WinOpt)
                         "NewTabPagePrerenderEnabled"):
                set_registry_dword("HKLM", edge_pol, name, 0)
            # Drop syncs files to OneDrive; crypto wallet + asset delivery service
            # are promo/feature-download surfaces
            for name in ("DropEnabled", "CryptoWalletEnabled",
                         "EdgeAssetDeliveryServiceEnabled",
                         # Insider-program promo + donation-wallet promos
                         "MicrosoftEdgeInsiderPromotionEnabled",
                         "WalletDonationEnabled"):
                set_registry_dword("HKLM", edge_pol, name, 0)
            # Send the DoNotTrack header (harmless privacy signal)
            set_registry_dword("HKLM", edge_pol, "ConfigureDoNotTrack", 1)
            # Edge AI surface (zoicware/RemoveWindowsAI policy set): page-context
            # Copilot, inline compose, history AI search, generated themes,
            # DevTools AI (2 = disabled), browsing-history sharing with Copilot
            for name in ("CopilotPageContext", "EdgeEntraCopilotPageContext",
                         "EdgeHistoryAISearchEnabled", "ComposeInlineEnabled",
                         "BuiltInAIAPIsEnabled", "AIGenThemesEnabled",
                         "ShareBrowsingHistoryWithCopilotSearchAllowed",
                         # Copilot+ connected-page context + NTP Bing chat
                         # (Raphire/Win11Debloat Edge AI diff)
                         "CopilotCDPPageContext", "NewTabPageBingChatEnabled",
                         # 3rd-party SERP telemetry (hellzerg/Optimizer)
                         "Edge3PSerpTelemetryEnabled"):
                set_registry_dword("HKLM", edge_pol, name, 0)
            set_registry_dword("HKLM", edge_pol, "DevToolsGenAiSettings", 2)
            # 1 = disable the local on-device foundation model used by Edge AI
            set_registry_dword("HKLM", edge_pol, "GenAILocalFoundationalModelSettings", 1)
            # NTP content feed + default-browser campaign nag + tab services
            # (Raphire/Win11Debloat Edge ads/suggestions diff)
            for name in ("NewTabPageContentEnabled", "TabServicesEnabled",
                         "DefaultBrowserSettingsCampaignEnabled"):
                set_registry_dword("HKLM", edge_pol, name, 0)
            # 1 = hide the sponsored top-sites tile row on new tabs
            set_registry_dword("HKLM", edge_pol, "NewTabPageHideDefaultTopSites", 1)
            logger.info("Applied: DisableEdgeBloat (sidebar/startup-boost/"
                        "prelaunch/first-run/shopping/recommendations/AI off)")

        except Exception as e:
            logger.warning(f"DisableEdgeBloat layer failed: {e}")
    if prev.get("DisableStartupBloat", True):
        try:
            disable_startup_bloat(config, logger)

        except Exception as e:
            logger.warning(f"DisableStartupBloat layer failed: {e}")
    if prev.get("DisableErrorReporting", True):
        try:
            wer = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting"
            wer_policy = r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
            set_registry_dword("HKLM", wer, "Disabled", 1)
            set_registry_dword("HKLM", wer, "DontSendAdditionalData", 1)
            set_registry_dword("HKLM", wer_policy, "Disabled", 1)
            set_registry_dword("HKLM", wer_policy, "AutoApproveOSDumps", 0)
            # WER report archiving off (25H2 ADMX — Machine+User)
            set_registry_dword("HKLM", wer_policy, "DisableArchive", 1)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\Windows"
                r"\Windows Error Reporting",
                "DisableArchive", 1, logger)
            # WER consent policy — default deny + lock the user out of
            # re-consenting (ReviOS privacy/wer.yml)
            set_registry_dword("HKLM", wer + r"\Consent", "DefaultConsent", 0)
            set_registry_dword("HKLM", wer + r"\Consent", "DefaultOverrideBehavior", 1)
            set_user_dword_all_hives(_USER_WER, "Disabled", 1, logger)
            set_user_dword_all_hives(_USER_WER, "DontShowUI", 1, logger)
            set_user_dword_all_hives(_USER_WER, "LoggingDisabled", 1, logger)
            # PCHealth reporting + CBS/drive-install WER spill channels (Atlas)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting",
                               "DoReport", 0)
            # ReviOS privacy.yml: HelpSvc online-help fetch channels off
            for name in ("Headlines", "MicrosoftKBSearch"):
                set_registry_dword(
                    "HKLM",
                    r"SOFTWARE\Policies\Microsoft\PCHealth\HelpSvc",
                    name, 0)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
                               "DisableWerReporting", 1)
            di = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings"
            set_registry_dword("HKLM", di, "DisableSendGenericDriverNotFoundToWER", 1)
            set_registry_dword("HKLM", di, "DisableSendRequestAdditionalSoftwareToWER", 1)
            # WER support service + companion → demand-start
            for svc in ("wercplsupport",):
                demote_service(svc)
            logger.info("Applied: DisableErrorReporting (WER uploads + UI + logging off)")

        except Exception as e:
            logger.warning(f"DisableErrorReporting layer failed: {e}")
    if prev.get("DisableEdgeUpdateBloat", True):
        try:
            for svc in ("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService"):
                demote_service(svc)
            # Scheduled tasks re-arm the services — disable them too
            for task in ("MicrosoftEdgeUpdateTaskMachineCore",
                         "MicrosoftEdgeUpdateTaskMachineUA",
                         "MicrosoftEdgeUpdateBrowserReplacementTask"):
                run_cmd(["schtasks.exe", "/Change", "/TN", task, "/DISABLE"], timeout=15)
            # EdgeUpdate channel GUIDs — installer drops desktop shortcuts on
            # every update; the policy suppresses them (Sophia Script
            # PreventEdgeShortcutCreation)
            edgeupd = r"SOFTWARE\Policies\Microsoft\EdgeUpdate"
            for guid in ("{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
                         "{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
                         "{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
                         "{65C35B14-6C1D-4122-AC46-7148CC9D6497}"):
                set_registry_dword("HKLM", edgeupd, f"CreateDesktopShortcut{guid}", 0)
            # Suppress the Edge desktop shortcut Windows updates recreate
            # (Disassembler Win10-Initial-Setup-Script)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                               "DisableEdgeDesktopShortcutCreation", 1)
            logger.info("Applied: DisableEdgeUpdateBloat "
                        "(edgeupdate/edgeupdatem/elevation → demand, update tasks off, "
                        "shortcut creation suppressed)")

        except Exception as e:
            logger.warning(f"DisableEdgeUpdateBloat layer failed: {e}")
    if prev.get("BlockOemDriverUpdates", True):
        try:
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                               "ExcludeWUDriversInQualityUpdate", 1)
            # Device Metadata channel off — OEM companion apps ship through it
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
                               "PreventDeviceMetadataFromNetwork", 1)
            # Never search Windows Update for drivers on new hardware either
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
                               "SearchOrderConfig", 0)
            # GPO twin: policy-pinned "do not search WU for drivers"
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\DriverSearching",
                               "DontSearchWindowsUpdate", 1)
            # SMB guest auth off + Schannel secure-renegotiation floor
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                               "AllowInsecureGuestAuth", 0)
            for _v in ("AllowInsecureRenegoClients", "AllowInsecureRenegoServers"):
                set_registry_dword("HKLM",
                                   r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
                                   _v, 0)
            _dh = (r"SYSTEM\CurrentControlSet\Control\SecurityProviders"
                   r"\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman")
            for _v in ("ClientMinKeyBitLength", "ServerMinKeyBitLength"):
                set_registry_dword("HKLM", _dh, _v, 2048)
            # Vendor driver co-installers — the channel that seeds OEM
            # companion apps alongside driver packages
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer",
                               "DisableCoInstallers", 1)
            logger.info("Applied: BlockOemDriverUpdates "
                        "(ExcludeWUDriversInQualityUpdate=1)")

        except Exception as e:
            logger.warning(f"BlockOemDriverUpdates layer failed: {e}")
    if prev.get("DisableAppPermissions", True):
        try:
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
                "LetAppsAccessGenerativeAI", "LetAppsAccessCalendar",
                "LetAppsAccessGraphicsCaptureProgrammatic",
                "LetAppsAccessGraphicsCaptureWithoutBorder",
                # Newer sensor/AI capabilities (Espionage724 App
                # Permissions Deny)
                "LetAppsAccessGazeInput",
                "LetAppsAccessHumanPresence",
                "LetAppsAccessBackgroundSpatialPerception",
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
            # systemAIModels consent-store usage recording off (zoicware)
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                r"\CapabilityAccessManager\Capabilities\systemAIModels",
                "RecordUsageData", 0)
            # Paint targeting opt-out + getting-started suppression (zoicware)
            _pv = (r"Software\Microsoft\Windows\CurrentVersion"
                   r"\Applets\Paint\View")
            set_user_dword_all_hives(_pv, "IsSignedUpForTargetingService", 0, logger)
            set_user_dword_all_hives(_pv, "LeftTargetingService", 1, logger)
            set_user_dword_all_hives(_pv, "IsNotInterestedInTargetingService", 1, logger)
            for _pvf in ("GettingStartedWelcomePageViewed",
                         "GettingStartedStickerGeneratorPageViewed",
                         "GettingStartedGenerativeImageEditPageViewed",
                         "GettingStartedGenerativeErasePageViewed",
                         "GettingStartedGenerativeFillPageViewed",
                         "GettingStartedImageCreatorPageViewed",
                         "GettingStartedCocreatorPageViewed"):
                set_user_dword_all_hives(_pv, _pvf, 1, logger)
            # Notepad store banner/recommendation off (zoicware, Reclaim)
            for _nv in ("ShowStoreBanner", "ShowStoreRecommendation"):
                set_user_dword_all_hives(
                    r"Software\Microsoft\Notepad", _nv, 0, logger)
            # Startup-impact toast off (Reclaim)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer",
                "StartupNotify", 0, logger)
            logger.info(f"Applied: DisableAppPermissions ({len(app_privacy)} "
                        "force-denied + ad-ID/FindMyDevice policies)")

        except Exception as e:
            logger.warning(f"DisableAppPermissions layer failed: {e}")
    if prev.get("DisablePrintSpooler", False):
        try:
            # Opt-in — kills the PrintNightmare surface but breaks printing
            run_cmd(["sc.exe", "stop", "Spooler"], timeout=15)
            run_cmd(["sc.exe", "config", "Spooler", "start=", "disabled"], timeout=15)
            logger.info("Applied: DisablePrintSpooler (Spooler stopped + disabled)")

        except Exception as e:
            logger.warning(f"DisablePrintSpooler layer failed: {e}")
    if prev.get("DisableModernStandbyNetworking", False):
        try:
            # Opt-in — documented power policy (ConnectivityInStandby) that
            # severs network connectivity during Modern Standby: stops
            # background sync/telemetry while asleep on S0 systems
            standby = (r"SOFTWARE\Policies\Microsoft\Power\PowerSettings"
                       r"\f15576e8-98b7-4186-b944-eafa664402d9")
            set_registry_dword("HKLM", standby, "ACSettingIndex", 0)
            set_registry_dword("HKLM", standby, "DCSettingIndex", 0)
            logger.info("Applied: DisableModernStandbyNetworking")

        except Exception as e:
            logger.warning(f"DisableModernStandbyNetworking layer failed: {e}")
    if prev.get("BlockOemWpbtExecution", True):
        try:
            # WPBT: OEMs inject executables into the boot chain via UEFI
            # (abused e.g. by ASUS Live Update) — DisableWpbtExecution makes
            # Windows ignore the table
            set_registry_dword("HKLM",
                               r"SYSTEM\CurrentControlSet\Control\Session Manager",
                               "DisableWpbtExecution", 1)
            logger.info("Applied: BlockOemWpbtExecution (WPBT disabled)")

        except Exception as e:
            logger.warning(f"BlockOemWpbtExecution layer failed: {e}")
    if prev.get("DisableReservedStorage", True):
        try:
            # Free the ~7GB reserved for updates (they use free space pre-1903 style)
            reserve = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager"
            for name, val in (("ShippedWithReserves", 0),
                              ("MiscPolicyInfo", 2), ("PassedPolicy", 0)):
                set_registry_dword("HKLM", reserve, name, val)
            logger.info("Applied: DisableReservedStorage (ReserveManager)")

        except Exception as e:
            logger.warning(f"DisableReservedStorage layer failed: {e}")
    if prev.get("DisableCloudClipboard", True):
        try:
            # Local history stays usable; stop the cloud sync of copied content
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\System",
                               "AllowCrossDeviceClipboard", 0)
            set_user_dword_all_hives(
                r"Software\Microsoft\Clipboard",
                "EnableClipboardHistory", 0, logger)
            # No automatic upload of clipboard contents (WGO)
            set_user_dword_all_hives(
                r"Software\Microsoft\Clipboard",
                "CloudClipboardAutomaticUpload", 0, logger)
            # Per-user cloud-clipboard switch (LeDragoX WinDebloatTools)
            set_user_dword_all_hives(
                r"Software\Microsoft\Clipboard",
                "EnableCloudClipboard", 0, logger)
            # Suggested clipboard AI actions off (Winnow ExtendedAIPurge)
            set_user_dword_all_hives(
                r"Software\Microsoft\Clipboard",
                "EnableSuggestedClipboardActions", 0, logger)
            logger.info("Applied: DisableCloudClipboard")

        except Exception as e:
            logger.warning(f"DisableCloudClipboard layer failed: {e}")
    if prev.get("DisableRemoteAssistance", True):
        try:
            # Inbound help-request offers off
            for name in ("fAllowToGetHelp", "fAllowFullControl"):
                set_registry_dword(
                    "HKLM",
                    r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
                    name, 0)
            logger.info("Applied: DisableRemoteAssistance")

        except Exception as e:
            logger.warning(f"DisableRemoteAssistance layer failed: {e}")
    if prev.get("BlockInsiderPreview", True):
        try:
            # Preview builds ship heavier telemetry + instability
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds",
                               "AllowBuildPreview", 0)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility",
                               "HideInsiderPage", 1)
            # Insider diagnostic-data nag strings blanked (speedup-windows10)
            for _sv in ("DiagnosticErrorText", "DiagnosticLinkText"):
                set_registry_string(
                    "HKLM", r"SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings",
                    _sv, "")
            set_registry_dword(
                "HKLM",
                r"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds",
                "ManagePreviewBuildsPolicyValue", 0)
            logger.info("Applied: BlockInsiderPreview")

        except Exception as e:
            logger.warning(f"BlockInsiderPreview layer failed: {e}")
    if prev.get("DisableXboxServices", True):
        try:
            # Demand-start (Start=3) — Game Bar/Xbox sign-in still work on demand
            for svc in ("XblAuthManager", "XblGameSave",
                        "XboxNetApiSvc", "XboxGipSvc"):
                demote_service(svc)
            # Neuter the Xbox GamingAI companion host's WinRT activation —
            # ActivationType=0xffffffff + empty Server stops GameAssist
            # (ReviOS privacy.yml)
            gai = (r"SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId"
                   r"\Microsoft.Xbox.GamingAI.Companion.Host."
                   r"GamingCompanionHostOptions")
            set_registry_dword("HKLM", gai, "ActivationType", 0xFFFFFFFF)
            set_registry_string("HKLM", gai, "Server", "")
            # 0 = never allow SmartGlass (Xbox companion phone-app) connections
            # (Optimizer privacy diff)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass",
                               "UserAuthPolicy", 0)
            logger.info("Applied: DisableXboxServices (4 services -> demand-start)")

        except Exception as e:
            logger.warning(f"DisableXboxServices layer failed: {e}")
    if prev.get("DisableMiscBloatServices", True):
        try:
            # Demand-start (Start=3) — all stay usable when actually invoked.
            # Vendor services absent from the machine are skipped (open, not create).
            for svc in _MISC_DEMOTE_SERVICES:
                demote_service(svc)
            # Remote Registry: remote registry read/write over SMB — disabled
            # outright (demand-start would still leave the surface reachable)
            run_cmd(["sc.exe", "stop", "RemoteRegistry"], timeout=15)
            run_cmd(["sc.exe", "config", "RemoteRegistry", "start=", "disabled"], timeout=15)
            logger.info("Applied: DisableMiscBloatServices "
                        f"({len(_MISC_DEMOTE_SERVICES)} services -> "
                        "demand-start, RemoteRegistry disabled)")

        except Exception as e:
            logger.warning(f"DisableMiscBloatServices layer failed: {e}")
    if prev.get("DisableSpotlight", True):
        try:
            # Desktop Spotlight = content-delivery channel (wallpaper promos)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings",
                "Enabled", 0, logger)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers",
                "BackgroundType", 0, logger)
            # Spotlight-on-welcome onboarding surface
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement",
                "ShowSpotlightOnWelcome", 0, logger)
            # "Learn about this picture" desktop icon — Spotlight promo
            # surface (Win-Debloat: GUID under NewStartPanel hidden-icons)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel",
                "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}", 1, logger)
            # Per-hive CloudContent policies — block Spotlight features + the
            # per-user collection feeding them
            cloud = r"Software\Policies\Microsoft\Windows\CloudContent"
            for name in ("DisableWindowsSpotlightFeatures",
                         "DisableSpotlightCollectionOnDesktop",
                         "DisableWindowsSpotlightOnDesktop",
                         "DisableSoftLanding",
                         # Welcome experience / Action Center / Settings pages
                         "DisableWindowsSpotlightWindowsWelcomeExperience",
                         "DisableWindowsSpotlightOnActionCenter",
                         "DisableWindowsSpotlightOnSettings"):
                set_user_dword_all_hives(cloud, name, 1, logger)
            # Enterprise Spotlight content off — inverse polarity (ledr)
            set_user_dword_all_hives(
                cloud, "IncludeEnterpriseSpotlight", 0, logger)
            # Organizational-messages feed off per user (25H2 ADMX
            # CloudContent — User class only)
            set_user_dword_all_hives(
                cloud, "EnableOrganizationalMessages", 0, logger)
            # Phone→PC notification mirroring off per user (25H2 ADMX
            # PushNotifications — User class only)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\Windows\CurrentVersion"
                r"\PushNotifications",
                "DisallowNotificationMirroring", 1, logger)
            # Location hidden in Settings region page per user (25H2
            # ADMX Control Panel International — User class only)
            set_user_dword_all_hives(
                r"Software\Policies\Microsoft\Control Panel\International",
                "HideCurrentLocation", 1, logger)
            # Lock-screen overlay promos + Settings online tips + Start
            # recommended-sites promo (mxk group-policy diff)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
                "LockScreenOverlaysDisabled", 1)
            set_registry_dword(
                "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
                "DisableWindowsSpotlightOnLockScreen", 1)
            expol = r"SOFTWARE\Policies\Microsoft\Windows\Explorer"
            set_registry_dword("HKLM", expol, "AllowOnlineTips", 0)
            set_registry_dword("HKLM", expol,
                               "HideRecommendedPersonalizedSites", 1)
            logger.info("Applied: DisableSpotlight "
                        "(DesktopSpotlight + wallpaper + per-hive CloudContent)")

        except Exception as e:
            logger.warning(f"DisableSpotlight layer failed: {e}")
    if prev.get("DisableAutoplay", True):
        try:
            # NoDriveTypeAutoRun=255 + NoAutorun=1 — media auto-execute off
            pol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            set_registry_dword("HKLM", pol, "NoDriveTypeAutoRun", 255)
            set_registry_dword("HKLM", pol, "NoAutorun", 1)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun", 255, logger)
            logger.info("Applied: DisableAutoplay")

        except Exception as e:
            logger.warning(f"DisableAutoplay layer failed: {e}")
    if prev.get("NoForcedReboot", True):
        try:
            # Never force-reboot while a user is logged on
            au = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            set_registry_dword("HKLM", au, "NoAutoRebootWithLoggedOnUsers", 1)
            set_registry_dword("HKLM", au, "AlwaysAutoRebootAtScheduledTime", 0)
            logger.info("Applied: NoForcedReboot (WU reboot policy)")

        except Exception as e:
            logger.warning(f"NoForcedReboot layer failed: {e}")
    if prev.get("HideStartRecommendations", True):
        try:
            # Start "Recommended" section — promoted apps surface (22H2+)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
                               "HideRecommendedSection", 1)
            # Start "Recently added" list — same HKLM Explorer policy hive
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
                               "HideRecentlyAddedApps", 1)
            # Start "Frequently used" list — sibling Explorer policy
            # (dvandenburgh/Disable-Win11AI)
            set_registry_dword("HKLM",
                               r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
                               "HideFrequentlyUsedApps", 1)
            # The section draws from recent-doc tracking — stop collecting it
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                "Start_TrackDocs", 0, logger)
            # Explorer recent-docs history policy kill (Reclaim)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoRecentDocsHistory", 1, logger)
            # Phone Link companion panel in Start (mobile-device promo surface)
            set_user_dword_all_hives(
                r"Software\Microsoft\Windows\CurrentVersion\Start\Companions"
                r"\Microsoft.YourPhone_8wekyb3d8bbwe",
                "IsEnabled", 0, logger)
            logger.info("Applied: HideStartRecommendations")
        except Exception as e:
            logger.warning(f"HideStartRecommendations layer failed: {e}")


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
    user_run32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    user_runonce32 = \
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
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

    def _scan(root, run_path, approved_path, peer_path=None):
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
            # StartupApproved markers are name-keyed and shared between the
            # 64-bit and 32-bit registry views; don't stamp a name that an
            # unmatched entry in the peer view also uses, or the marker would
            # disable that non-bloat entry as well.
            if peer_path is not None and targets:
                blocked = []
                try:
                    peer = winreg.OpenKey(root, peer_path)
                except OSError:
                    peer = None
                if peer is not None:
                    try:
                        i = 0
                        while True:
                            try:
                                pname, pdata, _ = winreg.EnumValue(peer, i)
                                i += 1
                                if pname.lower() in (t.lower() for t in targets) \
                                        and not _is_bloat(pname, pdata):
                                    blocked.append(pname)
                            except OSError:
                                break
                    finally:
                        peer.Close()
                for b in blocked:
                    logger.info(
                        f"Skipped startup marker for '{b}': same-named "
                        "non-bloat entry exists in the paired 32/64-bit view")
                targets = [t for t in targets
                           if t.lower() not in (b.lower() for b in blocked)]
            if not targets:
                return
            try:
                ap_key = winreg.CreateKeyEx(root, approved_path, 0,
                                            winreg.KEY_WRITE)
            except OSError as e:
                logger.warning(
                    f"Cannot write startup-approved markers for "
                    f"{run_path}: {e}")
                return
            try:
                for name in targets:
                    try:
                        winreg.SetValueEx(ap_key, name, 0, winreg.REG_BINARY,
                                          _STARTUP_DISABLED_MARKER)
                    except OSError as e:
                        logger.warning(
                            f"Could not disable startup entry {name}: {e}")
                        continue
                    applied += 1
                    logger.info(f"Disabled startup entry: {name}")
            finally:
                ap_key.Close()
        finally:
            run_key.Close()

    machine_runonce32 = \
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    _scan(winreg.HKEY_LOCAL_MACHINE, machine_run, approved, machine_run32)
    _scan(winreg.HKEY_LOCAL_MACHINE, machine_run32, approved, machine_run)
    _scan(winreg.HKEY_LOCAL_MACHINE, machine_runonce, approved_once,
          machine_runonce32)
    # 32-bit view of RunOnce — same StartupApproved marker semantics
    _scan(winreg.HKEY_LOCAL_MACHINE, machine_runonce32, approved_once,
          machine_runonce)

    def _scan_user(root, prefix):
        p = (prefix + "\\") if prefix else ""
        _scan(root, p + user_run, p + approved, p + user_run32)
        _scan(root, p + user_run32, p + approved, p + user_run)
        _scan(root, p + user_runonce, p + approved_once, p + user_runonce32)
        _scan(root, p + user_runonce32, p + approved_once, p + user_runonce)

    for_each_user_hive(_scan_user, logger)

    # Explorer\Run policy keys — an autostart vector Task Manager never
    # lists and StartupApproved can't mark, so matching values are removed
    # outright (data logged for manual restore). HKLM + every user hive.
    def _purge_policy_run(root, policy_path):
        nonlocal applied
        try:
            key = winreg.OpenKey(root, policy_path, 0,
                                 winreg.KEY_READ | winreg.KEY_SET_VALUE)
        except OSError:
            return
        try:
            targets = []
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    i += 1
                    if _is_bloat(name, data):
                        targets.append((name, data))
                except OSError:
                    break
            for name, data in targets:
                try:
                    winreg.DeleteValue(key, name)
                except OSError as e:
                    logger.warning(
                        f"Could not remove policy-run entry {name}: {e}")
                    continue
                applied += 1
                logger.info(f"Removed policy-run autostart: "
                            f"{name} (was: {data})")
        finally:
            key.Close()

    _purge_policy_run(winreg.HKEY_LOCAL_MACHINE,
                      r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                      r"\Policies\Explorer\Run")

    user_policy_run = (r"Software\Microsoft\Windows\CurrentVersion"
                       r"\Policies\Explorer\Run")

    def _purge_user(root, prefix):
        p = (prefix + "\\") if prefix else ""
        _purge_policy_run(root, p + user_policy_run)

    for_each_user_hive(_purge_user, logger)

    # Startup folders aren't governed by StartupApproved — match the same
    # needles against filenames and rename to .bgdisabled (restorable;
    # deleting would lose the restore path)
    startup_dirs = []
    for env_var in ("APPDATA", "ProgramData"):
        base = os.environ.get(env_var)
        if base:
            startup_dirs.append(
                os.path.join(base,
                             r"Microsoft\Windows\Start Menu\Programs\Startup"))
    for folder in startup_dirs:
        try:
            for fname in os.listdir(folder):
                fpath = os.path.join(folder, fname)
                if (fname.lower().endswith(".bgdisabled") or
                        not os.path.isfile(fpath) or
                        not _is_bloat(fname, None)):
                    continue
                os.rename(fpath, fpath + ".bgdisabled")
                applied += 1
                logger.info(f"Disabled startup folder item: {fname}")
        except OSError:
            continue
    # Active Setup stub installers — re-run at EVERY user sign-in
    disable_active_setup_stubs(config, logger)

    logger.info(f"Applied: DisableStartupBloat ({applied} entries)")


# ─── Reprovisioning Prevention ────────────────────────────────────────────────

_DEPROVISIONED_PATH = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx"
                       r"\AppxAllUserStore\Deprovisioned")
_EOL_PATH = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx"
             r"\AppxAllUserStore\EndOfLife")
_REMOVE_DEFAULT_PKGS_PATH = (r"SOFTWARE\Policies\Microsoft\Windows\Appx"
                             r"\RemoveDefaultMicrosoftStorePackages")


def _provisioned_family(package_name: str, display_name: str) -> str:
    """Get-AppxProvisionedPackage returns no PublisherId — the publisher is the
    last '_' segment of PackageName. The package name is
    Name_version_arch_[resourceid_]_publisher and the name itself may contain
    underscores — split the four well-formed suffix fields off the RIGHT end."""
    segs = package_name.split('_')
    if len(segs) >= 5:
        return '_'.join(segs[:-4]) + '_' + segs[-1]
    if "_" in package_name:
        return f"{package_name.split('_')[0]}_{package_name.rsplit('_', 1)[-1]}"
    return display_name


def mark_deprovisioned(family_names, logger: logging.Logger) -> int:
    """Write HKLM Deprovisioned markers for blacklisted families so feature
    updates don't re-provision them (documented Windows behavior). Also mark
    the families EndOfLife so the Store itself declines reinstall
    (GDStudiosDev/fortify — the EOL marker Windows writes for retired inbox
    apps like Cortana)."""
    import winreg
    bases = []
    for path in (_DEPROVISIONED_PATH, _EOL_PATH):
        try:
            bases.append(winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                            path, 0, winreg.KEY_WRITE))
        except OSError as e:
            logger.warning(f"Deprovisioned markers: cannot open HKLM key ({e})")
            bases.append(None)
    marked = 0
    try:
        for family in family_names:
            try:
                # CreateKey returns an open handle — close it or the service
                # loop leaks a native registry handle every interval
                for base in bases:
                    if base is not None:
                        winreg.CreateKey(base, family).Close()
                marked += 1
            except OSError:
                continue
    finally:
        for base in bases:
            if base is not None:
                base.Close()
    return marked


def apply_remove_default_store_packages(family_names, logger: logging.Logger) -> bool:
    """Windows 11 25H2 policy: the OS itself removes the listed default Store
    packages at first sign-in of NEW user profiles. Unknown entries are ignored
    by older builds — harmless forward-compat.

    The documented mechanism is a subkey per package family name with
    RemovePackage=1, plus DynamicRemovalList (REG_MULTI_SZ) for families the
    GPO UI does not enumerate (zoicware/RemoveWindowsAI, appxpackagemanager
    .admx)."""
    import winreg
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                 _REMOVE_DEFAULT_PKGS_PATH, 0,
                                 winreg.KEY_READ | winreg.KEY_WRITE)
        # Merge with existing entries — a family removed in an earlier scan
        # must stay listed or new users get it re-provisioned.
        try:
            prior = list(winreg.QueryValueEx(key, "DynamicRemovalList")[0])
        except OSError:
            prior = []
        # Migrate any names an older build recorded in the non-standard
        # PackageList value before dropping it, so they stay listed.
        try:
            legacy_raw = winreg.QueryValueEx(key, "PackageList")[0]
            if isinstance(legacy_raw, (list, tuple)):
                legacy = list(legacy_raw)
            else:
                legacy = [p for p in re.split(r"[;,\r\n]+", str(legacy_raw))
                          if p.strip()]
        except OSError:
            legacy = []
        # Case-insensitive dedup (family names are case-insensitive in Appx
        # — C# merges with OrdinalIgnoreCase; keep first-seen casing)
        seen = set()
        merged = []
        for f in list(prior) + legacy + list(family_names):
            f = f.strip()
            if f and f.lower() not in seen:
                seen.add(f.lower())
                merged.append(f)
        winreg.SetValueEx(key, "Enabled", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "DynamicRemovalList", 0,
                          winreg.REG_MULTI_SZ, merged)
        # Older builds of this tool wrote a non-standard PackageList value —
        # drop it so only the documented mechanism remains.
        try:
            winreg.DeleteValue(key, "PackageList")
        except OSError:
            pass
        for family in merged:
            try:
                sub = winreg.CreateKey(key, family)
                winreg.SetValueEx(sub, "RemovePackage", 0,
                                  winreg.REG_DWORD, 1)
                sub.Close()
            except OSError:
                continue
        winreg.CloseKey(key)
        logger.info(f"Applied: RemoveDefaultStorePackages "
                    f"({len(merged)} families listed)")
        return True
    except Exception as e:
        logger.warning(f"RemoveDefaultStorePackages: {e}")
        return False


# ─── Telemetry Endpoint Block (hosts file) ───────────────────────────────────

# Pure-telemetry endpoints null-routed via the hosts file — the Spybot
# Anti-Beacon technique. Conservative: no Windows Update/Store/activation.
_TELEMETRY_HOSTS = (
    "vortex.data.microsoft.com", "vortex-win.data.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "telecommand.telemetry.microsoft.com.nsatc.net",
    "oca.telemetry.microsoft.com", "oca.telemetry.microsoft.com.nsatc.net",
    "sqm.telemetry.microsoft.com",
    "sqm.ppe.telemetry.microsoft.com", "sqm.telemetry.microsoft.com.nsatc.net",
    "watson.telemetry.microsoft.com", "watson.telemetry.microsoft.com.nsatc.net",
    "watson.ppe.telemetry.microsoft.com", "watson.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com", "wes.df.telemetry.microsoft.com",
    "services.wes.df.telemetry.microsoft.com", "sqm.df.telemetry.microsoft.com",
    "settings-win.data.microsoft.com", "settings.data.microsoft.com",
    "statsfe2.ws.microsoft.com", "redir.metaservices.microsoft.com",
    # RealSyferX/windows-11-debloat diff — app-experience bing telemetry,
    # UAP telemetry, telemetry redirection, activity-feed upload
    "telemetry.appex.bing.com", "telemetry-uap.microsoft.com",
    "redirection.telemetry.microsoft.com", "prod.activity.windows.com",
    # MS "manage connections" endpoint doc: Connected Devices Platform API
    # (already policy/service-killed — server-side reinforcement) and the
    # device-metadata service (PreventDeviceMetadataFromNetwork channel)
    "api.cdp.microsoft.com", "msedge.api.cdp.microsoft.com",
    "dmd.metaservices.microsoft.com",
    "choice.microsoft.com", "choice.microsoft.com.nsatc.net",
    "telemetry.appex.bing.net", "telemetry.urs.microsoft.com",
    "feedback.microsoft-hohm.com", "vortex-bn2.metron.live.com.nsatc.net",
    # *.events.data.microsoft.com — Vortex/ARIA event ingest (Win10+
    # universal telemetry pipeline; v10/v20 suffixes + WER/Edge variants)
    "v10.events.data.microsoft.com", "v20.events.data.microsoft.com",
    "browser.events.data.microsoft.com", "umwatsonc.events.data.microsoft.com",
    "watson.events.data.microsoft.com", "survey.watson.microsoft.com",
    # Office/ARIA telemetry pipe + diagnostics report upload endpoint
    "mobile.pipe.aria.microsoft.com", "diagnostics.support.microsoft.com",
    # *.events.data.microsoft.com regional/v10c ingest variants (hagezi
    # dns-blocklists + MS Learn non-Enterprise endpoint doc; same ARIA pipe)
    "self.events.data.microsoft.com", "v10c.events.data.microsoft.com",
    "au-v10.events.data.microsoft.com", "eu-v10.events.data.microsoft.com",
    "jp-v10.events.data.microsoft.com", "us-v10.events.data.microsoft.com",
    "au-v10c.events.data.microsoft.com", "eu-v10c.events.data.microsoft.com",
    "jp-v10c.events.data.microsoft.com", "us-v10c.events.data.microsoft.com",
    # Timeline activity-history sync (ActivityFeedPolicy disabled in policy)
    "activity.windows.com",
    # Office diagnostics upload endpoint
    "api.diagnostics.office.com",
    # DiagTrack ingest FQDNs actually queried by the Connected User
    # Experiences service — vortex-win.data.microsoft.com above is the
    # CNAME base, the live endpoints carry v10/v20 prefixes
    "v10.vortex-win.data.microsoft.com", "v20.vortex-win.data.microsoft.com",
    # BSI (German federal) telemetry endpoint list — vortex/ARIA
    # ingest regional + akadns + sandbox variants
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
    # universal events ingest + Office diagnostics fronts + MSN arc
    "events.data.microsoft.com",
    "pipe.dev.trafficmanager.net",
    # Device Directory Service + CDP certificate fronts (gdid-guard
    # device-graph endpoints — the IdentityCRL/CDP registration channel)
    "dds.microsoft.com",
    "fd.dds.microsoft.com",
    "cdpcs.access.microsoft.com",
    "diagnostics.office.com",
    "cjs-diagnostics-office-com-gvdhgwfwbbfsd9g3.z01.azurefd.net",
    "arc.msn.com",
    # MSN/CDN tracking + location inference + WU stats alias (eplord
    # Win-Debloat7 + classic spy-blocker lists)
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
    # Desktop/Edge counterpart of the mobile ARIA pipe above
    "browser.pipe.aria.microsoft.com", "us.pipe.aria.microsoft.com", "eu.pipe.aria.microsoft.com",
    "az.pipe.aria.microsoft.com", "v20c.events.data.microsoft.com", "functional.events.data.microsoft.com",
    "aimodels.microsoft.com", "models.microsoft.com", "directml.microsoft.com", "aifabric.microsoft.com",
    "copilot.microsoft.com", "sydney.bing.com", "edgeservices.bing.com", "onesettings-public.azureedge.net",
    "onesettings-bn2.azureedge.net", "onesettings-co2.azureedge.net", "widgetcdn.azureedge.net", "shell.msn.com",
    "assets.msn.com", "umwatson.events.data.microsoft.com", "nw-umwatson.events.data.microsoft.com",
    "kmwatson.events.data.microsoft.com", "kmwatsonc.events.data.microsoft.com", "df.telemetry.microsoft.com",
    "alpha.telemetry.microsoft.com", "telemetry.microsoft.com", "ca.telemetry.microsoft.com", "watson.live.com",
    "eu-v20.events.data.microsoft.com", "us-v20.events.data.microsoft.com", "eu.vortex-win.data.microsoft.com",
    "us.vortex-win.data.microsoft.com", "eu.vortex.data.microsoft.com",
    "server6.pipe.aria.microsoft.com", "server7.pipe.aria.microsoft.com",
    "browser.events.data.msn.com",
    "ic3.events.data.microsoft.com", "mobile.events.data.microsoft.com",
    "teams.events.data.microsoft.com",
    # WindowsSpyBlocker data/hosts/spy.txt diff — sandbox/PPE telemetry
    # environments, activity pipeline, residual Cortana/Edge-offer calls,
    # legacy IE web service (capability removed), GameDVR asset CDN
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
    # Azure Data Lake diagnostic ingest front (WindowsSpyBlocker
    # spy ruleset)
    "adl.windows.com",
    "adbroker.mp.dse.microsoft.com",
    "adsystem.microsoft.com",
    "api.msn.com",
    "asimov.settings.data.microsoft.com.akadns.net",
    "business.bing.com",
    "c.bing.com",
    "cdnprod.myanalytics.microsoft.com",
    "ceuswatcab01.blob.core.windows.net",
    "ceuswatcab02.blob.core.windows.net",
    "clarity-ingest-eus2-b-sc.eastus2.cloudapp.azure.com",
    "co4.telecommand.telemetry.microsoft.com",
    "cy2.vortex.data.microsoft.com",
    "dc.applicationinsights.azure.com",
    "dc.applicationinsights.microsoft.com",
    "eaus2watcab01.blob.core.windows.net",
    "eaus2watcab02.blob.core.windows.net",
    "eu-office.events.data.microsoft.com",
    "eu-watsonc.events.data.microsoft.com",
    "events.vungle.akadns.net",
    "fd.api.iris.microsoft.com",
    "insider.windows.com",
    "insideruser.microsoft.com",
    "iris-de-ppe-azsc-v2-wus2.westus2.cloudapp.azure.com",
    "iris-de-prod-azsc-v2-wus2.westus2.cloudapp.azure.com",
    "iris-de-prod-azsc-wus2-b.westus2.cloudapp.azure.com",
    "iris-de-prod-azsc-wus2.westus2.cloudapp.azure.com",
    "kmwatsonc.telemetry.microsoft.com",
    "microsoft.geo.appnexusgslb.net",
    "microsoftmscompoc.tt.omtrdc.net",
    "modern.watson.data.microsoft.com",
    "myanalytics-gcc.microsoft.com",
    "ntp.msn.com",
    "oca.microsoft.com",
    "onecollector.cloudapp.aria.akadns.net",
    "prod-w.nexus.live.com.akadns.net",
    "prod.nexusrules.live.com.akadns.net",
    "ris.api.iris.microsoft.com.akadns.net",
    "solitaireevents.microsoftcasualgames.com",
    "sqmfe.glbdns2.microsoft.com",
    "srtb.msn.com",
    "umwatsonc.telemetry.microsoft.com",
    "v10.vortex-win.data.metron.life.com.nsatc.net",
    "weus2watcab01.blob.core.windows.net",
    "weus2watcab02.blob.core.windows.net",
    "xblgdvrassets3010.blob.core.windows.net",
    # Ad-delivery endpoints serving MSN/Edge/widget surfaces
    "adnxs.com", "m.adnxs.com", "secure.adnxs.com", "adnexus.net",
    "a.ads1.msn.com", "a.ads2.msn.com", "b.ads1.msn.com", "ads.msn.com",
    "ads1.msn.com",  # MSN ad delivery (eplord Win-Debloat7 hosts)
    "g.msn.com",     # MSN telemetry/tracking beacon
    "g.msn.com.nsatc.net",
    "search.msn.com",  # MSN search-redirect (Start-search query leak)
    "ads1.msads.net", "a.ads2.msads.net", "bingads.microsoft.com",
    "a.rad.msn.com", "b.rad.msn.com", "ac3.msn.com", "live.rads.msn.com",
    "bs.serving-sys.com", "msntest.serving-sys.com",
    "secure.flashtalking.com",
    "aidps.atdmt.com", "c.atdmt.com", "cdn.atdmt.com",
    "db3aqu.atdmt.com", "ec.atdmt.com", "view.atdmt.com",
    "aka-cdn-ns.adtech.de", "pre.footprintpredict.com",
    # Ad/feedback ingestion (DisableWinTracking diff)
    "ad.doubleclick.net", "s0.2mdn.net", "static.2mdn.net",
    "b.ads2.msads.net", "compatexchange.cloudapp.net",
    "feedback.search.microsoft.com", "feedback.windows.com",
    # bloatbox/W4RH4WK extended-hosts diff: nsatc/akadns aliases,
    # insider/flighting rings, social services, ad/AN nets
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
    "apac.rel.msn.com",
)
_HOSTS_BLOCK_BEGIN = "# >>> BloatwareGuard telemetry block"
_HOSTS_BLOCK_END = "# <<< BloatwareGuard telemetry block"


def _hosts_file_path() -> Path:
    return (Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32" / "drivers" / "etc" / "hosts")


def set_telemetry_hosts_block(enabled: bool, logger: logging.Logger) -> None:
    """Add/remove a marked hosts block that null-routes pure-telemetry
    endpoints. Toggle-off removes it — fully reversible. No-ops when disabled
    and no block exists."""
    hosts = _hosts_file_path()
    try:
        # Strict decode — silently replacing undecodable bytes would corrupt
        # unrelated hosts content on rewrite. Skip rather than write garbage.
        text = hosts.read_text(encoding="utf-8") if hosts.exists() else ""
    except (OSError, UnicodeDecodeError) as e:
        logger.warning(f"Cannot read hosts file (skipped): {e}")
        return
    original = text  # single read — a second read could fail on absent file

    begin = text.find(_HOSTS_BLOCK_BEGIN)
    end = text.find(_HOSTS_BLOCK_END)
    if begin >= 0 and end >= 0:
        text = (text[:begin].rstrip("\n") + "\n"
                + text[end + len(_HOSTS_BLOCK_END):].lstrip("\n"))
    if enabled:
        block = "\n".join(f"0.0.0.0 {d}" for d in _TELEMETRY_HOSTS)
        text = (text.rstrip("\n")
                + f"\n\n{_HOSTS_BLOCK_BEGIN}\n{block}\n{_HOSTS_BLOCK_END}\n")
    if begin == -1 and not enabled:
        return  # nothing to do — don't touch the file
    if hosts.exists() and text == original:
        return  # already in the desired state
    try:
        _atomic_write_text(hosts, text)
        state = "applied" if enabled else "removed"
        logger.info(f"Telemetry hosts block {state} ({len(_TELEMETRY_HOSTS)} domains)")
    except OSError as e:
        logger.warning(f"Cannot write hosts file (admin required?): {e}")


# ─── winget sweep ────────────────────────────────────────────────────────────

def winget_sweep(config: dict, logger: logging.Logger) -> int:
    """Uninstall blacklist entries that look like winget package ids via
    `winget uninstall --silent --disable-interactivity`. Catches Store apps
    winget can see but Get-AppxPackage can't."""
    if shutil.which("winget") is None:
        logger.info("winget not found — skipping winget sweep")
        return 0
    removed = 0
    whitelist = config.get("Whitelist", [])
    for entry in config.get("Blacklist", []):
        e = (entry or "").strip()
        if "." not in e or not _WINGET_ID_RE.fullmatch(e):
            continue
        # Whitelist still wins — a protected entry never reaches winget
        if any(w.strip() and w.strip().lower() in e.lower() for w in whitelist):
            logger.info(f"Whitelisted (winget skip): {e}")
            continue
        _, rc = run_cmd(["winget", "uninstall", "-e", "--id", e,
                         "--silent", "--disable-interactivity",
                         "--accept-source-agreements"], timeout=300)
        if rc == 0:
            logger.info(f"winget removed: {e}")
            record_removal(config, {"kind": "winget", "name": e})
            removed += 1
    if removed:
        logger.info(f"Applied: WingetSweep ({removed} packages)")
    return removed


# ─── Active Setup sweep ──────────────────────────────────────────────────────

# OEM stub installers that re-run at EVERY user sign-in
_ACTIVE_SETUP_PATHS = (
    r"SOFTWARE\Microsoft\Active Setup\Installed Components",
    r"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components",
)


def disable_active_setup_stubs(config: dict, logger: logging.Logger) -> int:
    """Delete Active Setup 'Installed Components' entries whose key name,
    display value, LocalizedName or StubPath matches a bloat needle."""
    import winreg
    whitelist = config.get("Whitelist", [])
    needles = [s for s in list(config.get("Blacklist", []))
               + list(_STARTUP_BLOAT_NAMES) if s and s.strip()]

    def _bloat(text):
        t = text.lower()
        if any(w and w.strip().lower() in t for w in whitelist):
            return False
        return any(n.lower() in t for n in needles)

    deleted = 0
    for path in _ACTIVE_SETUP_PATHS:
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                  winreg.KEY_READ | winreg.KEY_WRITE)
        except OSError:
            continue
        try:
            subs, i = [], 0
            while True:
                try:
                    subs.append(winreg.EnumKey(root, i))
                    i += 1
                except OSError:
                    break
            for sub in subs:
                try:
                    sk = winreg.OpenKey(root, sub)
                    parts = [sub]
                    for val in ("", "StubPath", "LocalizedName"):
                        try:
                            parts.append(str(winreg.QueryValueEx(sk, val)[0]))
                        except OSError:
                            pass
                    sk.Close()
                    if not _bloat(" ".join(parts)):
                        continue
                    winreg.DeleteKey(root, sub)
                    deleted += 1
                    logger.info(f"Deleted Active Setup stub: {sub} ({path})")
                except OSError:
                    continue
        finally:
            root.Close()
    if deleted:
        logger.info(f"Applied: Active Setup sweep ({deleted} stubs deleted)")
    return deleted


# ─── Extended ETW AutoLogger kill ────────────────────────────────────────────

# Boot-time ETW trace sessions that feed telemetry (privacy.sexy / Sophia
# Script technique). Diagtrack-Listener is already covered by DisableTelemetry;
# kept here too for idempotence when only this layer is on.
_EXTRA_AUTOLOGGERS = (
    "AutoLogger-Diagtrack-Listener", "SQMLogger", "WiFiSession",
    "LwtNetLog", "NetCore", "NtfsLog", "UBPM", "MellonTelemetry",
    "Circular Kernel Context Logger", "DiagLog", "WFP-IPsec Diagnostics",
    "RadioManager", "SetupPlatformTel",
    # optimizerDuck diff: appx-activation model trace, cellular OEM
    # capture, OOBE/CloudExperience trace, DataMarket share-in-use,
    # WDI diagnostic context log
    "AppModel", "Cellcore", "CloudExperienceHostOobe", "DataMarket",
    "WdiContextLog",
)

# Diagnostic ETW event-log channels feeding power/sleep diagnostics —
# Enabled=0 under WINEVT\Channels (the wevtutil sl /e:false mechanism,
# noverse.dev sleep-study doc). Same open-only convention as AutoLoggers.
_EXTRA_DIAG_CHANNELS = (
    "Microsoft-Windows-SleepStudy/Diagnostic",
    "Microsoft-Windows-Kernel-Processor-Power/Diagnostic",
    "Microsoft-Windows-UserModePowerService/Diagnostic",
)


def disable_telemetry_autologgers(logger: logging.Logger) -> int:
    """Start=0 on telemetry ETW AutoLoggers plus Enabled=0 on diagnostic
    ETW channels. Opens — never creates — each key, so absent sessions
    don't get phantom entries."""
    import winreg
    killed = 0
    for session in _EXTRA_AUTOLOGGERS:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\{session}",
                0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            killed += 1
        except OSError:
            continue
    channels = 0
    for channel in _EXTRA_DIAG_CHANNELS:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SOFTWARE\Microsoft\Windows\CurrentVersion"
                rf"\WINEVT\Channels\{channel}",
                0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "Enabled", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            channels += 1
        except OSError:
            continue
    logger.info(f"Applied: DisableTelemetryAutologgers "
                f"({killed}/{len(_EXTRA_AUTOLOGGERS)} sessions, "
                f"{channels}/{len(_EXTRA_DIAG_CHANNELS)} channels)")
    return killed


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
        "Customer Experience Improvement|Reinstall|Restore|Bloatware|"
        "Intel|Realtek|Waves|MSI|Razer|AMD|AUEP"
    )
    ps_cmd = (
        f"Get-ScheduledTask | "
        f"Where-Object {{$_.TaskPath -like '*OEM*' -or $_.TaskName -match '{patterns}'}} | "
        f"Select-Object TaskName,TaskPath,State | ConvertTo-Json"
    )
    # 120s — parity with C# Proc.Capture(120000); large task lists on slow
    # machines can exceed a minute
    stdout, _, rc = run_powershell(ps_cmd, timeout=120)

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
            out, ret = run_cmd(["schtasks", "/Change", "/TN", full_path, "/DISABLE"], timeout=15)
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
    # "Exp" variant shipped on newer builds — same telemetry role
    "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser Exp",
    "\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
    # Chkdsk Proxy — event-driven disk diagnostic collector
    # (tiny11Coremaker task-file deletion list)
    "\\Microsoft\\Windows\\Chkdsk\\Proxy",
    "\\Microsoft\\Windows\\Application Experience\\PcaPatchDbTask",
    # Shim-DB merge task — same AppCompat collection pipeline (privacy.sexy)
    "\\Microsoft\\Windows\\Application Experience\\SdbinstMergeDbTask",
    "\\Microsoft\\Windows\\Application Experience\\PcaWallpaperAppDetect",
    # DUSM data-usage metering task (WindowsMize task-list diff)
    "\\Microsoft\\Windows\\DUSM\\dusmtask",
    "\\Microsoft\\Windows\\Diagnosis\\UnexpectedCodepath",
    "\\Microsoft\\Windows\\PerformanceTrace\\RequestTrace",
    # Insider flighting config usage reporting
    "\\Microsoft\\Windows\\Flighting\\FeatureConfig\\BootstrapUsageDataReporting",
    # Peripheral/input settings cloud-sync tasks (SettingSync layer)
    "\\Microsoft\\Windows\\input\\InputSettingsRestoreDataAvailable",
    "\\Microsoft\\Windows\\input\\MouseSyncDataAvailable",
    "\\Microsoft\\Windows\\input\\PenSyncDataAvailable",
    "\\Microsoft\\Windows\\input\\RemoteMouseSyncDataAvailable",
    "\\Microsoft\\Windows\\input\\RemotePenSyncDataAvailable",
    "\\Microsoft\\Windows\\input\\RemoteTouchpadSyncDataAvailable",
    "\\Microsoft\\Windows\\input\\syncpensettings",
    "\\Microsoft\\Windows\\International\\Synchronize Language Settings",
    "\\Microsoft\\Windows\\Management\\Provisioning\\Cellular",
    "\\Microsoft\\Windows\\Management\\Provisioning\\Logon",
    "\\Microsoft\\Windows\\EnterpriseMgmt\\MDMMaintenenceTask",
    "\\Microsoft\\Windows\\EnterpriseMgmt\\MDMMaintenanceTask",
    # Theme/FO sync
    "\\Microsoft\\Windows\\Shell\\ThemesSyncedImageDownload",
    "\\Microsoft\\Windows\\Shell\\ThemeAssetTask_SyncFODState",
    "\\Microsoft\\Windows\\RemoteAssistance\\RemoteAssistanceTask",
    "\\Microsoft\\Windows\\Offline Files\\Background Synchronization",
    "\\Microsoft\\Windows\\Offline Files\\Logon Synchronization",
    "\\Microsoft\\Windows\\PushToInstall\\Registration",
    "\\Microsoft\\Windows\\AppListBackup\\BackupNonMaintenance",
    "\\Microsoft\\Windows\\ApplicationData\\DsSvcCleanup",
    "\\Microsoft\\Windows\\User Profile Service\\HiveUploadTask",
    "\\Microsoft\\Windows\\UsageAndQualityInsights\\UsageAndQualityInsights-MaintenanceTask",
    "\\Microsoft\\Windows\\Application Experience\\StartupAppTask",
    # Gathers Win32 app data for the Windows Backup app scenario (24H2+)
    "\\Microsoft\\Windows\\Application Experience\\MareBackup",
    "\\Microsoft\\Windows\\Autochk\\Proxy",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
    # Bluetooth CEIP SQM uploader (hst-windows-utility task list)
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\BthSQM",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
    # CEIP Uploader task — distinct from the Broker node UploadCachedReports
    # (noverse.dev task catalog)
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Uploader",
    # Server CEIP node (Windows Server CEIP tasks — privacy.sexy)
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Server\\ServerCeipAssistant",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Server\\ServerRoleCollector",
    "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Server\\ServerRoleUsageCollector",
    # CEIP Broker — uploads cached CEIP reports (RealSyferX/windows-11-debloat)
    "\\Microsoft\\Windows\\Customer Experience Improvement Program Broker\\UploadCachedReports",
    # OOBE third-party app scan triggers — usoclient-driven re-provisioning
    # of OEM/Store apps after updates (privacy.sexy)
    "\\Microsoft\\Windows\\UpdateOrchestrator\\StartOobeAppsScanAfterUpdate",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\StartOobeAppsScan_LicenseAccepted",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\StartOobeAppsScan_OobeAppReady",
    "\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\\Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
    "\\Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
    "\\Microsoft\\Windows\\Maps\\MapsUpdateTask",
    "\\Microsoft\\Windows\\Maps\\MapsToastTask",
    # Winhance: power-efficiency diagnostic ETW collection task
    "\\Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem",
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
    # Device Census (hardware/app inventory upload), Family Safety usage
    # monitor, on-demand network-info collection
    "\\Microsoft\\Windows\\Device Information\\Device",
    "\\Microsoft\\Windows\\Device Information\\Device User",
    "\\Microsoft\\Windows\\Shell\\FamilySafetyMonitor",
    "\\Microsoft\\Windows\\Shell\\FamilySafetyRefreshTask",
    # Family Safety usage-data upload (Debloat-Win11 diff) + Xbox cloud
    # save sync scheduler (XblGameSave service is already demand-gated)
    "\\Microsoft\\Windows\\Shell\\FamilySafetyUpload",
    "\\Microsoft\\XblGameSave\\XblGameSaveTask",
    # Game Bar "now playing" presence writer (per-user root task —
    # Reclaim diff; broadcasts current-game state to Xbox widgets)
    "\\GameBarPresenceWriter",
    # OOBE cloud-experience host provisioning + RetailDemo offline
    # content cleanup (HST Windows Utility / win-debloat diffs —
    # pairs with the killed RetailDemo service + CDM kills)
    "\\Microsoft\\Windows\\CloudExperienceHost\\CreateObjectTask",
    "\\Microsoft\\Windows\\RetailDemo\\CleanupOfflineContent",
    # Win-Debloat7 privacy tasks diff: 25H2 AI-subtree tasks (Copilot+
    # recall/model/index pipelines) + OneSettings cache pulls + UCPD
    # velocity config flighting + UNP campaign manager + EOS nag toasts
    "\\Microsoft\\Windows\\WindowsAI\\RecallSnapshot",
    "\\Microsoft\\Windows\\WindowsAI\\ModelMaintenance",
    "\\Microsoft\\Windows\\WindowsAI\\AIPlatformServiceTask",
    "\\Microsoft\\Windows\\WindowsAI\\WorkloadsHostTask",
    "\\Microsoft\\Windows\\AISystem\\AIAnalyzer",
    "\\Microsoft\\Windows\\AISystem\\ModelUpdateTask",
    "\\Microsoft\\Windows\\AISystem\\SemanticIndexTask",
    "\\Microsoft\\Windows\\NarrativeFlows\\UserJourneyTracker",
    "\\Microsoft\\Windows\\Flighting\\OneSettings\\RefreshCache",
    "\\Microsoft\\Windows\\Flighting\\OneSettings\\QuerySettings",
    "\\Microsoft\\Windows\\AppxDeploymentClient\\UcpdVelocity",
    "\\Microsoft\\Windows\\UNP\\RunCampaignManager",
    "\\Microsoft\\Windows\\Setup\\EOSNotify",
    "\\Microsoft\\Windows\\Setup\\EOSNotify2",
    # Store push-install login hook + setting-sync uploads (service and
    # policies already off — kill the schedulers too)
    "\\Microsoft\\Windows\\PushToInstall\\LoginCheck",
    "\\Microsoft\\Windows\\SettingSync\\BackgroundUploadTask",
    "\\Microsoft\\Windows\\SettingSync\\BackupTask",
    # PCA db update, location telemetry beacons, feedback nag tasks,
    # retail-demo cleanup
    "\\Microsoft\\Windows\\Application Experience\\PcaPatchDbUpdate",
    "\\Microsoft\\Windows\\Location\\Notifications",
    "\\Microsoft\\Windows\\Location\\WindowsActionNotification",
    "\\Microsoft\\Windows\\RetailDemo\\CleanupContent",
    # CEIP perf-tracking surveyor, IME telemetry sender, input-method sync
    # uploads, WMP library sharing, Store install-retry hook
    "\\Microsoft\\Windows\\PerfTrack\\BackgroundConfigSurveyor",
    "\\Microsoft\\Windows\\IME\\SQM data sender",
    "\\Microsoft\\Windows\\Input\\LocalUserSyncDataAvailable",
    "\\Microsoft\\Windows\\Input\\TouchpadSyncDataAvailable",
    "\\Microsoft\\Windows\\Windows Media Sharing\\UpdateLibrary",
    "\\Microsoft\\Windows\\InstallService\\SmartRetry",
    # Store broker-infra maintenance + WDI resolution host (the WDI
    # services are already demoted — kill the task too)
    "\\Microsoft\\Windows\\BrokerInfrastructure\\BgTaskRegistrationMaintenanceTask",
    "\\Microsoft\\Windows\\WDI\\ResolutionHost",
    "\\Microsoft\\Windows\\NetTrace\\GatherNetworkInfo",
    # Application Impact Telemetry, speech-model download, disk diagnostics
    "\\Microsoft\\Windows\\Application Experience\\AitEnableAgent",
    "\\Microsoft\\Windows\\Speech\\SpeechModelDownloadTask",
    "\\Microsoft\\Windows\\DiskFootprint\\Diagnostics",
    # HST Windows Utility diff: app-uninstall verifier telemetry +
    # app-list backup to the cloud profile store
    "\\Microsoft\\Windows\\ApplicationData\\appuriverifierdaily",
    "\\Microsoft\\Windows\\ApplicationData\\appuriverifierinstall",
    "\\Microsoft\\Windows\\AppListBackup\\Backup",
    # Windows Error Reporting queue upload
    "\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
    # Consumer subscription/license offers (Microsoft 365 upsell channel)
    "\\Microsoft\\Windows\\Subscription\\EnableLicenseAcquisition",
    "\\Microsoft\\Windows\\Subscription\\LicenseAcquisition",
    # Recommended-troubleshooting scanner uploads diagnostic packages
    "\\Microsoft\\Windows\\Diagnosis\\RecommendedTroubleshootingScanner",
    "\\Microsoft\\Windows\\Diagnosis\\Scheduled",
    # SQM telemetry task + disk-diagnostic resolver + WinSAT scoring run
    "\\Microsoft\\Windows\\PI\\Sqm-Tasks",
    "\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticResolver",
    "\\Microsoft\\Windows\\Maintenance\\WinSAT",
    # WindowsAI Recall snapshot configuration tasks + Office AI Actions
    # server (zoicware/RemoveWindowsAI task set)
    "\\Microsoft\\Windows\\WindowsAI\\Recall\\InitialConfiguration",
    "\\Microsoft\\Windows\\WindowsAI\\Recall\\PolicyConfiguration",
    "\\Microsoft\\Office\\Office Actions Server",
    # GDStudiosDev/fortify diff: ClickToDo model caching, WindowsAI
    # settings init, flighting usage-data pipeline, perf-trace feedback
    # toast, sustainability telemetry
    "\\Microsoft\\Windows\\WindowsAI\\ClickToDo\\ModelCachingIdle",
    "\\Microsoft\\Windows\\WindowsAI\\ClickToDo\\ModelCachingLimit",
    "\\Microsoft\\Windows\\WindowsAI\\ClickToDo\\ModelCachingUpdate",
    "\\Microsoft\\Windows\\WindowsAI\\Settings\\InitialConfiguration",
    "\\Microsoft\\Windows\\Flighting\\FeatureConfig\\UsageDataFlushing",
    "\\Microsoft\\Windows\\Flighting\\FeatureConfig\\UsageDataReceiver",
    "\\Microsoft\\Windows\\Flighting\\FeatureConfig\\GovernedFeatureUsageProcessing",
    "\\Microsoft\\Windows\\PerformanceTrace\\ShowFeedbackToast",
    "\\Microsoft\\Windows\\Sustainability\\SustainabilityTelemetry",
    "\\Microsoft\\Windows\\WindowsAI\\RecallConfiguration",
    "\\Microsoft\\Windows\\WindowsAI\\RecallPipeline",
)


def disable_telemetry_tasks(logger: logging.Logger):
    """Disable the known Microsoft telemetry/CEIP scheduled tasks."""
    for full_path in TELEMETRY_TASK_PATHS:
        out, ret = run_cmd(["schtasks", "/Change", "/TN", full_path, "/DISABLE"], timeout=15)
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

    matched_families = set()

    # 0.5 Back up every HKLM key BEFORE any writes — run_scan touches the
    # deprovision/Store-policy keys before apply_registry_prevention would
    # back them up; the once-per-process guard makes the later call a no-op
    if prev.get("BackupRegistry", True):
        if dry_run:
            logger.info("[DRY-RUN] Would export registry backup")
        else:
            backup_registry_keys(logger)

    # 1. Remove installed packages
    if prev.get("RemoveAppxPackages", True):
        packages = _enum_blacklisted_packages(blacklist, whitelist)
        matched += len(packages)
        for family_name, display_name, install_path, full_name in packages:
            matched_families.add(family_name)
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
            matched_families.add(_provisioned_family(package_name, display_name))
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
            try:
                remove_optional_capabilities(logger, config)
            except Exception as e:
                logger.warning(f"RemoveOptionalCapabilities layer failed: {e}")

    # 2.6 Remove Win32 programs matching blacklist — primary OEM preinstall
    # channel (McAfee/Norton are Win32, not Appx). MSI silent only.
    if prev.get("RemoveWin32Programs", True):
        for display, uninstall, quiet, user_hive in get_blacklisted_win32(
                blacklist, whitelist):
            matched += 1
            if user_hive:
                # HKU\<sid> is user-writable — never execute its strings as SYSTEM
                logger.info(f"Win32 bloat in user hive (report only, not executed): {display}")
                continue
            if dry_run:
                logger.info(f"[DRY-RUN] Would uninstall Win32 program: {display} [requires admin]")
            else:
                if remove_win32_program(display, uninstall, quiet, logger):
                    logger.info(f"Removed Win32 program: {display}")
                    record_removal(config, {"kind": "win32", "name": display})
                    removed += 1
                else:
                    logger.warning(f"Failed/manual: {display} [admin required or no silent uninstaller]")

    # 2.9 Reprovisioning persistence — the deprovision markers + the 25H2
    # policy need the family list even when a removal toggle is off, so
    # enumerate matches independently when persistence is on but removal off.
    if prev.get("MarkDeprovisioned", True) or prev.get("RemoveDefaultStorePackages", True):
        if not (prev.get("RemoveAppxPackages", True)
                and prev.get("RemoveProvisionedPackages", True)):
            for family_name, _, _, _ in _enum_blacklisted_packages(blacklist, whitelist):
                matched_families.add(family_name)
            for display_name, package_name in get_blacklisted_provisioned(
                    blacklist, whitelist):
                matched_families.add(_provisioned_family(package_name, display_name))
        if matched_families:
            if dry_run:
                logger.info(f"[DRY-RUN] Would mark {len(matched_families)} families "
                            f"deprovisioned and list them for RemoveDefaultStorePackages")
            else:
                if prev.get("MarkDeprovisioned", True):
                    n = mark_deprovisioned(sorted(matched_families), logger)
                    logger.info(f"Applied: MarkDeprovisioned ({n} markers)")
                if prev.get("RemoveDefaultStorePackages", True):
                    apply_remove_default_store_packages(sorted(matched_families), logger)

    # 3. Re-apply registry (idempotent, Windows Update may reset)
    if dry_run:
        logger.info("[DRY-RUN] Would apply registry prevention")
    else:
        try:
            apply_registry_prevention(config, logger)
        except Exception as e:
            logger.warning(f"RegistryPrevention layer failed: {e}")

    # 4. Disable OEM tasks
    if prev.get("DisableOemScheduledTasks", True):
        if dry_run:
            logger.info("[DRY-RUN] Would disable OEM scheduled tasks")
        else:
            try:
                disable_oem_scheduled_tasks(logger)
            except Exception as e:
                logger.warning(f"DisableOemScheduledTasks layer failed: {e}")

    # 4.5 Disable Microsoft telemetry/CEIP tasks (CompatTelRunner etc.)
    if prev.get("DisableTelemetryTasks", True):
        if dry_run:
            logger.info("[DRY-RUN] Would disable Microsoft telemetry tasks")
        else:
            try:
                disable_telemetry_tasks(logger)
            except Exception as e:
                logger.warning(f"DisableTelemetryTasks layer failed: {e}")

    # 4.6 Boot-time ETW autologgers (diagtrack listener etc.)
    if prev.get("DisableTelemetryAutologgers", True):
        if dry_run:
            logger.info("[DRY-RUN] Would disable telemetry ETW autologgers")
        else:
            try:
                disable_telemetry_autologgers(logger)
            except Exception as e:
                logger.warning(f"DisableTelemetryAutologgers layer failed: {e}")

    # 4.7 hosts-file null-route for pure telemetry endpoints (reversible).
    # Called unconditionally so toggling off removes a previously written block.
    if dry_run:
        logger.info("[DRY-RUN] Would manage telemetry endpoints hosts block")
    else:
        set_telemetry_hosts_block(prev.get("BlockTelemetryEndpoints", True), logger)

    # 4.8 winget sweep for Store apps Appx removal can't see
    if prev.get("WingetSweep", True):
        if dry_run:
            logger.info("[DRY-RUN] Would run winget uninstall sweep")
        else:
            try:
                winget_sweep(config, logger)
            except Exception as e:
                logger.warning(f"WingetSweep layer failed: {e}")

    logger.info(f"Scan complete. {matched} packages matched blacklist; removed {removed}.")
    return removed


# ─── Service Mode ────────────────────────────────────────────────────────────

def run_service(config: dict, logger: logging.Logger):
    """Run as a persistent background process."""
    try:
        interval = int(config.get("ScanIntervalSeconds", 300))
    except (TypeError, ValueError):
        interval = 300
    # Each scan spawns real work — clamp a zero/negative/garbage interval to
    # a floor instead of letting it spin or crash the service loop.
    if interval < 60:
        logger.warning(
            f"ScanIntervalSeconds={config.get('ScanIntervalSeconds')!r} invalid"
            " — clamped to 60s minimum")
        interval = 60
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
    seen_win32: set = set()
    first_scan = True

    # Apply prevention once at startup — skipped entirely in dry-run mode
    if config.get("DryRun", False):
        logger.info("[DRY-RUN] Startup prevention changes skipped")
    else:
        if not is_admin():
            logger.warning("Running without admin rights — some prevention may fail.")
        try:
            apply_registry_prevention(config, logger)
        except Exception as e:
            logger.warning(f"RegistryPrevention layer failed: {e}")
        if prev.get("DisableOemScheduledTasks", True):
            try:
                disable_oem_scheduled_tasks(logger)
            except Exception as e:
                logger.warning(f"DisableOemScheduledTasks layer failed: {e}")
        if prev.get("DisableTelemetryTasks", True):
            try:
                disable_telemetry_tasks(logger)
            except Exception as e:
                logger.warning(f"DisableTelemetryTasks layer failed: {e}")

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
                installed_map = {
                    family: full_name
                    for family, _, _, full_name
                    in _enum_blacklisted_packages(blacklist, whitelist)
                }
                current_installed = set(installed_map)
                # Win32 display names — OEMs re-push these via their updaters,
                # so the monitor must watch the non-Appx channel too
                try:
                    current_win32 = {
                        (d, u, q, uh) for d, u, q, uh
                        in get_blacklisted_win32(blacklist, whitelist)
                    }
                except Exception:
                    current_win32 = set()

                if not first_scan:
                    for display_name in current_provisioned - seen_provisioned:
                        logger.warning(
                            f"[MONITOR] RE-INSTALLED detected: {display_name} — removing immediately!")
                        if config.get("DryRun", False):
                            logger.info(f"[DRY-RUN] Would re-remove provisioned: {display_name}")
                        elif remove_provisioned_package(prov_map[display_name]):
                            logger.info(f"[MONITOR] Re-removal complete: {display_name}")
                        else:
                            logger.warning(f"[MONITOR] Re-removal failed: {display_name}")

                    reinstalled = current_installed - seen_installed
                    for family_name in reinstalled:
                        logger.warning(
                            f"[MONITOR] RE-INSTALLED AppxPackage: {family_name} — removing!")
                        full_name = installed_map.get(family_name)
                        if config.get("DryRun", False):
                            logger.info(f"[DRY-RUN] Would re-remove AppxPackage: {family_name}")
                        elif full_name and remove_appx_package(full_name):
                            logger.info(f"[MONITOR] Re-removal complete: {family_name}")
                        else:
                            logger.warning(f"[MONITOR] Re-removal failed: {family_name}")

                    seen_names = {d for d, _, _, _ in seen_win32}
                    for display, uninstall, quiet, user_hive in current_win32:
                        if display in seen_names or user_hive:
                            continue  # user-hive entries are report-only
                        logger.warning(
                            f"[MONITOR] RE-INSTALLED Win32: {display} — removing!")
                        if config.get("DryRun", False):
                            logger.info(f"[DRY-RUN] Would re-remove Win32: {display}")
                        elif remove_win32_program(display, uninstall, quiet, logger):
                            logger.info(f"[MONITOR] Re-removal complete: {display}")
                        else:
                            logger.warning(
                                f"[MONITOR] Re-removal failed or manual: {display}")

                seen_provisioned = current_provisioned
                seen_installed = current_installed
                seen_win32 = current_win32
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

    run_cmd(["sc", "stop", SERVICE_NAME])
    run_cmd(["sc", "delete", SERVICE_NAME])
    run_cmd([nssm, "remove", SERVICE_NAME, "confirm"])
    time.sleep(2)

    out, rc = run_cmd(
        [nssm, "install", SERVICE_NAME, str(pythonw), str(script_path), "--service"])
    print(out)
    if rc != 0:
        return False

    run_cmd([nssm, "set", SERVICE_NAME, "Start", "SERVICE_AUTO_START"])
    run_cmd(
        [nssm, "set", SERVICE_NAME, "AppStdout", str(LOG_DIR / "service-stdout.log")])
    print(f"Service '{SERVICE_NAME}' installed via NSSM. "
          f"Use 'sc start {SERVICE_NAME}' to start.")
    return True


def uninstall_service():
    run_cmd(["sc", "stop", SERVICE_NAME])
    out, _ = run_cmd(["sc", "delete", SERVICE_NAME])
    print(out)
    # The hosts block is tool-owned runtime state that outlives the service —
    # strip it so an uninstalled tool leaves no stale null-routes. Registry
    # policies and deprovision/startup markers intentionally persist: they are
    # the hardening itself and removing them would re-enable the telemetry
    # and reprovisioning the tool was installed to kill.
    set_telemetry_hosts_block(False, logging.getLogger(APP_NAME))


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
             "Name": "Microsoft.XboxGamingOverlay",
             "PackageFullName": "Microsoft.XboxGamingOverlay_1.0_x64__8wekyb3d8bbwe"},
        ])
        orig = run_powershell
        globals()["run_powershell"] = lambda cmd, timeout=60: (fake_json, "", 0)
        try:
            pkgs = _enum_blacklisted_packages(["Xbox"], [])
            assert pkgs and pkgs[0][3] == \
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
                    "NoForcedReboot", "HideStartRecommendations",
                    "MarkDeprovisioned", "RemoveDefaultStorePackages",
                    "BlockTelemetryEndpoints", "WingetSweep",
                    "DisableTelemetryAutologgers",
                    "DisableModernStandbyNetworking"]
        missing = [k for k in required if k not in prev]
        assert not missing, f"missing prevention keys: {missing}"
        # every prevention key must exist in the C# mirror too
        cs = Path(__file__).parent / "src" / "Program.cs"
        if cs.exists():
            cs_src = cs.read_text(encoding="utf-8", errors="ignore")
            miss_cs = [k for k in required if k not in cs_src]
            assert not miss_cs, \
                f"prevention keys missing from Program.cs: {miss_cs}"

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
    check("T6: Prevention layers — 46 registered", t_prevention_layers)
    check("T7: Removal ledger write/read", t_removal_ledger)
    check("T8: Full-name batch map", t_full_name_map)

    def t_defaults_config_parity():
        """config.json Prevention keys must exist in load_config defaults —
        a missing default silently skips the layer on fresh installs."""
        cfg = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8-sig"))
        # load_config writes the file when absent — point it at a temp dir
        with tempfile.TemporaryDirectory() as td:
            defaults = load_config(Path(td) / "config.json")
        missing = set(cfg["Prevention"].keys()) - set(defaults["Prevention"].keys())
        extra = set(defaults["Prevention"].keys()) - set(cfg["Prevention"].keys())
        assert not missing and not extra, f"defaults/config drift: -{missing} +{extra}"
        missing_bl = set(cfg["Blacklist"]) - set(DEFAULT_BLACKLIST)
        assert not missing_bl, f"defaults missing blacklist entries: {missing_bl}"
        # src/config.json ships with the C# build — silent drift from the
        # root config means the two impls run different defaults
        src_cfg_path = Path(__file__).parent / "src" / "config.json"
        if src_cfg_path.exists():
            src_cfg = json.loads(src_cfg_path.read_text(encoding="utf-8-sig"))
            assert src_cfg == cfg, \
                "src/config.json diverged from root config.json"
        # version parity with the C# implementation (repo checkouts only —
        # src/Program.cs is absent on end-user machines)
        cs = Path(__file__).parent / "src" / "Program.cs"
        if cs.exists():
            cs_src = cs.read_text(encoding="utf-8", errors="ignore")
            assert f"v{APP_VERSION}" in cs_src, \
                f"APP_VERSION {APP_VERSION} not found in src/Program.cs"
            # shared data-list parity: every Python entry must appear in C#
            # (C# uses @"..." verbatim literals — backslashes appear unescaped)
            for name, entries in (("TELEMETRY_TASK_PATHS", TELEMETRY_TASK_PATHS),
                                  ("_EXTRA_AUTOLOGGERS", _EXTRA_AUTOLOGGERS),
                                  ("_TELEMETRY_HOSTS", _TELEMETRY_HOSTS),
                                  ("_STARTUP_BLOAT_NAMES", _STARTUP_BLOAT_NAMES),
                                  ("DEFAULT_BLACKLIST", DEFAULT_BLACKLIST),
                                  ("MICROSOFT_SYSTEM_TASK_PREFIXES",
                                   MICROSOFT_SYSTEM_TASK_PREFIXES),
                                  ("_BACKUP_KEY_PATHS", _BACKUP_KEY_PATHS),
                                  ("_USER_BACKUP_KEY_PATHS",
                                   _USER_BACKUP_KEY_PATHS),
                                  ("_EXTRA_BACKUP_SERVICES",
                                   _EXTRA_BACKUP_SERVICES),
                                  ("_WIN32_BLOAT_NAMES", _WIN32_BLOAT_NAMES),
                                  ("_MISC_DEMOTE_SERVICES",
                                   _MISC_DEMOTE_SERVICES),
                                  ("_ACTIVE_SETUP_PATHS", _ACTIVE_SETUP_PATHS),
                                  ("_VELOCITY_AI_IDS", _VELOCITY_AI_IDS),
                                  ("_VELOCITY_COPILOT_IDS",
                                   _VELOCITY_COPILOT_IDS),
                                  # scalar shared constants — drift breaks
                                  # parity silently, so assert presence too
                                  ("_DEPROVISIONED_PATH",
                                   (_DEPROVISIONED_PATH,)),
                                  ("_EOL_PATH", (_EOL_PATH,)),
                                  ("_REMOVE_DEFAULT_PKGS_PATH",
                                   (_REMOVE_DEFAULT_PKGS_PATH,)),
                                  ("_USER_DELIVERY_OPT",
                                   (_USER_DELIVERY_OPT,)),
                                  ("_USER_NOTIFICATION_SETTINGS",
                                   (_USER_NOTIFICATION_SETTINGS,)),
                                  ("_USER_OUTLOOK_MIGRATION",
                                   (_USER_OUTLOOK_MIGRATION,)),
                                  ("_USER_OUTLOOK_PREFERENCES",
                                   (_USER_OUTLOOK_PREFERENCES,)),
                                  ("_USER_SUGGESTED_TOAST",
                                   (_USER_SUGGESTED_TOAST,)),
                                  ("_USER_VOICE_ACTIVATION",
                                   (_USER_VOICE_ACTIVATION,)),
                                  ("_HOSTS_BLOCK_BEGIN",
                                   (_HOSTS_BLOCK_BEGIN,)),
                                  ("_HOSTS_BLOCK_END",
                                   (_HOSTS_BLOCK_END,))):
                miss = []
                for e in entries:
                    # structured entries ((subkey, value) pairs) — verify each
                    # string component appears rather than the tuple itself
                    parts = e if isinstance(e, tuple) else (e,)
                    if any(isinstance(p, str) and p not in cs_src for p in parts):
                        miss.append(e)
                assert not miss, f"{name} entries missing from Program.cs: {miss}"

    check("T9: defaults <-> config.json parity", t_defaults_config_parity)

    def t_no_duplicate_entries():
        """Shared lists must be duplicate-free — dups silently inflate counts
        (a blacklist dup shipped until the doc-vs-list audit caught it)."""
        for name, entries in (("TELEMETRY_TASK_PATHS", TELEMETRY_TASK_PATHS),
                              ("_EXTRA_AUTOLOGGERS", _EXTRA_AUTOLOGGERS),
                              ("_TELEMETRY_HOSTS", _TELEMETRY_HOSTS),
                              ("_STARTUP_BLOAT_NAMES", _STARTUP_BLOAT_NAMES),
                              ("DEFAULT_BLACKLIST", DEFAULT_BLACKLIST),
                              ("MICROSOFT_SYSTEM_TASK_PREFIXES",
                               MICROSOFT_SYSTEM_TASK_PREFIXES),
                              ("_BACKUP_KEY_PATHS", _BACKUP_KEY_PATHS),
                              ("_USER_BACKUP_KEY_PATHS", _USER_BACKUP_KEY_PATHS),
                              ("_EXTRA_BACKUP_SERVICES", _EXTRA_BACKUP_SERVICES),
                              ("_WIN32_BLOAT_NAMES", _WIN32_BLOAT_NAMES),
                              ("_MISC_DEMOTE_SERVICES", _MISC_DEMOTE_SERVICES),
                              ("_ACTIVE_SETUP_PATHS", _ACTIVE_SETUP_PATHS),
                              ("_VELOCITY_AI_IDS", _VELOCITY_AI_IDS),
                              ("_VELOCITY_COPILOT_IDS", _VELOCITY_COPILOT_IDS)):
            dupes = {e for e in entries if entries.count(e) > 1}
            assert not dupes, f"{name} has duplicate entries: {dupes}"
            # Service names are case-insensitive on Windows — catch
            # case-variant dups too (SensrSvc/sensrsvc shipped as both).
            # Structured entries (e.g. (subkey, value) velocity pairs) carry
            # no case-insensitive namespace — skip them here.
            lower = [e.lower() for e in entries if isinstance(e, str)]
            case_dupes = {e for e in lower if lower.count(e) > 1}
            assert not case_dupes, f"{name} has case-variant duplicates: {case_dupes}"

    check("T10: shared lists are duplicate-free", t_no_duplicate_entries)

    def t_registry_value_parity():
        """Every registry value name the Python impl writes must also be
        written by src/Program.cs — drift here ships silently since the
        writes are the tool's actual payload. Extracts py names from
        set_registry_*/set_user_dword_all_hives call args (including names
        fed through for-loop variables and (name, value) tuple loops) and
        checks each appears in the C# source. The reverse direction is
        asserted too: any quoted name extracted from C# that has no py
        string literal is drift (task/service/package/path strings in
        new[] literals are all mirrored, so they pass as literals).
        Repo checkouts only."""
        cs = Path(__file__).parent / "src" / "Program.cs"
        if not cs.exists():
            return
        cs_src = cs.read_text(encoding="utf-8", errors="ignore")
        # strip line comments — quoted words in comments are not writes
        cs_src = re.sub(r'//[^\n]*', '', cs_src)
        cs_names = set(re.findall(r'SetValue\(\s*"([^"]+)"', cs_src))
        cs_names |= set(re.findall(
            r'SetUserDwordAllHives\([^,]+,\s*\n?\s*"([^"]+)"', cs_src))
        cs_names |= set(re.findall(
            r'SetHiveDword\([^,]+,[^,]+,\s*\n?\s*"([^"]+)"', cs_src))
        # names written via loop variables — any quoted string in a
        # new[] { ... } literal is a candidate value name
        for m in re.finditer(r'new\[\]\s*\{([^}]*)\}', cs_src):
            cs_names |= set(re.findall(r'"([^"]+)"', m.group(1)))

        set_fns = {"set_registry_dword", "set_registry_string",
                   "set_registry_qword", "set_user_dword_all_hives", "w"}
        src = Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        loop_vars: Dict[str, List[str]] = {}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.For)
                    and isinstance(node.iter, (ast.Tuple, ast.List))):
                continue
            lit_elts = [e.value for e in node.iter.elts
                        if isinstance(e, ast.Constant)
                        and isinstance(e.value, str)]
            pair_elts = [e.elts for e in node.iter.elts
                         if isinstance(e, ast.Tuple)]
            has_set = any(isinstance(s, ast.Call)
                          and isinstance(s.func, ast.Name)
                          and s.func.id in set_fns
                          for s in ast.walk(node))
            if not has_set:
                continue
            if isinstance(node.target, ast.Name) and lit_elts:
                loop_vars.setdefault(node.target.id, []).extend(lit_elts)
            elif isinstance(node.target, ast.Tuple):
                # `for name, val in (("a", 0), ("b", 1))` — position i of
                # the target maps to element i of each pair
                for i, t in enumerate(node.target.elts):
                    if isinstance(t, ast.Name):
                        loop_vars.setdefault(t.id, []).extend(
                            p[i].value for p in pair_elts
                            if len(p) > i
                            and isinstance(p[i], ast.Constant)
                            and isinstance(p[i].value, str))
        py_names: Set[str] = set()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in set_fns):
                continue
            idx = 1 if node.func.id in ("set_user_dword_all_hives", "w") else 2
            if len(node.args) <= idx:
                continue
            arg = node.args[idx]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                py_names.add(arg.value)
            elif isinstance(arg, ast.Name) and arg.id in loop_vars:
                py_names.update(loop_vars[arg.id])
        py_names.discard("")
        miss = sorted(py_names - cs_names)
        assert not miss, \
            f"registry value names missing from Program.cs: {miss}"
        # cs -> py: every string literal anywhere in the py source is a
        # valid match — names shared via task/service/package/path lists
        # are mirrored, so only a genuine cs-only name fails here.
        py_literals = {
            e.value for e in ast.walk(tree)
            if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        miss_rev = sorted(cs_names - py_literals)
        assert not miss_rev, \
            f"names in Program.cs with no py counterpart: {miss_rev}"

    check("T11: registry value-name parity (py <-> cs)",
          t_registry_value_parity)

    def t_backup_path_coverage():
        """Every HKLM key path the tool writes must be exported by
        _BACKUP_KEY_PATHS (or by a parent/child of an entry) so `restore`
        can revert it. A write without a backup is a one-way door — this
        gate caught 15 such paths when first run manually. Resolves
        simple `name = r"..."` path variables before checking; cs side
        does the same against BackupKeyPaths. Repo checkouts only."""
        src = Path(__file__).read_text(encoding="utf-8")
        # module-level + function-local `name = r"..."` assignments
        vars_ = dict(re.findall(r'^\s*([a-zA-Z_]+)\s*=\s*r?"([^"]+)"',
                                src, re.M))
        backup = {p.lower() for p in _BACKUP_KEY_PATHS}
        py_writes = set()
        for m in re.finditer(
                r'set_registry_(?:dword|string|qword)\(\s*"HKLM",\s*'
                r'(?:r?"([^"]+)"|([a-zA-Z_]+))', src):
            t = m.group(1) or vars_.get(m.group(2))
            if t:
                py_writes.add(t.lower())
        miss = sorted(w for w in py_writes
                      if not any(w.startswith(b) or b.startswith(w)
                                 for b in backup))
        assert not miss, f"HKLM write paths with no backup: {miss}"
        # cs: every literal-path CreateSubKey on LocalMachine must be
        # covered by BackupKeyPaths (containment either direction)
        cs = Path(__file__).parent / "src" / "Program.cs"
        if not cs.exists():
            return
        cs_src = cs.read_text(encoding="utf-8", errors="ignore")
        i = re.search(r'BackupKeyPaths\s*=\s*\{', cs_src).start()
        cs_backup = {p.lower() for p in re.findall(
            r'@"([^"]+)"', cs_src[i:cs_src.find("};", i)])}
        cs_writes = set(re.findall(
            r'(?:LocalMachine|Registry\.LocalMachine)\.CreateSubKey'
            r'\(\s*@?"([^"]+)"', cs_src))
        miss_cs = sorted(
            w.lower() for w in cs_writes
            if not any(w.lower().startswith(b) or b.startswith(w.lower())
                       for b in cs_backup))
        assert not miss_cs, \
            f"HKLM write paths in Program.cs with no backup: {miss_cs}"

        # Per-user coverage: every path written through the per-user
        # writers must appear in _USER_BACKUP_KEY_PATHS so the exported
        # .reg safety net covers user-scope writes too.
        def _resolve_path_expr(expr):
            """Resolve `'lit' + CONST + 'lit'` style first args."""
            parts = []
            for piece in re.split(r'\s*\+\s*', expr.strip()):
                m = re.match(r'^r?"([^"]+)"$', piece)
                if m:
                    parts.append(m.group(1))
                elif re.match(r'^[a-zA-Z_]+$', piece):
                    if piece not in vars_:
                        return None
                    parts.append(vars_[piece])
                else:
                    return None
            return ''.join(parts)

        user_backup = {p.lower() for p in _USER_BACKUP_KEY_PATHS}
        py_user = set()
        for m in re.finditer(
                r'(?:set_user_dword_all_hives|\bw)\(\s*([^,]+),', src):
            t = _resolve_path_expr(m.group(1))
            if t:
                py_user.add(t.lower())
        for m in re.finditer(
                r'set_registry_(?:dword|string|qword)\(\s*'
                r'"HK(?:CU|EY_CURRENT_USER)",\s*([^,]+),', src):
            t = _resolve_path_expr(m.group(1))
            if t:
                py_user.add(t.lower())
        miss_u = sorted(p for p in py_user if p not in user_backup)
        assert not miss_u, \
            f"per-user write paths with no backup: {miss_u}"
        # cs side: SetHiveDword/SetUserDwordAllHives path args vs
        # UserBackupKeyPaths — resolve `const + @"lit"` expressions.
        cs_consts = dict(re.findall(
            r'(?:private const string|static readonly string)\s+(\w+)'
            r'\s*=\s*@?"([^"]+)"', cs_src))
        i2 = re.search(r'UserBackupKeyPaths\s*=\s*\{', cs_src).start()
        cs_ubackup = {p.lower() for p in re.findall(
            r'@"([^"]+)"', cs_src[i2:cs_src.find("};", i2)])}
        cs_user = set()
        for m in re.finditer(
                r'(?:SetHiveDword|SetUserDwordAllHives)\(\s*'
                r'(?:hive,\s*)?([^,\n]+),', cs_src):
            expr = m.group(1).strip()
            parts = []
            ok = True
            for piece in re.split(r'\s*\+\s*', expr):
                pm = re.match(r'^@?"([^"]+)"$', piece)
                if pm:
                    parts.append(pm.group(1))
                elif piece in cs_consts:
                    parts.append(cs_consts[piece])
                else:
                    ok = False
            if ok:
                cs_user.add(''.join(parts).lower())
        miss_ucs = sorted(p for p in cs_user if p not in cs_ubackup)
        assert not miss_ucs, \
            f"per-user write paths in Program.cs with no backup: {miss_ucs}"

        # Service coverage: every service demoted/disabled by name must
        # be in _MISC_DEMOTE_SERVICES ∪ _EXTRA_BACKUP_SERVICES so its
        # Services\<name> key is exported for the backup net.
        svc_backup = {s.lower() for s in
                      _MISC_DEMOTE_SERVICES + _EXTRA_BACKUP_SERVICES}
        py_svc = set(re.findall(r'demote_service\("([^"]+)"', src))
        py_svc |= set(re.findall(
            r'"sc\.exe",\s*"config",\s*"([^"]+)"', src))
        for m in re.finditer(r'for\s+svc\s+in\s*\(([^)]*)\)', src):
            py_svc |= set(re.findall(r'"([^"]+)"', m.group(1)))
        miss_svc = sorted(s for s in py_svc if s.lower() not in svc_backup)
        assert not miss_svc, \
            f"demoted/disabled services with no backup: {miss_svc}"
        # cs side: DemoteService literals, sc config names, new[] svc
        # arrays ⊆ MiscBloatServices ∪ ExtraBackupServiceNames
        cs_svc_backup = set()
        for arr in ("MiscBloatServices", "ExtraBackupServiceNames"):
            i3 = re.search(arr + r'\s*=\s*\{', cs_src).start()
            cs_svc_backup |= {s.lower() for s in re.findall(
                r'"([A-Za-z][\w.]*)"', cs_src[i3:cs_src.find("};", i3)])}
        cs_svc = set(re.findall(r'DemoteService\("([^"]+)"', cs_src))
        cs_svc |= set(re.findall(
            r'config\s+([A-Za-z][\w.]*)\s+start=', cs_src))
        for m in re.finditer(
                r'foreach\s*\(var\s+svc\s+in\s+new\[\]\s*\{([^}]*)\}',
                cs_src):
            cs_svc |= set(re.findall(r'"([^"]+)"', m.group(1)))
        miss_scs = sorted(s for s in cs_svc
                          if s.lower() not in cs_svc_backup)
        assert not miss_scs, \
            f"demoted/disabled services in Program.cs with no backup: {miss_scs}"

    check("T12: HKLM write-path backup coverage", t_backup_path_coverage)

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
    # Windows consoles default to cp1252/cp932 — a stray non-ASCII char in a
    # log line hard-crashes print/logger output. Force UTF-8 + replace so
    # encoding never takes the tool down.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description="BloatwareGuard - Auto-remove Windows bloatware")
    parser.add_argument("--scan", action="store_true", help="Run one scan and exit")
    parser.add_argument("--dry-run", action="store_true", help="Scan and log planned actions WITHOUT executing removal")
    parser.add_argument("--service", action="store_true", help="Run in service mode (background loop)")
    parser.add_argument("--service-dry-run", action="store_true",
                        help="Service mode with forced dry-run (monitoring only, mirrors C# --service-dry-run)")
    parser.add_argument("--install", action="store_true", help="Install as Windows service")
    parser.add_argument("--uninstall", action="store_true", help="Remove Windows service")
    parser.add_argument("--status", action="store_true", help="Show service status")
    parser.add_argument("--list-installed", action="store_true",
                        help="List installed packages matching blacklist (C# parity: list-installed)")
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
        out, _ = run_cmd(["sc", "query", SERVICE_NAME])
        print(out)
        return

    if args.install:
        if not is_admin():
            _relaunch_elevated("--install")
            return
        install_service()
        return

    if args.uninstall:
        if not is_admin():
            _relaunch_elevated("--uninstall")
            return
        uninstall_service()
        return

    # Load config
    config = load_config(args.config)

    # Setup logging
    log_path = Path(config.get("LogFilePath", str(LOG_FILE)))
    logger = setup_logging(log_path)

    if not is_admin():
        logger.warning("Running without admin rights — registry changes and package removal may fail.")

    if args.list_installed:
        blacklist = config.get("Blacklist", [])
        whitelist = config.get("Whitelist", [])
        pkgs = get_blacklisted_packages(blacklist, whitelist)
        logger.info("Installed packages matching blacklist:")
        for family, name, _install_path in pkgs:
            logger.info(f"  {family} ({name})")
        logger.info("Total: %d package(s) installed.", len(pkgs))
        return

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
