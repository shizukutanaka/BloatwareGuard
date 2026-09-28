# BloatwareGuard Verification Script (SYSTEM-compatible)
# Intended to run as Scheduled Task at SYSTEM privilege
# No UAC prompt, no python dependency, uses C# self-contained exe directly
# Deploy: run deploy_verify.bat first (builds + verifies)

$ErrorActionPreference = "SilentlyContinue"

$exe = Join-Path $PSScriptRoot "src\bin\Release\net8.0-windows\win-x64\BloatwareGuard.exe"
$log = "C:\temp\verify_scan.log"

"=== BloatwareGuard Verification ===" | Out-File -Append $log
"Timestamp: $(Get-Date)" | Out-File -Append $log

# Ensure C:\temp exists
if (!(Test-Path C:\temp)) { mkdir C:\temp | Out-Null }

# Check exe
if (-not (Test-Path $exe)) {
    "ERROR: $exe not found. Run deploy_verify.bat first." | Out-File -Append $log
    exit 1
}

# --- BEFORE snapshots ---
"Taking BEFORE snapshots..." | Out-File -Append $log
Get-AppxProvisionedPackage -Online | Select-Object PackageName | Out-File -Append C:\temp\prov_before.txt
Get-AppxPackage | Where-Object { $_.Name -like "*Xbox*" -or $_.Name -like "*Solitaire*" -or $_.Name -like "*YourPhone*" -or $_.Name -like "*Zune*" } | Select-Object PackageFamilyName | Out-File -Append C:\temp\appx_before.txt
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows" C:\temp\before.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" C:\temp\before_sys.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned" C:\temp\before_deprov.reg 2>$null
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\*" | Select-Object TaskName,State | Out-File -Append C:\temp\tasks_before.txt
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Autochk\*" | Select-Object TaskName,State | Out-File -Append C:\temp\tasks_before.txt
sc.exe qc DiagTrack > C:\temp\svc_before.txt
sc.exe qc WerSvc >> C:\temp\svc_before.txt
sc.exe qc wercplsupport >> C:\temp\svc_before.txt
Select-String -Path "$env:windir\System32\drivers\etc\hosts" -Pattern "BloatwareGuard telemetry block" > C:\temp\hosts_before.txt

# --- RUN scan (real removal!) ---
"Running BloatwareGuard scan..." | Out-File -Append $log
$proc = Start-Process -FilePath $exe -ArgumentList "scan" -Wait -PassThru -RedirectStandardOutput C:\temp\scan_stdout.txt -RedirectStandardError C:\temp\scan_stderr.txt
"Scan exit code: $($proc.ExitCode)" | Out-File -Append $log

# --- AFTER snapshots ---
"Taking AFTER snapshots..." | Out-File -Append $log
Get-AppxProvisionedPackage -Online | Select-Object PackageName | Out-File -Append C:\temp\prov_after.txt
Get-AppxPackage | Where-Object { $_.Name -like "*Xbox*" -or $_.Name -like "*Solitaire*" -or $_.Name -like "*YourPhone*" -or $_.Name -like "*Zune*" } | Select-Object PackageFamilyName | Out-File -Append C:\temp\appx_after.txt
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows" C:\temp\after.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" C:\temp\after_sys.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned" C:\temp\after_deprov.reg 2>$null
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\*" | Select-Object TaskName,State | Out-File -Append C:\temp\tasks_after.txt
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Autochk\*" | Select-Object TaskName,State | Out-File -Append C:\temp\tasks_after.txt
sc.exe qc DiagTrack > C:\temp\svc_after.txt
sc.exe qc WerSvc >> C:\temp\svc_after.txt
sc.exe qc wercplsupport >> C:\temp\svc_after.txt
Select-String -Path "$env:windir\System32\drivers\etc\hosts" -Pattern "BloatwareGuard telemetry block" > C:\temp\hosts_after.txt

# --- DIFF REPORT ---
"" | Out-File -Append $log
"=== DIFF REPORT ===" | Out-File -Append $log

"--- Provisioned Package Diff ---" | Out-File -Append $log
Compare-Object (Get-Content C:\temp\prov_before.txt) (Get-Content C:\temp\prov_after.txt) | Out-File -Append $log

"--- Appx Package Diff (removed = <=) ---" | Out-File -Append $log
Compare-Object (Get-Content C:\temp\appx_before.txt) (Get-Content C:\temp\appx_after.txt) | Out-File -Append $log

"--- Registry Diff (CloudContent) ---" | Out-File -Append $log
fc C:\temp\before.reg C:\temp\after.reg | findstr /i "CloudContent\|Consumer\|Disable" | Out-File -Append $log

"--- Deprovisioned Markers Diff ---" | Out-File -Append $log
fc C:\temp\before_deprov.reg C:\temp\after_deprov.reg | findstr "HKEY" | Out-File -Append $log

"--- Telemetry Tasks Diff ---" | Out-File -Append $log
fc C:\temp\tasks_before.txt C:\temp\tasks_after.txt | Out-File -Append $log

"--- Service Start Types (DiagTrack/WerSvc/wercplsupport) ---" | Out-File -Append $log
fc C:\temp\svc_before.txt C:\temp\svc_after.txt | Out-File -Append $log

"--- Hosts Telemetry Block ---" | Out-File -Append $log
Get-Content C:\temp\hosts_after.txt | Out-File -Append $log

"=== VERIFICATION COMPLETE ===" | Out-File -Append $log
"Reboot required. After reboot + 10min, check:" | Out-File -Append $log
"  Get-AppxPackage | Where-Object { `$_.Name -like '*Xbox*' }" | Out-File -Append $log
"  Get-AppxProvisionedPackage" | Out-File -Append $log
