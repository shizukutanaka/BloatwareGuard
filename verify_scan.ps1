# Verify BloatwareGuard scan effectiveness
# MUST RUN AS ADMINISTRATOR
# Tests: AppxPackage removal + ProvisionedPackage removal + Registry changes
#        + telemetry tasks/hosts + service demote + deprovision markers
# Usage: Right-click -> "Run with PowerShell" (as Admin)

Write-Host "=== BloatwareGuard Verification ===" -ForegroundColor Cyan
if (!(Test-Path C:\temp)) { mkdir C:\temp | Out-Null }
Write-Host "Taking BEFORE snapshots..." -ForegroundColor Yellow

# 1. Registry snapshot BEFORE
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows" C:\temp\before.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" C:\temp\before_system.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned" C:\temp\before_deprov.reg 2>$null

# 2. Provisioned packages BEFORE
powershell "Get-AppxProvisionedPackage -Online | Select PackageName" > C:\temp\prov_before.txt

# 3. Appx packages matching blacklist BEFORE
$installed_before = Get-AppxPackage | Where-Object { $_.Name -like "*Xbox*" -or $_.Name -like "*Solitaire*" -or $_.Name -like "*YourPhone*" -or $_.Name -like "*Zune*" }
$installed_before | Select PackageFamilyName | Export-Csv -NoType C:\temp\appx_before.csv

# 4. Telemetry surface BEFORE: tasks, hosts block, service start types
powershell "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program\*' | Select TaskName,State" > C:\temp\tasks_before.txt
powershell "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Autochk\*' | Select TaskName,State" >> C:\temp\tasks_before.txt
powershell "sc.exe qc DiagTrack; sc.exe qc WerSvc; sc.exe qc wercplsupport" > C:\temp\svc_before.txt
Select-String -Path "$env:windir\System32\drivers\etc\hosts" -Pattern "BloatwareGuard telemetry block" > C:\temp\hosts_before.txt 2>$null

# 5. Run the actual scan (real removal!)
Write-Host "`nRunning BloatwareGuard scan..." -ForegroundColor Green
python (Join-Path $PSScriptRoot "bloatware_guard.py") --scan

# 6. AFTER snapshots
Write-Host "Taking AFTER snapshots..." -ForegroundColor Yellow
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows" C:\temp\after.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" C:\temp\after_system.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned" C:\temp\after_deprov.reg 2>$null
powershell "Get-AppxProvisionedPackage -Online | Select PackageName" > C:\temp\prov_after.txt
$installed_after = Get-AppxPackage | Where-Object { $_.Name -like "*Xbox*" -or $_.Name -like "*Solitaire*" -or $_.Name -like "*YourPhone*" -or $_.Name -like "*Zune*" }
$installed_after | Select PackageFamilyName | Export-Csv -NoType C:\temp\appx_after.csv
powershell "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program\*' | Select TaskName,State" > C:\temp\tasks_after.txt
powershell "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Autochk\*' | Select TaskName,State" >> C:\temp\tasks_after.txt
powershell "sc.exe qc DiagTrack; sc.exe qc WerSvc; sc.exe qc wercplsupport" > C:\temp\svc_after.txt
Select-String -Path "$env:windir\System32\drivers\etc\hosts" -Pattern "BloatwareGuard telemetry block" > C:\temp\hosts_after.txt 2>$null

# 7. DIFF REPORT
Write-Host "`n=== DIFF REPORT ===" -ForegroundColor Cyan

Write-Host "[Provisioned Packages]" -ForegroundColor Yellow
fc C:\temp\prov_before.txt C:\temp\prov_after.txt | findstr "<"

Write-Host "[Registry Changes (CloudContent)]" -ForegroundColor Yellow
fc C:\temp\before.reg C:\temp\after.reg | findstr /i "CloudContent\|Consumer\|Disable"

Write-Host "[Deprovisioned Markers]" -ForegroundColor Yellow
fc C:\temp\before_deprov.reg C:\temp\after_deprov.reg | findstr "HKEY"

Write-Host "[Telemetry Tasks]" -ForegroundColor Yellow
fc C:\temp\tasks_before.txt C:\temp\tasks_after.txt

Write-Host "[Service Start Types (DiagTrack/WerSvc/wercplsupport)]" -ForegroundColor Yellow
fc C:\temp\svc_before.txt C:\temp\svc_after.txt

Write-Host "[Hosts Telemetry Block]" -ForegroundColor Yellow
Get-Content C:\temp\hosts_after.txt -ErrorAction SilentlyContinue

Write-Host "[Removed Appx Packages]" -ForegroundColor Yellow
Compare-Object (Import-Csv C:\temp\appx_before.csv).PackageFamilyName (Import-Csv C:\temp\appx_after.csv).PackageFamilyName | Where-Object SideIndicator -eq "<="

Write-Host "`n=== VERIFICATION COMPLETE ===" -ForegroundColor Green
Write-Host "Reboot Windows. After 10-30 minutes, re-run:" -ForegroundColor Magenta
Write-Host "  Get-AppxPackage | Where-Object { `$_.Name -like '*Xbox*' }" -ForegroundColor White
Write-Host "  Get-AppxProvisionedPackage" -ForegroundColor White
