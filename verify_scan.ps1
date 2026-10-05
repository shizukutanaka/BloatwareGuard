# Verify BloatwareGuard scan effectiveness
# MUST RUN AS ADMINISTRATOR
# Tests: AppxPackage removal + ProvisionedPackage removal + Registry changes
# Usage: Right-click -> "Run with PowerShell" (as Admin)

Write-Host "=== BloatwareGuard Verification ===" -ForegroundColor Cyan
if (!(Test-Path C:\temp)) { mkdir C:\temp | Out-Null }
Write-Host "Taking BEFORE snapshots..." -ForegroundColor Yellow

# 1. Registry snapshot BEFORE
reg export "HKLM\SOFTWARE\Policies\Microsoft" C:\temp\before.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" C:\temp\before_system.reg 2>$null

# 2. Provisioned packages BEFORE
powershell "Get-AppxProvisionedPackage -Online | Select PackageName" > C:\temp\prov_before.txt

# 3. Appx packages matching blacklist BEFORE
$blacklist_patterns = @("Xbox", "Solitaire", "YourPhone", "MicrosoftTeams", "Zune", "Copilot", "Disney", "Spotify", "Clipchamp", "TikTok", "CandyCrush", "BingSearch")
$installed_before = Get-AppxPackage | Where-Object { $n = $_.Name; $blacklist_patterns | Where-Object { $n -like "*$_*" } }
$installed_before | Select PackageFamilyName | Export-Csv -NoType C:\temp\appx_before.csv

# 4. Run the actual scan (real removal!)
Write-Host "`nRunning BloatwareGuard scan..." -ForegroundColor Green
python (Join-Path $PSScriptRoot "bloatware_guard.py") --scan

# 5. AFTER snapshots
Write-Host "Taking AFTER snapshots..." -ForegroundColor Yellow
reg export "HKLM\SOFTWARE\Policies\Microsoft" C:\temp\after.reg 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" C:\temp\after_system.reg 2>$null
powershell "Get-AppxProvisionedPackage -Online | Select PackageName" > C:\temp\prov_after.txt
$installed_after = Get-AppxPackage | Where-Object { $n = $_.Name; $blacklist_patterns | Where-Object { $n -like "*$_*" } }
$installed_after | Select PackageFamilyName | Export-Csv -NoType C:\temp\appx_after.csv

# 6. DIFF REPORT
Write-Host "`n=== DIFF REPORT ===" -ForegroundColor Cyan

Write-Host "[Provisioned Packages]" -ForegroundColor Yellow
fc C:\temp\prov_before.txt C:\temp\prov_after.txt | findstr "<"

Write-Host "[Registry Changes (CloudContent)]" -ForegroundColor Yellow
fc C:\temp\before.reg C:\temp\after.reg | findstr /i "CloudContent\|Consumer\|Disable\|Copilot\|Recall\|Restrict\|Internet Explorer\|Telemetry"

Write-Host "[Removed Appx Packages]" -ForegroundColor Yellow
Compare-Object (Import-Csv C:\temp\appx_before.csv).PackageFamilyName (Import-Csv C:\temp\appx_after.csv).PackageFamilyName | Where-Object SideIndicator -eq "<="

Write-Host "`n=== VERIFICATION COMPLETE ===" -ForegroundColor Green
Write-Host "Reboot Windows. After 10-30 minutes, re-run:" -ForegroundColor Magenta
Write-Host "  Get-AppxPackage | Where-Object { `$_.Name -like '*Xbox*' }" -ForegroundColor White
Write-Host "  Get-AppxProvisionedPackage" -ForegroundColor White
