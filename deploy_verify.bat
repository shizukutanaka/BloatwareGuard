@echo off
REM BloatwareGuard - Build & Verify Automation
REM This script builds the C# exe to a clean location and prepares the SYSTEM verification task
REM Requires: .NET 8 SDK (already installed)

echo [1/4] Building C# project to C:\BGOut ...
cd /d C:\Users\HP\bloatware-guard\src
dotnet build -c Debug -p:OutputPath="C:/BGOut/" 2>&1 | tail -5
if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)

echo [2/4] Copying config.json ...
copy /Y C:\Users\HP\bloatware-guard\src\config.json C:\BGOut\config.json

echo [3/4] Preparing verify_scan_sys.ps1 ...
if not exist C:\temp mkdir C:\temp
copy /Y C:\Users\HP\bloatware-guard\verify_scan_sys.ps1 C:\temp\verify_scan_sys.ps1 2>&1

echo [4/4] Registering SYSTEM Scheduled Task (runs at next boot) ...
REM Note: schtasks requires Admin. If not admin, manual registration needed.
schtasks /delete /tn "BloatwareGuardVerify" /f 2>nul
schtasks /create /tn "BloatwareGuardVerify" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\temp\verify_scan_sys.ps1" /sc daily /st 03:00 /ru SYSTEM /rl HIGHEST 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [WARNING] Scheduled Task registration failed (likely not admin).
    echo Manual run: Run "C:\temp\verify_scan_sys.ps1" as Administrator
    echo Or: schtasks /run /tn "BloatwareGuardVerify" after manual registration
)

echo.
echo DONE. Reboot now:
echo   shutdown /r /t 0
echo.
echo After reboot + 10min, check results:
echo   type C:\temp\verify_scan.log
echo   type C:\temp\prov_after.txt
echo   type C:\temp\appx_after.txt
echo   fc C:\temp\before.reg C:\temp\after.reg
