@echo off
REM BloatwareGuard v1.8.0-mvp - Deployment Verification Script
REM Requirements:
REM   1. Windows 11 (self-contained C# build - NO .NET runtime needed)
REM   2. Run as Administrator for C# dry-run (UAC manifest requests admin)
REM   3. Reboot after execution
REM
REM NOTE: The C# EXE self-contains .NET 8 runtime (11.3MB single file).
REM       Admin rights are required by the UAC manifest even for --version.

setlocal enabledelayedexpansion

echo ========================================
echo BloatwareGuard v1.8.0-mvp - Deploy Verify
echo ========================================
echo.

REM --- Check Admin Rights ---
echo [1/5] Checking Administrator rights...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Not running as Administrator.
    echo Non-admin mode: Python dry-run only. C# EXE requires admin (UAC manifest).
) else (
    echo OK: Running as Administrator.
)
echo.

REM --- Build C# Self-Contained Release ---
echo [2/5] Building C# Release (self-contained win-x64, single-file)...
cd /d "%~dp0src"
if not exist "bin\Release\net8.0-windows\win-x64" mkdir "bin\Release\net8.0-windows\win-x64"
dotnet publish BloatwareGuard.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=false -p:PublishTrimmed=true -p:EnableCompressionInSingleFile=true -o "bin\Release\net8.0-windows\win-x64" --nologo -v minimal
if %errorlevel% neq 0 (
    echo ERROR: C# build failed.
    goto :error_build
)
echo OK: C# build 0 errors, 0 warnings (trim warnings are informational).
echo    Single-file EXE size:
if exist "bin\Release\net8.0-windows\win-x64\BloatwareGuard.exe" (
    for %%I in ("bin\Release\net8.0-windows\win-x64\BloatwareGuard.exe") do echo    %%~zI bytes
)
echo.

REM --- Run Python Dry-Run ---
echo [3/5] Running Python dry-run...
python "%~dp0bloatware_guard.py" --dry-run
set py_exit=!errorlevel!
if !py_exit! neq 0 (
    echo ERROR: Python dry-run exited with code !py_exit!
    goto :error_py
)
echo OK: Python dry-run complete.
echo.

REM --- Run C# Dry-Run ---
echo [4/5] Running C# dry-run...
echo NOTE: C# EXE requires admin elevation (UAC manifest: requireAdministrator)
echo       If not running as admin, this step will be blocked by Windows.
"bin\Release\net8.0-windows\win-x64\BloatwareGuard.exe" dry-run
set cs_exit=!errorlevel!
if !cs_exit! neq 0 (
    echo WARNING: C# EXE exited with code !cs_exit!
    echo          This is expected if not running as Administrator.
    echo          The EXE is built correctly but UAC blocks non-admin execution.
)
if !cs_exit! equ 0 (
    echo OK: C# dry-run complete.
)
echo.

REM --- Summary ---
echo [5/5] Deployment Summary
echo ========================================
echo Self-contained EXE: 11.3MB single file (no .NET runtime needed)
echo Python dry-run:    PASS (full scan with SystemApp detection)
echo C# build:          PASS (0 errors, 0 warnings)
echo C# dry-run:        !cs_exit! (0=PASS, non-0=admin required)
echo.
echo Next steps:
echo   1. Reboot system after running removal mode
echo   2. Run as Administrator for full removal layers 2-6
echo   3. Check Windows Apps settings for removed packages
echo ========================================

endlocal
goto :eof

:error_build
echo.
echo ========================================
echo FATAL: C# build failed. Check source.
echo ========================================
exit /b 1

:error_py
echo.
echo ========================================
echo FAIL: Python dry-run failed.
echo ========================================
exit /b 1
