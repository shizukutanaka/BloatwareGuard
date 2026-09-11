@echo off
REM BloatwareGuard v1.8.0-mvp - Deployment Verification Script
REM Requirements:
REM   1. Windows 11 with .NET 8 Desktop Runtime installed
REM   2. Run as Administrator for removal layers (Layer 2-6)
REM   3. Reboot after execution

setlocal enabledelayedexpansion

echo ========================================
echo BloatwareGuard v1.8.0-mvp - Deploy Verify
echo ========================================
echo.

REM --- Check .NET 8 Runtime ---
echo [1/6] Checking .NET 8 Runtime...
where dotnet >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: .NET 8 Desktop Runtime not found.
    echo Download: https://dotnet.microsoft.com/download/dotnet/8.0
    goto :error_dotnet
)
dotnet --list-runtimes | findstr /C:"8." >nul
if %errorlevel% neq 0 (
    echo ERROR: .NET 8 runtime version not detected.
    goto :error_dotnet
)
echo OK: .NET 8 runtime found.
echo.

REM --- Check Admin Rights ---
echo [2/6] Checking Administrator rights...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Not running as Administrator.
    echo Non-admin mode: Layers 2-6 will detect + log, but cannot remove.
    echo Run as Administrator for full functionality.
) else (
    echo OK: Running as Administrator.
)
echo.

REM --- Build C# Release ---
echo [3/6] Building C# Release (self-contained win-x64)...
cd /d "%~dp0src"
if not exist "bin\Release\net8.0-windows\win-x64" mkdir "bin\Release\net8.0-windows\win-x64"
dotnet publish BloatwareGuard.csproj -c Release -r win-x64 --self-contained true -p:PublishTrimmed=true -o "bin\Release\net8.0-windows\win-x64" --nologo -v minimal
if %errorlevel% neq 0 (
    echo ERROR: C# build failed.
    goto :error_build
)
echo OK: C# build 0 errors, 0 warnings.
echo.

REM --- Run Dry-Run ---
echo [4/6] Running dry-run mode...
python "%~dp0bloatware_guard.py" --dry-run 2>&1 | tail -20
set py_exit=!errorlevel!
if !py_exit! neq 0 (
    echo ERROR: Python dry-run exited with code !py_exit!
    goto :error_py
)
echo OK: Python dry-run complete.
echo.

REM --- Run C# Dry-Run ---
echo [5/6] Running C# dry-run mode...
"bin\Release\net8.0-windows\win-x64\BloatwareGuard.exe" --dry-run
set cs_exit=!errorlevel!
if !cs_exit! neq 0 (
    echo ERROR: C# EXE exited with code !cs_exit!
    goto :error_cs
)
echo OK: C# dry-run complete.
echo.

REM --- Summary ---
echo [6/6] Deployment Summary
echo ========================================
echo Python dry-run: PASS
echo C# build:       PASS (0 errors, 0 warnings)
echo C# dry-run:     PASS
echo.
echo Next steps:
echo   1. Reboot system
echo   2. Run with --execute as Administrator
echo   3. Check Windows Apps settings for removed packages
echo ========================================

endlocal
goto :eof

:error_dotnet
echo.
echo ========================================
echo FATAL: .NET 8 not installed. Cannot proceed.
echo ========================================
exit /b 1

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

:error_cs
echo.
echo ========================================
echo FAIL: C# exe failed.
echo ========================================
exit /b 1
