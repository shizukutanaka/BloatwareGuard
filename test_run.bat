@echo off
cd /d "c:\Users\HP\bloatware-guard\src\bin\Release\net8.0-windows\win-x64"
timeout /t 3 >nul
BloatwareGuard.exe --version < nul
echo ExitCode: %errorlevel%
