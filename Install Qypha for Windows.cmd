@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "WIZARD=%SCRIPT_DIR%Install Qypha for Windows.ps1"

if not exist "%WIZARD%" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Install Qypha for Windows.ps1 was not found next to Install Qypha for Windows.cmd.','Qypha Setup',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null"
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%WIZARD%"
exit /b %ERRORLEVEL%
