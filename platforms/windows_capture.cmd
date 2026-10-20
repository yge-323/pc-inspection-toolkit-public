@echo off
setlocal DisableDelayedExpansion
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%~dp0..\data\raw\inspection-evidence"
if exist "%OUT%" (
  echo Refusing to reuse an existing output path.
  exit /b 2
)
if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" (
  echo PowerShell 2.0 or later is required; legacy WMIC/VBS fallback is not automatic.
  exit /b 126
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0inspect.ps1" -OutputDirectory "%OUT%"
exit /b %ERRORLEVEL%
