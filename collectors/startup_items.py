from __future__ import annotations

import platform
from typing import Any

from .common import base_result, mark_error, powershell_json, powershell_safe_command_helpers


def _powershell_script() -> str:
    return powershell_safe_command_helpers() + r"""
    $ErrorActionPreference = 'Stop'
    $items = @()
    $errors = @()

    function Add-StartupItem {
      param(
        [string]$Name,
        [string]$Command,
        [string]$Location,
        [string]$Scope,
        [string]$SourceType
      )
      $imagePath = Get-PciSafeImagePath $Command
      $scriptPath = Get-PciSafeScriptPath $Command $imagePath
      $safeScriptPath = $null
      $scriptExtension = $null
      if ($scriptPath -ne 'UNKNOWN') {
        $safeScriptPath = $scriptPath
        $extensionMatch = [regex]::Match($scriptPath, '(?i)\.(ps1|bat|cmd|vbs|js|jse|wsf|hta|py)$')
        if ($extensionMatch.Success) { $scriptExtension = '.' + $extensionMatch.Groups[1].Value.ToLowerInvariant() }
      }
      $item = [pscustomobject]@{
        Name = Protect-PciUserProfilePath $Name
        Command = $imagePath
        ImagePath = $imagePath
        ScriptPath = $safeScriptPath
        ScriptExtension = $scriptExtension
        Location = Protect-PciUserProfilePath $Location
        Scope = Protect-PciUserProfilePath $Scope
        SourceType = Protect-PciUserProfilePath $SourceType
        ArgumentsOmitted = $true
      }
      if ($imagePath -eq 'UNKNOWN') {
        $script:errors += 'A startup image path could not be safely resolved; command arguments were omitted.'
      }
      if ($Command -match '(?i)(?:^|\s)-File(?:\s|$)' -and $scriptPath -eq 'UNKNOWN') {
        $script:errors += 'A startup script path could not be safely resolved; command arguments were omitted.'
      }
      $script:items += $item
    }

    $runKeys = @(
      [pscustomobject]@{ Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope='LocalMachine' },
      [pscustomobject]@{ Path='HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Scope='LocalMachine' },
      [pscustomobject]@{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope='CurrentUser' }
    )

    foreach ($key in $runKeys) {
      try {
        if (Test-Path -LiteralPath $key.Path) {
          $props = Get-ItemProperty -LiteralPath $key.Path
          foreach ($prop in $props.PSObject.Properties) {
            if ($prop.MemberType -eq 'NoteProperty' -and $prop.Name -notlike 'PS*') {
              Add-StartupItem -Name $prop.Name -Command ([string]$prop.Value) -Location $key.Path -Scope $key.Scope -SourceType 'RegistryRun'
            }
          }
        }
      } catch {
        $errors += Protect-PciUserProfilePath ("$($key.Path): $($_.Exception.Message)")
      }
    }

    $folders = @(
      [pscustomobject]@{ Path=[Environment]::GetFolderPath('Startup'); Scope='CurrentUser' },
      [pscustomobject]@{ Path=[Environment]::GetFolderPath('CommonStartup'); Scope='Public' }
    )

    foreach ($folder in $folders) {
      try {
        if ($folder.Path -and (Test-Path -LiteralPath $folder.Path)) {
          Get-ChildItem -LiteralPath $folder.Path -File -ErrorAction Stop | ForEach-Object {
            $command = $_.FullName
            if ($_.Extension -ieq '.lnk') {
              try {
                $shell = New-Object -ComObject WScript.Shell
                $shortcut = $shell.CreateShortcut($_.FullName)
                $target = @($shortcut.TargetPath, $shortcut.Arguments) -join ' '
                if ($target.Trim()) { $command = $target.Trim() }
              } catch {
                $errors += Protect-PciUserProfilePath ("$($_.FullName): shortcut target read failed: $($_.Exception.Message)")
              }
            }
            Add-StartupItem -Name $_.Name -Command $command -Location $folder.Path -Scope $folder.Scope -SourceType 'StartupFolder'
          }
        }
      } catch {
        $errors += Protect-PciUserProfilePath ("$($folder.Path): $($_.Exception.Message)")
      }
    }

    [pscustomobject]@{
      Items = $items
      Findings = @()
      Errors = $errors
      ArgumentsAndUserNames = 'OMITTED_FOR_PRIVACY'
    } | ConvertTo-Json -Depth 6 -Compress
    """


def collect() -> dict[str, Any]:
    result = base_result("startup_items")
    if platform.system().lower() != "windows":
        result["status"] = "skipped"
        result["data"] = {"Items": [], "Findings": [], "Errors": ["Skipped: non-Windows system."]}
        return result

    try:
        data = powershell_json(_powershell_script(), timeout=30)
        data = data or {"Items": [], "Findings": [], "Errors": []}
        result["data"] = data
        items = data.get("Items", []) if isinstance(data, dict) else []
        if any(
            isinstance(item, dict) and str(item.get("ImagePath") or "").upper() == "UNKNOWN"
            for item in (items if isinstance(items, list) else [])
        ):
            result["status"] = "partial"
            result["errors"].append(
                "One or more startup image paths could not be safely resolved; command arguments were omitted."
            )
        if data.get("Errors"):
            result["status"] = "partial" if data.get("Items") else "skipped"
            result["errors"].extend(data["Errors"])
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        if "Access is denied" in message or "拒绝访问" in message:
            result["status"] = "need_admin"
            result["errors"].append(message)
        else:
            mark_error(result, exc)
    return result
