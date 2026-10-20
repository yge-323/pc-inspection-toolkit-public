from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any

from .common import base_result, mark_error, powershell_json


def collect() -> dict[str, Any]:
    result = base_result("windows_security")
    if platform.system().casefold() != "windows":
        result["status"] = "skipped"
        result["errors"].append("Windows security settings are only available on Windows.")
        return result

    if getattr(sys, "frozen", False):
        application_root = Path(sys.executable).resolve().parent
        helper_path = application_root / "platforms" / "windows_capture_helpers.ps1"
        if not helper_path.is_file():
            helper_path = Path(getattr(sys, "_MEIPASS", application_root)) / "platforms" / "windows_capture_helpers.ps1"
    else:
        helper_path = Path(__file__).resolve().parents[1] / "platforms" / "windows_capture_helpers.ps1"
    helper_literal = "'" + str(helper_path).replace("'", "''") + "'"

    script = r"""
    $helperPath = __PCI_HELPER_PATH__
    . $helperPath
    $errors = @()
    $policy = @{}
    $passwordPolicyStatus = 'unavailable'
    $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('pcit-security-' + [guid]::NewGuid().ToString('N'))
    try {
      [void](Assert-PciNoReparsePath -Path $tempDirectory)
      if (Test-Path -LiteralPath $tempDirectory) { throw 'TEMP_DIRECTORY_COLLISION' }
      New-Item -ItemType Directory -Path $tempDirectory -ErrorAction Stop | Out-Null
      [void](Assert-PciNoReparsePath -Path $tempDirectory)
      $cfg = Join-Path $tempDirectory 'merged-policy.inf'
      $log = Join-Path $tempDirectory 'secedit.log'
      $secedit = Join-Path $env:SystemRoot 'System32\secedit.exe'
      if (Test-Path -LiteralPath $secedit -PathType Leaf) {
        & $secedit /export /mergedpolicy /cfg $cfg /areas securitypolicy /log $log /quiet 2>$null | Out-Null
        $seceditExitCode = $LASTEXITCODE
        $policyExists = Test-Path -LiteralPath $cfg -PathType Leaf
        $policyLines = @()
        if ($policyExists) { $policyLines = @(Get-Content -LiteralPath $cfg -ErrorAction Stop) }
        $parsedPolicy = Resolve-PciSecurityPolicyExport -ExitCode $seceditExitCode -FileExists $policyExists -Lines $policyLines
        $policy = $parsedPolicy.Values
        $passwordPolicyStatus = $parsedPolicy.Status
        if ($passwordPolicyStatus -ne 'collected') {
          $errors += 'Effective password/account policy export was denied, unavailable, or incomplete.'
        }
      }
      else { $passwordPolicyStatus = 'tool_unavailable'; $errors += 'secedit.exe is unavailable.' }
    }
    catch { $passwordPolicyStatus = 'failed'; $errors += 'Effective password/account policy could not be read.' }
    finally {
      try { Remove-PciPrivateTempDirectory -Path $tempDirectory -Prefix 'pcit-security' }
      catch { $errors += 'Temporary security-policy data could not be safely removed.' }
    }

    function Read-Value([string]$Path, [string]$Name) {
      try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
      catch { return $null }
    }
    $rdpBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $smbPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $rdpDisabled = Read-Value $rdpBase 'fDenyTSConnections'
    $nlaRequired = Read-Value ($rdpBase + '\WinStations\RDP-Tcp') 'UserAuthentication'
    $smb1 = Read-Value $smbPath 'SMB1'
    $autoLogon = Read-Value $winlogon 'AutoAdminLogon'
    $firewall = @()
    foreach ($profile in @('DomainProfile','StandardProfile','PublicProfile')) {
      $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' + $profile
      $firewall += [pscustomobject]@{
        Name=$profile
        Enabled=(Read-Value $path 'EnableFirewall')
        DefaultInboundAction=(Read-Value $path 'DefaultInboundAction')
      }
    }
    $guestEnabled = $null
    $localAccountCount = $null
    $enabledLocalAccountCount = $null
    try {
      $accounts = @(Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
      $localAccountCount = $accounts.Count
      $enabledLocalAccountCount = @($accounts | Where-Object { -not $_.Disabled }).Count
      $guest = @($accounts | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1)
      if ($guest.Count -gt 0) { $guestEnabled = [bool](-not $guest[0].Disabled) }
    }
    catch { $errors += 'Local account summary unavailable; names and SIDs were not exported.' }

    $audit = @()
    $auditStatus = 'unavailable'
    $auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    if (Test-Path -LiteralPath $auditpol -PathType Leaf) {
      try {
        $rows = @(& $auditpol /get /category:* /r 2>$null | ConvertFrom-Csv)
        if ($LASTEXITCODE -eq 0) {
          foreach ($row in ($rows | Select-Object -First 256)) {
            $values = @($row.PSObject.Properties | ForEach-Object { $_.Value })
            if ($values.Count -ge 6) {
              $audit += [pscustomobject]@{ Subcategory=$values[2]; Guid=$values[3]; Inclusion=$values[4]; Exclusion=$values[5] }
            }
          }
          $auditStatus = 'collected'
          if ($rows.Count -gt 256) { $errors += 'Audit policy detail capped at 256 subcategories.' }
        }
        else { $auditStatus = 'permission_denied_or_unavailable'; $errors += 'Audit policy query failed.' }
      }
      catch { $auditStatus = 'failed'; $errors += 'Audit policy query failed.' }
    }
    else { $auditStatus = 'tool_unavailable'; $errors += 'auditpol.exe is unavailable.' }

    $patchSummary = @{ Status='unavailable'; Count=$null; LatestInstalled=$null }
    try {
      $hotfixes = @(Get-WmiObject Win32_QuickFixEngineering -ErrorAction Stop)
      $patchSummary = Get-PciHotfixSummary -Hotfixes $hotfixes
      if ($patchSummary.Status -ne 'collected') {
        $errors += 'Quick-fix engineering dates were missing, ambiguous, or invalid; freshness was not rated.'
      }
    }
    catch { $errors += 'Quick-fix engineering summary unavailable; freshness was not rated.' }

    $defender = @{ Status='not_applicable_or_unavailable'; AntivirusEnabled=$null; RealTimeProtectionEnabled=$null; SignatureAge=$null }
    try {
      if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defender = @{ Status='collected'; AntivirusEnabled=[bool]$mp.AntivirusEnabled; RealTimeProtectionEnabled=[bool]$mp.RealTimeProtectionEnabled; SignatureAge=$mp.AntivirusSignatureAge }
      }
    }
    catch { $defender = @{ Status='permission_denied_or_unavailable'; AntivirusEnabled=$null; RealTimeProtectionEnabled=$null; SignatureAge=$null } }

    $autoEnabled = $null
    if ($null -ne $autoLogon) { $autoEnabled = ([string]$autoLogon -eq '1') }
    $rdpEnabled = $null
    if ($null -ne $rdpDisabled) { $rdpEnabled = ([int]$rdpDisabled -eq 0) }
    $nlaValue = $null
    if ($null -ne $nlaRequired) { $nlaValue = ([int]$nlaRequired -eq 1) }
    $smbEnabled = $null
    if ($null -ne $smb1) { $smbEnabled = ([int]$smb1 -eq 1) }
    foreach ($fact in @(
      @{ Name='RDP enablement'; Value=$rdpEnabled },
      @{ Name='RDP NLA requirement'; Value=$nlaValue },
      @{ Name='explicit SMB1 setting'; Value=$smbEnabled },
      @{ Name='automatic logon flag'; Value=$autoEnabled },
      @{ Name='built-in Guest state'; Value=$guestEnabled }
    )) {
      if ($null -eq $fact.Value) { $errors += ($fact.Name + ' is unknown because its source value was unavailable.') }
    }
    foreach ($profile in $firewall) {
      if ($null -eq $profile.Enabled) { $errors += ($profile.Name + ' firewall state is unknown.') }
    }
    [pscustomobject]@{
      PasswordPolicy=@{ Status=$passwordPolicyStatus; Values=$policy }
      AuditPolicy=@{ Status=$auditStatus; Rows=$audit }
      Rdp=@{ Enabled=$rdpEnabled; NlaRequired=$nlaValue; Evidence='Terminal Server registry values; firewall reachability not tested' }
      Smb1=@{ Enabled=$smbEnabled; Evidence='Explicit LanmanServer SMB1 registry value; missing value remains unknown' }
      AutoLogon=@{ Enabled=$autoEnabled; Evidence='AutoAdminLogon flag only; credentials were not read' }
      FirewallProfiles=$firewall
      LocalAccounts=@{ Total=$localAccountCount; Enabled=$enabledLocalAccountCount; GuestEnabled=$guestEnabled; Identities='omitted' }
      PatchSummary=$patchSummary
      Defender=$defender
      Errors=$errors
    } | ConvertTo-Json -Depth 7 -Compress
    """
    script = script.replace("__PCI_HELPER_PATH__", helper_literal)
    try:
        data = powershell_json(script, timeout=45)
        if not isinstance(data, dict):
            raise ValueError("Windows security collector returned an invalid result.")
        result["data"] = data
        errors = data.get("Errors") or []
        if errors:
            result["status"] = "partial"
            result["errors"].extend(str(item) for item in (errors if isinstance(errors, list) else [errors]))
    except Exception as exc:  # noqa: BLE001
        mark_error(result, exc)
    return result
