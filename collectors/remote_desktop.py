from __future__ import annotations

import platform
from typing import Any

from .common import base_result, mark_error, powershell_json


DEFAULT_RDP_PORT = 3389


def collect() -> dict[str, Any]:
    result = base_result("remote_desktop")
    if platform.system().lower() != "windows":
        result["status"] = "skipped"
        result["errors"].append("Windows Remote Desktop collector is only available on Windows.")
        return result

    try:
        script = r"""
        $errors = @()
        $rdpSettings = $null
        $termService = $null
        $rdpRules = @()
        $listeners = @()

        try {
          $ts = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop
          $tcp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -ErrorAction Stop
          $port = [int]$tcp.PortNumber
          $rdpSettings = [pscustomobject]@{
            FDenyTSConnections = [int]$ts.fDenyTSConnections
            RemoteDesktopEnabled = ([int]$ts.fDenyTSConnections -eq 0)
            PortNumber = $port
          }
        } catch {
          $errors += "Registry read failed: $($_.Exception.Message)"
        }

        try {
          $termService = Get-Service -Name 'TermService' -ErrorAction Stop |
            Select-Object Name,DisplayName,Status,StartType,ServiceType,CanStop
        } catch {
          $errors += "TermService read failed: $($_.Exception.Message)"
        }

        if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
          try {
            $ruleCandidates = Get-NetFirewallRule -ErrorAction Stop |
              Where-Object {
                $_.Direction -eq 'Inbound' -and
                (
                  $_.DisplayName -match 'Remote Desktop|远程桌面' -or
                  $_.DisplayGroup -match 'Remote Desktop|远程桌面'
                )
              }
            $rdpRules = foreach ($rule in $ruleCandidates) {
              $ports = ''
              if (Get-Command Get-NetFirewallPortFilter -ErrorAction SilentlyContinue) {
                try {
                  $ports = (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop |
                    ForEach-Object { "$($_.Protocol)/$($_.LocalPort)" }) -join '; '
                } catch {}
              }
              [pscustomobject]@{
                Name=$rule.Name
                DisplayName=$rule.DisplayName
                DisplayGroup=$rule.DisplayGroup
                Enabled=$rule.Enabled
                Direction=$rule.Direction
                Action=$rule.Action
                Profile=$rule.Profile
                Ports=$ports
              }
            }
          } catch {
            $errors += "Remote Desktop firewall rule read failed: $($_.Exception.Message)"
          }
        } else {
          $errors += "Get-NetFirewallRule is not available"
        }

        try {
          $targetPort = if ($rdpSettings -and $rdpSettings.PortNumber) { [int]$rdpSettings.PortNumber } else { __DEFAULT_RDP_PORT__ }
          $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalPort -eq $targetPort -or $_.LocalPort -eq __DEFAULT_RDP_PORT__ } |
            ForEach-Object {
              $p = $null
              try { $p = Get-Process -Id $_.OwningProcess -ErrorAction Stop } catch {}
              [pscustomobject]@{
                LocalAddress=$_.LocalAddress
                LocalPort=$_.LocalPort
                OwningProcess=$_.OwningProcess
                ProcessName=if ($p) { $p.ProcessName } else { 'Unknown' }
              }
            }
        } catch {
          $errors += "RDP listener read failed: $($_.Exception.Message)"
        }

        [pscustomobject]@{
          Settings=$rdpSettings
          TermService=$termService
          FirewallRules=$rdpRules
          Listeners=$listeners
          Errors=$errors
        } | ConvertTo-Json -Depth 5 -Compress
        """
        script = script.replace("__DEFAULT_RDP_PORT__", str(DEFAULT_RDP_PORT))
        data = powershell_json(script, timeout=35)
        result["data"] = data
        if data.get("Errors"):
            result["status"] = "partial"
            result["errors"].extend(data["Errors"] if isinstance(data["Errors"], list) else [data["Errors"]])
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        if "not available" in message:
            result["status"] = "skipped"
            result["errors"].append(message)
        elif "Access is denied" in message or "拒绝访问" in message:
            result["status"] = "need_admin"
            result["errors"].append(message)
        else:
            mark_error(result, exc)
    return result
