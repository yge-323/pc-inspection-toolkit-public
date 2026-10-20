from __future__ import annotations

import platform
from typing import Any

from .common import base_result, mark_error, powershell_json


def collect() -> dict[str, Any]:
    result = base_result("firewall")
    if platform.system().lower() != "windows":
        result["status"] = "skipped"
        result["errors"].append("Windows firewall collector is only available on Windows.")
        return result

    try:
        script = r"""
        $profiles = @()
        $allowRules = @()
        $smbRules = @()
        $rdpRules = @()

        if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
          throw "Get-NetFirewallProfile is not available"
        }
        if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
          throw "Get-NetFirewallRule is not available"
        }
        if (-not (Get-Command Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
          throw "Get-NetFirewallPortFilter is not available"
        }

        $profiles = Get-NetFirewallProfile -ErrorAction Stop |
          Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,LogAllowed,LogBlocked,LogFileName

        $allAllowInbound = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop

        $allowRules = $allAllowInbound |
          Select-Object -First 80 Name,DisplayName,DisplayGroup,Enabled,Direction,Action,Profile

        $smbRules = Get-NetFirewallRule -ErrorAction Stop |
          Where-Object {
            $_.Direction -eq 'Inbound' -and
            (
              $_.DisplayName -match 'SMB-In|File and Printer Sharing|文件和打印机共享' -or
              $_.DisplayGroup -match 'File and Printer Sharing|文件和打印机共享' -or
              $_.Name -match 'SMB-In'
            )
          } |
          Select-Object Name,DisplayName,DisplayGroup,Enabled,Direction,Action,Profile

        $rdpRuleCandidates = Get-NetFirewallRule -ErrorAction Stop |
          Where-Object {
            $_.Direction -eq 'Inbound' -and
            (
              $_.DisplayName -match 'Remote Desktop|远程桌面' -or
              $_.DisplayGroup -match 'Remote Desktop|远程桌面'
            )
          }

        $rdpRules = foreach ($rule in $rdpRuleCandidates) {
          $ports = ''
          try {
            $ports = (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop |
              ForEach-Object { "$($_.Protocol)/$($_.LocalPort)" }) -join '; '
          } catch {}
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

        [pscustomobject]@{
          Profiles=$profiles
          InboundAllowRulesSample=$allowRules
          SmbInboundRules=$smbRules
          RemoteDesktopInboundRules=$rdpRules
        } | ConvertTo-Json -Depth 5 -Compress
        """
        data = powershell_json(script, timeout=35)
        result["data"] = data
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
