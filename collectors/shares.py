from __future__ import annotations

import platform
from typing import Any

from .common import base_result, mark_error, powershell_json


DEFAULT_ADMIN_SHARES = {"ADMIN$", "IPC$"}


def collect() -> dict[str, Any]:
    result = base_result("shares")
    if platform.system().lower() != "windows":
        result["status"] = "skipped"
        result["errors"].append("Windows SMB share collector is only available on Windows.")
        return result

    try:
        script = r"""
        $errors = @()
        $fallbackOutput = @()
        $shares = @()
        $usedFallback = $false

        if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
          try {
            $shareItems = Get-SmbShare -ErrorAction Stop
            $shares = foreach ($share in $shareItems) {
              $access = @()
              if (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue) {
                try {
                  $access = Get-SmbShareAccess -Name $share.Name -ErrorAction Stop |
                    Select-Object Name,AccountName,AccessControlType,AccessRight
                } catch {
                  $errors += "Get-SmbShareAccess failed for $($share.Name): $($_.Exception.Message)"
                }
              } else {
                $errors += "Get-SmbShareAccess is not available"
              }

              $broad = @($access | Where-Object {
                $_.AccountName -match 'Everyone|Guest|Anonymous|ANONYMOUS LOGON|来宾'
              })

              [pscustomobject]@{
                Name=$share.Name
                Path=$share.Path
                Description=$share.Description
                ShareType=$share.ShareType
                IsDefaultAdminShare=($share.Name -eq 'ADMIN$' -or $share.Name -eq 'IPC$' -or $share.Name -match '^[A-Z]\$$')
                Access=$access
                HasBroadAccess=($broad.Count -gt 0)
                BroadAccessAccounts=(@($broad | Select-Object -ExpandProperty AccountName -Unique) -join '; ')
              }
            }
          } catch {
            $errors += "Get-SmbShare failed: $($_.Exception.Message)"
          }
        } else {
          $errors += "Get-SmbShare is not available"
        }

        if (-not $shares -or $shares.Count -eq 0) {
          try {
            $usedFallback = $true
            $fallbackOutput = net share 2>&1
          } catch {
            $errors += "net share fallback failed: $($_.Exception.Message)"
          }
        }

        [pscustomobject]@{
          Shares=$shares
          UsedFallback=$usedFallback
          NetShareOutput=$fallbackOutput
          Errors=$errors
        } | ConvertTo-Json -Depth 6 -Compress
        """
        data = powershell_json(script, timeout=35)
        result["data"] = data
        if data.get("Errors"):
            result["status"] = "partial"
            errors = data["Errors"] if isinstance(data["Errors"], list) else [data["Errors"]]
            result["errors"].extend(errors)
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
