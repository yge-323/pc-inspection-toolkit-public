from __future__ import annotations

from typing import Any

from .common import base_result, mark_error, powershell_json


def collect() -> dict[str, Any]:
    result = base_result("users")
    try:
        script = r"""
        $users = @()
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
          $users = Get-LocalUser | Select-Object Name,Enabled,LastLogon,SID
        }
        $admins = @()
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
          $admins = Get-LocalGroupMember -Group 'Administrators' |
            Select-Object Name,ObjectClass,PrincipalSource,SID
        }
        [pscustomobject]@{ Users=$users; Administrators=$admins } | ConvertTo-Json -Depth 4 -Compress
        """
        data = powershell_json(script)
        result["data"] = data
    except Exception as exc:  # noqa: BLE001
        mark_error(result, exc)
    return result
