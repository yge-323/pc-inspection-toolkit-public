from __future__ import annotations

from typing import Any

from .common import base_result, mark_error, powershell_json


def collect() -> dict[str, Any]:
    result = base_result("network_ports")
    try:
        script = r"""
        Get-NetTCPConnection -State Listen -ErrorAction Stop |
          ForEach-Object {
            $p = $null
            try { $p = Get-Process -Id $_.OwningProcess -ErrorAction Stop } catch {}
            [pscustomobject]@{
              LocalAddress=$_.LocalAddress
              LocalPort=$_.LocalPort
              OwningProcess=$_.OwningProcess
              ProcessName=if ($p) { $p.ProcessName } else { 'Unknown' }
            }
          } | Sort-Object LocalPort,LocalAddress | ConvertTo-Json -Depth 3 -Compress
        """
        data = powershell_json(script)
        if isinstance(data, dict):
            data = [data]
        result["data"] = data or []
    except Exception as exc:  # noqa: BLE001
        mark_error(result, exc)
    return result
