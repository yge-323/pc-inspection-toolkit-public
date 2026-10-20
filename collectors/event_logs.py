from __future__ import annotations

from typing import Any

from .common import base_result, mark_error, powershell_json


def collect() -> dict[str, Any]:
    result = base_result("event_logs")
    try:
        script = r"""
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3} -MaxEvents 50 -ErrorAction Stop
        $events | Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message |
          ConvertTo-Json -Depth 3 -Compress
        """
        data = powershell_json(script, timeout=30)
        if isinstance(data, dict):
            data = [data]
        result["data"] = data or []
    except Exception as exc:  # noqa: BLE001
        mark_error(result, exc)
    return result
