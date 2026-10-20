from __future__ import annotations

import platform
from typing import Any

from .common import base_result, mark_error, powershell_json


MAX_PROCESS_ROWS = 1000


def collect() -> dict[str, Any]:
    result = base_result("processes")
    if platform.system().casefold() != "windows":
        result["status"] = "skipped"
        result["errors"].append("Windows process inventory is only available on Windows.")
        return result

    try:
        script = rf"""
        $all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $ordered = @($all | Sort-Object {{ [int64]$_.WorkingSetSize }} -Descending)
        $items = @($ordered | Select-Object -First {MAX_PROCESS_ROWS} |
          Select-Object Name,ProcessId,ParentProcessId,WorkingSetSize,ThreadCount)
        [pscustomobject]@{{
          Items=$items
          TotalCount=$all.Count
          Truncated=($all.Count -gt {MAX_PROCESS_ROWS})
          SensitiveFieldsOmitted=@('CommandLine','ExecutablePath','Owner')
        }} | ConvertTo-Json -Depth 4 -Compress
        """
        data = powershell_json(script, timeout=35)
        if not isinstance(data, dict):
            raise ValueError("Windows process collector returned an invalid result.")
        items = data.get("Items")
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            raise ValueError("Windows process collector omitted its inventory.")
        data["Items"] = items
        result["data"] = data
        if data.get("Truncated") is True:
            result["status"] = "partial"
            result["errors"].append(f"Process inventory capped at {MAX_PROCESS_ROWS} rows.")
    except Exception as exc:  # noqa: BLE001
        mark_error(result, exc)
    return result
