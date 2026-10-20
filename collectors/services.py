from __future__ import annotations

from typing import Any

from .common import base_result, mark_error, powershell_json, powershell_safe_command_helpers


def _powershell_script() -> str:
    return powershell_safe_command_helpers() + r"""
    Get-CimInstance Win32_Service -ErrorAction Stop |
      ForEach-Object {
        $imagePath = Get-PciSafeImagePath ([string]$_.PathName)
        [pscustomobject]@{
          Name = [string]$_.Name
          DisplayName = [string]$_.DisplayName
          State = [string]$_.State
          StartMode = [string]$_.StartMode
          PathName = $imagePath
          ArgumentsOmitted = $true
        }
      } |
      Sort-Object Name |
      ConvertTo-Json -Depth 3 -Compress
    """


def collect() -> dict[str, Any]:
    result = base_result("services")
    try:
        data = powershell_json(_powershell_script(), timeout=30)
        if isinstance(data, dict):
            data = [data]
        result["data"] = data or []
        if any(
            isinstance(item, dict) and str(item.get("PathName") or "").upper() == "UNKNOWN"
            for item in result["data"]
        ):
            result["status"] = "partial"
            result["errors"].append(
                "One or more service image paths could not be safely resolved; command arguments were omitted."
            )
    except Exception as exc:  # noqa: BLE001
        mark_error(result, exc)
    return result
