from __future__ import annotations

import getpass
import os
import platform
import socket
from typing import Any

from .common import base_result, mark_error, powershell_json


def collect() -> dict[str, Any]:
    result = base_result("system_info")
    try:
        script = r"""
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        [pscustomobject]@{
          Hostname = $env:COMPUTERNAME
          Caption = $os.Caption
          Version = $os.Version
          BuildNumber = $os.BuildNumber
          LastBootUpTime = $os.LastBootUpTime
          Manufacturer = $cs.Manufacturer
          Model = $cs.Model
          TotalPhysicalMemory = $cs.TotalPhysicalMemory
        } | ConvertTo-Json -Compress
        """
        info = powershell_json(script)
        result["data"] = {
            "hostname": info.get("Hostname") or socket.gethostname(),
            "os": info.get("Caption") or platform.platform(),
            "version": info.get("Version"),
            "build": info.get("BuildNumber"),
            "current_user": getpass.getuser(),
            "is_admin": _is_admin(),
            "last_boot": info.get("LastBootUpTime"),
            "manufacturer": info.get("Manufacturer"),
            "model": info.get("Model"),
            "total_memory_bytes": info.get("TotalPhysicalMemory"),
        }
    except Exception as exc:  # noqa: BLE001
        result["data"] = {
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "current_user": getpass.getuser(),
            "is_admin": _is_admin(),
        }
        mark_error(result, exc)
    return result


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
