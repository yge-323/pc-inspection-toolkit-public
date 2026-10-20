from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any


def powershell_safe_command_helpers() -> str:
    """PowerShell projection helpers that never serialize command arguments."""
    return r"""
    function Protect-PciUserProfilePath([string]$Value) {
      $safe = [regex]::Replace([string]$Value, '(?i)\\Users\\[^\\]+', '\Users\<redacted>')
      $safe = [regex]::Replace($safe, '[\x00-\x1f]', ' ')
      if ($safe.Length -gt 500) { return $safe.Substring(0, 500) }
      return $safe
    }

    function Get-PciSafeImagePath([string]$CommandLine) {
      $extensions = '(?:exe|com|sys|dll|cmd|bat|vbs|js|jse|wsf|hta|ps1|py)'
      $pattern = '^\s*"(?<quoted>[^"]+?\.' + $extensions + ')"|^\s*(?<bare>(?:(?:[A-Za-z]:\\|\\\\)[^\s"]*?\.' + $extensions + '|[^\s"]+?\.' + $extensions + '))(?=\s|$)'
      $match = [regex]::Match($CommandLine, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
      $imagePath = $match.Groups['quoted'].Value
      if ($imagePath -and $imagePath -match ('(?i)\.' + $extensions + '\s+')) {
        $imagePath = ''
      }
      if (-not $imagePath) { $imagePath = $match.Groups['bare'].Value }
      if (-not $imagePath) { return 'UNKNOWN' }
      return Protect-PciUserProfilePath $imagePath
    }

    function Get-PciSafeScriptPath([string]$CommandLine, [string]$ImagePath) {
      $extensions = '(?:ps1|bat|cmd|vbs|js|jse|wsf|hta|py)'
      $pattern = '(?i)(?:^|\s)(?:-File|-f|/c|/k)\s+"(?<quoted>(?:[a-z]:\\|\\\\)[^"]+\.' + $extensions + ')"|(?:^|\s)(?:-File|-f|/c|/k)\s+(?<bare>(?:[a-z]:\\|\\\\)[^\s"]+?\.' + $extensions + ')(?=\s|$)'
      $match = [regex]::Match($CommandLine, $pattern)
      if (-not $match.Success) {
        $pattern = '(?i)^\s*"(?<quoted>(?:[a-z]:\\|\\\\)[^"]+\.' + $extensions + ')"|^\s*(?<bare>(?:[a-z]:\\|\\\\)[^\s"]+?\.' + $extensions + ')(?=\s|$)'
        $match = [regex]::Match($CommandLine, $pattern)
      }
      $scriptPath = $match.Groups['quoted'].Value
      if (-not $scriptPath) { $scriptPath = $match.Groups['bare'].Value }
      if ($scriptPath -and $scriptPath -match '(?i)\.(?:exe|com|sys|dll|cmd|bat|vbs|js|jse|wsf|hta|ps1|py)\s+') {
        $scriptPath = ''
      }
      $wrappedUnresolvedCommand = $ImagePath -eq 'UNKNOWN' -and
        $CommandLine -match '(?i)^\s*"[^"]+\.(?:exe|com|sys|dll|cmd|bat|vbs|js|jse|wsf|hta|ps1|py)\s+'
      if (-not $scriptPath -or $wrappedUnresolvedCommand) { return 'UNKNOWN' }
      return Protect-PciUserProfilePath $scriptPath
    }
    """


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def base_result(name: str) -> dict[str, Any]:
    return {
        "collector": name,
        "status": "ok",
        "timestamp": utc_now(),
        "data": [],
        "errors": [],
    }


def run_command(args: list[str], timeout: int = 20) -> tuple[int, str, str]:
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def powershell_json(script: str, timeout: int = 25) -> Any:
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    code, stdout, stderr = run_command(command, timeout=timeout)
    if code != 0:
        raise RuntimeError(stderr or stdout or f"PowerShell exited with {code}")
    if not stdout:
        return []
    return json.loads(stdout)


def mark_error(result: dict[str, Any], exc: Exception) -> dict[str, Any]:
    result["status"] = "partial" if result.get("data") else "failed"
    result["errors"].append(str(exc))
    return result
