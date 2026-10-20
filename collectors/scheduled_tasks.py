from __future__ import annotations

from typing import Any

from .common import base_result, mark_error, powershell_json, powershell_safe_command_helpers


def _powershell_script() -> str:
    return powershell_safe_command_helpers() + r"""
    function ConvertTo-PciSafeScheduledTask([object]$Task) {
      $safeActions = New-Object System.Collections.ArrayList
      $safeScriptPaths = New-Object System.Collections.ArrayList
      $unknownActionPathCount = 0
      foreach ($action in @($Task.Actions)) {
        if ($null -eq $action) { continue }
        $execute = [string]$action.Execute
        $arguments = [string]$action.Arguments
        $imagePath = Get-PciSafeImagePath $execute
        if ($imagePath -eq 'UNKNOWN') { $unknownActionPathCount++ }
        $combinedCommand = $execute
        if ($arguments) { $combinedCommand += ' ' + $arguments }
        $scriptPath = Get-PciSafeScriptPath $combinedCommand $imagePath
        if ($scriptPath -ne 'UNKNOWN') {
          if (-not $safeScriptPaths.Contains($scriptPath)) { [void]$safeScriptPaths.Add($scriptPath) }
        } elseif ($combinedCommand -match '(?i)(?:^|\s)-File(?:\s|$)') {
          $unknownActionPathCount++
        }
        [void]$safeActions.Add($imagePath)
      }
      return [pscustomobject]@{
        TaskName = Protect-PciUserProfilePath ([string]$Task.TaskName)
        TaskPath = Protect-PciUserProfilePath ([string]$Task.TaskPath)
        State = [string]$Task.State
        Actions = (@($safeActions.ToArray()) -join ' | ')
        ScriptPaths = [string[]]$safeScriptPaths.ToArray()
        ActionCount = $safeActions.Count
        UnknownActionPathCount = $unknownActionPathCount
        ArgumentsAndAuthor = 'OMITTED_FOR_PRIVACY'
      }
    }

    Get-ScheduledTask -ErrorAction Stop |
      Where-Object { $_.State -ne 'Disabled' } |
      ForEach-Object { ConvertTo-PciSafeScheduledTask $_ } |
      Sort-Object TaskPath,TaskName |
      ConvertTo-Json -Depth 4 -Compress
    """


def collect() -> dict[str, Any]:
    result = base_result("scheduled_tasks")
    try:
        data = powershell_json(_powershell_script(), timeout=35)
        if isinstance(data, dict):
            data = [data]
        result["data"] = data or []
        if any(
            isinstance(item, dict) and str(item.get("UnknownActionPathCount") or "0").isdigit()
            and int(item.get("UnknownActionPathCount") or 0) > 0
            for item in result["data"]
        ):
            result["status"] = "partial"
            result["errors"].append(
                "One or more scheduled task action paths could not be safely resolved; command arguments and author names were omitted."
            )
    except Exception as exc:  # noqa: BLE001
        mark_error(result, exc)
    return result
