from __future__ import annotations

import os
import platform
import re
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .common import base_result, powershell_json, powershell_safe_command_helpers
from rules.loader import is_safe_vendor_directory_candidate

DEFAULT_TIMEOUT_SECONDS = 15
INSTALLED_PROGRAMS_TIMEOUT_SECONDS = 10

INSTALLED_PROGRAM_FIELDS = ("display_name", "publisher", "install_location")
DRIVER_FIELDS = ("name", "display_name", "path_name")

PowerShellRunner = Callable[..., Any]
PathExists = Callable[[Path], bool]
VendorPatterns = Mapping[str, Mapping[str, Sequence[str]]]


def _installed_programs_script() -> str:
    return powershell_safe_command_helpers() + r"""
    function ConvertTo-PciSafeInstalledProgram([object]$Item, [string]$Source) {
      return [pscustomobject]@{
        DisplayName = [string]$Item.DisplayName
        DisplayVersion = [string]$Item.DisplayVersion
        Publisher = [string]$Item.Publisher
        InstallLocation = Protect-PciUserProfilePath ([string]$Item.InstallLocation)
        RegistrySource = $Source
      }
    }
    $targets = @(
      [pscustomobject]@{ Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source='HKLM64' },
      [pscustomobject]@{ Path='HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source='HKLM32' },
      [pscustomobject]@{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source='HKCU' }
    )
    $items = @()
    $errors = @()
    $successfulSources = 0
    foreach ($target in $targets) {
      try {
        $found = Get-ItemProperty -Path $target.Path -ErrorAction Stop |
          Where-Object { $_.DisplayName } |
          ForEach-Object { ConvertTo-PciSafeInstalledProgram $_ $target.Source }
        $items += $found
        $successfulSources += 1
      } catch {
        $status = if ($_.Exception.Message -match 'Access is denied|拒绝访问') { 'need_admin' } else { 'failed' }
        $errors += [pscustomobject]@{
          source = 'installed_programs'
          status = $status
          message = "$($target.Source): $($_.Exception.Message)"
        }
      }
    }
    [pscustomobject]@{
      Items = $items
      Errors = $errors
      SuccessfulSources = $successfulSources
    } | ConvertTo-Json -Depth 5 -Compress
    """


def _drivers_script() -> str:
    return powershell_safe_command_helpers() + r"""
    function ConvertTo-PciSafeSystemDriver([object]$Item) {
      return [pscustomobject]@{
        Name = [string]$Item.Name
        DisplayName = [string]$Item.DisplayName
        State = [string]$Item.State
        StartMode = [string]$Item.StartMode
        PathName = Get-PciSafeImagePath ([string]$Item.PathName)
        ServiceType = [string]$Item.ServiceType
        ArgumentsOmitted = $true
      }
    }
    $items = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
      ForEach-Object { ConvertTo-PciSafeSystemDriver $_ })
    $unresolvedPathCount = @($items | Where-Object { $_.PathName -eq 'UNKNOWN' }).Count
    [pscustomobject]@{
      Items = $items
      UnresolvedPathCount = $unresolvedPathCount
    } | ConvertTo-Json -Depth 4 -Compress
    """


def collect(
    vendor_patterns: VendorPatterns,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    *,
    powershell_runner: PowerShellRunner = powershell_json,
    path_exists: PathExists | None = None,
    environ: Mapping[str, str] | None = None,
    system_name: str | None = None,
) -> dict[str, Any]:
    result = base_result("security_vendors")
    result["data"] = _empty_data()

    current_system = system_name or platform.system()
    if current_system.casefold() != "windows":
        result["status"] = "skipped"
        result["errors"].append(_error("collector", "skipped", "Windows security vendor collector is only available on Windows."))
        return result

    installed = collect_installed_programs(
        vendor_patterns,
        timeout_seconds=min(timeout_seconds, INSTALLED_PROGRAMS_TIMEOUT_SECONDS),
        powershell_runner=powershell_runner,
    )
    drivers = collect_drivers(
        vendor_patterns,
        timeout_seconds=timeout_seconds,
        powershell_runner=powershell_runner,
    )
    directories = collect_directories(
        vendor_patterns,
        path_exists=path_exists,
        environ=environ,
    )

    result["data"]["installed_programs"] = installed["items"]
    result["data"]["drivers"] = drivers["items"]
    result["data"]["directories"] = directories["items"]
    result["data"]["summary"] = build_summary(result["data"])

    sources = (installed, drivers, directories)
    for source in sources:
        result["errors"].extend(source["errors"])
    result["status"] = _overall_status(sources)
    return result


def match_vendor(
    fields: Mapping[str, Any],
    allowed_fields: Sequence[str],
    vendor_patterns: VendorPatterns,
) -> dict[str, str] | None:
    for field_name in allowed_fields:
        value = fields.get(field_name)
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = value.casefold()
        for vendor, rule in vendor_patterns.items():
            for keyword in rule.get("keywords", ()):
                if keyword.casefold() in normalized:
                    return {"matched_vendor": vendor, "matched_keyword": keyword}
    return None


def normalize_installed_programs(raw_items: Any, vendor_patterns: VendorPatterns) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in _as_list(raw_items):
        if not isinstance(item, dict):
            continue
        row = {
            "display_name": _first_present(item, "DisplayName", "display_name"),
            "display_version": _first_present(item, "DisplayVersion", "display_version"),
            "publisher": _first_present(item, "Publisher", "publisher"),
            "install_location": _redact_windows_user_profile(
                _first_present(item, "InstallLocation", "install_location")
            ),
            "uninstall_string": None,
            "quiet_uninstall_string": None,
            "registry_source": _first_present(item, "RegistrySource", "registry_source"),
        }
        match = match_vendor(row, INSTALLED_PROGRAM_FIELDS, vendor_patterns)
        if match is None:
            continue
        row.update(match)
        row["source_type"] = "installed_program"
        normalized.append(row)
    return normalized


def normalize_drivers(raw_items: Any, vendor_patterns: VendorPatterns) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in _as_list(raw_items):
        if not isinstance(item, dict):
            continue
        row = {
            "name": _first_present(item, "Name", "name"),
            "display_name": _first_present(item, "DisplayName", "display_name"),
            "state": _first_present(item, "State", "state"),
            "start_mode": _first_present(item, "StartMode", "start_mode"),
            "path_name": _safe_driver_image_path(_first_present(item, "PathName", "path_name")),
            "service_type": _first_present(item, "ServiceType", "service_type"),
        }
        match = match_vendor(row, DRIVER_FIELDS, vendor_patterns)
        if match is None:
            continue
        row.update(match)
        row["source_type"] = "driver"
        normalized.append(row)
    return normalized


def collect_installed_programs(
    vendor_patterns: VendorPatterns,
    timeout_seconds: int = INSTALLED_PROGRAMS_TIMEOUT_SECONDS,
    *,
    powershell_runner: PowerShellRunner = powershell_json,
) -> dict[str, Any]:
    script = _installed_programs_script()
    try:
        raw = powershell_runner(script, timeout=timeout_seconds)
    except Exception as exc:  # noqa: BLE001
        status = _exception_status(exc)
        return _source_result(status, [], [_error("installed_programs", status, str(exc))])

    payload = raw if isinstance(raw, dict) else {"Items": raw, "Errors": [], "SuccessfulSources": 1}
    items = normalize_installed_programs(payload.get("Items"), vendor_patterns)
    errors = _normalize_errors(payload.get("Errors"), "installed_programs")
    successful_sources = _integer(payload.get("SuccessfulSources"), default=1)
    status = _subcollection_status(successful_sources, errors)
    return _source_result(status, items, errors)


def collect_drivers(
    vendor_patterns: VendorPatterns,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    *,
    powershell_runner: PowerShellRunner = powershell_json,
) -> dict[str, Any]:
    script = _drivers_script()
    try:
        raw = powershell_runner(script, timeout=timeout_seconds)
    except Exception as exc:  # noqa: BLE001
        status = _exception_status(exc)
        return _source_result(status, [], [_error("drivers", status, str(exc))])
    payload = raw if isinstance(raw, dict) and "Items" in raw else {"Items": raw}
    items = normalize_drivers(payload.get("Items"), vendor_patterns)
    unresolved_count = _integer(payload.get("UnresolvedPathCount"), default=0)
    if not isinstance(raw, dict) or "UnresolvedPathCount" not in raw:
        unresolved_count = sum(
            1 for item in _as_list(payload.get("Items"))
            if isinstance(item, dict) and
            str(_first_present(item, "PathName", "path_name") or "").upper() == "UNKNOWN"
        )
    errors = (
        [_error("drivers", "partial", "One or more driver image paths could not be safely resolved; command arguments were omitted.")]
        if unresolved_count > 0 else []
    )
    return _source_result("partial" if unresolved_count > 0 else "ok", items, errors)


def collect_directories(
    vendor_patterns: VendorPatterns,
    *,
    path_exists: PathExists | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    exists = path_exists or Path.is_dir
    environment = environ if environ is not None else os.environ
    roots = _directory_roots(environment)
    items: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    checked = 0
    seen: set[str] = set()

    for root in roots:
        for vendor, pattern in vendor_patterns.items():
            relative_paths = pattern.get("directory_candidates", ())
            for relative_path in relative_paths:
                if not isinstance(relative_path, str) or not is_safe_vendor_directory_candidate(relative_path):
                    errors.append(_error(
                        "directories",
                        "failed",
                        "Rejected an unsafe vendor directory candidate.",
                    ))
                    continue
                candidate = root.joinpath(*relative_path.replace("\\", "/").split("/"))
                identity = str(candidate).casefold()
                if identity in seen:
                    continue
                seen.add(identity)
                try:
                    present = bool(exists(candidate))
                    checked += 1
                except Exception as exc:  # noqa: BLE001
                    status = _exception_status(exc)
                    errors.append(_error("directories", status, f"{candidate}: {exc}"))
                    continue
                if present:
                    items.append({
                        "path": _redact_windows_user_profile(candidate),
                        "exists": True,
                        "matched_vendor": vendor,
                        "matched_keyword": relative_path,
                        "source_type": "directory",
                    })

    status = _subcollection_status(checked, errors)
    return _source_result(status, items, errors)


def build_summary(data: Mapping[str, Any]) -> dict[str, Any]:
    installed_programs = [item for item in _as_list(data.get("installed_programs")) if isinstance(item, dict)]
    drivers = [item for item in _as_list(data.get("drivers")) if isinstance(item, dict)]
    directories = [item for item in _as_list(data.get("directories")) if isinstance(item, dict)]
    all_items = installed_programs + drivers + directories
    vendors = sorted({str(item["matched_vendor"]) for item in all_items if item.get("matched_vendor")})
    installed_vendors = {str(item["matched_vendor"]) for item in installed_programs if item.get("matched_vendor")}
    return {
        "vendors_detected": vendors,
        "installed_vendor_count": len(installed_vendors),
        "driver_count": len(drivers),
        "directory_count": len(directories),
    }


def _empty_data() -> dict[str, Any]:
    return {
        "installed_programs": [],
        "drivers": [],
        "directories": [],
        "summary": {
            "vendors_detected": [],
            "installed_vendor_count": 0,
            "driver_count": 0,
            "directory_count": 0,
        },
    }


def _directory_roots(environ: Mapping[str, str]) -> list[Path]:
    roots: list[Path] = []
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA"):
        value = environ.get(key)
        if value:
            roots.append(Path(value))
    user_profile = environ.get("USERPROFILE")
    if user_profile:
        roots.append(Path(user_profile) / "AppData" / "LocalLow")
    return roots


def _redact_windows_user_profile(value: Any) -> str | None:
    if value is None:
        return None
    text = re.sub(r"[\x00-\x1f]", " ", str(value))
    return re.sub(
        r"(?i)\\Users\\[^\\]+",
        lambda _match: r"\Users\<redacted>",
        text,
    )[:500]


def _safe_driver_image_path(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    text = re.sub(r"[\x00-\x1f]", " ", str(value)).strip()
    extensions = r"(?:exe|com|sys|dll|cmd|bat|vbs|js|jse|wsf|hta|ps1|py)"
    quoted = re.match(rf'^"(?P<path>[^"]+?\.{extensions})"', text, re.IGNORECASE)
    if quoted:
        path = quoted.group("path")
        if re.search(rf"\.{extensions}\s+", path, re.IGNORECASE):
            return "UNKNOWN"
    else:
        bare = re.match(
            rf'(?P<path>(?:(?:[A-Za-z]:\\|\\\\)[^\s"]*?|[^\s"]+?)\.{extensions})(?=\s|$)',
            text,
            re.IGNORECASE,
        )
        if not bare:
            return "UNKNOWN"
        path = bare.group("path")
    return _redact_windows_user_profile(path) or "UNKNOWN"


def _overall_status(sources: Sequence[Mapping[str, Any]]) -> str:
    statuses = [str(source.get("status") or "failed") for source in sources]
    if all(status == "ok" for status in statuses):
        return "ok"
    if any(status in {"ok", "partial"} for status in statuses):
        return "partial"
    if statuses and all(status == "need_admin" for status in statuses):
        return "need_admin"
    return "failed"


def _subcollection_status(successful_operations: int, errors: Sequence[Mapping[str, Any]]) -> str:
    if not errors:
        return "ok"
    if successful_operations > 0:
        return "partial"
    if all(str(error.get("status")) == "need_admin" for error in errors):
        return "need_admin"
    return "failed"


def _exception_status(exc: Exception) -> str:
    message = str(exc).casefold()
    if "access is denied" in message or "access denied" in message or "拒绝访问" in message:
        return "need_admin"
    return "failed"


def _normalize_errors(value: Any, source: str) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for item in _as_list(value):
        if isinstance(item, dict):
            status = str(item.get("status") or "failed")
            message = str(item.get("message") or item)
            errors.append(_error(str(item.get("source") or source), status, message))
        elif item:
            message = str(item)
            status = _exception_status(RuntimeError(message))
            errors.append(_error(source, status, message))
    return errors


def _source_result(status: str, items: list[dict[str, Any]], errors: list[dict[str, str]]) -> dict[str, Any]:
    return {"status": status, "items": items, "errors": errors}


def _error(source: str, status: str, message: str) -> dict[str, str]:
    return {
        "source": source,
        "status": status,
        "message": _redact_windows_user_profile(message) or "",
    }


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_present(item: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return value
    return None


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
