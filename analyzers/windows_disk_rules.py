from __future__ import annotations

import math
import re
from typing import Any

from models.finding import Finding

BYTES_PER_GB = 1024 ** 3


def parse_native_disk_facts(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("Drive="):
            continue
        fields: dict[str, str] = {}
        malformed = False
        for part in line.split(";"):
            if "=" not in part:
                malformed = True
                continue
            key, value = part.split("=", 1)
            if key in fields:
                malformed = True
            fields[key] = value
        drive = fields.get("Drive", "").strip()
        size = _strict_number(fields.get("SizeBytes"), minimum=1)
        free = _strict_number(fields.get("FreeBytes"), minimum=0)
        free_percent = _strict_number(fields.get("FreePercent"), minimum=0, maximum=100)
        if not drive:
            malformed = True
        if size is None:
            gaps.append(f"WINDOWS_DISK_SIZE_UNKNOWN:line_{line_number}")
        if free is None:
            gaps.append(f"WINDOWS_DISK_FREE_SPACE_UNKNOWN:line_{line_number}")
        if fields.get("FreePercent") not in (None, "") and free_percent is None:
            gaps.append(f"WINDOWS_DISK_PERCENT_FORMAT_INVALID:line_{line_number}")
        if malformed:
            gaps.append(f"WINDOWS_DISK_ROW_FORMAT_INVALID:line_{line_number}")
        if size is None and free is None and not drive:
            continue
        rows.append({
            "Drive": drive or None,
            "FileSystem": fields.get("FileSystem") or None,
            "Size": size,
            "Free": free,
            "FreePercent": free_percent,
        })
    if not rows:
        gaps.append("WINDOWS_DISK_FACTS_MISSING_OR_UNKNOWN")
    identity_gaps, _conflicted = windows_disk_identity_state(rows)
    gaps.extend(identity_gaps)
    return rows, list(dict.fromkeys(gaps))


def analyze_windows_disk_facts(
    volumes: Any,
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if isinstance(volumes, dict):
        volumes = volumes.get("VolumeSummary") or volumes.get("Volumes") or volumes.get("LogicalDisks")
    if not isinstance(volumes, list):
        return []
    rules = rules or {
        str(rule.get("id")): rule for rule in registry.get("rules", []) if isinstance(rule, dict)
    }
    rule = rules.get("WIN_DISK_LOW_SPACE")
    if not isinstance(rule, dict) or rule.get("enabled") is not True:
        return []
    thresholds = registry.get("thresholds", {})
    percent_threshold = _strict_number(thresholds.get("disk_free_percent_warning"))
    gb_threshold = _strict_number(thresholds.get("disk_free_gb_warning"))
    if percent_threshold is None or gb_threshold is None:
        return []

    _identity_gaps, conflicted_ids = windows_disk_identity_state(volumes)
    emitted_signatures: set[tuple[str, tuple[Any, ...]]] = set()
    findings: list[dict[str, Any]] = []
    for raw in volumes:
        row = raw if isinstance(raw, dict) else {}
        volume_id = _volume_id(_first(row, "Drive", "drive", "Volume", "volume", "DeviceID", "device_id", "MountPoint", "mount_point", "letter"))
        if volume_id is None or volume_id in conflicted_ids:
            continue
        signature = _disk_signature(row)
        unique_key = (volume_id, signature)
        if unique_key in emitted_signatures:
            continue
        emitted_signatures.add(unique_key)
        free_bytes = _first(row, "Free", "FreeSpace", "SizeRemaining")
        total_bytes = _first(row, "Size", "Total", "TotalSize")
        free_gb = _strict_number(_first(row, "free_gb", "free_space_gb", "FreeGB", "FreeSpaceGB"))
        total_gb = _strict_number(_first(row, "total_gb", "size_gb", "TotalGB", "SizeGB"))
        if free_gb is None:
            parsed_free = _strict_number(free_bytes, minimum=0)
            free_gb = parsed_free / BYTES_PER_GB if parsed_free is not None else None
        if total_gb is None:
            parsed_total = _strict_number(total_bytes, minimum=1)
            total_gb = parsed_total / BYTES_PER_GB if parsed_total is not None else None
        free_percent = _strict_number(_first(row, "FreePercent", "free_percent", "percent_free", "free_space_percent"),
                                      minimum=0, maximum=100)
        if free_percent is None and free_gb is not None and total_gb is not None and total_gb > 0:
            free_percent = free_gb / total_gb * 100
        percent_low = free_percent is not None and free_percent <= percent_threshold
        absolute_low = free_gb is not None and free_gb <= gb_threshold
        if not percent_low and not absolute_low:
            continue

        evidence = {
            "source": "disks",
            "drive": _first(row, "Drive", "drive", "Volume", "volume", "DeviceID", "device_id", "MountPoint", "mount_point", "letter"),
            "volume": _first(row, "Label", "VolumeName", "volume_name", "FileSystemLabel"),
            "mount_point": _first(row, "MountPoint", "mount_point", "Root"),
            "device_id": _first(row, "DeviceID", "device_id"),
            "free_gb": _rounded(free_gb),
            "total_gb": _rounded(total_gb),
            "free_percent": _rounded(free_percent),
            "threshold": {
                "free_percent_lte": percent_threshold,
                "free_gb_lte": gb_threshold,
            },
        }
        finding = Finding(
            finding_id=f"WIN_DISK_LOW_SPACE:{volume_id}",
            title=str(rule["name"]),
            severity=str(rule["severity"]),
            category=str(rule["category"]),
            component="disks",
            description=str(rule["condition_description"]),
            evidence=evidence,
            impact=str(rule["risk"]),
            recommendation=str(rule["recommendation"]),
            precheck=str(rule.get("precheck", "")),
            applicability=str(rule.get("applicability", "")),
            rollback=str(rule.get("rollback", "")),
            verification_checkpoint=str(rule.get(
                "verification_checkpoint",
                "重新采集该卷容量与剩余空间，并复核日志、备份和临时目录是否持续增长。",
            )),
            references=list(rule.get("references", [])),
        ).to_dict()
        finding.update({"rule_id": "WIN_DISK_LOW_SPACE", "name": finding["title"],
                        "level": finding["severity"], "auto_fix": "否"})
        findings.append(finding)
    return findings


def windows_disk_identity_state(volumes: Any) -> tuple[list[str], set[str]]:
    if not isinstance(volumes, list):
        return ["WINDOWS_DISK_FACTS_MISSING_OR_UNKNOWN"], set()
    groups: dict[str, set[tuple[Any, ...]]] = {}
    gaps: list[str] = []
    for index, raw in enumerate(volumes, start=1):
        row = raw if isinstance(raw, dict) else {}
        volume_id = _volume_id(_first(row, "Drive", "drive", "Volume", "volume", "DeviceID", "device_id", "MountPoint", "mount_point", "letter"))
        if volume_id is None:
            gaps.append(f"WINDOWS_DISK_VOLUME_ID_UNKNOWN:row_{index}")
            continue
        groups.setdefault(volume_id, set()).add(_disk_signature(row))
    conflicted = {volume_id for volume_id, signatures in groups.items() if len(signatures) > 1}
    gaps.extend(f"WINDOWS_DISK_VOLUME_ID_CONFLICT:{volume_id}" for volume_id in sorted(conflicted))
    return list(dict.fromkeys(gaps)), conflicted


def _volume_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"\s*([A-Za-z]:)\s*", value)
    return match.group(1).upper() if match else None


def _disk_signature(row: dict[str, Any]) -> tuple[Any, ...]:
    size = _strict_number(_first(row, "SizeBytes", "Size", "Total", "TotalSize"), minimum=1)
    free = _strict_number(_first(row, "FreeBytes", "Free", "FreeSpace", "SizeRemaining"), minimum=0)
    percent = _strict_number(_first(row, "FreePercent", "free_percent", "percent_free", "free_space_percent"),
                             minimum=0, maximum=100)
    if percent is None and size is not None and free is not None:
        percent = free / size * 100
    filesystem = str(_first(row, "FileSystem", "filesystem") or "").casefold()
    label = str(_first(row, "Label", "VolumeName", "volume_name", "FileSystemLabel") or "").casefold()
    return (size, free, percent, filesystem, label)


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return None


def _strict_number(value: Any, *, minimum: float | None = None, maximum: float | None = None) -> float | None:
    if value is None or isinstance(value, bool) or not re.fullmatch(r"-?\d+(?:\.\d+)?", str(value).strip()):
        return None
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or (minimum is not None and number < minimum) or (maximum is not None and number > maximum):
        return None
    return number


def _rounded(value: float | None) -> float | None:
    return round(value, 2) if value is not None else None
