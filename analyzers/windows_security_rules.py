from __future__ import annotations

import re
from typing import Any

from models.finding import Finding


def local_security_facts(data: Any) -> dict[str, Any]:
    source = data if isinstance(data, dict) else {}
    rdp = source.get("Rdp") if isinstance(source.get("Rdp"), dict) else {}
    smb1 = source.get("Smb1") if isinstance(source.get("Smb1"), dict) else {}
    autologon = source.get("AutoLogon") if isinstance(source.get("AutoLogon"), dict) else {}
    accounts = source.get("LocalAccounts") if isinstance(source.get("LocalAccounts"), dict) else {}
    password = source.get("PasswordPolicy") if isinstance(source.get("PasswordPolicy"), dict) else {}
    password_values = password.get("Values") if isinstance(password.get("Values"), dict) else {}
    firewall_profiles = source.get("FirewallProfiles")
    disabled_profiles = [
        str(item.get("Name")) for item in (firewall_profiles if isinstance(firewall_profiles, list) else [])
        if isinstance(item, dict) and _bool(item.get("Enabled")) is False
    ]
    return {
        "rdp_enabled": _bool(rdp.get("Enabled")),
        "rdp_nla_required": _bool(rdp.get("NlaRequired")),
        "smb1_enabled": _bool(smb1.get("Enabled")),
        "autologon_enabled": _bool(autologon.get("Enabled")),
        "guest_enabled": _bool(accounts.get("GuestEnabled")),
        "password_complexity": _int(password_values.get("PasswordComplexity")),
        "minimum_password_length": _int(password_values.get("MinimumPasswordLength")),
        "lockout_threshold": _int(password_values.get("LockoutBadCount")),
        "firewall_disabled_profiles": disabled_profiles,
    }


def native_security_facts(text: str) -> dict[str, Any]:
    values: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values.setdefault(key.strip(), []).append(value.strip())

    def one(key: str) -> str | None:
        found = values.get(key, [])
        return found[0] if len(found) == 1 else None

    rdp_disabled = _int(one("RdpDisabled"))
    rdp_enabled = None if rdp_disabled is None else rdp_disabled == 0
    profiles: list[str] = []
    for raw in values.get("FirewallProfile", []):
        profile, _separator, attributes = raw.partition(";")
        fields = dict(part.split("=", 1) for part in attributes.split(";") if "=" in part)
        if _bool(fields.get("Enabled")) is False:
            profiles.append(profile or "unknown")
    smb_value = _bool(one("Smb1ExplicitValue"))
    if smb_value is None:
        smb_value = _bool(one("Smb1Enabled"))
    auto_value = _bool(one("AutoAdminLogonEnabled"))
    return {
        "rdp_enabled": rdp_enabled,
        "rdp_nla_required": _bool(one("RdpNlaRequired")),
        "smb1_enabled": smb_value,
        "autologon_enabled": auto_value,
        "guest_enabled": _bool(one("GuestEnabled")),
        "password_complexity": _int(one("PasswordComplexity")),
        "minimum_password_length": _int(one("MinimumPasswordLength")),
        "lockout_threshold": _int(one("LockoutBadCount")),
        "firewall_disabled_profiles": profiles,
    }


def native_service_facts(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.startswith("Name="):
            continue
        fields: dict[str, str] = {}
        for part in line.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                fields[key] = value
        if fields.get("Name"):
            rows.append({
                "Name": fields["Name"],
                "State": fields.get("State", "UNKNOWN"),
                "StartMode": fields.get("StartMode", "UNKNOWN"),
                "PathName": fields.get("PathName", "UNKNOWN"),
            })
    return rows


def parse_native_administrator_count(text: str) -> tuple[int | None, list[str]]:
    values = [line.split("=", 1)[1].strip() for line in text.splitlines()
              if line.startswith("AdministratorMemberCount=")]
    if len(values) != 1:
        return None, ["WINDOWS_ADMINISTRATOR_COUNT_UNKNOWN"]
    value = _int(values[0])
    if value is None or value < 0:
        return None, ["WINDOWS_ADMINISTRATOR_COUNT_UNKNOWN"]
    return value, []


def parse_native_startup_facts(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    declared_count: int | None = None
    count_values = [line.split("=", 1)[1].strip() for line in text.splitlines()
                    if line.startswith("RecordCount=")]
    if len(count_values) == 1:
        declared_count = _int(count_values[0])
    if declared_count is None or declared_count < 0:
        gaps.append("WINDOWS_STARTUP_RECORD_COUNT_UNKNOWN")

    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("TRUNCATED="):
            gaps.append("WINDOWS_STARTUP_EVIDENCE_TRUNCATED")
            continue
        if not line.startswith("Name="):
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
        if malformed or not fields.get("Name"):
            gaps.append(f"WINDOWS_STARTUP_ROW_FORMAT_INVALID:line_{line_number}")
            continue
        image_path = fields.get("ImagePath", "").strip()
        script_path = fields.get("ScriptPath", "").strip()
        if not image_path or image_path.upper() == "UNKNOWN":
            gaps.append(f"WINDOWS_STARTUP_IMAGE_PATH_UNKNOWN:line_{line_number}")
        rows.append({
            "Name": fields["Name"],
            "Location": fields.get("Location", ""),
            "ImagePath": image_path or None,
            "Path": image_path or None,
            "ScriptPath": script_path or None,
            "ScriptExtension": fields.get("ScriptExtension") or None,
            "Scope": fields.get("Scope") or None,
            "SourceType": fields.get("SourceType") or None,
        })

    if declared_count is not None and declared_count != len(rows):
        gaps.append("WINDOWS_STARTUP_RECORD_COUNT_MISMATCH")
    if declared_count is None or declared_count > 0 and not rows:
        gaps.append("WINDOWS_STARTUP_FACTS_MISSING_OR_UNKNOWN")
    return rows, list(dict.fromkeys(gaps))


def analyze_windows_administrator_count(
    count: int | None,
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        return []
    rules = rules or {str(rule.get("id")): rule for rule in registry.get("rules", []) if isinstance(rule, dict)}
    rule = rules.get("WIN_ADMINISTRATOR_COUNT_REVIEW")
    threshold = _int(registry.get("thresholds", {}).get("administrator_member_count_attention_above"))
    if not isinstance(rule, dict) or rule.get("enabled") is not True or threshold is None or count <= threshold:
        return []
    finding = Finding(
        finding_id="WIN_ADMINISTRATOR_COUNT_REVIEW",
        title=str(rule["name"]), severity=str(rule["severity"]), category=str(rule["category"]),
        component="users", description=str(rule["condition_description"]),
        evidence={"administrator_count": count, "threshold": threshold},
        impact=str(rule["risk"]), recommendation=str(rule["recommendation"]),
        precheck=str(rule.get("precheck", "")), applicability=str(rule.get("applicability", "")),
        rollback=str(rule.get("rollback", "")),
        verification_checkpoint=str(rule.get("verification_checkpoint", "")),
        references=list(rule.get("references", [])),
    ).to_dict()
    finding.update({"rule_id": "WIN_ADMINISTRATOR_COUNT_REVIEW", "name": finding["title"],
                    "level": finding["severity"], "auto_fix": "否"})
    return [finding]


def analyze_windows_startup_facts(
    items: Any,
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]] | None = None,
    *,
    collector: str = "startup_items",
) -> list[dict[str, Any]]:
    rules = rules or {str(rule.get("id")): rule for rule in registry.get("rules", []) if isinstance(rule, dict)}
    rule = rules.get("WIN_STARTUP_SUSPICIOUS_PATH")
    if not isinstance(rule, dict) or rule.get("enabled") is not True:
        return []
    suspicious: list[tuple[dict[str, Any], list[str]]] = []
    patterns = registry.get("path_patterns", {})
    candidates = [
        *patterns.get("startup_suspicious_path_substrings", []),
        *patterns.get("startup_interpreter_substrings", []),
        *patterns.get("startup_script_extensions", []),
    ]
    for raw in items if isinstance(items, list) else []:
        row = raw if isinstance(raw, dict) else {}
        haystack = " ".join(str(row.get(key) or "") for key in (
            "Command", "command", "Path", "path", "ImagePath", "image_path", "ScriptPath",
            "script_path", "Executable", "executable", "Arguments", "arguments", "Location", "location",
            "ScriptExtension", "script_extension",
        )).casefold()
        clues = [str(needle) for needle in candidates if isinstance(needle, str) and needle.casefold() in haystack]
        if clues:
            suspicious.append((row, clues))
    if not suspicious:
        return []

    evidence_items = []
    for row, clues in suspicious[:10]:
        image_path = _startup_image_path(row)
        script_path = _first(row, "ScriptPath", "script_path") or _startup_script_path(row)
        evidence_items.append({
            "name": _redact_startup_text(_first(row, "Name", "name")),
            "command": _redact_startup_text(image_path),
            "script_path": _redact_startup_text(script_path),
            "location": _redact_startup_text(_first(row, "Location", "location")),
            "scope": _redact_startup_text(_first(row, "Scope", "scope")),
            "source_type": _redact_startup_text(_first(row, "SourceType", "source_type")),
            "matched_clues": clues,
        })
    finding = Finding(
        finding_id="WIN_STARTUP_SUSPICIOUS_PATH", title=str(rule["name"]),
        severity=str(rule["severity"]), category=str(rule["category"]), component="startup_items",
        description=str(rule["condition_description"]),
        evidence={"collector": collector, "matched_count": len(suspicious), "items": evidence_items},
        impact=str(rule["risk"]), recommendation=str(rule["recommendation"]),
        precheck=str(rule.get("precheck", "")), applicability=str(rule.get("applicability", "")),
        rollback=str(rule.get("rollback", "")),
        verification_checkpoint=str(rule.get("verification_checkpoint", "")),
        references=list(rule.get("references", [])),
    ).to_dict()
    finding.update({"rule_id": "WIN_STARTUP_SUSPICIOUS_PATH", "name": finding["title"],
                    "level": finding["severity"], "auto_fix": "否"})
    return [finding]


def analyze_windows_service_facts(services: Any, registry: dict[str, Any]) -> list[dict[str, Any]]:
    rules = {str(rule.get("id")): rule for rule in registry.get("rules", []) if isinstance(rule, dict)}
    rule = rules.get("WIN_SERVICE_SUSPICIOUS_PATH")
    if not isinstance(rule, dict) or rule.get("enabled") is not True:
        return []
    patterns = registry.get("path_patterns", {}).get("service_suspicious_substrings", [])
    normalized_patterns = [str(value).casefold() for value in patterns]
    suspicious = [
        str(service.get("Name") or "unknown")
        for service in (services if isinstance(services, list) else [])
        if isinstance(service, dict)
        and str(service.get("StartMode") or "").casefold() == "auto"
        and any(pattern in str(service.get("PathName") or "").casefold() for pattern in normalized_patterns)
    ]
    if not suspicious:
        return []
    finding = Finding(
        finding_id=str(rule["id"]),
        title=str(rule["name"]),
        severity=str(rule["severity"]),
        category=str(rule["category"]),
        component="services",
        description=str(rule["condition_description"]),
        evidence={"services": suspicious[:10], "matched_count": len(suspicious)},
        impact=str(rule["risk"]),
        recommendation=str(rule["recommendation"]),
        precheck=str(rule.get("precheck", "")),
        applicability=str(rule.get("applicability", "")),
        rollback=str(rule.get("rollback", "")),
        verification_checkpoint=str(rule.get("verification_checkpoint", "")),
        references=list(rule.get("references", [])),
    ).to_dict()
    finding.update({"rule_id": str(rule["id"]), "name": finding["title"],
                    "level": finding["severity"], "auto_fix": "否"})
    return [finding]


def analyze_windows_security_facts(facts: dict[str, Any], registry: dict[str, Any]) -> list[dict[str, Any]]:
    rules = {str(rule.get("id")): rule for rule in registry.get("rules", []) if isinstance(rule, dict)}
    findings: list[dict[str, Any]] = []

    def emit(rule_id: str, evidence: dict[str, Any]) -> None:
        rule = rules.get(rule_id)
        if not isinstance(rule, dict) or rule.get("enabled") is not True:
            return
        finding = Finding(
            finding_id=rule_id,
            title=str(rule["name"]),
            severity=str(rule["severity"]),
            category=str(rule["category"]),
            component="windows_security",
            description=str(rule["condition_description"]),
            evidence=evidence,
            impact=str(rule["risk"]),
            recommendation=str(rule["recommendation"]),
            precheck=str(rule.get("precheck", "")),
            applicability=str(rule.get("applicability", "")),
            rollback=str(rule.get("rollback", "")),
            verification_checkpoint=str(rule.get("verification_checkpoint", "")),
            references=list(rule.get("references", [])),
        ).to_dict()
        finding.update({"rule_id": rule_id, "name": finding["title"],
                        "level": finding["severity"], "auto_fix": "否"})
        findings.append(finding)

    if facts.get("rdp_enabled") is True and facts.get("rdp_nla_required") is False:
        emit("WIN_BASELINE_RDP_NLA_DISABLED", {"rdp_enabled": True, "nla_required": False,
                                                "network_reachability_checked": False})
    if facts.get("smb1_enabled") is True:
        emit("WIN_BASELINE_SMB1_ENABLED", {"smb1_enabled": True, "evidence_source": "explicit setting"})
    if facts.get("autologon_enabled") is True:
        emit("WIN_BASELINE_AUTOLOGON_ENABLED", {"auto_logon_enabled": True, "credential_value_read": False})
    if facts.get("guest_enabled") is True:
        emit("WIN_BASELINE_GUEST_ENABLED", {"built_in_guest_enabled": True, "account_name_exported": False})
    disabled = facts.get("firewall_disabled_profiles")
    if isinstance(disabled, list) and disabled:
        emit("WIN_BASELINE_FIREWALL_PROFILE_DISABLED", {"disabled_profiles": sorted(set(map(str, disabled)))})
    complexity = facts.get("password_complexity")
    if complexity == 0:
        emit("WIN_BASELINE_PASSWORD_COMPLEXITY_DISABLED", {"password_complexity": 0})
    min_length = facts.get("minimum_password_length")
    if isinstance(min_length, int) and not isinstance(min_length, bool) and min_length < 8:
        emit("WIN_BASELINE_PASSWORD_MINIMUM_LENGTH_LOW", {"minimum_password_length": min_length, "reference_floor": 8})
    lockout = facts.get("lockout_threshold")
    if lockout == 0:
        emit("WIN_BASELINE_ACCOUNT_LOCKOUT_DISABLED", {"lockout_threshold": 0})
    return findings


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    return None


def _int(value: Any) -> int | None:
    try:
        if value is None or isinstance(value, bool) or not re.fullmatch(r"-?[0-9]{1,8}", str(value).strip()):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return None


def _redact_startup_text(value: Any) -> str:
    text = str(value if value is not None else "")
    text = re.sub(r"[\x00-\x1f]", " ", text)
    text = re.sub(r"(?i)\\Users\\[^\\]+", lambda _match: r"\Users\<redacted>", text)
    return text[:500]


def _startup_image_path(row: dict[str, Any]) -> str:
    value = _first(row, "ImagePath", "image_path", "Path", "path", "Executable", "executable")
    if value:
        return str(value)
    command = str(_first(row, "Command", "command") or "")
    match = re.match(r'^\s*"(?P<quoted>[^"]+)"|^\s*(?P<bare>\S+)', command)
    if not match:
        return "UNKNOWN"
    return match.group("quoted") or match.group("bare") or "UNKNOWN"


def _startup_script_path(row: dict[str, Any]) -> str | None:
    command = str(_first(row, "Command", "command", "Arguments", "arguments") or "")
    match = re.search(
        r'(?i)"(?P<quoted>(?:[a-z]:\\|\\\\)[^"]+\.(?:ps1|bat|cmd|vbs|js|jse|wsf|hta))"'
        r'|(?P<bare>(?:[a-z]:\\|\\\\)[^\s"]+\.(?:ps1|bat|cmd|vbs|js|jse|wsf|hta))',
        command,
    )
    if not match:
        return None
    return match.group("quoted") or match.group("bare")
