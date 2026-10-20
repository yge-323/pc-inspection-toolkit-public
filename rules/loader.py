from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any


SUPPORTED_SCHEMA_VERSION = 1
DEFAULT_REGISTRY_FILENAME = "windows_risk_rules.example.json"
OVERRIDE_FILENAME = "windows-risk-rules.override.json"
LOCAL_PROFILE_FILENAME = "local-profile.json"

VALID_SEVERITIES = {
    "Critical",
    "Attention",
    "Warning",
    "Need Admin",
    "Info",
    "OK",
    "Skipped",
    "Failed",
}
VALID_LOCAL_OVERRIDE_POLICIES = {"annotate_only", "allow_exact_expected"}
REQUIRED_RULE_IDS = {
    "WIN_ADMINISTRATOR_COUNT_REVIEW",
    "WIN_SERVICE_SUSPICIOUS_PATH",
    "WIN_SCHEDULED_TASK_SUSPICIOUS_PATH",
    "WIN_EVENT_LOG_ERROR_VOLUME",
    "WIN_PORT_22_REVIEW",
    "WIN_SMB_445_ALLOWED",
    "WIN_RDP_EXPOSED_REVIEW",
    "WIN_PROXY_PORT_EXPOSED",
    "WIN_STARTUP_SUSPICIOUS_PATH",
    "WIN_DISK_LOW_SPACE",
    "WIN_BITLOCKER_NEED_ADMIN",
    "WIN_SECURITY_VENDOR_PRESENT",
    "WIN_SECURITY_VENDOR_RESIDUE",
    "WIN_SECURITY_VENDOR_DRIVER_REVIEW",
    "WIN_BASELINE_RDP_NLA_DISABLED",
    "WIN_BASELINE_SMB1_ENABLED",
    "WIN_BASELINE_AUTOLOGON_ENABLED",
    "WIN_BASELINE_GUEST_ENABLED",
    "WIN_BASELINE_FIREWALL_PROFILE_DISABLED",
    "WIN_BASELINE_PASSWORD_COMPLEXITY_DISABLED",
    "WIN_BASELINE_PASSWORD_MINIMUM_LENGTH_LOW",
    "WIN_BASELINE_ACCOUNT_LOCKOUT_DISABLED",
}
NON_DISABLEABLE_RULE_IDS = {
    "WIN_BITLOCKER_NEED_ADMIN",
}
REQUIRED_RULE_FIELDS = {
    "id",
    "name",
    "category",
    "applies_to_collectors",
    "condition_description",
    "severity",
    "risk",
    "recommendation",
    "evidence_fields",
    "enabled",
    "local_override_policy",
}
OPTIONAL_RULE_FIELDS = {"precheck", "applicability", "rollback", "verification_checkpoint", "references"}
REGISTRY_FIELDS = {
    "schema_version",
    "registry_version",
    "registry_role",
    "description",
    "severity_levels",
    "thresholds",
    "ports",
    "path_patterns",
    "vendor_patterns",
    "rules",
}
OVERRIDE_ROOT_FIELDS = {"schema_version", "base_registry_version", "overrides"}
OVERRIDE_SECTION_FIELDS = {"thresholds", "ports", "path_patterns", "vendor_patterns", "rules"}
RULE_OVERRIDE_FIELDS = {"enabled", "severity", "risk", "recommendation", "local_override_policy"}
LOCAL_PROFILE_FIELDS = {
    "schema_version",
    "profile_id",
    "machine_match",
    "expected_accounts",
    "expected_listeners",
    "expected_processes",
    "rule_exceptions",
}
LOCAL_MACHINE_MATCH_FIELDS = {"hostnames"}
LOCAL_LISTENER_FIELDS = {"protocol", "port", "process", "addresses", "rule_ids"}
LOCAL_EXCEPTION_FIELDS = {"rule_id", "match", "note"}
LOCAL_LISTENER_REQUIRED_FIELDS = {"protocol", "port", "process", "addresses"}
LOCAL_EXCEPTION_MATCH_FIELDS = {
    "WIN_ADMINISTRATOR_COUNT_REVIEW": {"administrator_count", "threshold"},
    "WIN_SERVICE_SUSPICIOUS_PATH": {"services", "matched_count"},
    "WIN_SCHEDULED_TASK_SUSPICIOUS_PATH": {"tasks", "matched_count"},
    "WIN_EVENT_LOG_ERROR_VOLUME": {"critical_count", "error_count", "thresholds"},
    "WIN_PORT_22_REVIEW": {"address", "addresses", "port", "process", "protocol"},
    "WIN_SMB_445_ALLOWED": {"address", "addresses", "port", "process", "protocol"},
    "WIN_RDP_EXPOSED_REVIEW": {"address", "addresses", "port", "process", "protocol"},
    "WIN_PROXY_PORT_EXPOSED": {"address", "addresses", "port", "process", "protocol"},
    "WIN_STARTUP_SUSPICIOUS_PATH": {"collector", "matched_count", "items"},
    "WIN_DISK_LOW_SPACE": {
        "source",
        "drive",
        "volume",
        "mount_point",
        "device_id",
        "free_gb",
        "total_gb",
        "free_percent",
        "threshold",
    },
    "WIN_BITLOCKER_NEED_ADMIN": {"collector", "collector_status", "errors", "bitlocker"},
    "WIN_SECURITY_VENDOR_PRESENT": {
        "vendor",
        "matched_keyword",
        "source_type",
        "name",
        "display_name",
        "path",
        "status",
        "start_type",
        "uninstall_present",
        "service_present",
        "driver_present",
        "task_present",
        "startup_present",
        "directory_present",
        "related_item_count",
    },
    "WIN_SECURITY_VENDOR_RESIDUE": {
        "vendor",
        "matched_keyword",
        "source_type",
        "name",
        "display_name",
        "path",
        "status",
        "start_type",
        "uninstall_present",
        "service_present",
        "driver_present",
        "task_present",
        "startup_present",
        "directory_present",
        "related_item_count",
    },
    "WIN_SECURITY_VENDOR_DRIVER_REVIEW": {
        "vendor",
        "matched_keyword",
        "source_type",
        "name",
        "display_name",
        "path",
        "status",
        "start_type",
        "uninstall_present",
        "service_present",
        "driver_present",
        "task_present",
        "startup_present",
        "directory_present",
        "related_item_count",
    },
}
COUNT_THRESHOLD_FIELDS = {
    "administrator_member_count_attention_above",
    "event_log_critical_count_warning_at_least",
    "event_log_error_count_warning_at_least",
}
DISK_THRESHOLD_FIELDS = {"disk_free_percent_warning", "disk_free_gb_warning"}
PATH_PATTERN_FIELDS = {
    "service_suspicious_substrings",
    "scheduled_task_suspicious_substrings",
    "startup_suspicious_path_substrings",
    "startup_interpreter_substrings",
    "startup_script_extensions",
}


class ConfigurationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(slots=True)
class RuleResolution:
    status: str
    registry: dict[str, Any] | None
    local_profile: dict[str, Any] | None
    config_evidence: dict[str, dict[str, Any]]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def can_analyze(self) -> bool:
        return self.registry is not None and self.status != "FAILED"


def load_rules(path: str | Path) -> dict[str, Any]:
    """Backward-compatible single-document loader with explicit failures."""
    return _load_json_document(Path(path), "rules")


def validate_rules(rules: dict[str, Any]) -> list[str]:
    """Backward-compatible registry validator used by existing callers."""
    return validate_registry(rules)


def validate_registry(registry: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(registry, dict):
        return ["registry root must be an object"]

    unknown = sorted(set(registry) - REGISTRY_FIELDS)
    errors.extend(f"registry.{name} is not allowed" for name in unknown)
    if not _supported_schema_version(registry.get("schema_version")):
        errors.append(f"schema_version must be {SUPPORTED_SCHEMA_VERSION}")
    if not _non_empty_string(registry.get("registry_version")):
        errors.append("registry_version is required")
    if registry.get("registry_role") != "default":
        errors.append("registry_role must be default")

    severity_levels = registry.get("severity_levels")
    severity_names: set[str] = set()
    if not isinstance(severity_levels, list):
        errors.append("severity_levels must be a list")
    else:
        severity_names = {_severity_name(item) for item in severity_levels}
        severity_names.discard("")
        missing_severities = sorted(VALID_SEVERITIES - severity_names)
        errors.extend(f"severity_levels is missing {name}" for name in missing_severities)

    thresholds = registry.get("thresholds")
    if not isinstance(thresholds, dict):
        errors.append("thresholds must be an object")
    else:
        for name in sorted(DISK_THRESHOLD_FIELDS):
            _validate_positive_number(thresholds, name, errors, "thresholds")
        for name in sorted(COUNT_THRESHOLD_FIELDS):
            _validate_positive_integer(thresholds, name, errors, "thresholds")
        unknown_thresholds = sorted(set(thresholds) - DISK_THRESHOLD_FIELDS - COUNT_THRESHOLD_FIELDS)
        errors.extend(f"thresholds.{name} is not allowed" for name in unknown_thresholds)

    ports = registry.get("ports")
    if not isinstance(ports, dict):
        errors.append("ports must be an object")
    else:
        allowed_port_fields = {"ssh", "smb", "rdp", "proxy_ranges", "proxy_loopback_processes"}
        errors.extend(f"ports.{name} is not allowed" for name in sorted(set(ports) - allowed_port_fields))
        for name in ("ssh", "smb", "rdp"):
            _validate_port_list(ports.get(name), f"ports.{name}", errors)
        _validate_port_ranges(ports.get("proxy_ranges"), errors)
        _validate_string_list(ports.get("proxy_loopback_processes"), "ports.proxy_loopback_processes", errors)

    _validate_path_patterns(registry.get("path_patterns"), errors, "path_patterns")

    vendor_patterns = registry.get("vendor_patterns")
    _validate_vendor_patterns(vendor_patterns, errors, "vendor_patterns")

    rule_items = registry.get("rules")
    if not isinstance(rule_items, list):
        errors.append("rules must be a list")
        return errors

    seen_ids: set[str] = set()
    for index, rule in enumerate(rule_items):
        prefix = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix} must be an object")
            continue
        missing = sorted(REQUIRED_RULE_FIELDS - set(rule))
        errors.extend(f"{prefix}.{name} is required" for name in missing)
        unknown_rule_fields = sorted(set(rule) - REQUIRED_RULE_FIELDS - OPTIONAL_RULE_FIELDS)
        errors.extend(f"{prefix}.{name} is not allowed" for name in unknown_rule_fields)
        rule_id = rule.get("id")
        if not _non_empty_string(rule_id):
            errors.append(f"{prefix}.id must be a non-empty string")
        elif rule_id in seen_ids:
            errors.append(f"{prefix}.id is duplicated: {rule_id}")
        else:
            seen_ids.add(rule_id)
        if rule.get("severity") not in severity_names:
            errors.append(f"{prefix}.severity is not defined in severity_levels")
        if not isinstance(rule.get("enabled"), bool):
            errors.append(f"{prefix}.enabled must be boolean")
        elif rule.get("enabled") is True and rule_id not in REQUIRED_RULE_IDS:
            errors.append(f"{prefix}.id has no runtime analyzer entry: {rule_id}")
        if rule.get("local_override_policy") not in VALID_LOCAL_OVERRIDE_POLICIES:
            errors.append(f"{prefix}.local_override_policy is invalid")
        _validate_string_list(rule.get("applies_to_collectors"), f"{prefix}.applies_to_collectors", errors)
        _validate_string_list(rule.get("evidence_fields"), f"{prefix}.evidence_fields", errors)
        for name in ("name", "category", "condition_description", "risk", "recommendation"):
            if not _non_empty_string(rule.get(name)):
                errors.append(f"{prefix}.{name} must be a non-empty string")
        for name in OPTIONAL_RULE_FIELDS - {"references"}:
            if name in rule and not isinstance(rule[name], str):
                errors.append(f"{prefix}.{name} must be a string")
        if "references" in rule:
            references = rule["references"]
            if (not isinstance(references, list) or len(references) > 10
                    or any(not isinstance(url, str) or not url.startswith("https://learn.microsoft.com/") for url in references)):
                errors.append(f"{prefix}.references must contain Microsoft Learn HTTPS URLs")

    missing_rules = sorted(REQUIRED_RULE_IDS - seen_ids)
    errors.extend(f"required rule is missing: {rule_id}" for rule_id in missing_rules)
    return errors


def resolve_rule_configuration(
    application_root: Path,
    *,
    default_path: Path | None = None,
    override_path: Path | None = None,
    local_profile_path: Path | None = None,
) -> RuleResolution:
    default_path = default_path or application_root / "rules" / DEFAULT_REGISTRY_FILENAME
    override_path = override_path or application_root / "config" / OVERRIDE_FILENAME
    local_profile_path = local_profile_path or application_root / "config" / LOCAL_PROFILE_FILENAME
    evidence = {
        "default_registry": _evidence("not_loaded", default_path.name),
        "user_override": _evidence("not_configured", override_path.name, applied=False),
        "local_profile": _evidence("not_configured", local_profile_path.name, applied=False),
    }
    warnings: list[str] = []
    errors: list[str] = []

    try:
        registry = _load_json_document(default_path, "default registry")
    except ConfigurationError as exc:
        evidence["default_registry"] = _evidence("failed", default_path.name, error_code=exc.code)
        errors.append(str(exc))
        return RuleResolution("FAILED", None, None, evidence, warnings, errors)

    registry_errors = validate_registry(registry)
    if registry_errors:
        evidence["default_registry"] = _evidence(
            "failed", default_path.name, error_code="DEFAULT_SCHEMA_INVALID"
        )
        errors.extend(f"Default registry: {message}" for message in registry_errors)
        return RuleResolution("FAILED", None, None, evidence, warnings, errors)
    evidence["default_registry"] = _evidence(
        "loaded",
        default_path.name,
        registry_version=registry["registry_version"],
    )

    override_state = _optional_config_path_state(override_path)
    if override_state == "invalid":
        evidence["user_override"] = _evidence(
            "failed", override_path.name, applied=False, error_code="OVERRIDE_PATH_INVALID"
        )
        errors.append(f"User override is not a readable regular file: {override_path.name}")
        return RuleResolution("FAILED", None, None, evidence, warnings, errors)
    if override_state == "file":
        try:
            override = _load_json_document(override_path, "user override")
            override_errors = validate_override(override, registry)
            if override_errors:
                evidence["user_override"] = _evidence(
                    "failed", override_path.name, applied=False, error_code="OVERRIDE_SCHEMA_INVALID"
                )
                errors.extend(f"User override: {message}" for message in override_errors)
                return RuleResolution("FAILED", None, None, evidence, warnings, errors)
            registry = merge_override(registry, override)
            evidence["user_override"] = _evidence("loaded", override_path.name, applied=True)
        except ConfigurationError as exc:
            evidence["user_override"] = _evidence(
                "failed", override_path.name, applied=False, error_code=exc.code
            )
            errors.append(str(exc))
            return RuleResolution("FAILED", None, None, evidence, warnings, errors)

    local_profile: dict[str, Any] | None = None
    status = "OK"
    local_profile_state = _optional_config_path_state(local_profile_path)
    if local_profile_state == "invalid":
        evidence["local_profile"] = _evidence(
            "failed", local_profile_path.name, applied=False, error_code="LOCAL_PROFILE_PATH_INVALID"
        )
        errors.append(f"Local profile is not a readable regular file: {local_profile_path.name}")
        status = "PARTIAL"
    elif local_profile_state == "file":
        try:
            candidate = _load_json_document(local_profile_path, "local profile")
            profile_errors = validate_local_profile(candidate, registry)
            if profile_errors:
                evidence["local_profile"] = _evidence(
                    "failed", local_profile_path.name, applied=False, error_code="LOCAL_PROFILE_SCHEMA_INVALID"
                )
                errors.extend(f"Local profile: {message}" for message in profile_errors)
                status = "PARTIAL"
            else:
                local_profile = candidate
                evidence["local_profile"] = _evidence(
                    "loaded", local_profile_path.name, applied=False
                )
        except ConfigurationError as exc:
            evidence["local_profile"] = _evidence(
                "failed", local_profile_path.name, applied=False, error_code=exc.code
            )
            errors.append(str(exc))
            status = "PARTIAL"

    return RuleResolution(status, registry, local_profile, evidence, warnings, errors)


def validate_override(override: Any, registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(override, dict):
        return ["override root must be an object"]
    errors.extend(f"override.{name} is not allowed" for name in sorted(set(override) - OVERRIDE_ROOT_FIELDS))
    if not _supported_schema_version(override.get("schema_version")):
        errors.append(f"schema_version must be {SUPPORTED_SCHEMA_VERSION}")
    if override.get("base_registry_version") != registry.get("registry_version"):
        errors.append("base_registry_version does not match the default registry")
    patches = override.get("overrides")
    if not isinstance(patches, dict):
        errors.append("overrides must be an object")
        return errors
    errors.extend(f"overrides.{name} is not allowed" for name in sorted(set(patches) - OVERRIDE_SECTION_FIELDS))

    thresholds = patches.get("thresholds", {})
    if not isinstance(thresholds, dict):
        errors.append("overrides.thresholds must be an object")
    else:
        for name, value in thresholds.items():
            if name not in registry["thresholds"]:
                errors.append(f"overrides.thresholds.{name} is unknown")
            elif name in COUNT_THRESHOLD_FIELDS and not _positive_integer(value):
                errors.append(f"overrides.thresholds.{name} must be a positive integer")
            elif name not in COUNT_THRESHOLD_FIELDS and not _positive_number(value):
                errors.append(f"overrides.thresholds.{name} must be a positive number")

    ports = patches.get("ports", {})
    if not isinstance(ports, dict):
        errors.append("overrides.ports must be an object")
    else:
        for name, value in ports.items():
            if name not in registry["ports"]:
                errors.append(f"overrides.ports.{name} is unknown")
            elif name == "proxy_ranges":
                _validate_port_ranges(value, errors, "overrides.ports.proxy_ranges")
            elif name == "proxy_loopback_processes":
                _validate_string_list(value, "overrides.ports.proxy_loopback_processes", errors)
            else:
                _validate_port_list(value, f"overrides.ports.{name}", errors)

    path_patterns = patches.get("path_patterns", {})
    if not isinstance(path_patterns, dict):
        errors.append("overrides.path_patterns must be an object")
    else:
        unknown_patterns = sorted(set(path_patterns) - PATH_PATTERN_FIELDS)
        errors.extend(f"overrides.path_patterns.{name} is unknown" for name in unknown_patterns)
        for name, value in path_patterns.items():
            if name in PATH_PATTERN_FIELDS:
                _validate_non_empty_string_list(value, f"overrides.path_patterns.{name}", errors)

    vendor_patterns = patches.get("vendor_patterns", {})
    if not isinstance(vendor_patterns, dict):
        errors.append("overrides.vendor_patterns must be an object")
    elif vendor_patterns:
        _validate_vendor_patterns(vendor_patterns, errors, "overrides.vendor_patterns")

    rule_patches = patches.get("rules", {})
    if not isinstance(rule_patches, dict):
        errors.append("overrides.rules must be an object")
    else:
        known_rules = {item["id"]: item for item in registry["rules"]}
        for rule_id, patch in rule_patches.items():
            prefix = f"overrides.rules.{rule_id}"
            if rule_id not in known_rules:
                errors.append(f"{prefix} is an unknown rule id")
                continue
            if not isinstance(patch, dict):
                errors.append(f"{prefix} must be an object")
                continue
            errors.extend(f"{prefix}.{name} is not allowed" for name in sorted(set(patch) - RULE_OVERRIDE_FIELDS))
            if "enabled" in patch:
                if not isinstance(patch["enabled"], bool):
                    errors.append(f"{prefix}.enabled must be boolean")
                elif patch["enabled"] is False and rule_id in NON_DISABLEABLE_RULE_IDS:
                    errors.append(f"{prefix}.enabled cannot disable a protected rule")
            if "severity" in patch and patch["severity"] not in VALID_SEVERITIES:
                errors.append(f"{prefix}.severity is invalid")
            if "local_override_policy" in patch and patch["local_override_policy"] not in VALID_LOCAL_OVERRIDE_POLICIES:
                errors.append(f"{prefix}.local_override_policy is invalid")
            for name in ("risk", "recommendation"):
                if name in patch and not _non_empty_string(patch[name]):
                    errors.append(f"{prefix}.{name} must be a non-empty string")
    return errors


def merge_override(registry: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(registry)
    patches = override.get("overrides", {})
    merged["thresholds"].update(copy.deepcopy(patches.get("thresholds", {})))
    merged["ports"].update(copy.deepcopy(patches.get("ports", {})))
    merged["path_patterns"].update(copy.deepcopy(patches.get("path_patterns", {})))
    for vendor, pattern in patches.get("vendor_patterns", {}).items():
        merged["vendor_patterns"][vendor] = copy.deepcopy(pattern)
    rule_map = {item["id"]: item for item in merged["rules"]}
    for rule_id, patch in patches.get("rules", {}).items():
        rule_map[rule_id].update(copy.deepcopy(patch))
    return merged


def validate_local_profile(profile: Any, registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(profile, dict):
        return ["profile root must be an object"]
    errors.extend(f"profile.{name} is not allowed" for name in sorted(set(profile) - LOCAL_PROFILE_FIELDS))
    missing = sorted(LOCAL_PROFILE_FIELDS - set(profile))
    errors.extend(f"profile.{name} is required" for name in missing)
    if not _supported_schema_version(profile.get("schema_version")):
        errors.append(f"schema_version must be {SUPPORTED_SCHEMA_VERSION}")
    if not _non_empty_string(profile.get("profile_id")):
        errors.append("profile_id must be a non-empty string")

    machine_match = profile.get("machine_match")
    if not isinstance(machine_match, dict):
        errors.append("machine_match must be an object")
    else:
        errors.extend(f"machine_match.{name} is not allowed" for name in sorted(set(machine_match) - LOCAL_MACHINE_MATCH_FIELDS))
        _validate_string_list(machine_match.get("hostnames"), "machine_match.hostnames", errors)

    for name in ("expected_accounts", "expected_processes"):
        _validate_string_list(profile.get(name), name, errors)

    listeners = profile.get("expected_listeners")
    if not isinstance(listeners, list):
        errors.append("expected_listeners must be a list")
    else:
        for index, listener in enumerate(listeners):
            prefix = f"expected_listeners[{index}]"
            if not isinstance(listener, dict):
                errors.append(f"{prefix} must be an object")
                continue
            errors.extend(f"{prefix}.{name} is not allowed" for name in sorted(set(listener) - LOCAL_LISTENER_FIELDS))
            missing_listener_fields = sorted(LOCAL_LISTENER_REQUIRED_FIELDS - set(listener))
            errors.extend(f"{prefix}.{name} is required" for name in missing_listener_fields)
            if type(listener.get("port")) is not int or not 1 <= listener["port"] <= 65535:
                errors.append(f"{prefix}.port must be an integer from 1 to 65535")
            if not isinstance(listener.get("protocol"), str) or listener["protocol"].strip().casefold() not in {"tcp", "udp"}:
                errors.append(f"{prefix}.protocol must be tcp or udp")
            if not _non_empty_string(listener.get("process")):
                errors.append(f"{prefix}.process must be a non-empty string")
            _validate_non_empty_string_list(listener.get("addresses"), f"{prefix}.addresses", errors)
            if "rule_ids" in listener:
                if not listener["rule_ids"]:
                    errors.append(f"{prefix}.rule_ids must be a non-empty list when provided")
                _validate_rule_id_list(listener["rule_ids"], f"{prefix}.rule_ids", registry, errors)

    exceptions = profile.get("rule_exceptions")
    if not isinstance(exceptions, list):
        errors.append("rule_exceptions must be a list")
    else:
        known_rules = {item["id"]: item for item in registry["rules"]}
        for index, exception in enumerate(exceptions):
            prefix = f"rule_exceptions[{index}]"
            if not isinstance(exception, dict):
                errors.append(f"{prefix} must be an object")
                continue
            errors.extend(f"{prefix}.{name} is not allowed" for name in sorted(set(exception) - LOCAL_EXCEPTION_FIELDS))
            rule_id = exception.get("rule_id")
            if rule_id not in known_rules:
                errors.append(f"{prefix}.rule_id is unknown")
            match = exception.get("match")
            if not isinstance(match, dict) or not match:
                errors.append(f"{prefix}.match must be a non-empty object")
            elif not _safe_exact_match_document(match):
                errors.append(f"{prefix}.match contains an unsupported value")
            else:
                allowed_match_fields = LOCAL_EXCEPTION_MATCH_FIELDS.get(str(rule_id), set())
                unknown_match_fields = sorted(set(match) - allowed_match_fields)
                errors.extend(
                    f"{prefix}.match.{name} is not allowed for {rule_id}"
                    for name in unknown_match_fields
                )
            if "note" in exception and not _non_empty_string(exception["note"]):
                errors.append(f"{prefix}.note must be a non-empty string")
    return errors


def rule_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in registry.get("rules", []) if isinstance(item, dict)}


def _load_json_document(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigurationError(f"{_code_prefix(label)}_MISSING", f"{label.title()} is missing: {path.name}") from exc
    except OSError as exc:
        raise ConfigurationError(f"{_code_prefix(label)}_UNREADABLE", f"{label.title()} could not be read: {path.name}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"{_code_prefix(label)}_JSON_INVALID",
            f"{label.title()} JSON is invalid at line {exc.lineno}, column {exc.colno}",
        ) from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"{_code_prefix(label)}_ROOT_INVALID", f"{label.title()} root must be an object")
    return data


def _evidence(status: str, filename: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, "filename": filename, **extra}


def _code_prefix(label: str) -> str:
    return label.upper().replace(" ", "_")


def _severity_name(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and isinstance(item.get("name"), str):
        return item["name"]
    return ""


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _positive_integer(value: Any) -> bool:
    return type(value) is int and value > 0


def _supported_schema_version(value: Any) -> bool:
    return type(value) is int and value == SUPPORTED_SCHEMA_VERSION


def _validate_positive_number(data: dict[str, Any], name: str, errors: list[str], prefix: str) -> None:
    if not _positive_number(data.get(name)):
        errors.append(f"{prefix}.{name} must be a positive number")


def _validate_positive_integer(data: dict[str, Any], name: str, errors: list[str], prefix: str) -> None:
    if not _positive_integer(data.get(name)):
        errors.append(f"{prefix}.{name} must be a positive integer")


def _validate_port_list(value: Any, prefix: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{prefix} must be a non-empty list")
        return
    if any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in value):
        errors.append(f"{prefix} must contain only ports from 1 to 65535")


def _validate_port_ranges(value: Any, errors: list[str], prefix: str = "ports.proxy_ranges") -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{prefix} must be a non-empty list")
        return
    for index, item in enumerate(value):
        if (
            not isinstance(item, list)
            or len(item) != 2
            or any(not isinstance(port, int) or isinstance(port, bool) for port in item)
            or not 1 <= item[0] <= item[1] <= 65535
        ):
            errors.append(f"{prefix}[{index}] must be [start, end] ports")


def _validate_string_list(value: Any, prefix: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{prefix} must be a list")
    elif any(not _non_empty_string(item) for item in value):
        errors.append(f"{prefix} must contain only non-empty strings")


def _validate_non_empty_string_list(value: Any, prefix: str, errors: list[str]) -> None:
    _validate_string_list(value, prefix, errors)
    if isinstance(value, list) and not value:
        errors.append(f"{prefix} must be a non-empty list")


def _validate_vendor_patterns(value: Any, errors: list[str], prefix: str) -> None:
    if not isinstance(value, dict) or not value:
        errors.append(f"{prefix} must be a non-empty object")
        return
    for vendor, pattern in value.items():
        item_prefix = f"{prefix}.{vendor}"
        if not _non_empty_string(vendor) or not isinstance(pattern, dict):
            errors.append(f"{item_prefix} must be an object")
            continue
        unknown = sorted(set(pattern) - {"keywords", "directory_candidates"})
        errors.extend(f"{item_prefix}.{name} is not allowed" for name in unknown)
        _validate_string_list(pattern.get("keywords"), f"{item_prefix}.keywords", errors)
        _validate_string_list(pattern.get("directory_candidates", []), f"{item_prefix}.directory_candidates", errors)
        candidates = pattern.get("directory_candidates", [])
        if isinstance(candidates, list):
            for index, candidate in enumerate(candidates):
                if isinstance(candidate, str) and not is_safe_vendor_directory_candidate(candidate):
                    errors.append(
                        f"{item_prefix}.directory_candidates[{index}] must be a controlled relative directory"
                    )


def _validate_path_patterns(value: Any, errors: list[str], prefix: str) -> None:
    if not isinstance(value, dict):
        errors.append(f"{prefix} must be an object")
        return
    unknown = sorted(set(value) - PATH_PATTERN_FIELDS)
    missing = sorted(PATH_PATTERN_FIELDS - set(value))
    errors.extend(f"{prefix}.{name} is not allowed" for name in unknown)
    errors.extend(f"{prefix}.{name} is required" for name in missing)
    for name in sorted(PATH_PATTERN_FIELDS & set(value)):
        _validate_non_empty_string_list(value.get(name), f"{prefix}.{name}", errors)


def _validate_rule_id_list(value: Any, prefix: str, registry: dict[str, Any], errors: list[str]) -> None:
    _validate_string_list(value, prefix, errors)
    if not isinstance(value, list):
        return
    known = {item["id"] for item in registry["rules"]}
    for rule_id in value:
        if isinstance(rule_id, str) and rule_id not in known:
            errors.append(f"{prefix} contains unknown rule id {rule_id}")


def _safe_exact_match_document(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(_safe_exact_match_document(item) for item in value)
    if isinstance(value, dict):
        return all(_non_empty_string(key) and _safe_exact_match_document(item) for key, item in value.items())
    return False


def is_safe_vendor_directory_candidate(value: str) -> bool:
    if not _non_empty_string(value):
        return False
    candidate = value.strip()
    normalized = candidate.replace("\\", "/")
    if normalized.startswith("/") or normalized.endswith("/") or "//" in normalized:
        return False
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    windows_path = PureWindowsPath(candidate)
    posix_path = PurePosixPath(normalized)
    if windows_path.drive or windows_path.root or windows_path.is_absolute() or posix_path.is_absolute():
        return False
    return True


def _optional_config_path_state(path: Path) -> str:
    try:
        if path.is_symlink():
            return "invalid"
        if not path.exists():
            return "absent"
        if not path.is_file():
            return "invalid"
        with path.open("r", encoding="utf-8"):
            pass
    except OSError:
        return "invalid"
    return "file"
