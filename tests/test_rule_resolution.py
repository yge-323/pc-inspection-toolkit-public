from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rules.loader import (  # noqa: E402
    load_rules,
    resolve_rule_configuration,
    validate_local_profile,
    validate_override,
)


DEFAULT_TEXT = (ROOT / "rules" / "windows_risk_rules.example.json").read_text(encoding="utf-8")


def make_root() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    owner = tempfile.TemporaryDirectory()
    root = Path(owner.name)
    (root / "rules").mkdir()
    (root / "config").mkdir()
    (root / "rules" / "windows_risk_rules.example.json").write_text(DEFAULT_TEXT, encoding="utf-8")
    return owner, root


def valid_override() -> dict:
    return {
        "schema_version": 1,
        "base_registry_version": "0.1.0",
        "overrides": {
            "thresholds": {"disk_free_percent_warning": 12},
            "ports": {},
            "path_patterns": {
                "service_suspicious_substrings": ["\\custom\\"],
            },
            "vendor_patterns": {},
            "rules": {"WIN_PORT_22_REVIEW": {"severity": "Attention"}},
        },
    }


def valid_profile() -> dict:
    return {
        "schema_version": 1,
        "profile_id": "mock-profile",
        "machine_match": {"hostnames": ["mock-host"]},
        "expected_accounts": [],
        "expected_listeners": [],
        "expected_processes": [],
        "rule_exceptions": [],
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_default_registry_success_and_optional_files_absent() -> None:
    owner, root = make_root()
    try:
        result = resolve_rule_configuration(root)
        assert result.status == "OK", result
        assert result.can_analyze is True
        assert result.config_evidence["default_registry"]["status"] == "loaded"
        assert result.config_evidence["user_override"]["status"] == "not_configured"
        assert result.config_evidence["local_profile"]["status"] == "not_configured"
    finally:
        owner.cleanup()


def test_default_registry_missing_and_invalid_json_are_failed() -> None:
    owner, root = make_root()
    try:
        default_path = root / "rules" / "windows_risk_rules.example.json"
        default_path.unlink()
        missing = resolve_rule_configuration(root)
        assert missing.status == "FAILED"
        assert missing.registry is None
        assert missing.config_evidence["default_registry"]["error_code"] == "DEFAULT_REGISTRY_MISSING"
        default_path.write_text("{broken", encoding="utf-8")
        broken = resolve_rule_configuration(root)
        assert broken.status == "FAILED"
        assert broken.config_evidence["default_registry"]["error_code"] == "DEFAULT_REGISTRY_JSON_INVALID"
    finally:
        owner.cleanup()


def test_override_success_and_merge_order() -> None:
    owner, root = make_root()
    try:
        write_json(root / "config" / "windows-risk-rules.override.json", valid_override())
        result = resolve_rule_configuration(root)
        assert result.status == "OK", result.errors
        assert result.registry is not None
        assert result.registry["thresholds"]["disk_free_percent_warning"] == 12
        assert result.registry["path_patterns"]["service_suspicious_substrings"] == ["\\custom\\"]
        rules = {item["id"]: item for item in result.registry["rules"]}
        assert rules["WIN_PORT_22_REVIEW"]["severity"] == "Attention"
        assert result.config_evidence["user_override"] == {
            "status": "loaded",
            "filename": "windows-risk-rules.override.json",
            "applied": True,
        }
    finally:
        owner.cleanup()


def test_override_json_schema_required_fields_and_forbidden_fields_fail() -> None:
    owner, root = make_root()
    try:
        path = root / "config" / "windows-risk-rules.override.json"
        path.write_text("{broken", encoding="utf-8")
        assert resolve_rule_configuration(root).status == "FAILED"

        bad_schema = valid_override()
        bad_schema["schema_version"] = 2
        write_json(path, bad_schema)
        assert resolve_rule_configuration(root).status == "FAILED"

        missing = valid_override()
        del missing["overrides"]
        write_json(path, missing)
        assert resolve_rule_configuration(root).status == "FAILED"

        forbidden = valid_override()
        forbidden["overrides"]["rules"]["WIN_PORT_22_REVIEW"]["condition_description"] = "replace"
        write_json(path, forbidden)
        result = resolve_rule_configuration(root)
        assert result.status == "FAILED"
        assert any("condition_description is not allowed" in item for item in result.errors)
    finally:
        owner.cleanup()


def test_override_unknown_rule_and_protected_disable_fail() -> None:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    unknown = valid_override()
    unknown["overrides"]["rules"] = {"WIN_UNKNOWN": {"enabled": False}}
    assert any("unknown rule id" in item for item in validate_override(unknown, registry))
    protected = valid_override()
    protected["overrides"]["rules"] = {"WIN_BITLOCKER_NEED_ADMIN": {"enabled": False}}
    assert any("protected rule" in item for item in validate_override(protected, registry))


def test_local_profile_success_missing_and_invalid_are_distinct() -> None:
    owner, root = make_root()
    try:
        missing = resolve_rule_configuration(root)
        assert missing.config_evidence["local_profile"]["status"] == "not_configured"

        profile_path = root / "config" / "local-profile.json"
        write_json(profile_path, valid_profile())
        loaded = resolve_rule_configuration(root)
        assert loaded.status == "OK"
        assert loaded.local_profile == valid_profile()
        assert loaded.config_evidence["local_profile"]["status"] == "loaded"

        profile_path.write_text("{broken", encoding="utf-8")
        broken = resolve_rule_configuration(root)
        assert broken.status == "PARTIAL"
        assert broken.registry is not None
        assert broken.local_profile is None
    finally:
        owner.cleanup()


def test_local_profile_rejects_forbidden_override_and_unsafe_match_values() -> None:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    forbidden = valid_profile()
    forbidden["rules"] = {"WIN_PORT_22_REVIEW": {"enabled": False}}
    errors = validate_local_profile(forbidden, registry)
    assert any("profile.rules is not allowed" in item for item in errors)

    unsafe = valid_profile()
    unsafe["rule_exceptions"] = [{
        "rule_id": "WIN_PORT_22_REVIEW",
        "match": {"process": {"command": [object()]}},
    }]
    errors = validate_local_profile(unsafe, registry)
    assert any("unsupported value" in item for item in errors)

    null_match = valid_profile()
    null_match["rule_exceptions"] = [{
        "rule_id": "WIN_PORT_22_REVIEW",
        "match": {"port": None},
    }]
    errors = validate_local_profile(null_match, registry)
    assert any("unsupported value" in item for item in errors)

    unknown_match = valid_profile()
    unknown_match["rule_exceptions"] = [{
        "rule_id": "WIN_PORT_22_REVIEW",
        "match": {"missing_key": "value"},
    }]
    errors = validate_local_profile(unknown_match, registry)
    assert any("missing_key is not allowed" in item for item in errors)


def test_vendor_local_profile_fields_match_production_evidence_names() -> None:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    valid = valid_profile()
    valid["rule_exceptions"] = [{
        "rule_id": "WIN_SECURITY_VENDOR_RESIDUE",
        "match": {"task_present": True, "startup_present": False},
    }]
    assert validate_local_profile(valid, registry) == []

    for obsolete_field in ("scheduled_task_present", "startup_item_present"):
        obsolete = valid_profile()
        obsolete["rule_exceptions"] = [{
            "rule_id": "WIN_SECURITY_VENDOR_RESIDUE",
            "match": {obsolete_field: True},
        }]
        errors = validate_local_profile(obsolete, registry)
        assert any(f"{obsolete_field} is not allowed" in item for item in errors), errors

    unknown = valid_profile()
    unknown["rule_exceptions"] = [{
        "rule_id": "WIN_SECURITY_VENDOR_RESIDUE",
        "match": {"unobserved_vendor_field": True},
    }]
    errors = validate_local_profile(unknown, registry)
    assert any("unobserved_vendor_field is not allowed" in item for item in errors), errors


def test_bool_values_are_rejected_for_schema_threshold_and_listener_port() -> None:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")

    override = valid_override()
    override["schema_version"] = True
    assert any("schema_version" in item for item in validate_override(override, registry))

    override = valid_override()
    override["overrides"]["thresholds"]["disk_free_percent_warning"] = True
    assert any("positive number" in item for item in validate_override(override, registry))

    override = valid_override()
    override["overrides"]["thresholds"] = {"administrator_member_count_attention_above": 3.5}
    assert any("positive integer" in item for item in validate_override(override, registry))

    profile = valid_profile()
    profile["schema_version"] = True
    profile["expected_listeners"] = [{
        "protocol": "tcp",
        "port": True,
        "process": "mock-process",
        "addresses": ["127.0.0.1"],
    }]
    errors = validate_local_profile(profile, registry)
    assert any("schema_version" in item for item in errors)
    assert any("port must be an integer" in item for item in errors)

    owner, root = make_root()
    try:
        default = json.loads(DEFAULT_TEXT)
        default["schema_version"] = True
        write_json(root / "rules" / "windows_risk_rules.example.json", default)
        assert resolve_rule_configuration(root).status == "FAILED"
    finally:
        owner.cleanup()


def test_expected_listener_requires_full_identity_fields() -> None:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    base = valid_profile()
    base["expected_listeners"] = [{"port": 22}]
    errors = validate_local_profile(base, registry)
    for field in ("protocol", "process", "addresses"):
        assert any(f"{field} is required" in item for item in errors), errors

    complete = valid_profile()
    complete["expected_listeners"] = [{
        "protocol": "TCP",
        "port": 22,
        "process": "mock-process",
        "addresses": ["127.0.0.1"],
        "rule_ids": ["WIN_PORT_22_REVIEW"],
    }]
    assert validate_local_profile(complete, registry) == []


def test_vendor_directory_candidates_reject_escape_forms() -> None:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    unsafe_candidates = (
        r"C:\Users\Private",
        r"\\server\share",
        r"..\Secret",
        r"safe\..\Secret",
        ".",
        "..",
        "/rooted",
        r"\rooted",
        "safe/../Secret",
        "safe\\/../Secret",
    )
    for candidate in unsafe_candidates:
        override = valid_override()
        override["overrides"]["vendor_patterns"] = {
            "MockVendor": {
                "keywords": ["mock"],
                "directory_candidates": [candidate],
            }
        }
        errors = validate_override(override, registry)
        assert any("controlled relative directory" in item for item in errors), candidate

    safe = valid_override()
    safe["overrides"]["vendor_patterns"] = {
        "MockVendor": {
            "keywords": ["mock"],
            "directory_candidates": [r"Vendor\Product"],
        }
    }
    assert validate_override(safe, registry) == []


def test_optional_config_paths_that_are_not_regular_files_are_visible_failures() -> None:
    owner, root = make_root()
    try:
        override_path = root / "config" / "windows-risk-rules.override.json"
        override_path.mkdir()
        override = resolve_rule_configuration(root)
        assert override.status == "FAILED"
        assert override.config_evidence["user_override"]["error_code"] == "OVERRIDE_PATH_INVALID"
    finally:
        owner.cleanup()

    owner, root = make_root()
    try:
        profile_path = root / "config" / "local-profile.json"
        profile_path.mkdir()
        profile = resolve_rule_configuration(root)
        assert profile.status == "PARTIAL"
        assert profile.registry is not None
        assert profile.local_profile is None
        assert profile.config_evidence["local_profile"]["error_code"] == "LOCAL_PROFILE_PATH_INVALID"
    finally:
        owner.cleanup()


def test_default_registry_required_field_failure_is_visible() -> None:
    owner, root = make_root()
    try:
        registry = json.loads(DEFAULT_TEXT)
        del registry["thresholds"]
        write_json(root / "rules" / "windows_risk_rules.example.json", registry)
        result = resolve_rule_configuration(root)
        assert result.status == "FAILED"
        assert any("thresholds must be an object" in item for item in result.errors)
    finally:
        owner.cleanup()


def main() -> int:
    test_default_registry_success_and_optional_files_absent()
    test_default_registry_missing_and_invalid_json_are_failed()
    test_override_success_and_merge_order()
    test_override_json_schema_required_fields_and_forbidden_fields_fail()
    test_override_unknown_rule_and_protected_disable_fail()
    test_local_profile_success_missing_and_invalid_are_distinct()
    test_local_profile_rejects_forbidden_override_and_unsafe_match_values()
    test_vendor_local_profile_fields_match_production_evidence_names()
    test_bool_values_are_rejected_for_schema_threshold_and_listener_port()
    test_expected_listener_requires_full_identity_fields()
    test_vendor_directory_candidates_reject_escape_forms()
    test_optional_config_paths_that_are_not_regular_files_are_visible_failures()
    test_default_registry_required_field_failure_is_visible()
    print("Rule resolution tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
