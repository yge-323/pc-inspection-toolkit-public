from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rules.loader import REQUIRED_RULE_IDS, load_rules, validate_rules  # noqa: E402


def test_example_rules_load_and_validate() -> None:
    rules = load_rules(str(ROOT / "rules" / "windows_risk_rules.example.json"))
    errors = validate_rules(rules)
    assert errors == [], errors
    assert rules["registry_role"] == "default", rules
    assert rules["registry_version"] == "0.1.0", rules
    assert rules["thresholds"]["disk_free_percent_warning"] == 10.0, rules
    assert rules["thresholds"]["administrator_member_count_attention_above"] == 3, rules
    assert rules["ports"]["ssh"] == [22], rules
    assert rules["path_patterns"]["startup_script_extensions"], rules
    assert rules["vendor_patterns"]["Huorong"]["keywords"], rules
    assert all("local_override_policy" in item for item in rules["rules"]), rules
    rule_ids = {item["id"] for item in rules["rules"]}
    assert rule_ids == REQUIRED_RULE_IDS, (rule_ids, REQUIRED_RULE_IDS)
    assert "WIN_SHARE_BROAD_ACCESS" not in rule_ids


def test_duplicate_id_is_reported() -> None:
    rules = load_rules(str(ROOT / "rules" / "windows_risk_rules.example.json"))
    sample = copy.deepcopy(rules)
    sample["rules"][1]["id"] = sample["rules"][0]["id"]
    errors = validate_rules(sample)
    assert any("duplicated" in error for error in errors), errors


def test_missing_required_field_is_reported() -> None:
    rules = load_rules(str(ROOT / "rules" / "windows_risk_rules.example.json"))
    sample = copy.deepcopy(rules)
    del sample["rules"][0]["recommendation"]
    errors = validate_rules(sample)
    assert any("recommendation is required" in error for error in errors), errors


def test_all_registry_backed_finding_text_fields_are_required() -> None:
    rules = load_rules(str(ROOT / "rules" / "windows_risk_rules.example.json"))
    for field in ("name", "severity", "risk", "recommendation"):
        sample = copy.deepcopy(rules)
        del sample["rules"][0][field]
        errors = validate_rules(sample)
        assert any(f"{field} is required" in error for error in errors), (field, errors)

    unsupported = copy.deepcopy(rules)
    unsupported["rules"].append({**copy.deepcopy(rules["rules"][0]), "id": "WIN_NO_ANALYZER"})
    errors = validate_rules(unsupported)
    assert any("no runtime analyzer entry" in error for error in errors), errors


def test_network_rules_describe_listener_only_evidence() -> None:
    registry = load_rules(str(ROOT / "rules" / "windows_risk_rules.example.json"))
    rules = {item["id"]: item for item in registry["rules"]}
    for rule_id in ("WIN_PORT_22_REVIEW", "WIN_SMB_445_ALLOWED", "WIN_RDP_EXPOSED_REVIEW"):
        rule = rules[rule_id]
        assert rule["applies_to_collectors"] == ["network_ports"], rule
        assert rule["evidence_fields"] == [
            "network_ports.LocalPort",
            "network_ports.LocalAddress",
        ], rule
        assert "network_ports.ProcessName" not in rule["evidence_fields"], rule
        assert "listener-only check" in rule["condition_description"], rule

    assert "appears to be sshd" not in rules["WIN_PORT_22_REVIEW"]["condition_description"]
    assert "Allow rules appear enabled" not in rules["WIN_SMB_445_ALLOWED"]["condition_description"]
    assert "Remote Desktop is enabled" not in rules["WIN_RDP_EXPOSED_REVIEW"]["condition_description"]

    for rule_id in ("WIN_PORT_22_REVIEW", "WIN_SMB_445_ALLOWED"):
        for field in ("precheck", "rollback", "verification_checkpoint", "references"):
            assert rules[rule_id].get(field), (rule_id, field)


def test_enabled_legacy_findings_have_complete_remediation_guidance() -> None:
    registry = load_rules(str(ROOT / "rules" / "windows_risk_rules.example.json"))
    rules = {item["id"]: item for item in registry["rules"]}
    for rule_id in ("WIN_PORT_22_REVIEW", "WIN_SMB_445_ALLOWED", "WIN_SECURITY_VENDOR_RESIDUE"):
        for field in ("precheck", "recommendation", "rollback", "verification_checkpoint"):
            assert rules[rule_id].get(field), (rule_id, field)
    assert "保留22端口" in rules["WIN_PORT_22_REVIEW"]["recommendation"]
    assert "不要仅凭端口监听直接封锁445" in rules["WIN_SMB_445_ALLOWED"]["recommendation"]
    assert "不要手工删除驱动" in rules["WIN_SECURITY_VENDOR_RESIDUE"]["recommendation"]


def main() -> int:
    tests = [
        test_example_rules_load_and_validate,
        test_duplicate_id_is_reported,
        test_missing_required_field_is_reported,
        test_all_registry_backed_finding_text_fields_are_required,
        test_network_rules_describe_listener_only_evidence,
        test_enabled_legacy_findings_have_complete_remediation_guidance,
    ]
    for test in tests:
        test()
    print("Rules loader tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
