from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.risk_analyzer import analyze as analyze_with_registry  # noqa: E402
from collectors.remote_desktop import DEFAULT_RDP_PORT  # noqa: E402
from rules.loader import load_rules  # noqa: E402


def analyze(results: dict) -> object:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    return analyze_with_registry(results, registry)


def test_bitlocker_need_admin_finding_is_generated() -> None:
    findings = analyze({
        "disks": {
            "collector": "disks",
            "status": "need_admin",
            "data": {
                "BitLocker": [],
                "Errors": ["Get-BitLockerVolume failed: 拒绝访问"],
            },
            "errors": ["Get-BitLockerVolume failed: 拒绝访问"],
        }
    })
    target = [item for item in findings if item.get("finding_id") == "WIN_BITLOCKER_NEED_ADMIN"]
    assert len(target) == 1, findings
    assert target[0]["severity"] == "Need Admin", target[0]
    assert target[0]["level"] == "Need Admin", target[0]
    assert "不导出恢复密钥" in target[0]["precheck"]
    assert "不代表卷未加密" in target[0]["applicability"]
    assert "只读方式" in target[0]["recommendation"]
    assert "无需系统回滚" in target[0]["rollback"]
    assert "ProtectionStatus" in target[0]["verification_checkpoint"]
    assert target[0]["references"]


def test_bitlocker_need_admin_finding_is_not_generated_without_signal() -> None:
    findings = analyze({
        "disks": {
            "collector": "disks",
            "status": "ok",
            "data": {
                "BitLocker": [],
                "Errors": [],
            },
            "errors": [],
        }
    })
    assert not any(item.get("finding_id") == "WIN_BITLOCKER_NEED_ADMIN" for item in findings), findings


def test_disk_low_space_finding_is_generated_from_free_percent() -> None:
    findings = analyze({
        "disks": {
            "collector": "disks",
            "status": "ok",
            "data": {
                "VolumeSummary": [
                    {
                        "Drive": "C:",
                        "Size": 100 * 1024**3,
                        "Free": 9 * 1024**3,
                        "FreePercent": 9,
                    }
                ],
            },
            "errors": [],
        }
    })

    target = [item for item in findings if item.get("rule_id") == "WIN_DISK_LOW_SPACE"]
    assert len(target) == 1, findings
    assert target[0]["severity"] == "Warning", target[0]
    assert target[0]["needs_human_review"] is True, target[0]
    assert target[0]["evidence"]["drive"] == "C:", target[0]
    assert target[0]["evidence"]["free_percent"] == 9, target[0]
    assert "请人工确认受影响卷" in target[0]["recommendation"], target[0]
    assert target[0]["evidence"]["threshold"]["free_percent_lte"] == 10.0, target[0]


def test_disk_low_space_finding_is_generated_from_free_gb() -> None:
    findings = analyze({
        "disks": {
            "collector": "disks",
            "status": "ok",
            "data": {
                "VolumeSummary": [
                    {
                        "drive": "D:",
                        "free_gb": 8,
                        "total_gb": 200,
                    }
                ],
            },
            "errors": [],
        }
    })

    target = [item for item in findings if item.get("rule_id") == "WIN_DISK_LOW_SPACE"]
    assert len(target) == 1, findings
    assert target[0]["severity"] == "Warning", target[0]
    assert target[0]["evidence"]["drive"] == "D:", target[0]
    assert target[0]["evidence"]["free_gb"] == 8, target[0]
    assert target[0]["evidence"]["free_percent"] == 4, target[0]


def test_disk_low_space_finding_can_be_generated_for_multiple_volumes() -> None:
    findings = analyze({
        "disks": {
            "collector": "disks",
            "status": "ok",
            "data": {
                "VolumeSummary": [
                    {"Drive": "C:", "FreePercent": 10, "Free": 10 * 1024**3, "Size": 100 * 1024**3},
                    {"Drive": "D:", "FreePercent": 5, "Free": 5 * 1024**3, "Size": 100 * 1024**3},
                    {"Drive": "E:", "FreePercent": 80, "Free": 80 * 1024**3, "Size": 100 * 1024**3},
                ],
            },
            "errors": [],
        }
    })

    target = [item for item in findings if item.get("rule_id") == "WIN_DISK_LOW_SPACE"]
    drives = [item["evidence"]["drive"] for item in target]
    assert drives == ["C:", "D:"], findings
    assert all(item["severity"] == "Warning" for item in target), target


def test_disk_low_space_finding_is_not_generated_for_normal_space() -> None:
    findings = analyze({
        "disks": {
            "collector": "disks",
            "status": "ok",
            "data": {
                "VolumeSummary": [
                    {"Drive": "C:", "FreePercent": 25, "Free": 50 * 1024**3, "Size": 200 * 1024**3},
                ],
            },
            "errors": [],
        }
    })

    assert not any(item.get("rule_id") == "WIN_DISK_LOW_SPACE" for item in findings), findings


def test_disk_low_space_malformed_fields_do_not_raise_or_generate() -> None:
    findings = analyze({
        "disks": {
            "collector": "disks",
            "status": "ok",
            "data": {
                "VolumeSummary": [
                    {"Drive": "C:", "FreePercent": "unknown", "Free": "n/a", "Size": "n/a"},
                    {"Drive": "D:"},
                    "not-a-dict",
                ],
            },
            "errors": [],
        }
    })

    assert not any(item.get("rule_id") == "WIN_DISK_LOW_SPACE" for item in findings), findings


def test_startup_suspicious_path_finding_is_generated() -> None:
    findings = analyze({
        "startup_items": {
            "collector": "startup_items",
            "status": "ok",
            "data": {
                "Items": [
                    {
                        "Name": "SuspiciousStartup",
                        "Command": "powershell.exe -File C:\\Users\\Example\\AppData\\Roaming\\updater.ps1",
                        "Location": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "Scope": "CurrentUser",
                        "SourceType": "RegistryRun",
                    }
                ]
            },
            "errors": [],
        }
    })
    target = [item for item in findings if item.get("finding_id") == "WIN_STARTUP_SUSPICIOUS_PATH"]
    assert len(target) == 1, findings
    assert target[0]["severity"] == "Warning", target[0]
    assert target[0]["needs_human_review"] is True, target[0]


def test_startup_suspicious_path_finding_is_not_generated_for_normal_item() -> None:
    findings = analyze({
        "startup_items": {
            "collector": "startup_items",
            "status": "ok",
            "data": {
                "Items": [
                    {
                        "Name": "NormalStartup",
                        "Command": "C:\\Program Files\\Vendor\\App\\app.exe",
                        "Location": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "Scope": "CurrentUser",
                        "SourceType": "RegistryRun",
                    }
                ]
            },
            "errors": [],
        }
    })
    assert not any(item.get("finding_id") == "WIN_STARTUP_SUSPICIOUS_PATH" for item in findings), findings


def test_administrator_threshold_comes_only_from_registry() -> None:
    configured = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    results = {"users": {"data": {"Administrators": [{"Name": str(index)} for index in range(4)]}}}

    findings = analyze_with_registry(results, configured)
    target = [item for item in findings if item.get("finding_id") == "WIN_ADMINISTRATOR_COUNT_REVIEW"]
    assert len(target) == 1, findings
    assert target[0]["severity"] == "Attention"
    assert target[0]["evidence"]["threshold"] == 3

    raised = copy.deepcopy(configured)
    raised["thresholds"]["administrator_member_count_attention_above"] = 4
    findings = analyze_with_registry(results, raised)
    assert not any(item.get("finding_id") == "WIN_ADMINISTRATOR_COUNT_REVIEW" for item in findings)


def test_event_thresholds_come_only_from_registry() -> None:
    configured = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    errors = [{"LevelDisplayName": "Error"} for _ in range(20)]
    result = analyze_with_registry({"event_logs": {"data": errors}}, configured)
    target = [item for item in result if item.get("finding_id") == "WIN_EVENT_LOG_ERROR_VOLUME"]
    assert len(target) == 1, result
    assert target[0]["evidence"]["error_count"] == 20

    raised = copy.deepcopy(configured)
    raised["thresholds"]["event_log_error_count_warning_at_least"] = 21
    result = analyze_with_registry({"event_logs": {"data": errors}}, raised)
    assert not any(item.get("finding_id") == "WIN_EVENT_LOG_ERROR_VOLUME" for item in result)

    critical = analyze_with_registry(
        {"event_logs": {"data": [{"LevelDisplayName": "Critical"}]}},
        configured,
    )
    assert any(item.get("finding_id") == "WIN_EVENT_LOG_ERROR_VOLUME" for item in critical)


def test_service_and_task_path_patterns_come_only_from_registry() -> None:
    configured = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    results = {
        "services": {"data": [{"Name": "Svc", "StartMode": "Auto", "PathName": r"C:\Users\Mock\svc.exe"}]},
        "scheduled_tasks": {"data": [{"TaskName": "Task", "Actions": r"C:\Temp\task.exe"}]},
    }
    findings = analyze_with_registry(results, configured)
    assert any(item.get("finding_id") == "WIN_SERVICE_SUSPICIOUS_PATH" for item in findings)
    assert any(item.get("finding_id") == "WIN_SCHEDULED_TASK_SUSPICIOUS_PATH" for item in findings)

    custom = copy.deepcopy(configured)
    custom["path_patterns"]["service_suspicious_substrings"] = ["\\custom-service\\"]
    custom["path_patterns"]["scheduled_task_suspicious_substrings"] = ["\\custom-task\\"]
    findings = analyze_with_registry(results, custom)
    assert not any(item.get("finding_id") in {
        "WIN_SERVICE_SUSPICIOUS_PATH", "WIN_SCHEDULED_TASK_SUSPICIOUS_PATH"
    } for item in findings)

    custom_results = {
        "services": {"data": [{"Name": "Svc", "StartMode": "Auto", "PathName": r"C:\custom-service\svc.exe"}]},
        "scheduled_tasks": {"data": [{"TaskName": "Task", "Actions": r"C:\custom-task\task.exe"}]},
    }
    findings = analyze_with_registry(custom_results, custom)
    assert any(item.get("finding_id") == "WIN_SERVICE_SUSPICIOUS_PATH" for item in findings)
    assert any(item.get("finding_id") == "WIN_SCHEDULED_TASK_SUSPICIOUS_PATH" for item in findings)


def test_startup_patterns_come_only_from_registry_and_ignore_legacy_risk_fields() -> None:
    configured = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    legacy_only = {
        "startup_items": {"data": {"Items": [{
            "Name": "Legacy",
            "Command": r"C:\Program Files\Vendor\app.exe",
            "HighAttentionPaths": ["appdata"],
            "ScriptInterpreters": ["powershell"],
            "ScriptExtensions": [".ps1"],
            "Status": "Warning",
            "Risk": "legacy risk",
        }]}}
    }
    findings = analyze_with_registry(legacy_only, configured)
    assert not any(item.get("finding_id") == "WIN_STARTUP_SUSPICIOUS_PATH" for item in findings)

    custom = copy.deepcopy(configured)
    custom["path_patterns"]["startup_suspicious_path_substrings"] = ["custom-startup-path"]
    custom["path_patterns"]["startup_interpreter_substrings"] = ["custom-interpreter"]
    custom["path_patterns"]["startup_script_extensions"] = [".customext"]

    old_policy = {"startup_items": {"data": {"Items": [{
        "Name": "Old", "Command": r"powershell C:\Users\Mock\AppData\old.ps1"
    }]}}}
    findings = analyze_with_registry(old_policy, custom)
    assert not any(item.get("finding_id") == "WIN_STARTUP_SUSPICIOUS_PATH" for item in findings)

    for command in ("custom-startup-path/app.exe", "custom-interpreter --run", "file.customext"):
        result = analyze_with_registry(
            {"startup_items": {"data": {"Items": [{"Name": "Custom", "Command": command}]}}},
            custom,
        )
        assert any(item.get("finding_id") == "WIN_STARTUP_SUSPICIOUS_PATH" for item in result), command


def test_all_runtime_findings_have_registry_backed_stable_ids_and_no_policy_fallbacks() -> None:
    configured = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    rule_ids = {item["id"] for item in configured["rules"]}
    results = {
        "users": {"data": {"Administrators": [{"Name": str(index)} for index in range(4)]}},
        "services": {"data": [{"Name": "Svc", "StartMode": "Auto", "PathName": r"C:\Users\Mock\svc.exe"}]},
        "scheduled_tasks": {"data": [{"TaskName": "Task", "Actions": r"C:\Temp\task.exe"}]},
        "event_logs": {"data": [{"LevelDisplayName": "Critical"}]},
    }
    findings = analyze_with_registry(results, configured)
    assert findings.findings
    assert all(item.get("finding_id") in rule_ids for item in findings)

    analyzer_source = (ROOT / "analyzers" / "risk_analyzer.py").read_text(encoding="utf-8")
    collector_source = (ROOT / "collectors" / "startup_items.py").read_text(encoding="utf-8")
    for forbidden in (
        "len(admins) > 3",
        "error >= 20",
        '"\\\\users\\\\" in path',
        '"appdata" in actions',
        'rule.get("severity") or',
        'rule.get("recommendation") or',
    ):
        assert forbidden not in analyzer_source, forbidden
    for forbidden in ("HighAttentionPaths", "ScriptInterpreters", "ScriptExtensions", "IsHighAttention", "Startup item review"):
        assert forbidden not in collector_source, forbidden


def test_legacy_network_findings_emit_standard_severity() -> None:
    findings = analyze({
        "network_ports": {
            "collector": "network_ports",
            "status": "ok",
            "data": [
                {
                    "LocalAddress": "0.0.0.0",
                    "LocalPort": 445,
                    "ProcessName": "System",
                },
                {
                    "LocalAddress": "0.0.0.0",
                    "LocalPort": 22,
                    "ProcessName": "sshd",
                },
            ],
            "errors": [],
        }
    })

    smb = [item for item in findings if item.get("finding_id") == "WIN_SMB_445_ALLOWED"]
    ssh = [item for item in findings if item.get("finding_id") == "WIN_PORT_22_REVIEW"]
    assert len(smb) == 1, findings
    assert len(ssh) == 1, findings
    assert smb[0]["severity"] == "Attention", smb[0]
    assert smb[0]["level"] == "Attention", smb[0]
    assert ssh[0]["severity"] == "Warning", ssh[0]
    assert ssh[0]["level"] == "Warning", ssh[0]
    assert all(item.get("severity") not in {"HIGH", "MEDIUM", "LOW"} for item in findings), findings


def test_ssh_ipv4_ipv6_listeners_generate_one_finding() -> None:
    findings = analyze({
        "network_ports": {
            "collector": "network_ports",
            "status": "ok",
            "data": [
                {"LocalAddress": "0.0.0.0", "LocalPort": 22, "ProcessName": "sshd"},
                {"LocalAddress": "::", "LocalPort": 22, "ProcessName": "sshd"},
            ],
            "errors": [],
        }
    })

    ssh = [item for item in findings if item.get("finding_id") == "WIN_PORT_22_REVIEW"]
    assert len(ssh) == 1, findings
    assert "0.0.0.0:22" in ssh[0]["evidence"], ssh[0]
    assert "[::]:22" in ssh[0]["evidence"], ssh[0]


def test_network_finding_text_does_not_claim_unverified_context() -> None:
    findings = analyze({
        "network_ports": {
            "collector": "network_ports",
            "status": "ok",
            "data": [
                {"LocalAddress": "0.0.0.0", "LocalPort": 22, "ProcessName": "not-sshd"},
                {"LocalAddress": "0.0.0.0", "LocalPort": 445, "ProcessName": "not-smb"},
                {"LocalAddress": "0.0.0.0", "LocalPort": 3389, "ProcessName": "not-rdp"},
            ],
            "errors": [],
        },
        "firewall": {
            "status": "ok",
            "data": {"SmbInboundRules": [{"Enabled": True, "Action": "Block"}]},
        },
        "remote_desktop": {
            "status": "ok",
            "data": {
                "Settings": {"RemoteDesktopEnabled": False},
                "FirewallRules": [{"Enabled": True, "Action": "Block"}],
            },
        },
    })
    by_id = {item["finding_id"]: item for item in findings}
    assert {
        "WIN_PORT_22_REVIEW",
        "WIN_SMB_445_ALLOWED",
        "WIN_RDP_EXPOSED_REVIEW",
    } <= set(by_id)

    ssh_text = " ".join(str(by_id["WIN_PORT_22_REVIEW"].get(field, "")) for field in (
        "title", "description", "impact", "recommendation"
    ))
    smb_text = " ".join(str(by_id["WIN_SMB_445_ALLOWED"].get(field, "")) for field in (
        "title", "description", "impact", "recommendation"
    ))
    rdp_text = " ".join(str(by_id["WIN_RDP_EXPOSED_REVIEW"].get(field, "")) for field in (
        "title", "description", "impact", "recommendation"
    ))
    assert "appears to be sshd" not in ssh_text
    assert "Allow rules appear enabled" not in smb_text
    assert "Remote Desktop is enabled" not in rdp_text
    assert "does not verify" in ssh_text
    assert "does not verify" in smb_text
    assert "does not determine" in rdp_text
    assert by_id["WIN_PORT_22_REVIEW"]["severity"] == "Warning"
    assert by_id["WIN_SMB_445_ALLOWED"]["severity"] == "Attention"
    assert by_id["WIN_RDP_EXPOSED_REVIEW"]["severity"] == "Attention"
    for rule_id in ("WIN_PORT_22_REVIEW", "WIN_SMB_445_ALLOWED"):
        for field in ("precheck", "recommendation", "rollback", "verification_checkpoint"):
            assert by_id[rule_id].get(field), (rule_id, field, by_id[rule_id])
    assert "备用" in by_id["WIN_PORT_22_REVIEW"]["precheck"]
    assert "维护连接" in by_id["WIN_PORT_22_REVIEW"]["rollback"]
    assert "共享清单" in by_id["WIN_SMB_445_ALLOWED"]["precheck"]


def test_startup_registry_evidence_fields_exist_in_actual_finding() -> None:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    result = analyze_with_registry({
        "startup_items": {
            "collector": "startup_items",
            "status": "ok",
            "data": {"Items": [{
                "Name": "Mock",
                "Command": r"C:\Temp\mock.ps1",
                "Location": "HKCU Run",
                "Scope": "CurrentUser",
                "SourceType": "Registry",
            }]},
        },
    }, registry)
    finding = next(item for item in result if item["finding_id"] == "WIN_STARTUP_SUSPICIOUS_PATH")
    actual_paths = {"collector", "matched_count"}
    for item in finding["evidence"]["items"]:
        actual_paths.update(f"items.{key}" for key in item)
    rule = next(item for item in registry["rules"] if item["id"] == "WIN_STARTUP_SUSPICIOUS_PATH")
    assert set(rule["evidence_fields"]) <= actual_paths, (rule["evidence_fields"], actual_paths)
    for obsolete in ("HighAttentionPaths", "ScriptInterpreters", "ScriptExtensions"):
        assert not any(obsolete in field for field in rule["evidence_fields"])


def test_rdp_risk_port_comes_from_registry_not_collector_default() -> None:
    assert DEFAULT_RDP_PORT == 3389
    collector_source = (ROOT / "collectors" / "remote_desktop.py").read_text(encoding="utf-8")
    analyzer_source = (ROOT / "analyzers" / "risk_analyzer.py").read_text(encoding="utf-8")
    assert collector_source.count("3389") == 1
    assert "DEFAULT_RDP_PORT" not in analyzer_source

    custom = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    custom["ports"]["rdp"] = [3395]
    result = analyze_with_registry({
        "network_ports": {
            "collector": "network_ports",
            "status": "ok",
            "data": [
                {"LocalAddress": "0.0.0.0", "LocalPort": 3389, "ProcessName": "default-port"},
                {"LocalAddress": "0.0.0.0", "LocalPort": 3395, "ProcessName": "configured-port"},
            ],
        },
    }, custom)
    rdp = [item for item in result if item["finding_id"] == "WIN_RDP_EXPOSED_REVIEW"]
    assert len(rdp) == 1, rdp
    assert rdp[0]["evidence_data"]["port"] == 3395, rdp[0]


def main() -> int:
    test_bitlocker_need_admin_finding_is_generated()
    test_bitlocker_need_admin_finding_is_not_generated_without_signal()
    test_disk_low_space_finding_is_generated_from_free_percent()
    test_disk_low_space_finding_is_generated_from_free_gb()
    test_disk_low_space_finding_can_be_generated_for_multiple_volumes()
    test_disk_low_space_finding_is_not_generated_for_normal_space()
    test_disk_low_space_malformed_fields_do_not_raise_or_generate()
    test_startup_suspicious_path_finding_is_generated()
    test_startup_suspicious_path_finding_is_not_generated_for_normal_item()
    test_administrator_threshold_comes_only_from_registry()
    test_event_thresholds_come_only_from_registry()
    test_service_and_task_path_patterns_come_only_from_registry()
    test_startup_patterns_come_only_from_registry_and_ignore_legacy_risk_fields()
    test_all_runtime_findings_have_registry_backed_stable_ids_and_no_policy_fallbacks()
    test_legacy_network_findings_emit_standard_severity()
    test_ssh_ipv4_ipv6_listeners_generate_one_finding()
    test_network_finding_text_does_not_claim_unverified_context()
    test_startup_registry_evidence_fields_exist_in_actual_finding()
    test_rdp_risk_port_comes_from_registry_not_collector_default()
    print("Risk analyzer tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
