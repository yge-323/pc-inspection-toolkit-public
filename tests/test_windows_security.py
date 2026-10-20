from __future__ import annotations

import copy
import json
import platform
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.windows_security_rules import (  # noqa: E402
    analyze_windows_administrator_count,
    analyze_windows_security_facts,
    analyze_windows_startup_facts,
    local_security_facts,
    native_security_facts,
    parse_native_administrator_count,
    parse_native_startup_facts,
)
from analyzers.windows_disk_rules import analyze_windows_disk_facts, parse_native_disk_facts  # noqa: E402
from collectors import windows_security  # noqa: E402
from rules.loader import load_rules, validate_registry  # noqa: E402


def _registry() -> dict:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    errors = validate_registry(registry)
    assert not errors, errors
    return registry


def test_native_and_local_security_facts_share_findings() -> None:
    registry = _registry()
    local_data = {
        "Rdp": {"Enabled": True, "NlaRequired": False},
        "Smb1": {"Enabled": True},
        "AutoLogon": {"Enabled": True},
        "LocalAccounts": {"GuestEnabled": True},
        "PasswordPolicy": {"Status": "collected", "Values": {
            "MinimumPasswordLength": 6, "PasswordComplexity": 0, "LockoutBadCount": 0,
        }},
        "FirewallProfiles": [
            {"Name": "DomainProfile", "Enabled": 1},
            {"Name": "StandardProfile", "Enabled": 1},
            {"Name": "PublicProfile", "Enabled": 0},
        ],
    }
    native_text = "\n".join([
        "RdpDisabled=0",
        "RdpNlaRequired=0",
        "Smb1ExplicitValue=1",
        "AutoAdminLogonEnabled=1",
        "GuestEnabled=True",
        "MinimumPasswordLength=6",
        "PasswordComplexity=0",
        "LockoutBadCount=0",
        "FirewallProfile=DomainProfile;Enabled=1;DefaultInboundAction=0",
        "FirewallProfile=StandardProfile;Enabled=1;DefaultInboundAction=0",
        "FirewallProfile=PublicProfile;Enabled=0;DefaultInboundAction=0",
    ])
    local_facts = local_security_facts(local_data)
    native_facts = native_security_facts(native_text)
    local_findings = analyze_windows_security_facts(local_facts, registry)
    native_findings = analyze_windows_security_facts(native_facts, registry)
    project = lambda findings: sorted(  # noqa: E731
        (item["finding_id"], item["evidence"]) for item in findings
    )
    assert project(native_findings) == project(local_findings)
    assert {finding_id for finding_id, _evidence in project(native_findings)} == {
        "WIN_BASELINE_RDP_NLA_DISABLED",
        "WIN_BASELINE_SMB1_ENABLED",
        "WIN_BASELINE_AUTOLOGON_ENABLED",
        "WIN_BASELINE_GUEST_ENABLED",
        "WIN_BASELINE_FIREWALL_PROFILE_DISABLED",
        "WIN_BASELINE_PASSWORD_MINIMUM_LENGTH_LOW",
        "WIN_BASELINE_PASSWORD_COMPLEXITY_DISABLED",
        "WIN_BASELINE_ACCOUNT_LOCKOUT_DISABLED",
    }
    for item in native_findings:
        assert item["precheck"]
        assert item["recommendation"]
        assert item["rollback"]
        assert item["verification_checkpoint"]
        assert item["references"]


def test_unknown_and_permission_gap_facts_never_become_a_clean_pass() -> None:
    registry = _registry()
    facts = native_security_facts(
        "COLLECTOR_STATUS=PARTIAL\n"
        "PasswordPolicyStatus=permission_denied_or_unavailable\n"
        "RdpDisabled=UNKNOWN\nSmb1ExplicitValue=UNKNOWN\n"
    )
    assert facts["rdp_enabled"] is None
    assert facts["password_complexity"] is None
    assert analyze_windows_security_facts(facts, registry) == []
    assert analyze_windows_security_facts(local_security_facts({}), registry) == []


def test_offline_bundle_analysis_uses_the_same_windows_security_rules() -> None:
    from analyzers.evidence_analyzer import analyze_evidence
    from analyzers.risk_analyzer import analyze as analyze_local

    registry = _registry()
    local_data = {
        "Rdp": {"Enabled": True, "NlaRequired": False},
        "Smb1": {"Enabled": True},
        "AutoLogon": {"Enabled": True},
        "LocalAccounts": {"GuestEnabled": True},
        "PasswordPolicy": {"Status": "collected", "Values": {
            "MinimumPasswordLength": 6, "PasswordComplexity": 0, "LockoutBadCount": 0,
        }},
        "FirewallProfiles": [{"Name": "PublicProfile", "Enabled": 0}],
    }
    security_text = "\n".join([
        "RdpDisabled=0", "RdpNlaRequired=0", "Smb1ExplicitValue=1",
        "AutoAdminLogonEnabled=1", "GuestEnabled=True",
        "MinimumPasswordLength=6", "PasswordComplexity=0", "LockoutBadCount=0",
        "FirewallProfile=PublicProfile;Enabled=0;DefaultInboundAction=0",
    ]) + "\n"
    service_text = (
        "Name=ExampleService;State=Running;StartMode=Auto;ProcessId=42;"
        "PathName=C:\\Users\\<redacted>\\AppData\\Local\\service.exe\n"
    )
    disk_text = f"Drive=C:;FileSystem=NTFS;SizeBytes={100 * 1024**3};FreeBytes={9 * 1024**3};FreePercent=9\n"
    with tempfile.TemporaryDirectory(prefix="pcit-security-evidence-") as temporary:
        from inspection_cli import _evidence_summary

        root = Path(temporary)
        (root / "security_status.txt").write_text(security_text, encoding="utf-8")
        (root / "services.txt").write_text(service_text, encoding="utf-8")
        (root / "disks.txt").write_text(disk_text, encoding="utf-8")
        manifest = {
            "target": {
                "os_family": "windows", "product": "Windows 11", "version": "10.0.22631",
                "architecture": "x64", "scope": "basic",
            },
            "items": [{
                "path": "security_status.txt", "status": "collected", "exit_code": 0, "reason": "",
            }, {
                "path": "services.txt", "status": "collected", "exit_code": 0, "reason": "",
            }, {
                "path": "disks.txt", "status": "collected", "exit_code": 0, "reason": "",
            }],
        }
        offline = analyze_evidence(root, manifest)
        report_summary = _evidence_summary(root, manifest)
    local = analyze_local(
        {"windows_security": {"status": "ok", "data": local_data},
         "services": {"status": "ok", "data": [{
             "Name": "ExampleService", "State": "Running", "StartMode": "Auto",
             "PathName": r"C:\Users\Example\AppData\Local\service.exe",
         }]},
         "disks": {"status": "ok", "collector": "disks", "data": {"VolumeSummary": [{
             "Drive": "C:", "FileSystem": "NTFS", "Size": 100 * 1024**3,
             "Free": 9 * 1024**3, "FreePercent": 9,
         }]}},
         "network_ports": {"status": "ok", "data": []}},
        registry,
    )
    project = lambda findings: sorted(  # noqa: E731
        (item["finding_id"], item["evidence"]) for item in findings
        if item["rule_id"].startswith("WIN_BASELINE_")
        or item.get("rule_id") in {"WIN_SERVICE_SUSPICIOUS_PATH", "WIN_DISK_LOW_SPACE"}
    )
    assert project(offline.findings) == project(local.findings)
    assert offline.config_evidence["windows_risk_registry"]["status"] == "loaded"
    assert offline.config_evidence["windows_risk_registry"]["sha256"]
    assert offline.status == "PARTIAL"  # Other required evidence is intentionally absent.
    assert "WIN_SERVICE_SUSPICIOUS_PATH" in {item["finding_id"] for item in offline.findings}
    assert "WIN_DISK_LOW_SPACE:C:" in {item["finding_id"] for item in offline.findings}
    assert report_summary["磁盘容量与剩余空间"]["卷数"] == 1
    assert "9.0 GB 可用 / 100.0 GB 总量" in report_summary["磁盘容量与剩余空间"]["卷剩余空间"]
    from reports.unified import render_html, render_csv, render_markdown

    metadata = {"evidence_summary": report_summary, "asset_alias": "test-asset", "bundle_id": "test"}
    html = render_html(offline, metadata)
    csv = render_csv(offline)
    markdown = render_markdown(offline, metadata)
    assert "整改前核查" in html and "回滚" in html and "复查" in html
    assert "密码复杂度" in html
    assert "precheck" in csv and "references" in csv
    assert "整改前核查" in markdown and "资料来源" in markdown
    assert "https" in markdown and "learn" in markdown


def test_native_service_facts_parse_redacted_image_path() -> None:
    from analyzers.windows_security_rules import analyze_windows_service_facts, native_service_facts

    rows = native_service_facts(
        "COLLECTOR_STATUS=PARTIAL\n"
        "Name=ExampleService;State=Running;StartMode=Auto;ProcessId=42;"
        "PathName=C:\\Users\\<redacted>\\AppData\\Local\\service.exe\n"
    )
    assert len(rows) == 1
    assert "<redacted>" in rows[0]["PathName"]
    findings = analyze_windows_service_facts(rows, _registry())
    assert [item["finding_id"] for item in findings] == ["WIN_SERVICE_SUSPICIOUS_PATH"]
    assert findings[0]["evidence"]["services"] == ["ExampleService"]


def test_native_account_and_startup_rules_share_local_analysis_without_arguments() -> None:
    from analyzers.risk_analyzer import analyze as analyze_local

    registry = _registry()
    local_startup = {
        "collector": "startup_items", "status": "ok", "data": {"Items": [{
            "Name": "FixtureStartup",
            "Command": r"powershell.exe -File C:\Users\Alice\AppData\Roaming\agent.ps1 -Token=PRIVATE",
            "Location": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "Scope": "CurrentUser", "SourceType": "RegistryRun",
        }]},
    }
    local_result = analyze_local({
        "users": {"status": "ok", "data": {"Administrators": [{"Name": f"account-{i}"} for i in range(4)]}},
        "startup_items": local_startup,
    }, registry)
    local_findings = [item for item in local_result.findings
                      if item["finding_id"] in {"WIN_ADMINISTRATOR_COUNT_REVIEW", "WIN_STARTUP_SUSPICIOUS_PATH"}]

    admin_count, account_gaps = parse_native_administrator_count("AdministratorMemberCount=4\n")
    startup_rows, startup_gaps = parse_native_startup_facts(
        "Name=FixtureStartup;Location=HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run;"
        "ImagePath=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe;"
        "ScriptPath=C:\\Users\\<redacted>\\AppData\\Roaming\\agent.ps1;"
        "ScriptExtension=.ps1;Scope=CurrentUser;SourceType=Win32_StartupCommand\nRecordCount=1\n"
    )
    assert account_gaps == []
    assert startup_gaps == []
    native_findings = analyze_windows_administrator_count(admin_count, registry)
    native_findings.extend(analyze_windows_startup_facts(startup_rows, registry, collector="native_windows"))
    assert {item["finding_id"] for item in native_findings} == {item["finding_id"] for item in local_findings}
    assert {item["severity"] for item in native_findings} == {item["severity"] for item in local_findings}
    startup_finding = next(item for item in native_findings if item["finding_id"] == "WIN_STARTUP_SUSPICIOUS_PATH")
    encoded = json.dumps(startup_finding["evidence"], ensure_ascii=False)
    assert "<redacted>" in encoded
    assert "PRIVATE" not in encoded and "-Token" not in encoded
    assert startup_finding["precheck"] and startup_finding["rollback"] and startup_finding["verification_checkpoint"]

    unknown_count, unknown_gaps = parse_native_administrator_count("AdministratorMemberCount=UNKNOWN\n")
    assert unknown_count is None and unknown_gaps == ["WINDOWS_ADMINISTRATOR_COUNT_UNKNOWN"]
    _, malformed_startup_gaps = parse_native_startup_facts("RecordCount=1\n")
    assert "WINDOWS_STARTUP_FACTS_MISSING_OR_UNKNOWN" in malformed_startup_gaps


def test_disk_space_analysis_is_shared_and_fails_closed_on_bad_values() -> None:
    registry = _registry()
    gb = 1024 ** 3
    normal_text = f"Drive=C:;FileSystem=NTFS;SizeBytes={100 * gb};FreeBytes={20 * gb};FreePercent=20\n"
    normal_rows, normal_gaps = parse_native_disk_facts(normal_text)
    assert normal_gaps == []
    assert analyze_windows_disk_facts(normal_rows, registry) == []

    low_text = f"Drive=C:;FileSystem=NTFS;SizeBytes={100 * gb};FreeBytes={9 * gb};FreePercent=9\n"
    native_rows, native_gaps = parse_native_disk_facts(low_text)
    local_rows = [{
        "Drive": "C:", "FileSystem": "NTFS", "Size": 100 * gb,
        "Free": 9 * gb, "FreePercent": 9,
    }]
    native_findings = analyze_windows_disk_facts(native_rows, registry)
    local_findings = analyze_windows_disk_facts(local_rows, registry)
    assert native_gaps == []
    assert native_findings == local_findings
    assert len(native_findings) == 1
    assert native_findings[0]["finding_id"] == "WIN_DISK_LOW_SPACE:C:"
    assert native_findings[0]["rule_id"] == "WIN_DISK_LOW_SPACE"
    assert native_findings[0]["severity"] == "Warning"
    assert native_findings[0]["evidence"]["free_gb"] == 9
    assert native_findings[0]["evidence"]["free_percent"] == 9

    bad_rows, bad_gaps = parse_native_disk_facts(
        "Drive=C:;FileSystem=NTFS;SizeBytes=bad;FreeBytes=n/a;FreePercent=120\n"
    )
    assert bad_gaps
    assert analyze_windows_disk_facts(bad_rows, registry) == []
    empty_rows, empty_gaps = parse_native_disk_facts("COLLECTOR_STATUS=PARTIAL\nnot-a-disk-row\n")
    assert empty_rows == []
    assert "WINDOWS_DISK_FACTS_MISSING_OR_UNKNOWN" in empty_gaps


def test_rule_disable_is_respected_by_shared_analyzer() -> None:
    registry = copy.deepcopy(_registry())
    rule = next(item for item in registry["rules"] if item["id"] == "WIN_BASELINE_SMB1_ENABLED")
    rule["enabled"] = False
    findings = analyze_windows_security_facts({"smb1_enabled": True}, registry)
    assert "WIN_BASELINE_SMB1_ENABLED" not in {item["finding_id"] for item in findings}


def test_windows_security_collector_skips_without_windows() -> None:
    original = windows_security.platform.system
    try:
        windows_security.platform.system = lambda: "Linux"
        result = windows_security.collect()
    finally:
        windows_security.platform.system = original
    assert result["status"] == "skipped"
    assert result["data"] == []
    assert result["errors"]


if __name__ == "__main__":
    for test in (
        test_native_and_local_security_facts_share_findings,
        test_unknown_and_permission_gap_facts_never_become_a_clean_pass,
        test_offline_bundle_analysis_uses_the_same_windows_security_rules,
        test_native_service_facts_parse_redacted_image_path,
        test_native_account_and_startup_rules_share_local_analysis_without_arguments,
        test_disk_space_analysis_is_shared_and_fails_closed_on_bad_values,
        test_rule_disable_is_respected_by_shared_analyzer,
        test_windows_security_collector_skips_without_windows,
    ):
        test()
    print("Windows security analysis tests passed.")
