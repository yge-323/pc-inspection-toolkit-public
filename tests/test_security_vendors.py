from __future__ import annotations

import sys
from pathlib import Path, PureWindowsPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.risk_analyzer import analyze as analyze_with_registry  # noqa: E402
from collectors.security_vendors import (  # noqa: E402
    build_summary,
    collect as collect_with_registry,
    collect_directories as collect_directories_with_registry,
    collect_installed_programs as collect_installed_programs_with_registry,
    match_vendor as match_vendor_with_registry,
    normalize_drivers as normalize_drivers_with_registry,
    normalize_installed_programs as normalize_installed_programs_with_registry,
)
from rules.loader import load_rules  # noqa: E402


REGISTRY = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
VENDOR_PATTERNS = REGISTRY["vendor_patterns"]
VENDOR_DIRECTORY_CANDIDATES = {
    vendor: tuple(pattern.get("directory_candidates", []))
    for vendor, pattern in VENDOR_PATTERNS.items()
}


def analyze(results: dict[str, Any]):
    return analyze_with_registry(results, REGISTRY)


def collect(*args: Any, **kwargs: Any):
    return collect_with_registry(VENDOR_PATTERNS, *args, **kwargs)


def collect_installed_programs(*args: Any, **kwargs: Any):
    return collect_installed_programs_with_registry(VENDOR_PATTERNS, *args, **kwargs)


def match_vendor(fields: Any, allowed_fields: Any):
    return match_vendor_with_registry(fields, allowed_fields, VENDOR_PATTERNS)


def normalize_drivers(raw: Any):
    return normalize_drivers_with_registry(raw, VENDOR_PATTERNS)


def normalize_installed_programs(raw: Any):
    return normalize_installed_programs_with_registry(raw, VENDOR_PATTERNS)


def security_vendors_result(
    *,
    installed_programs: list[dict[str, Any]] | None = None,
    drivers: list[dict[str, Any]] | None = None,
    directories: list[dict[str, Any]] | None = None,
    include_optional: bool = True,
    status: str = "ok",
    errors: list[str] | None = None,
) -> dict[str, Any]:
    installed_programs = installed_programs or []
    drivers = drivers or []
    directories = directories or []
    data: dict[str, Any] = {
        "installed_programs": installed_programs,
        "drivers": drivers,
        "directories": directories,
        "summary": {
            "vendors_detected": sorted({
                str(item.get("matched_vendor"))
                for item in installed_programs + drivers + directories
                if item.get("matched_vendor")
            }),
            "installed_vendor_count": len({
                item.get("matched_vendor") for item in installed_programs if item.get("matched_vendor")
            }),
            "driver_count": len(drivers),
            "directory_count": len(directories),
        },
    }
    if include_optional:
        data["browser_related"] = []
        data["security_status"] = {}
    return {
        "collector": "security_vendors",
        "status": status,
        "data": data,
        "errors": errors or [],
    }


def security_findings(results: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in analyze(results)
        if str(item.get("finding_id") or "").startswith("WIN_SECURITY_VENDOR_")
    ]


def findings_by_id(findings: list[dict[str, Any]], finding_id: str) -> list[dict[str, Any]]:
    return [item for item in findings if item.get("finding_id") == finding_id]


def assert_standard_vendor_finding(
    finding: dict[str, Any],
    *,
    finding_id: str,
    title: str,
    severity: str,
) -> None:
    expected_descriptions = {
        "WIN_SECURITY_VENDOR_PRESENT": "检测到相关安全软件或电脑管家组件，存在不等于恶意，需要确认是否为用户主动安装以及是否与其他安全软件冲突。",
        "WIN_SECURITY_VENDOR_RESIDUE": "卸载项中未发现对应产品，但仍存在服务、驱动、计划任务、启动项等残留线索，需要人工确认。",
        "WIN_SECURITY_VENDOR_DRIVER_REVIEW": "检测到安全软件相关驱动或驱动残留，驱动存在不等于异常，不建议自动删除，需要确认签名、状态、启动类型和文件路径。",
    }
    assert finding["finding_id"] == finding_id, finding
    assert finding["title"] == title, finding
    assert finding["severity"] == severity, finding
    assert finding["category"] == "Security Software", finding
    assert finding["component"] == "security_vendors", finding
    assert finding["description"] == expected_descriptions[finding_id], finding
    assert finding["needs_human_review"] is True, finding
    assert finding["severity"] != "Critical", finding


def test_security_vendor_collector_output_contract() -> None:
    def runner(script: str, *, timeout: int) -> Any:
        del timeout
        if "Win32_SystemDriver" in script:
            return []
        return {"Items": [], "Errors": [], "SuccessfulSources": 3}

    result = collect(
        powershell_runner=runner,
        path_exists=lambda path: False,
        environ={},
        system_name="Windows",
    )
    assert {"status", "data", "errors"} <= result.keys(), result
    assert {"installed_programs", "drivers", "directories", "summary"} <= result["data"].keys(), result
    assert {
        "vendors_detected",
        "installed_vendor_count",
        "driver_count",
        "directory_count",
    } <= result["data"]["summary"].keys(), result
    assert result["data"].get("browser_related", []) == [], result
    assert result["data"].get("security_status", {}) == {}, result


def test_vendor_policy_is_injected_from_registry_without_private_machine_values() -> None:
    source = (ROOT / "collectors" / "security_vendors.py").read_text(encoding="utf-8")
    assert "VENDOR_PATTERNS" not in source
    assert "VENDOR_DIRECTORY_CANDIDATES" not in source
    serialized = str(VENDOR_PATTERNS).casefold()
    for private_value in ("rog", "codexadmin", "googleuserpeh"):
        assert private_value not in serialized, private_value
    match = match_vendor({"display_name": "火绒安全软件"}, ["display_name"])
    assert match == {"matched_vendor": "Huorong", "matched_keyword": "火绒"}, match

    optional_omitted = security_vendors_result(include_optional=False)
    assert security_findings({"security_vendors": optional_omitted}) == []


def test_match_vendor_recognizes_first_version_patterns() -> None:
    cases = [
        ({"display_name": "360安全卫士"}, "360"),
        ({"publisher": "Qihoo Technology"}, "360"),
        ({"display_name": "火绒安全软件"}, "Huorong"),
        ({"name": "QQPCMgr"}, "Tencent PC Manager"),
        ({"publisher": "Kingsoft Corporation"}, "Kingsoft"),
        ({"display_name": "Ludashi"}, "Ludashi"),
        ({"display_name": "2345安全卫士"}, "2345"),
        ({"display_name": "Lenovo PC Manager"}, "Lenovo PC Manager"),
        ({"display_name": "DriverGenius"}, "DriverGenius"),
        ({"display_name": "DriverTalent"}, "DriverTalent"),
    ]
    allowed_fields = ["display_name", "publisher", "name"]
    for fields, expected_vendor in cases:
        match = match_vendor(fields, allowed_fields)
        assert match is not None, fields
        assert match["matched_vendor"] == expected_vendor, (fields, match)


def test_match_vendor_ignores_unrelated_numeric_fields() -> None:
    fields = {
        "port": 360,
        "size": 360,
        "version": "3.60",
        "filename": "report360.txt",
    }
    assert match_vendor(fields, ["display_name", "publisher", "install_location"]) is None
    assert match_vendor(fields, ["port", "size", "version"]) is None


def test_installed_program_normalization_adds_vendor_annotation() -> None:
    raw = [{
        "DisplayName": "360安全卫士",
        "DisplayVersion": "14.0",
        "Publisher": "北京奇虎科技有限公司",
        "InstallLocation": "C:\\Program Files (x86)\\360\\360Safe",
        "UninstallString": "C:\\Program Files (x86)\\360\\uninstall.exe",
        "QuietUninstallString": "",
        "RegistrySource": "HKLM32",
    }]
    items = normalize_installed_programs(raw)
    assert len(items) == 1, items
    assert items[0] == {
        "display_name": "360安全卫士",
        "display_version": "14.0",
        "publisher": "北京奇虎科技有限公司",
        "install_location": "C:\\Program Files (x86)\\360\\360Safe",
        "uninstall_string": None,
        "quiet_uninstall_string": None,
        "registry_source": "HKLM32",
        "matched_vendor": "360",
        "matched_keyword": "360安全卫士",
        "source_type": "installed_program",
    }, items[0]


def test_driver_normalization_matches_vendor_from_path() -> None:
    items = normalize_drivers([{
        "Name": "FileFilter",
        "DisplayName": "File Filter Driver",
        "State": "Running",
        "StartMode": "System",
        "PathName": "C:\\Windows\\System32\\drivers\\360FsFlt.sys",
        "ServiceType": "Kernel Driver",
    }])
    assert len(items) == 1, items
    assert items[0]["matched_vendor"] == "360", items[0]
    assert items[0]["matched_keyword"] == "360fsflt", items[0]
    assert items[0]["source_type"] == "driver", items[0]


def test_directory_collection_checks_only_known_candidates() -> None:
    checked: list[str] = []
    existing = "C:\\ProgramData\\360"

    def fake_exists(path: Path) -> bool:
        # Model the target's Windows path semantics even when this test runs on POSIX.
        windows_path = PureWindowsPath(str(path))
        checked.append(str(windows_path))
        return windows_path == PureWindowsPath(existing)

    result = collect(
        powershell_runner=lambda script, timeout: (
            [] if "Win32_SystemDriver" in script else {"Items": [], "Errors": [], "SuccessfulSources": 3}
        ),
        path_exists=fake_exists,
        environ={"ProgramData": "C:\\ProgramData"},
        system_name="Windows",
    )
    directory_items = result["data"]["directories"]
    assert len(directory_items) == 1, directory_items
    assert PureWindowsPath(directory_items[0]["path"]) == PureWindowsPath(existing), directory_items
    assert directory_items[0] == {
        "path": directory_items[0]["path"],
        "exists": True,
        "matched_vendor": "360",
        "matched_keyword": "360",
        "source_type": "directory",
    }, result
    assert len(checked) == sum(len(paths) for paths in VENDOR_DIRECTORY_CANDIDATES.values()), checked
    assert all("*" not in path for path in checked), checked
    assert all("/" not in path for path in checked), checked


def test_directory_collection_rejects_unsafe_candidates_before_path_access() -> None:
    checked: list[Path] = []

    def fake_exists(path: Path) -> bool:
        checked.append(path)
        raise AssertionError("unsafe path must not be checked")

    patterns = {
        "PrivateVendor": {
            "keywords": ["private"],
            "directory_candidates": [r"C:\Users\Private", r"..\Secret", r"\\server\share"],
        }
    }
    result = collect_directories_with_registry(
        patterns,
        path_exists=fake_exists,
        environ={"ProgramData": r"C:\ProgramData"},
    )
    assert checked == []
    assert result["items"] == []
    assert result["status"] == "failed"
    assert len(result["errors"]) == 3
    assert all("Private" not in item["message"] for item in result["errors"])


def test_driver_failure_returns_partial_data_and_structured_error() -> None:
    def runner(script: str, *, timeout: int) -> Any:
        assert timeout > 0
        if "Win32_SystemDriver" in script:
            raise RuntimeError("driver query failed")
        return {
            "Items": [{
                "DisplayName": "火绒安全软件",
                "Publisher": "Huorong",
                "RegistrySource": "HKLM64",
            }],
            "Errors": [],
            "SuccessfulSources": 3,
        }

    result = collect(
        powershell_runner=runner,
        path_exists=lambda path: False,
        environ={},
        system_name="Windows",
    )
    assert result["status"] == "partial", result
    assert len(result["data"]["installed_programs"]) == 1, result
    assert result["data"]["drivers"] == [], result
    assert result["errors"] == [{
        "source": "drivers",
        "status": "failed",
        "message": "driver query failed",
    }], result


def test_installed_program_source_failure_keeps_other_source_results() -> None:
    def runner(script: str, *, timeout: int) -> Any:
        assert "CurrentVersion\\Uninstall" in script
        assert timeout == 10
        return {
            "Items": [{
                "DisplayName": "360安全卫士",
                "Publisher": "Qihoo",
                "RegistrySource": "HKLM32",
            }],
            "Errors": [{
                "source": "installed_programs",
                "status": "failed",
                "message": "HKCU: query failed",
            }],
            "SuccessfulSources": 2,
        }

    result = collect_installed_programs(powershell_runner=runner)
    assert result["status"] == "partial", result
    assert len(result["items"]) == 1, result
    assert result["items"][0]["matched_vendor"] == "360", result
    assert result["errors"] == [{
        "source": "installed_programs",
        "status": "failed",
        "message": "HKCU: query failed",
    }], result


def test_driver_need_admin_is_partial_and_not_security_severity() -> None:
    def runner(script: str, *, timeout: int) -> Any:
        del timeout
        if "Win32_SystemDriver" in script:
            raise PermissionError("Access is denied while querying system drivers")
        return {"Items": [], "Errors": [], "SuccessfulSources": 3}

    result = collect(
        powershell_runner=runner,
        path_exists=lambda path: False,
        environ={},
        system_name="Windows",
    )
    assert result["status"] == "partial", result
    assert result["errors"][0]["source"] == "drivers", result
    assert result["errors"][0]["status"] == "need_admin", result
    assert all(error.get("status") != "Critical" for error in result["errors"]), result


def test_clean_collector_result_is_ok_with_zero_summary() -> None:
    calls: list[tuple[str, int]] = []

    def runner(script: str, *, timeout: int) -> Any:
        calls.append((script, timeout))
        if "Win32_SystemDriver" in script:
            return []
        return {"Items": [], "Errors": [], "SuccessfulSources": 3}

    result = collect(
        powershell_runner=runner,
        path_exists=lambda path: False,
        environ={},
        system_name="Windows",
    )
    assert result["status"] == "ok", result
    assert result["errors"] == [], result
    assert result["data"] == {
        "installed_programs": [],
        "drivers": [],
        "directories": [],
        "summary": {
            "vendors_detected": [],
            "installed_vendor_count": 0,
            "driver_count": 0,
            "directory_count": 0,
        },
    }, result
    assert len(calls) == 2, calls
    assert [timeout for _, timeout in calls] == [10, 15], calls


def test_summary_deduplicates_vendors_and_counts_items() -> None:
    summary = build_summary({
        "installed_programs": [
            {"matched_vendor": "360"},
            {"matched_vendor": "360"},
            {"matched_vendor": "Huorong"},
        ],
        "drivers": [
            {"matched_vendor": "360"},
            {"matched_vendor": "Tencent PC Manager"},
        ],
        "directories": [
            {"matched_vendor": "360"},
            {"matched_vendor": "Huorong"},
        ],
    })
    assert summary == {
        "vendors_detected": ["360", "Huorong", "Tencent PC Manager"],
        "installed_vendor_count": 2,
        "driver_count": 2,
        "directory_count": 2,
    }, summary


def test_installed_360_generates_present_attention() -> None:
    result = security_vendors_result(installed_programs=[{
        "display_name": "360安全卫士",
        "publisher": "北京奇虎科技有限公司",
        "install_location": "C:\\Program Files (x86)\\360\\360Safe",
        "matched_vendor": "360",
        "matched_keyword": "360",
    }])
    findings = security_findings({"security_vendors": result})
    present = findings_by_id(findings, "WIN_SECURITY_VENDOR_PRESENT")
    assert len(present) == 1, findings
    assert_standard_vendor_finding(
        present[0],
        finding_id="WIN_SECURITY_VENDOR_PRESENT",
        title="检测到安全软件或电脑管家组件",
        severity="Attention",
    )
    evidence = present[0]["evidence"]
    assert evidence["vendor"] == "360", evidence
    assert evidence["display_name"] == "360安全卫士", evidence
    assert evidence["source_type"] == "installed_program", evidence
    assert evidence["matched_keyword"] == "360", evidence
    assert evidence["uninstall_present"] is True, evidence
    assert evidence["driver_present"] is False, evidence
    assert evidence["related_item_count"] == 1, evidence


def test_installed_huorong_is_attention_not_residue_or_critical() -> None:
    result = security_vendors_result(installed_programs=[{
        "display_name": "火绒安全软件",
        "publisher": "Huorong",
        "matched_vendor": "Huorong",
        "matched_keyword": "火绒",
    }])
    findings = security_findings({"security_vendors": result})
    present = findings_by_id(findings, "WIN_SECURITY_VENDOR_PRESENT")
    assert len(present) == 1, findings
    assert_standard_vendor_finding(
        present[0],
        finding_id="WIN_SECURITY_VENDOR_PRESENT",
        title="检测到安全软件或电脑管家组件",
        severity="Attention",
    )
    assert not findings_by_id(findings, "WIN_SECURITY_VENDOR_RESIDUE"), findings
    assert all(item["severity"] != "Critical" for item in findings), findings


def test_microsoft_pc_manager_uses_precise_product_name_match() -> None:
    items = normalize_installed_programs([
        {
            "DisplayName": "Microsoft PC Manager",
            "Publisher": "Microsoft Corporation",
            "InstallLocation": "C:\\Program Files\\Microsoft PC Manager",
        },
        {
            "DisplayName": "Microsoft Visual C++ Redistributable",
            "Publisher": "Microsoft Corporation",
            "InstallLocation": "C:\\Program Files\\Microsoft Visual Studio",
        },
    ])

    assert len(items) == 1, items
    assert items[0]["matched_vendor"] == "Microsoft PC Manager", items[0]
    findings = security_findings({"security_vendors": security_vendors_result(installed_programs=items)})
    present = findings_by_id(findings, "WIN_SECURITY_VENDOR_PRESENT")
    assert len(present) == 1, findings
    assert present[0]["severity"] == "Attention", present[0]


def test_service_without_uninstall_generates_residue_only() -> None:
    result = security_vendors_result()
    services = {
        "collector": "services",
        "status": "ok",
        "data": [{
            "name": "360Safe",
            "display_name": "360 安全防护服务",
            "status": "Running",
            "binary_path": "C:\\Program Files (x86)\\360\\360Safe\\360Safe.exe",
        }],
        "errors": [],
    }
    findings = security_findings({"security_vendors": result, "services": services})
    residue = findings_by_id(findings, "WIN_SECURITY_VENDOR_RESIDUE")
    assert len(residue) == 1, findings
    assert_standard_vendor_finding(
        residue[0],
        finding_id="WIN_SECURITY_VENDOR_RESIDUE",
        title="检测到安全软件卸载残留",
        severity="Warning",
    )
    assert residue[0]["evidence"]["source_type"] == "service", residue[0]
    assert residue[0]["evidence"]["uninstall_present"] is False, residue[0]
    for field in ("precheck", "recommendation", "rollback", "verification_checkpoint", "references"):
        assert residue[0].get(field), (field, residue[0])
    assert "厂商发布" in residue[0]["recommendation"]
    assert "不手工回填" in residue[0]["rollback"]
    assert not findings_by_id(findings, "WIN_SECURITY_VENDOR_PRESENT"), findings


def test_safe_startup_script_path_remains_available_for_vendor_matching() -> None:
    startup_items = {
        "collector": "startup_items",
        "status": "ok",
        "data": {
            "Items": [{
                "Name": "FixtureUpdater",
                "Command": "powershell.exe",
                "ImagePath": "powershell.exe",
                "ScriptPath": r"C:\Program Files (x86)\360\Agent\updater.ps1",
                "ScriptExtension": ".ps1",
                "Location": r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                "Scope": "LocalMachine",
                "SourceType": "RegistryRun",
                "ArgumentsOmitted": True,
            }],
            "Errors": [],
            "ArgumentsAndUserNames": "OMITTED_FOR_PRIVACY",
        },
        "errors": [],
    }
    findings = security_findings({
        "security_vendors": security_vendors_result(),
        "startup_items": startup_items,
    })
    residue = findings_by_id(findings, "WIN_SECURITY_VENDOR_RESIDUE")
    assert len(residue) == 1, findings
    assert residue[0]["evidence"]["source_type"] == "startup_item"
    assert residue[0]["evidence"]["path"] == r"C:\Program Files (x86)\360\Agent\updater.ps1"


def test_driver_without_uninstall_generates_residue_and_driver_review() -> None:
    result = security_vendors_result(drivers=[{
        "name": "360FsFlt",
        "display_name": "360 File Filter",
        "state": "Running",
        "start_mode": "System",
        "path_name": "C:\\Windows\\System32\\drivers\\360FsFlt.sys",
        "matched_vendor": "360",
        "matched_keyword": "360",
    }])
    findings = security_findings({"security_vendors": result})
    residue = findings_by_id(findings, "WIN_SECURITY_VENDOR_RESIDUE")
    driver = findings_by_id(findings, "WIN_SECURITY_VENDOR_DRIVER_REVIEW")
    assert len(residue) == 1, findings
    assert len(driver) == 1, findings
    assert_standard_vendor_finding(
        residue[0],
        finding_id="WIN_SECURITY_VENDOR_RESIDUE",
        title="检测到安全软件卸载残留",
        severity="Warning",
    )
    assert_standard_vendor_finding(
        driver[0],
        finding_id="WIN_SECURITY_VENDOR_DRIVER_REVIEW",
        title="检测到安全软件相关驱动",
        severity="Warning",
    )
    evidence = driver[0]["evidence"]
    assert evidence["vendor"] == "360", evidence
    assert evidence["name"] == "360FsFlt", evidence
    assert evidence["source_type"] == "driver", evidence
    assert evidence["driver_present"] is True, evidence
    assert evidence["start_type"] == "System", evidence


def test_directory_only_does_not_generate_warning() -> None:
    result = security_vendors_result(directories=[{
        "path": "C:\\ProgramData\\360",
        "exists": True,
        "matched_vendor": "360",
        "matched_keyword": "360",
        "source_type": "directory",
    }])
    findings = security_findings({"security_vendors": result})
    assert findings == [], findings


def test_clean_system_does_not_generate_security_vendor_finding() -> None:
    findings = security_findings({"security_vendors": security_vendors_result()})
    assert findings == [], findings


def test_missing_fields_do_not_raise_or_generate() -> None:
    inputs = [
        {},
        {"security_vendors": {}},
        {"security_vendors": {"status": "ok", "errors": []}},
        {"security_vendors": {"status": "ok", "data": {}, "errors": []}},
    ]
    for results in inputs:
        assert security_findings(results) == [], results


def test_unrelated_number_360_does_not_match_vendor() -> None:
    result = {
        "collector": "security_vendors",
        "status": "ok",
        "data": {
            "installed_programs": [{
                "port": 360,
                "version": 3.60,
                "disk_size_gb": 360,
                "filename": "report360.txt",
            }],
            "drivers": [],
            "directories": [],
            "summary": {},
        },
        "errors": [],
    }
    assert security_findings({"security_vendors": result}) == []


def test_multiple_vendors_generate_at_most_one_present_each() -> None:
    result = security_vendors_result(installed_programs=[
        {"display_name": "360安全卫士", "matched_vendor": "360", "matched_keyword": "360"},
        {"display_name": "360安全浏览器", "matched_vendor": "360", "matched_keyword": "360"},
        {"display_name": "火绒安全软件", "matched_vendor": "Huorong", "matched_keyword": "火绒"},
        {
            "display_name": "腾讯电脑管家",
            "matched_vendor": "Tencent PC Manager",
            "matched_keyword": "腾讯电脑管家",
        },
    ])
    findings = security_findings({"security_vendors": result})
    present = findings_by_id(findings, "WIN_SECURITY_VENDOR_PRESENT")
    assert len(present) == 3, findings
    assert {item["evidence"]["vendor"] for item in present} == {
        "360",
        "Huorong",
        "Tencent PC Manager",
    }, present
    assert all(item["severity"] == "Attention" for item in present), present


def test_need_admin_does_not_block_or_become_critical() -> None:
    result = security_vendors_result(
        status="need_admin",
        errors=["driver query access denied"],
    )
    findings = security_findings({"security_vendors": result})
    assert findings == [], findings
    assert not any(item.get("severity") == "Critical" for item in analyze({"security_vendors": result}))


def main() -> int:
    test_security_vendor_collector_output_contract()
    test_vendor_policy_is_injected_from_registry_without_private_machine_values()
    test_match_vendor_recognizes_first_version_patterns()
    test_match_vendor_ignores_unrelated_numeric_fields()
    test_installed_program_normalization_adds_vendor_annotation()
    test_driver_normalization_matches_vendor_from_path()
    test_directory_collection_checks_only_known_candidates()
    test_directory_collection_rejects_unsafe_candidates_before_path_access()
    test_driver_failure_returns_partial_data_and_structured_error()
    test_installed_program_source_failure_keeps_other_source_results()
    test_driver_need_admin_is_partial_and_not_security_severity()
    test_clean_collector_result_is_ok_with_zero_summary()
    test_summary_deduplicates_vendors_and_counts_items()
    test_installed_360_generates_present_attention()
    test_installed_huorong_is_attention_not_residue_or_critical()
    test_microsoft_pc_manager_uses_precise_product_name_match()
    test_service_without_uninstall_generates_residue_only()
    test_driver_without_uninstall_generates_residue_and_driver_review()
    test_directory_only_does_not_generate_warning()
    test_clean_system_does_not_generate_security_vendor_finding()
    test_missing_fields_do_not_raise_or_generate()
    test_unrelated_number_360_does_not_match_vendor()
    test_multiple_vendors_generate_at_most_one_present_each()
    test_need_admin_does_not_block_or_become_critical()
    print("Security vendor mock tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
