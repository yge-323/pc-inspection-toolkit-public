from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from run_inspection import COLLECTORS, run_collection_pipeline  # noqa: E402


def collector_result(
    name: str,
    data: Any,
    *,
    status: str = "ok",
    errors: list[Any] | None = None,
) -> dict[str, Any]:
    return {
        "collector": name,
        "status": status,
        "timestamp": "mock",
        "data": data,
        "errors": errors or [],
    }


def mock_collector(
    name: str,
    result: dict[str, Any] | None = None,
    *,
    error: Exception | None = None,
    calls: list[str] | None = None,
) -> Callable[[], dict[str, Any]]:
    def collect() -> dict[str, Any]:
        if calls is not None:
            calls.append(name)
        if error is not None:
            raise error
        assert result is not None
        return result

    collect.collector_name = name  # type: ignore[attr-defined]
    return collect


def security_data(
    *,
    installed_programs: list[dict[str, Any]] | None = None,
    drivers: list[dict[str, Any]] | None = None,
    directories: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    installed_programs = installed_programs or []
    drivers = drivers or []
    directories = directories or []
    vendors = sorted({
        str(item["matched_vendor"])
        for item in installed_programs + drivers + directories
        if item.get("matched_vendor")
    })
    return {
        "installed_programs": installed_programs,
        "drivers": drivers,
        "directories": directories,
        "summary": {
            "vendors_detected": vendors,
            "installed_vendor_count": len({
                item["matched_vendor"] for item in installed_programs if item.get("matched_vendor")
            }),
            "driver_count": len(drivers),
            "directory_count": len(directories),
        },
    }


def security_result(
    *,
    status: str = "ok",
    installed_programs: list[dict[str, Any]] | None = None,
    drivers: list[dict[str, Any]] | None = None,
    directories: list[dict[str, Any]] | None = None,
    errors: list[Any] | None = None,
) -> dict[str, Any]:
    return collector_result(
        "security_vendors",
        security_data(
            installed_programs=installed_programs,
            drivers=drivers,
            directories=directories,
        ),
        status=status,
        errors=errors,
    )


def vendor_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in findings
        if str(item.get("finding_id") or "").startswith("WIN_SECURITY_VENDOR_")
    ]


def finding_ids(findings: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("finding_id")) for item in vendor_findings(findings)]


def empty_related_collectors() -> list[Callable[[], dict[str, Any]]]:
    return [
        mock_collector("services", collector_result("services", [])),
        mock_collector("scheduled_tasks", collector_result("scheduled_tasks", [])),
        mock_collector("startup_items", collector_result("startup_items", {"Items": []})),
    ]


def test_security_vendors_is_registered_and_passed_to_analyzer() -> None:
    names = [collector.__module__.rsplit(".", 1)[-1] for collector in COLLECTORS]
    assert "security_vendors" in names, names
    assert names.index("startup_items") < names.index("security_vendors") < names.index("event_logs"), names

    captured: dict[str, Any] = {}

    def analyzer(results: dict[str, Any]) -> list[dict[str, Any]]:
        captured.update(results)
        from analyzers.risk_analyzer import analyze
        from rules.loader import load_rules

        registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
        return analyze(results, registry)

    installed = [{
        "display_name": "360安全卫士",
        "matched_vendor": "360",
        "matched_keyword": "360安全卫士",
        "source_type": "installed_program",
    }]
    collectors = empty_related_collectors() + [
        mock_collector("security_vendors", security_result(installed_programs=installed)),
    ]
    results, findings = run_collection_pipeline(collectors, analyzer=analyzer)
    assert "security_vendors" in results, results
    assert "security_vendors" in captured, captured
    assert finding_ids(findings) == ["WIN_SECURITY_VENDOR_PRESENT"], findings


def test_partial_security_vendor_result_keeps_data_and_errors() -> None:
    installed = [{
        "display_name": "火绒安全软件",
        "matched_vendor": "Huorong",
        "matched_keyword": "火绒",
        "source_type": "installed_program",
    }]
    error = {"source": "drivers", "status": "need_admin", "message": "access denied"}
    collectors = empty_related_collectors() + [
        mock_collector(
            "security_vendors",
            security_result(status="partial", installed_programs=installed, errors=[error]),
        ),
    ]
    results, findings = run_collection_pipeline(collectors)
    assert results["security_vendors"]["status"] == "partial", results
    assert results["security_vendors"]["errors"] == [error], results
    assert finding_ids(findings) == ["WIN_SECURITY_VENDOR_PRESENT"], findings


def test_failed_security_vendor_result_does_not_stop_other_collectors() -> None:
    calls: list[str] = []
    collectors = [
        mock_collector(
            "security_vendors",
            security_result(status="failed", errors=[{"source": "collector", "status": "failed", "message": "mock"}]),
            calls=calls,
        ),
        mock_collector("system_info", collector_result("system_info", {"OS": "Mock Windows"}), calls=calls),
    ]
    results, findings = run_collection_pipeline(collectors)
    assert calls == ["security_vendors", "system_info"], calls
    assert results["security_vendors"]["status"] == "failed", results
    assert results["system_info"]["status"] == "ok", results
    assert vendor_findings(findings) == [], findings


def test_service_residue_uses_shared_vendor_matcher() -> None:
    services = collector_result("services", [{
        "name": "360Safe",
        "display_name": "360 安全防护服务",
        "status": "Running",
        "binary_path": "C:\\Program Files (x86)\\360\\360Safe\\360Safe.exe",
    }])
    collectors = [
        mock_collector("services", services),
        mock_collector("security_vendors", security_result()),
    ]
    _, findings = run_collection_pipeline(collectors)
    assert finding_ids(findings) == ["WIN_SECURITY_VENDOR_RESIDUE"], findings


def test_running_service_is_present_when_installed_inventory_is_unavailable() -> None:
    services = collector_result("services", [{
        "name": "360Safe",
        "display_name": "360 安全防护服务",
        "status": "Running",
        "binary_path": "C:\\Program Files (x86)\\360\\360Safe\\360Safe.exe",
    }])
    collectors = [
        mock_collector("services", services),
        mock_collector("security_vendors", security_result(status="failed", errors=["mock inventory failure"])),
    ]
    _, findings = run_collection_pipeline(collectors)
    assert finding_ids(findings) == ["WIN_SECURITY_VENDOR_PRESENT"], findings
    evidence = vendor_findings(findings)[0]["evidence"]
    assert evidence["source_type"] == "service", evidence
    assert evidence["status"] == "Running", evidence


def test_tasks_and_startup_items_use_shared_vendor_matcher() -> None:
    tasks = collector_result("scheduled_tasks", [{
        "task_name": "Huorong Update",
        "task_path": "\\Huorong\\",
        "command": "C:\\Program Files\\Huorong\\update.exe",
        "arguments": "--scheduled",
    }])
    startup = collector_result("startup_items", {"Items": [{
        "name": "QQPCMgr",
        "command": "C:\\Program Files\\Tencent\\QQPCMgr\\QQPCTray.exe",
        "location": "MockStartup",
    }]})
    collectors = [
        mock_collector("scheduled_tasks", tasks),
        mock_collector("startup_items", startup),
        mock_collector("security_vendors", security_result()),
    ]
    _, findings = run_collection_pipeline(collectors)
    residues = [
        item
        for item in vendor_findings(findings)
        if item["finding_id"] == "WIN_SECURITY_VENDOR_RESIDUE"
    ]
    assert len(residues) == 2, findings
    assert {item["evidence"]["vendor"] for item in residues} == {
        "Huorong",
        "Tencent PC Manager",
    }, residues


def test_installed_vendor_with_driver_is_present_and_driver_review_not_residue() -> None:
    installed = [{
        "display_name": "360安全卫士",
        "matched_vendor": "360",
        "matched_keyword": "360安全卫士",
        "source_type": "installed_program",
    }]
    drivers = [{
        "name": "360FsFlt",
        "display_name": "360 File Filter",
        "path_name": "C:\\Windows\\System32\\drivers\\360FsFlt.sys",
        "matched_vendor": "360",
        "matched_keyword": "360fsflt",
        "source_type": "driver",
    }]
    collectors = empty_related_collectors() + [
        mock_collector("security_vendors", security_result(installed_programs=installed, drivers=drivers)),
    ]
    _, findings = run_collection_pipeline(collectors)
    ids = finding_ids(findings)
    assert ids.count("WIN_SECURITY_VENDOR_PRESENT") == 1, findings
    assert ids.count("WIN_SECURITY_VENDOR_DRIVER_REVIEW") == 1, findings
    assert "WIN_SECURITY_VENDOR_RESIDUE" not in ids, findings


def test_directory_only_does_not_generate_vendor_warning() -> None:
    directories = [{
        "path": "C:\\ProgramData\\360",
        "exists": True,
        "matched_vendor": "360",
        "matched_keyword": "360",
        "source_type": "directory",
    }]
    _, findings = run_collection_pipeline([
        mock_collector("security_vendors", security_result(directories=directories)),
    ])
    assert vendor_findings(findings) == [], findings


def test_multiple_vendors_are_deduplicated_per_finding_type() -> None:
    installed = [
        {"display_name": "360安全卫士", "matched_vendor": "360", "matched_keyword": "360"},
        {"display_name": "360安全浏览器", "matched_vendor": "360", "matched_keyword": "360"},
        {"display_name": "火绒安全软件", "matched_vendor": "Huorong", "matched_keyword": "火绒"},
        {
            "display_name": "腾讯电脑管家",
            "matched_vendor": "Tencent PC Manager",
            "matched_keyword": "腾讯电脑管家",
        },
    ]
    _, findings = run_collection_pipeline([
        mock_collector("security_vendors", security_result(installed_programs=installed)),
    ])
    present = [item for item in vendor_findings(findings) if item["finding_id"] == "WIN_SECURITY_VENDOR_PRESENT"]
    assert len(present) == 3, present
    assert {item["evidence"]["vendor"] for item in present} == {
        "360",
        "Huorong",
        "Tencent PC Manager",
    }, present


def test_other_collector_exception_is_isolated() -> None:
    installed = [{
        "display_name": "360安全卫士",
        "matched_vendor": "360",
        "matched_keyword": "360",
    }]
    collectors = [
        mock_collector("services", error=RuntimeError("mock service failure")),
        mock_collector("security_vendors", security_result(installed_programs=installed)),
    ]
    with patch("run_inspection.logging.exception") as logged_exception:
        results, findings = run_collection_pipeline(collectors)
    assert results["services"]["status"] == "failed", results
    assert results["services"]["errors"] == ["mock service failure"], results
    assert finding_ids(findings) == ["WIN_SECURITY_VENDOR_PRESENT"], findings
    logged_exception.assert_called_once()


def test_unrelated_360_numeric_fields_do_not_match_service() -> None:
    services = collector_result("services", [{"port": 360, "version": 3.60}])
    _, findings = run_collection_pipeline([
        mock_collector("services", services),
        mock_collector("security_vendors", security_result()),
    ])
    assert vendor_findings(findings) == [], findings


def test_skipped_security_vendor_result_does_not_fail_pipeline() -> None:
    calls: list[str] = []
    collectors = [
        mock_collector(
            "security_vendors",
            security_result(status="skipped", errors=["non-Windows"]),
            calls=calls,
        ),
        mock_collector("system_info", collector_result("system_info", {"OS": "Mock"}), calls=calls),
    ]
    results, findings = run_collection_pipeline(collectors)
    assert calls == ["security_vendors", "system_info"], calls
    assert results["security_vendors"]["status"] == "skipped", results
    assert results["system_info"]["status"] == "ok", results
    assert vendor_findings(findings) == [], findings


def main() -> int:
    test_security_vendors_is_registered_and_passed_to_analyzer()
    test_partial_security_vendor_result_keeps_data_and_errors()
    test_failed_security_vendor_result_does_not_stop_other_collectors()
    test_service_residue_uses_shared_vendor_matcher()
    test_running_service_is_present_when_installed_inventory_is_unavailable()
    test_tasks_and_startup_items_use_shared_vendor_matcher()
    test_installed_vendor_with_driver_is_present_and_driver_review_not_residue()
    test_directory_only_does_not_generate_vendor_warning()
    test_multiple_vendors_are_deduplicated_per_finding_type()
    test_other_collector_exception_is_isolated()
    test_unrelated_360_numeric_fields_do_not_match_service()
    test_skipped_security_vendor_result_does_not_fail_pipeline()
    print("Run inspection security vendor mock tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
