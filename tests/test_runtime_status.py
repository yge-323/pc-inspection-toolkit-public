from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.risk_analyzer import analyze  # noqa: E402
from models.analysis import AnalysisResult  # noqa: E402
from reports.markdown_report import render_report  # noqa: E402
from rules.loader import RuleResolution, load_rules  # noqa: E402
from run_inspection import analysis_exit_code, run_collection_pipeline  # noqa: E402


def registry() -> dict:
    return copy.deepcopy(load_rules(ROOT / "rules" / "windows_risk_rules.example.json"))


def collector_result() -> dict:
    return {
        "collector": "system_info",
        "status": "ok",
        "timestamp": "mock",
        "data": {"hostname": "mock-host", "os": "Mock OS"},
        "errors": [],
    }


def test_analysis_result_ok_partial_failed_and_exit_codes() -> None:
    ok = analyze({}, registry())
    partial = analyze({"system_info": collector_result()}, None, errors=["mock config failure"])
    failed = analyze({}, None, errors=["mock config failure"])
    assert ok.status == "OK"
    assert partial.status == "PARTIAL"
    assert failed.status == "FAILED"
    assert analysis_exit_code(ok) == 0
    assert analysis_exit_code(partial) == 4
    assert analysis_exit_code(failed) == 4

    for item in (ok, partial, failed):
        try:
            bool(item)
        except TypeError as exc:
            assert "truthiness is ambiguous" in str(exc)
        else:
            raise AssertionError("AnalysisResult truthiness must be rejected")


def test_adjustable_policy_is_not_duplicated_in_analyzer_or_vendor_collector() -> None:
    analyzer_source = (ROOT / "analyzers" / "risk_analyzer.py").read_text(encoding="utf-8")
    vendor_source = (ROOT / "collectors" / "security_vendors.py").read_text(encoding="utf-8")
    for value in ("LOW_SPACE_PERCENT_THRESHOLD", "LOW_SPACE_GB_THRESHOLD"):
        assert value not in analyzer_source
    assert "VENDOR_PATTERNS" not in vendor_source
    assert "VENDOR_DIRECTORY_CANDIDATES" not in vendor_source


def test_configuration_failure_keeps_collected_result() -> None:
    def collect() -> dict:
        return collector_result()

    collect.collector_name = "system_info"  # type: ignore[attr-defined]
    resolution = RuleResolution(
        status="FAILED",
        registry=None,
        local_profile=None,
        config_evidence={"default_registry": {"status": "failed"}},
        errors=["default registry invalid"],
    )
    collected, analysis = run_collection_pipeline([collect], resolution=resolution)
    assert collected["system_info"]["status"] == "ok"
    assert analysis.status == "PARTIAL"
    assert analysis.findings == []
    assert "default registry invalid" in analysis.errors


def test_local_expected_annotation_preserves_base_severity_and_finding() -> None:
    profile = {
        "schema_version": 1,
        "profile_id": "mock-profile",
        "machine_match": {"hostnames": ["mock-host"]},
        "expected_accounts": [],
        "expected_listeners": [{
            "protocol": "tcp",
            "port": 22,
            "process": "mock-ssh",
            "addresses": ["0.0.0.0"],
            "rule_ids": ["WIN_PORT_22_REVIEW"],
        }],
        "expected_processes": [],
        "rule_exceptions": [],
    }
    results = {
        "system_info": collector_result(),
        "network_ports": {"data": [{
            "LocalAddress": "0.0.0.0",
            "LocalPort": 22,
            "ProcessName": "mock-ssh",
        }]},
    }
    result = analyze(results, registry(), local_profile=profile)
    target = [item for item in result if item.get("finding_id") == "WIN_PORT_22_REVIEW"]
    assert len(target) == 1
    assert target[0]["severity"] == "Warning"
    assert target[0]["base_severity"] == "Warning"
    assert target[0]["local_profile_disposition"] == "expected"
    annotation = target[0]["local_profile_annotations"][0]
    assert set(annotation) == {"match_type", "matched_fields", "disposition", "base_severity"}
    assert annotation["disposition"] == "expected"
    serialized = json.dumps(result.to_dict(), ensure_ascii=False)
    assert "mock-profile" not in serialized
    assert all("mock-profile" not in item for item in result.warnings + result.errors)

    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report(results, result, output, Path(temp))
        assert "mock-profile" not in output.read_text(encoding="utf-8")


def test_local_exception_missing_field_never_matches() -> None:
    profile = {
        "schema_version": 1,
        "profile_id": "private-profile",
        "machine_match": {"hostnames": ["mock-host"]},
        "expected_accounts": [],
        "expected_listeners": [],
        "expected_processes": [],
        "rule_exceptions": [{
            "rule_id": "WIN_PORT_22_REVIEW",
            "match": {"missing_key": "not-present"},
        }],
    }
    results = {
        "system_info": collector_result(),
        "network_ports": {"data": [{
            "LocalAddress": "0.0.0.0", "LocalPort": 22, "ProcessName": "mock-ssh"
        }]},
    }
    result = analyze(results, registry(), local_profile=profile)
    target = next(item for item in result if item.get("finding_id") == "WIN_PORT_22_REVIEW")
    assert "local_profile_disposition" not in target


def test_local_exception_requires_exact_non_string_types() -> None:
    results = {
        "system_info": collector_result(),
        "users": {
            "collector": "users",
            "status": "ok",
            "data": {"Administrators": [{"Name": str(index)} for index in range(4)]},
        },
    }

    def disposition(expected_value: object) -> str | None:
        profile = {
            "schema_version": 1,
            "profile_id": "private-profile",
            "machine_match": {"hostnames": ["mock-host"]},
            "expected_accounts": [],
            "expected_listeners": [],
            "expected_processes": [],
            "rule_exceptions": [{
                "rule_id": "WIN_ADMINISTRATOR_COUNT_REVIEW",
                "match": {"administrator_count": expected_value},
            }],
        }
        result = analyze(results, registry(), local_profile=profile)
        target = next(item for item in result if item["finding_id"] == "WIN_ADMINISTRATOR_COUNT_REVIEW")
        return target.get("local_profile_disposition")

    assert disposition(True) is None
    assert disposition(False) is None
    assert disposition(4) == "context_only"

    event_results = {
        "system_info": collector_result(),
        "event_logs": {
            "collector": "event_logs",
            "status": "ok",
            "data": [{"LevelDisplayName": "Critical"}],
        },
    }

    def event_disposition(field: str, expected_value: object) -> str | None:
        profile = {
            "schema_version": 1,
            "profile_id": "private-profile",
            "machine_match": {"hostnames": ["mock-host"]},
            "expected_accounts": [],
            "expected_listeners": [],
            "expected_processes": [],
            "rule_exceptions": [{
                "rule_id": "WIN_EVENT_LOG_ERROR_VOLUME",
                "match": {field: expected_value},
            }],
        }
        result = analyze(event_results, registry(), local_profile=profile)
        target = next(item for item in result if item["finding_id"] == "WIN_EVENT_LOG_ERROR_VOLUME")
        return target.get("local_profile_disposition")

    assert event_disposition("critical_count", True) is None  # actual is integer 1
    assert event_disposition("error_count", False) is None  # actual is integer 0
    assert event_disposition("critical_count", 1) == "context_only"

    vendor_profile = {
        "schema_version": 1,
        "profile_id": "private-profile",
        "machine_match": {"hostnames": ["mock-host"]},
        "expected_accounts": [],
        "expected_listeners": [],
        "expected_processes": [],
        "rule_exceptions": [{
            "rule_id": "WIN_SECURITY_VENDOR_RESIDUE",
            "match": {"task_present": True, "startup_present": False},
        }],
    }
    vendor_results = {
        "system_info": collector_result(),
        "security_vendors": {
            "collector": "security_vendors",
            "status": "ok",
            "data": {"installed_programs": [], "drivers": [], "directories": []},
        },
        "scheduled_tasks": {
            "collector": "scheduled_tasks",
            "status": "ok",
            "data": [{"TaskName": "火绒 mock task"}],
        },
    }
    result = analyze(vendor_results, registry(), local_profile=vendor_profile)
    target = next(item for item in result if item["finding_id"] == "WIN_SECURITY_VENDOR_RESIDUE")
    assert target["evidence"]["task_present"] is True
    assert target["evidence"]["startup_present"] is False
    assert target["local_profile_disposition"] == "context_only"


def test_expected_listener_requires_complete_identity_match() -> None:
    base_listener = {
        "protocol": "tcp",
        "port": 22,
        "process": "mock-ssh",
        "addresses": ["0.0.0.0"],
        "rule_ids": ["WIN_PORT_22_REVIEW"],
    }
    results = {
        "system_info": collector_result(),
        "network_ports": {"data": [
            {"LocalAddress": "0.0.0.0", "LocalPort": 22, "ProcessName": "mock-ssh"},
            {"LocalAddress": "::1", "LocalPort": 22, "ProcessName": "mock-ssh"},
        ]},
    }

    def disposition(listener: dict) -> str | None:
        profile = {
            "schema_version": 1,
            "profile_id": "private-profile",
            "machine_match": {"hostnames": ["mock-host"]},
            "expected_accounts": [],
            "expected_listeners": [listener],
            "expected_processes": [],
            "rule_exceptions": [],
        }
        result = analyze(results, registry(), local_profile=profile)
        target = next(item for item in result if item.get("finding_id") == "WIN_PORT_22_REVIEW")
        return target.get("local_profile_disposition")

    assert disposition(base_listener) == "expected"
    for patch in (
        {"process": "different"},
        {"protocol": "udp"},
        {"addresses": ["::1"]},
        {"addresses": ["0.0.0.0", "::1"]},
        {"addresses": ["127.0.0.1"]},
        {"rule_ids": ["WIN_PROXY_PORT_EXPOSED"]},
    ):
        candidate = {**base_listener, **patch}
        assert disposition(candidate) is None, candidate


def test_collector_incomplete_status_propagates_to_analysis_and_exit() -> None:
    resolution = RuleResolution(
        status="OK",
        registry=registry(),
        local_profile=None,
        config_evidence={"default_registry": {"status": "loaded"}},
    )

    def ok_collect() -> dict:
        return collector_result()

    def incomplete(name: str, status: str):
        def collect() -> dict:
            return {"collector": name, "status": status, "data": {}, "errors": []}
        return collect

    for status in ("failed", "partial", "need_admin"):
        collected, analysis = run_collection_pipeline(
            [ok_collect, incomplete(f"mock_{status}", status)],
            resolution=resolution,
        )
        assert collected[f"mock_{status}"]["status"] == status
        assert analysis.status == "PARTIAL"
        assert analysis_exit_code(analysis) == 4
        assert any(f":{status}" in warning for warning in analysis.warnings)

    _, skipped = run_collection_pipeline(
        [incomplete("mock_skipped", "skipped")],
        resolution=resolution,
    )
    assert skipped.status == "FAILED"
    assert analysis_exit_code(skipped) == 4
    assert skipped.findings == []
    assert skipped.warnings == ["COLLECTION_INCOMPLETE:all_collectors_skipped:无有效采集证据"]
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report({}, skipped, output, Path(temp))
        report = output.read_text(encoding="utf-8")
    assert "Analysis Status: FAILED" in report
    assert "仅可使用已保留的采集证据进行人工复核" in report
    assert "无有效采集证据" in report
    assert "未发现需要优先展示的风险" not in report


def test_analyzer_exceptions_are_structured_and_keep_collection() -> None:
    resolution = RuleResolution(
        status="OK",
        registry=registry(),
        local_profile=None,
        config_evidence={"default_registry": {"status": "loaded"}},
    )

    def collect() -> dict:
        return collector_result()

    for exception in (ValueError("private-profile-id"), RuntimeError("private-profile-id")):
        def broken_analyzer(_results: dict, failure: Exception = exception):
            raise failure

        collected, analysis = run_collection_pipeline(
            [collect], analyzer=broken_analyzer, resolution=resolution
        )
        assert collected["system_info"]["status"] == "ok"
        assert analysis.status == "PARTIAL"
        assert analysis_exit_code(analysis) == 4
        assert analysis.errors == [f"ANALYZER_EXCEPTION:{type(exception).__name__}"]
        serialized = json.dumps({"collectors": collected, "analysis": analysis.to_dict()})
        assert "private-profile-id" not in serialized
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.md"
            render_report(collected, analysis, output, Path(temp))
            report = output.read_text(encoding="utf-8")
        assert "Analysis Status: PARTIAL" in report
        assert "private-profile-id" not in report

    def always_fails(_results: dict):
        raise ValueError("private-profile-id")

    collected, failed = run_collection_pipeline([], analyzer=always_fails, resolution=resolution)
    assert collected == {}
    assert failed.status == "FAILED"
    assert analysis_exit_code(failed) == 4


def test_critical_finding_cannot_be_downgraded_or_deleted() -> None:
    configured = registry()
    for item in configured["rules"]:
        if item["id"] == "WIN_PORT_22_REVIEW":
            item["severity"] = "Critical"
    profile = {
        "schema_version": 1,
        "profile_id": "mock-profile",
        "machine_match": {"hostnames": ["mock-host"]},
        "expected_accounts": [],
        "expected_listeners": [],
        "expected_processes": [],
        "rule_exceptions": [{
            "rule_id": "WIN_PORT_22_REVIEW",
            "match": {"port": 22, "process": "mock-ssh"},
        }],
    }
    results = {
        "system_info": collector_result(),
        "network_ports": {"data": [{
            "LocalAddress": "0.0.0.0", "LocalPort": 22, "ProcessName": "mock-ssh"
        }]},
    }
    result = analyze(results, configured, local_profile=profile)
    target = [item for item in result if item.get("finding_id") == "WIN_PORT_22_REVIEW"]
    assert len(target) == 1
    assert target[0]["severity"] == "Critical"
    assert target[0]["base_severity"] == "Critical"
    assert target[0]["local_profile_disposition"] == "context_only"


def test_partial_report_never_claims_no_risk_and_redacts_private_profile() -> None:
    analysis = AnalysisResult(
        status="PARTIAL",
        findings=[],
        config_evidence={
            "default_registry": {"status": "loaded", "registry_version": "0.1.0"},
            "user_override": {"status": "failed", "applied": False},
            "local_profile": {"status": "failed", "applied": False},
        },
        errors=["Local profile JSON is invalid at line 1, column 2"],
    )
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report({"system_info": collector_result(), "started_at": "mock"}, analysis, output, Path(temp))
        text = output.read_text(encoding="utf-8")
    assert "Analysis Status: PARTIAL" in text
    assert "不能作为完整的无风险结论" in text
    assert "未发现需要优先展示的风险" not in text
    assert "mock-profile-private-value" not in text


def test_report_shows_local_annotation_without_profile_id_or_private_values() -> None:
    finding = {
        "finding_id": "WIN_PORT_22_REVIEW",
        "title": "SSH 远程访问监听",
        "severity": "Warning",
        "base_severity": "Warning",
        "local_profile_disposition": "expected",
        "local_profile_annotations": [{
            "profile_id": "private-profile-id",
            "match_type": "expected_listener",
            "matched_fields": ["port", "process"],
        }],
        "evidence": "mock evidence",
        "recommendation": "人工确认。",
    }
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report({}, AnalysisResult(status="OK", findings=[finding]), output, Path(temp))
        text = output.read_text(encoding="utf-8")
    assert "本机配置审计注释：expected" in text
    assert "本机配置匹配类型：expected_listener" in text
    assert "原始风险等级：Warning" in text
    assert "private-profile-id" not in text


def main() -> int:
    test_analysis_result_ok_partial_failed_and_exit_codes()
    test_adjustable_policy_is_not_duplicated_in_analyzer_or_vendor_collector()
    test_configuration_failure_keeps_collected_result()
    test_local_expected_annotation_preserves_base_severity_and_finding()
    test_local_exception_missing_field_never_matches()
    test_local_exception_requires_exact_non_string_types()
    test_expected_listener_requires_complete_identity_match()
    test_collector_incomplete_status_propagates_to_analysis_and_exit()
    test_analyzer_exceptions_are_structured_and_keep_collection()
    test_critical_finding_cannot_be_downgraded_or_deleted()
    test_partial_report_never_claims_no_risk_and_redacts_private_profile()
    test_report_shows_local_annotation_without_profile_id_or_private_values()
    print("Runtime status tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
