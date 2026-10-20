from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reports.markdown_report import render_report  # noqa: E402


def render_security_report(
    security_result: dict[str, Any] | None,
    findings: list[dict[str, Any]] | None = None,
) -> str:
    results: dict[str, Any] = {
        "system_info": {"data": {"hostname": "mock-host"}},
        "started_at": "2026-07-15",
    }
    if security_result is not None:
        results["security_vendors"] = security_result
    with tempfile.TemporaryDirectory() as temp:
        output_path = Path(temp) / "mock-report.md"
        render_report(results, findings or [], output_path, Path(temp) / "mock-raw")
        return output_path.read_text(encoding="utf-8")


def security_result(
    *,
    status: str = "ok",
    installed: list[dict[str, Any]] | None = None,
    drivers: list[dict[str, Any]] | None = None,
    directories: list[dict[str, Any]] | None = None,
    errors: list[Any] | None = None,
) -> dict[str, Any]:
    installed = installed or []
    drivers = drivers or []
    directories = directories or []
    all_items = installed + drivers + directories
    vendors = sorted({str(item["matched_vendor"]) for item in all_items if item.get("matched_vendor")})
    return {
        "collector": "security_vendors",
        "status": status,
        "data": {
            "installed_programs": installed,
            "drivers": drivers,
            "directories": directories,
            "summary": {
                "vendors_detected": vendors,
                "installed_vendor_count": len({
                    item["matched_vendor"] for item in installed if item.get("matched_vendor")
                }),
                "driver_count": len(drivers),
                "directory_count": len(directories),
            },
        },
        "errors": errors or [],
    }


def vendor_finding(
    finding_id: str,
    vendor: str,
    *,
    severity: str,
    title: str,
    description: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "category": "Security Software",
        "component": "security_vendors",
        "description": description,
        "evidence": {"vendor": vendor, **(evidence or {})},
        "impact": "Mock impact",
        "recommendation": "人工确认，不自动处置。",
        "verification_checkpoint": "复跑巡检并人工确认。",
        "needs_human_review": True,
        "auto_fix": "否",
    }


def installed_360(uninstall_string: str | None = None) -> dict[str, Any]:
    return {
        "display_name": "360安全卫士",
        "display_version": "14.0",
        "publisher": "北京奇虎科技有限公司",
        "install_location": "C:\\Program Files (x86)\\360\\360Safe",
        "uninstall_string": uninstall_string,
        "quiet_uninstall_string": uninstall_string,
        "matched_vendor": "360",
        "matched_keyword": "360安全卫士",
        "source_type": "installed_program",
    }


def test_installed_360_has_dedicated_section_without_uninstall_command() -> None:
    secret = '"C:\\Program Files (x86)\\360\\uninstall.exe" /token abc123 /user TEST_OPERATOR'
    finding = vendor_finding(
        "WIN_SECURITY_VENDOR_PRESENT",
        "360",
        severity="Attention",
        title="检测到安全软件或电脑管家组件",
        description="检测到相关组件，存在不等于恶意。",
    )
    text = render_security_report(security_result(installed=[installed_360(secret)]), [finding])
    assert "## 安全软件与电脑管家组件" in text
    assert "360安全卫士" in text
    assert "#### 已安装程序" in text
    assert "存在不等于恶意" in text
    assert "uninstall.exe" not in text
    assert "abc123" not in text
    assert "/user TEST_OPERATOR" not in text


def test_huorong_install_is_attention_not_critical() -> None:
    installed = [{
        "display_name": "火绒安全软件",
        "publisher": "Huorong",
        "matched_vendor": "Huorong",
        "matched_keyword": "火绒",
    }]
    finding = vendor_finding(
        "WIN_SECURITY_VENDOR_PRESENT",
        "Huorong",
        severity="Attention",
        title="检测到安全软件或电脑管家组件",
        description="火绒正常安装，存在不等于恶意。",
    )
    text = render_security_report(security_result(installed=installed), [finding])
    assert "### Huorong" in text
    assert "火绒安全软件" in text
    assert "Attention：检测到安全软件或电脑管家组件" in text
    assert "| Critical | 0 |" in text
    assert "- 风险等级：Critical" not in text


def test_driver_residue_shows_warning_and_no_auto_delete_guidance() -> None:
    drivers = [{
        "name": "360FsFlt",
        "display_name": "360 File Filter",
        "state": "Running",
        "start_mode": "System",
        "path_name": "C:\\Windows\\System32\\drivers\\360FsFlt.sys",
        "matched_vendor": "360",
        "matched_keyword": "360fsflt",
    }]
    finding = vendor_finding(
        "WIN_SECURITY_VENDOR_DRIVER_REVIEW",
        "360",
        severity="Warning",
        title="检测到安全软件相关驱动",
        description="检测到安全软件相关驱动或驱动残留。",
        evidence={"driver_present": True},
    )
    text = render_security_report(security_result(drivers=drivers), [finding])
    assert "360FsFlt" in text
    assert "Warning：检测到安全软件相关驱动" in text
    assert "不建议自动删除" in text


def test_directory_only_is_auxiliary_evidence_not_confirmed_residue() -> None:
    directories = [{
        "path": "C:\\ProgramData\\360",
        "matched_vendor": "360",
        "matched_keyword": "360",
    }]
    text = render_security_report(security_result(directories=directories))
    assert "#### 目录辅助证据" in text
    assert "仅目录痕迹" in text
    assert "目录只作为辅助证据" in text
    assert "已确认卸载残留" not in text
    assert "WIN_SECURITY_VENDOR_RESIDUE" not in text


def test_empty_data_shows_no_known_component_message() -> None:
    text = render_security_report(security_result())
    assert "未检测到已知安全软件或电脑管家组件" in text
    assert "## 15. 本次巡检限制与不确定项" in text


def test_partial_shows_short_error_without_traceback() -> None:
    errors = [{
        "source": "drivers",
        "status": "need_admin",
        "message": "driver query access denied Traceback: secret stack",
    }] + [
        {"source": "mock", "status": "failed", "message": f"mock-error-{index}"}
        for index in range(6)
    ]
    text = render_security_report(security_result(status="partial", errors=errors))
    assert "部分完成" in text
    assert "driver query access denied" in text
    assert "Traceback" not in text
    assert "secret stack" not in text
    assert "mock-error-3" in text
    assert "mock-error-4" not in text
    assert "另有 2 条错误未展开" in text


def test_need_admin_is_visible_without_critical_finding() -> None:
    text = render_security_report(security_result(status="need_admin", errors=[{
        "source": "drivers",
        "status": "need_admin",
        "message": "Access denied",
    }]))
    assert "需要管理员权限" in text
    assert "| Critical | 0 |" in text
    assert "- 风险等级：Critical" not in text


def test_missing_collector_and_missing_fields_do_not_break_report() -> None:
    missing_collector = render_security_report(None)
    missing_fields = render_security_report({"collector": "security_vendors", "status": "ok"})
    assert "未执行此项检查" in missing_collector
    assert "未检测到已知安全软件或电脑管家组件" in missing_fields


def test_multiple_vendors_are_grouped_in_stable_order() -> None:
    installed = [
        installed_360(),
        {"display_name": "火绒安全软件", "matched_vendor": "Huorong", "matched_keyword": "火绒"},
        {
            "display_name": "腾讯电脑管家",
            "matched_vendor": "Tencent PC Manager",
            "matched_keyword": "腾讯电脑管家",
        },
    ]
    text = render_security_report(security_result(installed=installed))
    positions = [text.index("### 360"), text.index("### Huorong"), text.index("### Tencent PC Manager")]
    assert positions == sorted(positions), positions
    assert text.count("### 360") == 1
    assert "检测到多个安全软件或电脑管家组件" in text


def test_each_detail_type_is_limited_to_ten_rows() -> None:
    installed = [
        {
            **installed_360(),
            "display_name": f"MockProduct-{index:02d}",
        }
        for index in range(12)
    ]
    text = render_security_report(security_result(installed=installed))
    assert "MockProduct-09" in text
    assert "MockProduct-10" not in text
    assert "MockProduct-11" not in text
    assert "另有 2 条未展开，详见 raw 数据" in text


def test_uninstall_command_is_filtered_from_generic_finding_evidence() -> None:
    secret = '"C:\\Program Files (x86)\\360\\uninstall.exe" /token abc123 /user TEST_OPERATOR'
    finding = vendor_finding(
        "WIN_SECURITY_VENDOR_PRESENT",
        "360",
        severity="Attention",
        title="检测到安全软件或电脑管家组件",
        description="Mock",
        evidence={"uninstall_string": secret, "quiet_uninstall_string": secret},
    )
    text = render_security_report(security_result(installed=[installed_360(secret)]), [finding])
    assert "abc123" not in text
    assert "/user TEST_OPERATOR" not in text
    assert "uninstall_string" not in text


def test_generic_finding_summary_and_details_remain_compatible() -> None:
    security_finding = vendor_finding(
        "WIN_SECURITY_VENDOR_PRESENT",
        "360",
        severity="Attention",
        title="检测到安全软件或电脑管家组件",
        description="Mock security finding",
    )
    warning = {
        "finding_id": "WIN_STARTUP_SUSPICIOUS_PATH",
        "title": "启动项路径需要复核",
        "severity": "Warning",
        "evidence": {"path": "Temp"},
        "recommendation": "人工确认。",
    }
    text = render_security_report(security_result(installed=[installed_360()]), [security_finding, warning])
    assert "| Attention | 1 |" in text
    assert "| Warning | 1 |" in text
    assert "WIN_SECURITY_VENDOR_PRESENT" in text
    assert "WIN_STARTUP_SUSPICIOUS_PATH" in text
    assert "## 3. 重点风险" in text


def main() -> int:
    test_installed_360_has_dedicated_section_without_uninstall_command()
    test_huorong_install_is_attention_not_critical()
    test_driver_residue_shows_warning_and_no_auto_delete_guidance()
    test_directory_only_is_auxiliary_evidence_not_confirmed_residue()
    test_empty_data_shows_no_known_component_message()
    test_partial_shows_short_error_without_traceback()
    test_need_admin_is_visible_without_critical_finding()
    test_missing_collector_and_missing_fields_do_not_break_report()
    test_multiple_vendors_are_grouped_in_stable_order()
    test_each_detail_type_is_limited_to_ten_rows()
    test_uninstall_command_is_filtered_from_generic_finding_evidence()
    test_generic_finding_summary_and_details_remain_compatible()
    print("Markdown security vendor report tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
