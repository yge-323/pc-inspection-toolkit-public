from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reports.markdown_report import render_report  # noqa: E402


def _render(findings: list[dict]) -> str:
    with tempfile.TemporaryDirectory() as temp:
        output_path = Path(temp) / "report.md"
        render_report(
            {"system_info": {"data": {"hostname": "test-host"}}, "started_at": "2026-07-05"},
            findings,
            output_path,
            Path(temp) / "raw",
        )
        return output_path.read_text(encoding="utf-8")


def test_standard_warning_severity_is_counted_in_summary() -> None:
    text = _render([
        {
            "finding_id": "WIN_STARTUP_SUSPICIOUS_PATH",
            "title": "启动项路径需要复核",
            "severity": "Warning",
            "category": "Startup",
            "component": "startup_items",
            "evidence": {"path": "Temp"},
            "recommendation": "人工复核启动项来源。",
        }
    ])

    assert "| Warning | 1 |" in text
    assert "| Need Admin | 0 |" in text
    assert "WIN_STARTUP_SUSPICIOUS_PATH" in text
    assert "启动项路径需要复核" in text


def test_standard_need_admin_severity_is_counted_separately() -> None:
    text = _render([
        {
            "finding_id": "WIN_BITLOCKER_NEED_ADMIN",
            "title": "BitLocker 状态需要管理员权限确认",
            "severity": "need_admin",
            "category": "Disk",
            "component": "disks",
            "description": "当前权限不足，无法完整确认 BitLocker 状态。",
            "evidence": {"collector_status": "need_admin", "errors": ["拒绝访问"]},
            "impact": "无法判断磁盘加密状态，需管理员权限复核。",
            "recommendation": "使用管理员权限重新运行巡检，或人工确认 BitLocker 状态。",
            "verification_checkpoint": "以管理员 PowerShell 执行 Get-BitLockerVolume 复核。",
            "needs_human_review": True,
            "auto_fix": "否",
        }
    ])

    assert "| Critical | 0 |" in text
    assert "| Need Admin | 1 |" in text
    assert "- 风险等级：Need Admin" in text
    assert "验证检查点" in text
    assert "需人工确认" in text


def test_standard_finding_fields_are_rendered() -> None:
    text = _render([
        {
            "finding_id": "WIN_BITLOCKER_NEED_ADMIN",
            "title": "BitLocker 状态需要管理员权限确认",
            "severity": "Need Admin",
            "category": "Disk",
            "component": "disks",
            "description": "当前权限不足，无法完整确认 BitLocker 状态。",
            "evidence": {"collector_status": "need_admin", "errors": ["拒绝访问"]},
            "impact": "无法判断磁盘加密状态，需管理员权限复核。",
            "recommendation": "使用管理员权限重新运行巡检，或人工确认 BitLocker 状态。",
            "verification_checkpoint": "以管理员 PowerShell 执行 Get-BitLockerVolume 复核。",
            "needs_human_review": True,
            "auto_fix": "否",
        }
    ])

    assert "WIN_BITLOCKER_NEED_ADMIN" in text
    assert "BitLocker 状态需要管理员权限确认" in text
    assert "Need Admin" in text
    assert "验证检查点" in text
    assert "需人工确认" in text


def test_legacy_finding_fields_are_still_rendered() -> None:
    text = _render([
        {
            "name": "旧格式风险",
            "level": "LOW",
            "evidence": "legacy evidence",
            "impact": "legacy impact",
            "recommendation": "legacy recommendation",
            "auto_fix": "否",
        },
        {
            "name": "旧格式 risk 字段风险",
            "risk": "failed",
            "recommendation": "legacy risk recommendation",
            "auto_fix": "否",
        },
    ])

    assert "旧格式风险" in text
    assert "| Warning | 1 |" in text
    assert "| Failed | 1 |" in text
    assert "- 风险等级：Warning" in text
    assert "- 风险等级：Failed" in text
    assert "legacy evidence" in text
    assert "legacy recommendation" in text


def test_unknown_severity_falls_back_to_info_without_breaking_report() -> None:
    text = _render([
        {
            "title": "未知等级风险",
            "severity": "mystery",
            "evidence": "unknown severity evidence",
            "recommendation": "人工确认等级。",
        }
    ])

    assert "| Info | 1 |" in text
    assert "- 风险等级：Info" in text
    assert "未知等级风险" in text
    assert "unknown severity evidence" in text


def main() -> int:
    test_standard_warning_severity_is_counted_in_summary()
    test_standard_need_admin_severity_is_counted_separately()
    test_standard_finding_fields_are_rendered()
    test_legacy_finding_fields_are_still_rendered()
    test_unknown_severity_falls_back_to_info_without_breaking_report()
    print("Markdown report tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
