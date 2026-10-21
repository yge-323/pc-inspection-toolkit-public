from __future__ import annotations

import sys
import re
import tempfile
import copy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reports.markdown_report import render_report  # noqa: E402
from locales import LocaleResourceError, display_finding, display_summary, validate_resources
from locales import findings as locale_findings
from reports.unified import render_csv, render_html, render_markdown
from models.analysis import AnalysisResult
from evidence.bundle import write_manifest, validate_bundle
from analyzers.evidence_analyzer import analyze_evidence


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


def test_curated_english_finding_is_localized_without_changing_machine_fields() -> None:
    evidence = {"port": 22, "addresses": ["0.0.0.0"]}
    finding = {
        "finding_id": "WIN_PORT_22_REVIEW", "rule_id": "WIN_PORT_22_REVIEW",
        "title": "SSH 常用端口外部监听审查",
        "description": "A configured SSH review port is listening on 0.0.0.0 or ::. This listener-only check does not verify that the process is sshd or that the access is expected.",
        "impact": "对外监听的 SSH 常用端口可能扩大远程访问面，但仅凭端口监听不能确认服务身份或是否属于预期配置。",
        "recommendation": "先由资产负责人确认SSH用途和监听进程。若属于获批维护通道，保留22端口并仅按批准来源范围收紧有效防火墙规则；若确认不再需要，按维护窗口通过受支持的服务/策略入口调整具体服务和规则。不要仅凭端口命中停止未知进程或阻断22。",
        "severity": "Warning", "evidence": evidence, "references": ["https://example.invalid/ref"],
    }
    original = dict(finding)
    shown = display_finding(finding, "zh")

    assert "正在 0.0.0.0 或 :: 上监听" in shown["description"]
    assert "不能确认服务身份" in shown["impact"]
    assert "不要仅凭端口命中停止未知进程或阻断22" in shown["recommendation"]
    assert shown["finding_id"] == finding["finding_id"]
    assert shown["severity"] == "Warning"
    assert shown["evidence"] == evidence
    assert shown["references"] == finding["references"]
    assert finding == original


def test_unknown_external_finding_is_preserved_and_marked_in_both_reports() -> None:
    finding = {"finding_id": "CUSTOM_RULE_1", "title": "Vendor title", "description": "Keep this exact text.",
               "severity": "Critical", "evidence": {"raw": "bytes"}, "recommendation": "Do not rewrite this."}
    result = AnalysisResult(status="PARTIAL", findings=[finding], warnings=["LISTENER_EVIDENCE_TRUNCATED"])
    md = render_markdown(result, {}, language="en-US")
    html = render_html(result, {}, language="en-US")
    csv_text = render_csv(result, language="en-US")

    assert "Rule text retained in its source language" in md
    assert "Vendor title" in html and "Keep this exact text." in html
    assert "Source text note" in csv_text
    assert "LISTENER_EVIDENCE_TRUNCATED" not in md
    assert "Listener evidence was truncated" in md
    assert "CUSTOM_RULE_1" in csv_text
    assert finding["evidence"] == {"raw": "bytes"}


def test_builtin_and_unknown_reasons_are_localized_or_marked() -> None:
    from locales import display_reason
    assert display_reason("local AI is opt-in and was not requested", "zh-CN") == "本地 AI 为可选功能，且本次未请求。"
    assert display_reason("provider, endpoint, and model are all required", "zh-CN") == "必须同时提供 provider、endpoint 和 model。"
    assert display_reason("ValueError: request or response rejected", "zh-CN") == "ValueError: 请求或响应被拒绝"
    assert display_reason("Vendor error: keep this exact", "en-US") == "Vendor error: keep this exact (source text retained)"
    assert display_reason(None, "en-US") == ""
    assert display_reason("", "zh-CN") == ""
    assert display_reason("The collector returned partial facts; see its notes and do not treat missing fields as passing.", "zh-CN") == "采集器仅返回部分事实；请查看采集说明，缺失字段不能视为检查通过。"
    assert display_reason("Exit status sidecar is malformed.", "zh-CN") == "退出状态 sidecar 格式无效。"
    assert display_reason("The bounded collector exceeded its output limit.", "en-US") == "The bounded collector exceeded its output limit."

    result = AnalysisResult(status="PARTIAL", warnings=["The collector returned partial facts; see its notes and do not treat missing fields as passing."])
    md = render_markdown(result, {"evidence_items": [
        {"name": "Collected", "status": "collected", "reason": ""},
        {"name": "Partial", "status": "collected", "reason": "The collector returned partial facts; see its notes and do not treat missing fields as passing."},
    ]}, "en-US")
    assert "(source text retained)" not in md
    assert "The collector returned partial facts" in md


def test_builtin_dynamic_gap_families_are_translated_with_codes_and_suffixes() -> None:
    from locales.findings import gap_text
    cases = {
        "WINDOWS_ADMINISTRATOR_COUNT_UNKNOWN": ("管理员组成员数量未知", "Administrator group member count is unknown"),
        "WINDOWS_STARTUP_RECORD_COUNT_UNKNOWN": ("启动项记录数量未知", "Startup item record count is unknown"),
        "EVIDENCE_PARTIAL:accounts.txt": ("证据文件仅部分采集", "Evidence file was only partially collected"),
        "WINDOWS_DISK_SIZE_UNKNOWN:line_4": ("磁盘总容量未知", "Disk total size is unknown"),
    }
    for source, (zh, en) in cases.items():
        zh_text = gap_text(source, "zh-CN")
        en_text = gap_text(source, "en-US")
        assert zh in zh_text and source in zh_text
        assert en in en_text and source in en_text
    result = AnalysisResult(status="PARTIAL", warnings=["WINDOWS_ADMINISTRATOR_COUNT_UNKNOWN",
                                                          "WINDOWS_STARTUP_RECORD_COUNT_UNKNOWN",
                                                          "EVIDENCE_PARTIAL:accounts.txt"])
    report = render_markdown(result, {}, "en-US")
    csv_text = render_csv(result, "en-US")
    assert "Administrator group member count is unknown" in report and "EVIDENCE_PARTIAL:accounts.txt" in report
    assert "Startup item record count is unknown" in csv_text and "WINDOWS_STARTUP_RECORD_COUNT_UNKNOWN" in csv_text
    unknown = gap_text("CUSTOM_VENDOR_GAP:retain", "en-US")
    assert unknown == "CUSTOM_VENDOR_GAP:retain (source text retained)"


def test_severity_meanings_preserve_tokens_and_caveats_in_reports() -> None:
    result = AnalysisResult(status="PARTIAL", findings=[
        {"finding_id": "W1", "title": "Review", "severity": "Warning"},
        {"finding_id": "A1", "title": "Permission", "severity": "Need Admin"},
    ])
    en = render_markdown(result, {}, "en-US")
    csv_text = render_csv(result, "en-US")
    assert "Severity: Warning" in en
    assert "does not necessarily indicate high risk" in en
    assert "not equivalent to Critical" in en
    assert "Severity meaning" in csv_text.splitlines()[0]
    assert "not equivalent to Critical" in csv_text


def test_unified_report_uses_english_headings_and_keeps_severity_token() -> None:
    finding = {"finding_id": "WIN_BITLOCKER_NEED_ADMIN", "title": "BitLocker 状态需要管理员权限确认",
               "description": "当前权限不足，无法完整确认 BitLocker 状态。", "impact": "无法判断磁盘加密状态，需管理员权限复核。",
               "recommendation": "由获批管理员以只读方式核对 BitLocker 卷状态；若权限暂不可用，保留此证据缺口并交接复核，不要为巡检启停加密或请求工具自动提权。",
               "severity": "Need Admin", "evidence": {"collector_status": "need_admin"}}
    result = AnalysisResult(status="PARTIAL", findings=[finding], warnings=["TARGET_VERSION_APPLICABILITY_UNVERIFIED"])
    md = render_markdown(result, {}, "en")
    html = render_html(result, {}, "en")
    csv_text = render_csv(result, "en")

    assert "Findings and remediation" in md
    assert "requires administrator review" in md
    assert "Need Admin" in md and "Need administrator" in md
    assert "Evidence gaps" in html
    assert "Target version applicability is unverified" in csv_text
    assert "analysis_status" not in csv_text.splitlines()[0]
    assert "row_type" in csv_text.splitlines()[0]


def test_legacy_report_localizes_curated_finding_and_preserves_raw_id() -> None:
    finding = {"finding_id": "WIN_PORT_22_REVIEW", "rule_id": "WIN_PORT_22_REVIEW",
               "title": "SSH 常用端口外部监听审查",
               "description": "A configured SSH review port is listening on 0.0.0.0 or ::. This listener-only check does not verify that the process is sshd or that the access is expected.",
               "impact": "对外监听的 SSH 常用端口可能扩大远程访问面，但仅凭端口监听不能确认服务身份或是否属于预期配置。",
               "recommendation": "先由资产负责人确认SSH用途和监听进程。若属于获批维护通道，保留22端口并仅按批准来源范围收紧有效防火墙规则；若确认不再需要，按维护窗口通过受支持的服务/策略入口调整具体服务和规则。不要仅凭端口命中停止未知进程或阻断22。",
               "severity": "Warning", "evidence": {"port": 22}}
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report({"system_info": {"data": {}}}, [finding], output, Path(temp) / "raw", language="en-US")
        text = output.read_text(encoding="utf-8")
    assert "Windows Inspection Report" in text
    assert "Finding ID: WIN_PORT_22_REVIEW" in text
    assert "Review external listener on the common SSH port" in text
    assert "the listener alone does not establish service identity" in text
    assert "Warning" in text and "Severity meaning: Requires manual confirmation but does not necessarily indicate high risk." in text
    assert not [line for line in text.splitlines() if re.search(r"[\u4e00-\u9fff]", line)]


def test_smb_listener_remediation_preserves_port_445_safety_condition() -> None:
    finding = {"finding_id": "WIN_SMB_445_ALLOWED", "rule_id": "WIN_SMB_445_ALLOWED",
               "title": "SMB 常用端口外部监听审查",
               "description": "A configured SMB review port is listening on 0.0.0.0 or ::. This listener-only check does not verify firewall Allow rules or share permissions.",
               "recommendation": "由业务所有者确认445对应的共享用途和授权。若承载获批文件、打印、备份、虚拟化或集群业务，保留必要通道并核对共享/NTFS最小权限及防火墙来源范围；只有确认无依赖后，才按变更流程通过Windows受支持管理入口禁用不需要的共享服务或收紧规则。不要仅凭端口监听直接封锁445。",
               "severity": "Warning"}
    en = display_finding(finding, "en-US")
    zh = display_finding({**finding, "description": "配置的 SMB 检查端口正在 0.0.0.0 或 :: 上监听。此项只检查监听状态，不验证防火墙允许规则或共享权限。"}, "zh-CN")
    assert "Do not block port 445 based only on the listener" in en["recommendation"]
    assert "不要仅凭端口监听直接封锁445" in zh["recommendation"]


def test_lifecycle_dynamic_title_and_english_description_are_localized() -> None:
    finding = {"finding_id": "OS_LIFECYCLE_WINDOWS_10_22H2", "rule_id": "OS_LIFECYCLE_REVIEW",
               "title": "Windows 10 22H2 生命周期支持已结束",
               "description": "Collected OS identity matches a lifecycle record whose normal support has ended. This is a version-support and migration-planning review, not a security finding or proof of exposure.",
               "severity": "Warning", "evidence": {"observed_product": "Windows 10", "observed_version": "22H2", "support_status": "ended"}}
    shown = display_finding(finding, "en")
    assert shown["title"] == "Windows 10 22H2 lifecycle support has ended"
    assert "不是安全发现" in shown["description"]


def test_lifecycle_coverage_gap_description_and_warning_are_localized() -> None:
    source = "Collected OS identity has no lifecycle record in the validated policy; support is unknown."
    finding = {"finding_id": "OS_LIFECYCLE_COVERAGE_GAP", "rule_id": "OS_LIFECYCLE_COVERAGE",
               "title": "操作系统生命周期覆盖未确认", "description": source, "severity": "Warning"}
    displayed = display_finding(finding, "zh-CN")
    assert "没有该操作系统身份的生命周期记录" in displayed["description"]
    assert "_locale_source_note" not in displayed
    from locales import display_reason
    assert display_reason("OS_LIFECYCLE_RECORD_UNAVAILABLE", "en-US") == "No lifecycle record for this OS identity exists in the validated policy"


def test_linux_builtin_dynamic_fields_are_localized_without_mutation() -> None:
    finding = {"finding_id": "LNX_SSH_ROOT_LOGIN_PERMITTED", "rule_id": "LNX_SSH_ROOT_LOGIN_PERMITTED",
               "title": "SSH 允许 root 相关登录", "description": "sshd_config 摘要显示 PermitRootLogin=prohibit-password。",
               "applicability": "仅依据已采集的摘要字段；精确发行版与配置生效状态需人工核实。",
               "rollback": "恢复 sshd_config 备份并 reload；验证管理通道。",
               "verification_checkpoint": "复采 security_status，确认 SSH_PERMIT_ROOT_LOGIN=no，并用普通账户验证登录。",
               "severity": "Attention", "evidence": {"permit_root_login": "prohibit-password"}}
    original = dict(finding)
    shown = display_finding(finding, "en-US")
    assert shown["description"] == "The sshd_config summary reports PermitRootLogin=prohibit-password."
    assert "effective configuration manually" in shown["applicability"]
    assert "Restore the sshd_config backup" in shown["rollback"]
    assert shown["evidence"] == finding["evidence"] and finding == original


def test_synthetic_windows_bundle_analyze_evidence_renders_english_findings() -> None:
    required = ("os.txt", "os_detail.txt", "cpu.txt", "memory.txt", "graphics.txt", "disks.txt", "processes.txt",
                "services.txt", "listeners.txt", "firewall.txt", "privilege.txt", "accounts.txt", "startup_items.txt",
                "security_status.txt")
    target = {"os_family": "windows", "product": "Windows 10", "version": "10.0.19045", "architecture": "x64",
              "use_case": "desktop", "scope": "basic"}
    collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00",
                  "timezone": "UTC", "privilege": "ordinary", "collector_version": "fixture", "command_catalog": "fixture"}
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for name in required:
            if name == "os.txt":
                content = "Windows 10\n"
            elif name == "os_detail.txt":
                content = "Caption=Windows 10 Pro\nVersion=10.0.19045\n"
            elif name == "listeners.txt":
                content = "TCP 0.0.0.0:22 0.0.0.0:0 LISTENING 100\n"
            else:
                content = "COLLECTOR_STATUS=COLLECTED\n"
            (root / name).write_text(content, encoding="utf-8")
            (root / (Path(name).stem + ".exit-code.txt")).write_text("0\n", encoding="ascii")
        write_manifest(root, project_alias="fixture", asset_alias="fixture", target=target, collection=collection)
        result = analyze_evidence(root, validate_bundle(root))
        original_findings = copy.deepcopy(result.findings)
        rendered = [render_markdown(result, {}, language="en-US"), render_html(result, {}, language="en-US"), render_csv(result, "en-US")]
    assert result.status == "PARTIAL"
    assert result.findings
    assert not [line for document in rendered for line in document.splitlines() if re.search(r"[\u4e00-\u9fff]", line)]
    assert result.findings == original_findings
    for finding in result.findings:
        assert any(finding["finding_id"] in document for document in rendered)
        assert any(finding["severity"] in document for document in rendered)


def test_analyzer_platform_description_survives_rule_catalog_merge_and_localizes() -> None:
    required = ("os.txt", "os_detail.txt", "cpu.txt", "memory.txt", "graphics.txt", "disks.txt", "processes.txt",
                "services.txt", "listeners.txt", "firewall.txt", "privilege.txt", "accounts.txt", "startup_items.txt",
                "security_status.txt")
    target = {"os_family": "windows", "product": "Windows 10", "version": "10.0.19045", "architecture": "x64",
              "use_case": "desktop", "scope": "basic"}
    collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00",
                  "timezone": "UTC", "privilege": "ordinary", "collector_version": "fixture", "command_catalog": "fixture"}
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for name in required:
            content = "Windows 10\n" if name == "os.txt" else (
                "Caption=Windows 10 Pro\nVersion=10.0.19045\n" if name == "os_detail.txt" else
                "TCP 0.0.0.0:8443 0.0.0.0:0 LISTENING 100\n" if name == "listeners.txt" else "COLLECTOR_STATUS=COLLECTED\n")
            (root / name).write_text(content, encoding="utf-8")
            (root / (Path(name).stem + ".exit-code.txt")).write_text("0\n", encoding="ascii")
        write_manifest(root, project_alias="fixture", asset_alias="fixture", target=target, collection=collection)
        result = analyze_evidence(root, validate_bundle(root))
    finding = next(item for item in result.findings if item["finding_id"].startswith("GENERIC_WILDCARD_LISTENER_REVIEW"))
    assert finding["description"] == "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."
    shown = display_finding(finding, "zh-CN")
    assert shown["description"] != finding["description"], (finding["finding_id"], finding.get("rule_id"))
    assert "确定性规则仅匹配明确采集到的证据" in shown["description"]
    assert finding["description"].startswith("Deterministic rule matched")
    oracle = display_finding({"finding_id": "ORACLE_VALID_NODE_CHECK_DISABLED_REVIEW",
                              "rule_id": "ORACLE_VALID_NODE_CHECK_DISABLED_REVIEW",
                              "description": "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."},
                             "zh-CN")
    assert oracle["description"].startswith("确定性规则仅匹配明确采集到的证据")


def test_unified_summary_localizes_owned_labels_and_templates_preserving_raw_facts() -> None:
    summary = {
        "硬件": {"CPU": "合成CPU 型号", "CPU数量": "8", "内存字节": 17179869184},
        "设备": {"CPU型号": "合成CPU 型号"},
        "磁盘容量与剩余空间": {"卷数": 1, "卷剩余空间": "C:：5.0 GB 可用 / 100.0 GB 总量（5.0%）"},
        "进程与服务": {"内存占用靠前进程": "原样进程名 (PID 9, 2.0 GB)"},
    }
    original = copy.deepcopy(summary)
    en_display = display_summary(summary, "en-US")
    zh_display = display_summary(summary, "zh-CN")
    result = AnalysisResult(status="PARTIAL")
    metadata = {"evidence_summary": summary}
    en_md = render_markdown(result, metadata, "en-US")
    en_html = render_html(result, metadata, "en-US")
    zh_md = render_markdown(result, metadata, "zh-CN")

    assert "Hardware" in en_display and "CPU" in en_display["Hardware"]
    assert "CPU model" in en_display["Device"] and en_display["Device"]["CPU model"] == "合成CPU 型号"
    assert en_display["Disk capacity and free space"]["Volume free space"] == "C: 5.0 GB free / 100.0 GB total (5.0%)"
    assert "磁盘容量与剩余空间" in zh_display
    assert "CPU=合成CPU 型号" in zh_md
    assert "Volume free space=C: 5\\.0 GB free / 100\\.0 GB total" in en_md
    assert "Volume free space=C: 5.0 GB free / 100.0 GB total (5.0%)" in en_html
    assert "原样进程名" in en_md and "原样进程名" in en_html
    assert metadata["evidence_summary"] == original


def test_actual_cli_local_summary_is_localized_in_human_reports_only() -> None:
    from inspection_cli import _local_summary
    collectors = {
        "system_info": {"status": "ok", "data": {"os": "合成OS 原样保留", "version": "合成版本"}},
        "cpu": {"status": "ok", "data": {"name": "合成CPU 原样保留", "logical_processors": 8}},
        "disks": {"status": "partial", "data": {"VolumeSummary": [
            {"Drive": "C:", "Free": 5368709120, "Size": 107374182400, "FreePercent": 5.0}] }},
        "services": {"status": "ok", "data": []},
        "network_ports": {"status": "ok", "data": []},
    }
    summary = _local_summary(collectors)
    original = copy.deepcopy(summary)
    result = AnalysisResult(status="PARTIAL")
    metadata = {"evidence_summary": summary}
    en_md = render_markdown(result, metadata, "en-US")
    en_html = render_html(result, metadata, "en-US")
    assert "Device" in en_md and "Operating system" in en_md
    assert "合成OS 原样保留" in en_md and "合成CPU 原样保留" in en_md
    assert "Disk free space" in en_md and "GB free" in en_md
    assert "Disk free space" in en_html and "GB free" in en_html
    assert "设备" not in en_md and "磁盘剩余空间" not in en_md
    assert summary == original


def test_local_summary_missing_facts_localize_only_generated_unknowns() -> None:
    from inspection_cli import _local_summary
    collectors = {
        "system_info": {"status": "partial", "data": {"os": "SYNTH-OS", "CPU": "未知"}},
        "cpu": {"status": "partial", "data": {"name": "未知"}},
        "disks": {"status": "partial", "data": {"VolumeSummary": [{"Drive": "SYNTH:"}]}},
        "windows_security": {"status": "partial", "data": {}},
    }
    summary = _local_summary(collectors)
    en_display = display_summary(summary, "en-US")
    zh_display = display_summary(summary, "zh-CN")

    assert "system_info" in en_display["Collection status"]
    assert "system_info" in zh_display["采集状态"]
    assert en_display["Device"]["Operating system"] == "SYNTH-OS"
    assert en_display["Device"]["CPU model"] == "未知"
    assert en_display["Processes and security baseline"]["RDP enabled"] == "Unknown"
    assert en_display["Processes and security baseline"]["RDP requires NLA"] == "Unknown"
    assert en_display["Processes and security baseline"]["SMB1 enabled"] == "Unknown"
    assert en_display["Processes and security baseline"]["Autologon enabled"] == "Unknown"
    assert en_display["Processes and security baseline"]["Local account count"] == "Unknown"
    assert en_display["Processes and security baseline"]["Built-in Guest enabled"] == "Unknown"
    assert en_display["Processes and security baseline"]["Firewall profiles"] == "Unknown"
    assert en_display["Processes and security baseline"]["Password policy read status"] == "Unknown"
    assert en_display["Capacity and services"]["Disk free space"] == "SYNTH: Unknown free / Unknown total (percentage unknown)"
    assert "未知 可用" in zh_display["容量与服务"]["磁盘剩余空间"]


def test_legacy_partial_disk_missing_cells_are_localized_without_rewriting_raw_value() -> None:
    results = {"disks": {"status": "partial", "collector": "disks", "data": {
        "VolumeSummary": [{"Drive": "SYNTH-VOL"}], "PhysicalDisks": [{"Model": "SYNTH-DISK"}],
        "BitLocker": [{"MountPoint": "SYNTH-VOL"}] }},
        "startup_items": {"status": "partial", "data": {"Items": [{"Name": "SYNTH-STARTUP"}]}}}
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report(results, AnalysisResult(status="PARTIAL"), output, Path(temp) / "raw", language="en-US")
        rendered = output.read_text(encoding="utf-8")
    assert "Unconfirmed" in rendered
    assert "未确认" not in rendered
    assert "SYNTH-VOL" in rendered and "SYNTH-DISK" in rendered and "SYNTH-STARTUP" in rendered


def test_every_bundled_rule_displays_all_curated_human_fields_in_english() -> None:
    import json
    rule_files = (ROOT / "rules" / "windows_risk_rules.example.json",
                  ROOT / "rules" / "platform_risk_rules.example.json",
                  ROOT / "rules" / "listener_knowledge.example.json")
    key_map = {"id": "finding_id", "name": "title", "condition_description": "description", "risk": "impact"}
    for path in rule_files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        for rule in payload["rules"]:
            finding = {key_map.get(key, key): value for key, value in rule.items() if key in {
                "id", "name", "title", "condition_description", "description", "risk", "impact", "recommendation",
                "precheck", "applicability", "rollback", "verification_checkpoint", "severity"}}
            finding["rule_id"] = rule["id"]
            shown = display_finding(finding, "en-US")
            prose = [shown.get(field, "") for field in ("title", "description", "impact", "recommendation",
                     "verification_checkpoint", "precheck", "applicability", "rollback")]
            assert not [value for value in prose if isinstance(value, str) and re.search(r"[\u4e00-\u9fff]", value)], rule["id"]


def test_locale_resource_inventory_is_complete() -> None:
    validate_resources()


def test_missing_required_locale_resource_fails_actual_report_render() -> None:
    key = "report.title"
    saved = locale_findings._TEXT.pop(key)
    try:
        try:
            render_markdown(AnalysisResult(status="PARTIAL"), {}, "en-US")
        except LocaleResourceError as exc:
            assert "report resource inventory" in str(exc)
        else:
            raise AssertionError("report rendering must fail when a required resource key is missing")
    finally:
        locale_findings._TEXT[key] = saved


def test_empty_required_locale_resource_fails_actual_report_render() -> None:
    key = "report.title"
    saved = locale_findings._TEXT[key]
    locale_findings._TEXT[key] = (saved[0], " ")
    try:
        try:
            render_markdown(AnalysisResult(status="PARTIAL"), {}, "en-US")
        except LocaleResourceError as exc:
            assert f"text:{key}" in str(exc)
        else:
            raise AssertionError("report rendering must fail when a required locale value is empty")
    finally:
        locale_findings._TEXT[key] = saved


def test_missing_finding_fields_get_localized_fallbacks_and_unknown_gap_stays_verbatim() -> None:
    result = AnalysisResult(status="PARTIAL", findings=[{"finding_id": "UNMAPPED", "title": "External", "severity": "Info"}],
                            warnings=["custom analyzer note"])
    md = render_markdown(result, {}, "en-US")
    csv_text = render_csv(result, "en-US")
    assert "Review impact scope, maintenance window, and backups" in md
    assert "custom analyzer note" in md
    assert "source text retained" in md
    assert "Manual review required" in csv_text
    assert "custom analyzer note" in csv_text


def test_legacy_english_translates_section_labels_but_keeps_collected_values() -> None:
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        results = {"system_info": {"data": {}}, "startup_items": {"status": "ok", "data": {"Items": [
            {"Name": "KeepThisStartup", "Scope": "user", "SourceType": "Registry", "Command": "C:\\tool.exe"}
        ]}}}
        render_report(results, [], output, Path(temp) / "raw", language="en-US")
        rendered = output.read_text(encoding="utf-8")
    assert "Startup items" in rendered
    assert "Startup item details" in rendered
    assert "Scope" in rendered and "Command/target" in rendered
    assert "KeepThisStartup" in rendered and "C:\\tool.exe" in rendered


def test_legacy_empty_partial_report_has_no_untranslated_builtin_chinese() -> None:
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report({}, AnalysisResult(status="PARTIAL"), output, Path(temp) / "raw", language="en-US")
        rendered = output.read_text(encoding="utf-8")
    remaining = [line for line in rendered.splitlines() if re.search(r"[\u4e00-\u9fff]", line)]
    assert remaining == []


def test_legacy_english_translates_empty_windows_module_summaries() -> None:
    keys = ("system_info", "users", "services", "network_ports", "scheduled_tasks", "startup_items",
            "security_vendors", "firewall", "remote_desktop", "shares", "disks", "event_logs")
    results = {key: {"status": "ok", "data": {}} for key in keys}
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report(results, AnalysisResult(status="PARTIAL"), output, Path(temp) / "raw", language="en-US")
        rendered = output.read_text(encoding="utf-8")
    remaining = [line for line in rendered.splitlines() if re.search(r"[\u4e00-\u9fff]", line)]
    assert remaining == []
    assert "File and Printer Sharing rule summary" in rendered
    assert "RDP listener:" in rendered


def test_legacy_english_translates_populated_windows_module_headers() -> None:
    results = {
        "system_info": {"status": "ok", "data": {}}, "users": {"status": "ok", "data": []},
        "services": {"status": "ok", "data": []}, "network_ports": {"status": "ok", "data": []},
        "scheduled_tasks": {"status": "ok", "data": []}, "event_logs": {"status": "ok", "data": []},
        "startup_items": {"status": "ok", "data": {"Items": [{"Name": "KeepName", "Command": "C:/app.exe"}]}},
        "security_vendors": {"status": "ok", "data": {"Items": [], "Summary": {}}},
        "firewall": {"status": "ok", "data": {"Profiles": [{"Name": "Public", "Enabled": True,
            "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"}],
            "SmbInboundRules": [{"Name": "SMB", "Enabled": True, "Action": "Allow", "Profile": "Domain"}],
            "RemoteDesktopInboundRules": [{"Name": "RDP", "Enabled": True, "Action": "Allow", "Profile": "Private"}]}},
        "remote_desktop": {"status": "ok", "data": {"Settings": {"RemoteDesktopEnabled": True, "PortNumber": 3389},
            "TermService": {"Status": "Running", "StartType": "Manual"},
            "Listeners": [{"LocalAddress": "0.0.0.0", "LocalPort": 3389, "ProcessName": "svchost", "OwningProcess": 99}],
            "FirewallRules": []}},
        "shares": {"status": "ok", "data": {"Shares": [{"Name": "Docs", "Path": "C:/Docs", "ShareType": "Disk",
            "IsDefaultAdminShare": False, "BroadAccessAccounts": ["Everyone"]}], "UsedFallback": False}},
        "disks": {"status": "ok", "data": {"VolumeSummary": [{"Drive": "C:", "FileSystem": "NTFS", "Size": 1000,
            "Free": 400, "FreePercent": 40, "Status": "OK"}], "PhysicalDisks": [{"Model": "Disk", "MediaType": "SSD",
            "BusType": "NVMe", "Size": 1000, "HealthStatus": "Healthy", "OperationalStatus": "Online"}],
            "BitLocker": [{"MountPoint": "C:", "VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On",
            "LockStatus": "Unlocked", "EncryptionPercentage": 100}]}}
    }
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report(results, AnalysisResult(status="PARTIAL"), output, Path(temp) / "raw", language="en-US")
        rendered = output.read_text(encoding="utf-8")
    assert [line for line in rendered.splitlines() if re.search(r"[\u4e00-\u9fff]", line)] == []
    assert "KeepName" in rendered and "C:/app.exe" in rendered and "Docs" in rendered


def test_legacy_localization_never_rewrites_raw_evidence_values_or_keys() -> None:
    results = {"firewall": {"collector": "firewall", "status": "ok", "data": {
        "Profiles": [{"Name": "状态", "Enabled": False, "DefaultInboundAction": "Allow", "DefaultOutboundAction": "Block"}]}}}
    finding = {"finding_id": "CUSTOM_RAW", "title": "External", "severity": "Info", "evidence": {
        "说明": "无数据。", "state": "未检测到", "raw_missing_word": "未确认"}}
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report(results, [finding], output, Path(temp) / "raw", language="en-US")
        rendered = output.read_text(encoding="utf-8")
    assert "| 状态 | False | Allow | Block |" in rendered
    assert "说明：无数据。" in rendered
    assert "state：未检测到" in rendered
    assert "raw_missing_word：未确认" in rendered


def main() -> int:
    test_standard_warning_severity_is_counted_in_summary()
    test_standard_need_admin_severity_is_counted_separately()
    test_standard_finding_fields_are_rendered()
    test_legacy_finding_fields_are_still_rendered()
    test_unknown_severity_falls_back_to_info_without_breaking_report()
    test_curated_english_finding_is_localized_without_changing_machine_fields()
    test_unknown_external_finding_is_preserved_and_marked_in_both_reports()
    test_builtin_and_unknown_reasons_are_localized_or_marked()
    test_severity_meanings_preserve_tokens_and_caveats_in_reports()
    test_unified_report_uses_english_headings_and_keeps_severity_token()
    test_legacy_report_localizes_curated_finding_and_preserves_raw_id()
    test_missing_finding_fields_get_localized_fallbacks_and_unknown_gap_stays_verbatim()
    test_legacy_english_translates_section_labels_but_keeps_collected_values()
    test_legacy_empty_partial_report_has_no_untranslated_builtin_chinese()
    test_legacy_english_translates_empty_windows_module_summaries()
    test_legacy_english_translates_populated_windows_module_headers()
    test_legacy_localization_never_rewrites_raw_evidence_values_or_keys()
    test_smb_listener_remediation_preserves_port_445_safety_condition()
    test_lifecycle_dynamic_title_and_english_description_are_localized()
    test_lifecycle_coverage_gap_description_and_warning_are_localized()
    test_linux_builtin_dynamic_fields_are_localized_without_mutation()
    test_synthetic_windows_bundle_analyze_evidence_renders_english_findings()
    test_analyzer_platform_description_survives_rule_catalog_merge_and_localizes()
    test_unified_summary_localizes_owned_labels_and_templates_preserving_raw_facts()
    test_actual_cli_local_summary_is_localized_in_human_reports_only()
    test_legacy_partial_disk_missing_cells_are_localized_without_rewriting_raw_value()
    test_every_bundled_rule_displays_all_curated_human_fields_in_english()
    test_locale_resource_inventory_is_complete()
    test_missing_required_locale_resource_fails_actual_report_render()
    test_empty_required_locale_resource_fails_actual_report_render()
    print("Markdown report tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
