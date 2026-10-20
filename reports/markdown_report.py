from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from models.analysis import AnalysisResult

MAX_DETAIL_ROWS = 20
SECURITY_VENDOR_DETAIL_LIMIT = 10
SECURITY_VENDOR_ERROR_LIMIT = 5
SECURITY_VENDOR_FINDING_IDS = {
    "WIN_SECURITY_VENDOR_PRESENT",
    "WIN_SECURITY_VENDOR_RESIDUE",
    "WIN_SECURITY_VENDOR_DRIVER_REVIEW",
}
SENSITIVE_REPORT_KEYS = {"uninstall_string", "quiet_uninstall_string"}
SEVERITY_ORDER = [
    "Critical",
    "Attention",
    "Warning",
    "Need Admin",
    "Info",
    "OK",
    "Skipped",
    "Failed",
]
SEVERITY_ALIASES = {
    "critical": "Critical",
    "crit": "Critical",
    # HIGH/MEDIUM/LOW are accepted only as legacy input; reports display standard severity.
    "high": "Critical",
    "attention": "Attention",
    "medium": "Attention",
    "warning": "Warning",
    "warn": "Warning",
    "low": "Warning",
    "need admin": "Need Admin",
    "need_admin": "Need Admin",
    "need-admin": "Need Admin",
    "info": "Info",
    "informational": "Info",
    "ok": "OK",
    "passed": "OK",
    "skipped": "Skipped",
    "skip": "Skipped",
    "failed": "Failed",
    "fail": "Failed",
}


def render_report(
    results: dict[str, Any],
    analysis: AnalysisResult | list[dict[str, Any]],
    output_path: Path,
    raw_dir: Path,
) -> None:
    analysis_result = (
        analysis
        if isinstance(analysis, AnalysisResult)
        else AnalysisResult(status="OK", findings=analysis)
    )
    findings = analysis_result.findings
    system = results.get("system_info", {}).get("data", {})
    counts = Counter(_finding_severity(f) for f in findings)
    lines: list[str] = [
        "# Windows 巡检报告",
        "",
        "## Analysis Status",
        "",
        f"- **Analysis Status: {analysis_result.status}**",
    ]
    if analysis_result.status == "PARTIAL":
        lines.append("- **风险分析未完整完成；本报告不能作为完整的无风险结论。**")
    elif analysis_result.status == "FAILED":
        lines.append("- **风险分析失败；仅可使用已保留的采集证据进行人工复核。**")
    lines.extend(_configuration_status_lines(analysis_result))
    lines.extend([
        "",
        "## 1. 基本信息",
        f"- 主机名：{system.get('hostname', 'Unknown')}",
        f"- 操作系统：{system.get('os', 'Unknown')}",
        f"- 当前用户：{system.get('current_user', 'Unknown')}",
        f"- 是否管理员：{system.get('is_admin', False)}",
        f"- 巡检时间：{results.get('started_at', '')}",
        "",
        "## 2. 总体风险摘要",
        "",
        "| 等级 | 数量 |",
        "|---|---:|",
        *[f"| {severity} | {counts.get(severity, 0)} |" for severity in SEVERITY_ORDER],
        "",
        f"- 关键发现：{len(findings)}",
        "",
        "## 3. 重点风险",
    ])
    if findings:
        for item in findings:
            _finding_section(lines, item)
    elif analysis_result.status == "OK":
        lines.extend(["未发现需要优先展示的风险。", ""])
    else:
        lines.extend(["风险分析未完整执行，不能据此判断为未发现风险。", ""])

    _section(lines, "4. 系统信息", results.get("system_info"))
    _section(lines, "5. 用户与权限", results.get("users"))
    _section(lines, "6. 服务", results.get("services"), limit=20)
    _section(lines, "7. 网络端口", results.get("network_ports"), limit=50)
    _section(lines, "8. 计划任务", results.get("scheduled_tasks"), limit=30)
    _startup_items_section(lines, results.get("startup_items"))
    _security_vendors_section(lines, results.get("security_vendors"), findings)
    _firewall_section(lines, results.get("firewall"))
    _remote_desktop_section(lines, results.get("remote_desktop"))
    _shares_section(lines, results.get("shares"))
    _disks_section(lines, results.get("disks"))
    _section(lines, "13. 事件日志摘要", results.get("event_logs"), limit=20)
    lines.extend([
        "## 14. 原始数据位置",
        f"- `{raw_dir}`",
        "",
        "## 15. 本次巡检限制与不确定项",
        "- 本工具只读采集并提示风险，不自动修复。",
        "- 普通权限下部分信息可能缺失。",
        "- 端口、账号、计划任务等发现需要结合业务背景人工确认。",
        "- 报告只展示关键摘要和前若干条明细，完整结构化数据见 raw。",
        "",
    ])
    output_path.write_text("\n".join(lines), encoding="utf-8")


def _configuration_status_lines(analysis: AnalysisResult) -> list[str]:
    evidence = analysis.config_evidence
    labels = (
        ("Default registry", "default_registry"),
        ("User override", "user_override"),
        ("Local profile", "local_profile"),
    )
    lines = ["- Configuration:"]
    for label, key in labels:
        item = evidence.get(key, {})
        status = str(item.get("status") or "not_provided")
        detail = ""
        if key == "default_registry" and item.get("registry_version"):
            detail = f" (registry {item['registry_version']})"
        elif item.get("applied") is True:
            detail = " (applied)"
        lines.append(f"  - {label}: {status}{detail}")
    for message in analysis.errors[:5]:
        lines.append(f"  - Error: {_safe_error_text(message, 180)}")
    if len(analysis.errors) > 5:
        lines.append(f"  - Additional errors not expanded: {len(analysis.errors) - 5}")
    for message in analysis.warnings[:5]:
        lines.append(f"  - Warning: {_safe_error_text(message, 180)}")
    return lines


def _finding_section(lines: list[str], item: dict[str, Any]) -> None:
    title = item.get("title") or item.get("name") or "未命名风险"
    severity = _finding_severity(item)
    evidence = item.get("evidence") or item.get("risk") or item.get("发现依据") or ""

    lines.append(f"### {title}")
    if item.get("finding_id"):
        lines.append(f"- Finding ID：{item.get('finding_id')}")
    lines.append(f"- 风险等级：{severity}")
    if item.get("base_severity"):
        lines.append(f"- 原始风险等级：{normalize_severity(item.get('base_severity'))}")
    if item.get("local_profile_disposition"):
        lines.append(f"- 本机配置审计注释：{item.get('local_profile_disposition')}")
        annotations = item.get("local_profile_annotations")
        if isinstance(annotations, list):
            match_types = sorted({
                str(annotation.get("match_type"))
                for annotation in annotations
                if isinstance(annotation, dict) and annotation.get("match_type")
            })
            if match_types:
                lines.append(f"- 本机配置匹配类型：{', '.join(match_types)}")
    if item.get("category"):
        lines.append(f"- 分类：{item.get('category')}")
    if item.get("component"):
        lines.append(f"- 组件：{item.get('component')}")
    if item.get("description"):
        lines.append(f"- 描述：{item.get('description')}")
    lines.extend(_format_evidence(evidence))
    if item.get("precheck"):
        lines.append(f"- 整改前核查：{item.get('precheck')}")
    if item.get("applicability"):
        lines.append(f"- 适用条件：{item.get('applicability')}")
    lines.append(f"- 可能影响：{item.get('impact', '未确认')}")
    lines.append(f"- 建议下一步检查：{item.get('recommendation', '未确认')}")
    if item.get("rollback"):
        lines.append(f"- 回滚方法：{item.get('rollback')}")
    if item.get("verification_checkpoint"):
        lines.append(f"- 验证检查点：{item.get('verification_checkpoint')}")
    references = item.get("references")
    if isinstance(references, list) and references:
        lines.append("- 资料来源：" + "；".join(str(source) for source in references))
    if item.get("needs_human_review") is True:
        lines.append("- 人工复核：需人工确认")
    lines.append(f"- 是否自动修复：{item.get('auto_fix', '否')}")
    lines.append("")


def _finding_severity(item: dict[str, Any]) -> str:
    return normalize_severity(item.get("severity") or item.get("level") or item.get("risk"))


def normalize_severity(value: Any) -> str:
    if value is None:
        return "Info"
    text = str(value).strip()
    if not text:
        return "Info"
    key = text.replace("_", " ").replace("-", " ").casefold()
    key = " ".join(key.split())
    return SEVERITY_ALIASES.get(key, "Info")


def _format_evidence(evidence: Any) -> list[str]:
    if isinstance(evidence, dict):
        lines = ["- 证据："]
        safe_items = [
            (key, value)
            for key, value in evidence.items()
            if str(key).casefold() not in SENSITIVE_REPORT_KEYS
        ]
        for key, value in safe_items[:10]:
            lines.append(f"  - {key}：{_short(_compact(value), 240)}")
        if len(safe_items) > 10:
            lines.append("  - 仅展示前 10 个证据字段，完整数据见 raw。")
        return lines
    if isinstance(evidence, list):
        lines = ["- 证据："]
        for index, value in enumerate(evidence[:10], start=1):
            lines.append(f"  - {index}. {_short(_compact(value), 240)}")
        if len(evidence) > 10:
            lines.append("  - 仅展示前 10 条证据，完整数据见 raw。")
        return lines
    return [f"- 发现依据：{_value(evidence)}"]


def _section(lines: list[str], title: str, result: Any, limit: int = 10) -> None:
    lines.extend([f"## {title}", ""])
    if not result:
        lines.extend(["无数据。", ""])
        return
    lines.append(f"- Collector：{result.get('collector')}")
    lines.append(f"- 状态：{result.get('status')}")
    if result.get("errors"):
        lines.append(f"- 错误：{'; '.join(result.get('errors', []))}")
    data = result.get("data")
    rows = data if isinstance(data, list) else [data]
    lines.append("")
    for row in rows[:limit]:
        lines.append(f"- `{_compact(row)}`")
    if len(rows) > limit:
        lines.append(f"- 仅展示前 {limit} 条，完整数据见 raw。")
    lines.append("")


def _collector_header(lines: list[str], title: str, result: Any) -> bool:
    lines.extend([f"## {title}", ""])
    if not result:
        lines.extend(["- 状态：未采集 / Skipped", "- 说明：该 collector 未出现在本次结果中。", ""])
        return False
    lines.append(f"- Collector：{result.get('collector', '未确认')}")
    lines.append(f"- 状态：{result.get('status', '未确认')}")
    if result.get("errors"):
        lines.append(f"- 错误/限制：{'; '.join(str(item) for item in result.get('errors', []))}")
    lines.append("")
    return True


def _firewall_section(lines: list[str], result: Any) -> None:
    if not _collector_header(lines, "防火墙状态", result):
        return
    data = _dict(result.get("data"))
    profiles = _as_list(data.get("Profiles"))
    smb_rules = _as_list(data.get("SmbInboundRules"))
    rdp_rules = _as_list(data.get("RemoteDesktopInboundRules"))

    lines.append("### Profile 摘要")
    if profiles:
        lines.append("| Profile | 是否启用 | 默认入站 | 默认出站 |")
        lines.append("|---|---:|---|---|")
        for item in profiles:
            row = _dict(item)
            lines.append(
                f"| {_cell(row.get('Name'))} | {_cell(row.get('Enabled'))} | "
                f"{_cell(row.get('DefaultInboundAction'))} | {_cell(row.get('DefaultOutboundAction'))} |"
            )
    else:
        lines.append("未采集到 Profile 信息，需人工确认。")
    lines.append("")

    _firewall_rules_table(lines, "SMB-In / File and Printer Sharing 相关规则摘要", smb_rules)
    _firewall_rules_table(lines, "Remote Desktop 相关规则摘要", rdp_rules)


def _remote_desktop_section(lines: list[str], result: Any) -> None:
    if not _collector_header(lines, "远程桌面状态", result):
        return
    data = _dict(result.get("data"))
    settings = _dict(data.get("Settings"))
    service = _dict(data.get("TermService"))
    listeners = _as_list(data.get("Listeners"))
    rules = _as_list(data.get("FirewallRules"))

    enabled = settings.get("RemoteDesktopEnabled", "未确认")
    port = settings.get("PortNumber", "未确认")
    lines.extend([
        f"- Remote Desktop 是否启用：{_value(enabled)}",
        f"- RDP 端口：{_value(port)}",
        f"- TermService 状态：{_value(service.get('Status'))}",
        f"- TermService 启动类型：{_value(service.get('StartType'))}",
        f"- RDP 端口监听数量：{len(listeners)}",
        "",
    ])

    if listeners:
        lines.append("### RDP 监听摘要")
        lines.append("| LocalAddress | LocalPort | Process | PID |")
        lines.append("|---|---:|---|---:|")
        for item in listeners[:MAX_DETAIL_ROWS]:
            row = _dict(item)
            lines.append(
                f"| {_cell(row.get('LocalAddress'))} | {_cell(row.get('LocalPort'))} | "
                f"{_cell(row.get('ProcessName'))} | {_cell(row.get('OwningProcess'))} |"
            )
        if len(listeners) > MAX_DETAIL_ROWS:
            lines.append(f"- 仅展示前 {MAX_DETAIL_ROWS} 条，完整数据见 raw。")
    else:
        lines.append("- RDP 监听：未发现或未采集到，需结合防火墙和服务状态人工确认。")
    lines.append("")
    _firewall_rules_table(lines, "Remote Desktop 防火墙规则摘要", rules)


def _shares_section(lines: list[str], result: Any) -> None:
    if not _collector_header(lines, "共享目录", result):
        return
    data = _dict(result.get("data"))
    shares = _as_list(data.get("Shares"))
    default_count = sum(1 for item in shares if _dict(item).get("IsDefaultAdminShare"))
    non_default_count = len(shares) - default_count
    broad = [_dict(item) for item in shares if _dict(item).get("HasBroadAccess")]

    lines.extend([
        f"- 共享数量：{len(shares)}",
        f"- 默认管理共享数量：{default_count}",
        f"- 非默认共享数量：{non_default_count}",
        f"- Everyone / Guest / Anonymous 权限线索：{'发现，需人工确认' if broad else '未发现'}",
        f"- 是否使用 fallback：{_value(data.get('UsedFallback'))}",
        "",
    ])

    if shares:
        lines.append("### 共享明细")
        lines.append("| 名称 | 路径 | 类型 | 默认管理共享 | 宽泛权限线索 |")
        lines.append("|---|---|---|---:|---|")
        for item in shares[:MAX_DETAIL_ROWS]:
            row = _dict(item)
            lines.append(
                f"| {_cell(row.get('Name'))} | {_cell(row.get('Path'))} | {_cell(row.get('ShareType'))} | "
                f"{_cell(row.get('IsDefaultAdminShare'))} | {_cell(row.get('BroadAccessAccounts') or '无')} |"
            )
        if len(shares) > MAX_DETAIL_ROWS:
            lines.append(f"- 仅展示前 {MAX_DETAIL_ROWS} 条，完整数据见 raw。")
    else:
        lines.append("未采集到结构化共享明细；如使用 fallback，请查看 raw。")
    lines.append("")


def _disks_section(lines: list[str], result: Any) -> None:
    if not _collector_header(lines, "磁盘与卷", result):
        return
    data = _dict(result.get("data"))
    volumes = _as_list(data.get("VolumeSummary"))
    physical = _as_list(data.get("PhysicalDisks")) or _as_list(data.get("DiskDrives"))
    bitlocker = _as_list(data.get("BitLocker"))
    findings = _as_list(data.get("Findings"))

    if volumes:
        lines.append("### 逻辑盘与空间")
        lines.append("| 盘符 | 文件系统 | 总容量 | 剩余空间 | 剩余百分比 | 状态 |")
        lines.append("|---|---|---:|---:|---:|---|")
        for item in volumes[:MAX_DETAIL_ROWS]:
            row = _dict(item)
            lines.append(
                f"| {_cell(row.get('Drive'))} | {_cell(row.get('FileSystem'))} | {_cell(_bytes(row.get('Size')))} | "
                f"{_cell(_bytes(row.get('Free')))} | {_cell(_percent(row.get('FreePercent')))} | {_cell(row.get('Status'))} |"
            )
        if len(volumes) > MAX_DETAIL_ROWS:
            lines.append(f"- 仅展示前 {MAX_DETAIL_ROWS} 条，完整数据见 raw。")
    else:
        lines.append("未采集到逻辑盘空间摘要，需人工确认。")
    lines.append("")

    lines.append("### 物理磁盘健康状态")
    if physical:
        lines.append("| 名称/型号 | 介质 | 接口 | 容量 | 健康状态 | 运行状态 |")
        lines.append("|---|---|---|---:|---|---|")
        for item in physical[:MAX_DETAIL_ROWS]:
            row = _dict(item)
            lines.append(
                f"| {_cell(row.get('FriendlyName') or row.get('Model'))} | {_cell(row.get('MediaType'))} | "
                f"{_cell(row.get('BusType') or row.get('InterfaceType'))} | {_cell(_bytes(row.get('Size')))} | "
                f"{_cell(row.get('HealthStatus') or row.get('Status'))} | {_cell(row.get('OperationalStatus'))} |"
            )
    else:
        lines.append("未采集到物理磁盘健康状态，需人工确认。")
    lines.append("")

    lines.append("### BitLocker 状态")
    if result.get("status") == "need_admin" and not bitlocker:
        lines.append("BitLocker 状态需要管理员权限复查。")
    elif bitlocker:
        lines.append("| 卷 | 卷状态 | 保护状态 | 锁定状态 | 加密进度 |")
        lines.append("|---|---|---|---|---:|")
        for item in bitlocker[:MAX_DETAIL_ROWS]:
            row = _dict(item)
            lines.append(
                f"| {_cell(row.get('MountPoint'))} | {_cell(row.get('VolumeStatus'))} | "
                f"{_cell(row.get('ProtectionStatus'))} | {_cell(row.get('LockStatus'))} | "
                f"{_cell(_percent(row.get('EncryptionPercentage')))} |"
            )
    else:
        lines.append("未采集到 BitLocker 信息，可能为不支持、未启用或权限不足。")
    if findings:
        lines.append("")
        lines.append("### 磁盘线索")
        for item in findings[:MAX_DETAIL_ROWS]:
            lines.append(f"- {_value(item)}")
    lines.append("")


def _startup_items_section(lines: list[str], result: Any) -> None:
    if not _collector_header(lines, "启动项", result):
        return
    data = _dict(result.get("data"))
    items = _as_list(data.get("Items"))

    lines.extend([
        f"- 启动项总数：{len(items)}",
        "- 风险判断：统一由 AnalysisResult Findings 提供，本节仅展示 Collector 事实。",
        "",
    ])

    if items:
        lines.append("### 启动项明细")
        lines.append("| 名称 | 范围 | 来源 | 命令/目标 |")
        lines.append("|---|---|---|---|")
        for item in items[:MAX_DETAIL_ROWS]:
            row = _dict(item)
            lines.append(
                f"| {_cell(row.get('Name'))} | {_cell(row.get('Scope'))} | {_cell(row.get('SourceType'))} | "
                f"{_cell(_short(row.get('Command'), 160))} |"
            )
        if len(items) > MAX_DETAIL_ROWS:
            lines.append(f"- 仅展示前 {MAX_DETAIL_ROWS} 条，完整数据见 raw。")
    else:
        lines.append("未采集到启动项或当前环境无启动项。")
    lines.append("")


def _security_vendors_section(
    lines: list[str],
    result: Any,
    findings: list[dict[str, Any]],
) -> None:
    lines.extend([
        "## 安全软件与电脑管家组件",
        "",
        "检测到安全软件或电脑管家组件不等于恶意。本章节用于确认已安装软件、相关驱动和卸载残留线索，不会自动卸载、删除或修改系统设置。",
        "",
        "### 检测摘要",
        "",
    ])
    if not isinstance(result, dict):
        lines.extend(["- 采集状态：未执行此项检查", ""])
        return

    data = _dict(result.get("data"))
    summary = _dict(data.get("summary"))
    installed = [_dict(item) for item in _as_list(data.get("installed_programs")) if isinstance(item, dict)]
    drivers = [_dict(item) for item in _as_list(data.get("drivers")) if isinstance(item, dict)]
    directories = [_dict(item) for item in _as_list(data.get("directories")) if isinstance(item, dict)]
    vendor_findings = [
        item
        for item in findings
        if isinstance(item, dict) and item.get("finding_id") in SECURITY_VENDOR_FINDING_IDS
    ]
    grouped = _group_security_vendor_report_items(installed, drivers, directories, vendor_findings, summary)
    status = str(result.get("status") or "").casefold()
    status_label = {
        "ok": "OK",
        "partial": "部分完成",
        "need_admin": "需要管理员权限",
        "skipped": "已跳过",
        "failed": "采集失败",
    }.get(status, "未确认")

    if status == "ok" and not grouped and not vendor_findings:
        lines.extend([
            f"- 采集状态：{status_label}",
            "- 未检测到已知安全软件或电脑管家组件。",
            "",
        ])
        return

    installed_vendors = {
        str(item.get("matched_vendor"))
        for item in installed
        if item.get("matched_vendor")
    }
    review_count = sum(1 for item in vendor_findings if item.get("needs_human_review") is True)
    vendor_names = sorted(grouped)
    lines.extend([
        "| 项目 | 结果 |",
        "|---|---|",
        f"| 采集状态 | {_cell(status_label)} |",
        f"| 检测到的厂商 | {_cell('、'.join(vendor_names) or '未检测到')} |",
        f"| 已安装厂商数量 | {_cell(summary.get('installed_vendor_count', len(installed_vendors)))} |",
        f"| 已安装程序数量 | {len(installed)} |",
        f"| 相关驱动数量 | {_cell(summary.get('driver_count', len(drivers)))} |",
        f"| 相关目录数量 | {_cell(summary.get('directory_count', len(directories)))} |",
        f"| 需人工复核 | {review_count} |",
        "",
    ])
    _security_vendor_errors(lines, result.get("errors"))

    if len(vendor_names) > 1:
        lines.extend([
            "检测到多个安全软件或电脑管家组件，可能存在功能重复或资源占用，需要结合用户实际用途确认。",
            "",
        ])

    if not vendor_names:
        lines.extend(["未获得可聚合的厂商明细。", ""])
        return

    for vendor in vendor_names:
        group = grouped[vendor]
        installed_items = group["installed_programs"]
        driver_items = group["drivers"]
        directory_items = group["directories"]
        finding_items = group["findings"]
        residue = any(item.get("finding_id") == "WIN_SECURITY_VENDOR_RESIDUE" for item in finding_items)
        service_present = any(_dict(item.get("evidence")).get("service_present") for item in finding_items)
        if installed_items:
            vendor_state = "已安装"
        elif residue:
            vendor_state = "疑似残留"
        elif driver_items:
            vendor_state = "相关驱动线索"
        elif directory_items:
            vendor_state = "仅目录痕迹"
        else:
            vendor_state = "需人工确认"

        lines.extend([
            f"### {_heading(vendor)}",
            "",
            f"- 状态：{vendor_state}",
            f"- 已安装程序：{len(installed_items)}",
            f"- 服务线索：{'有' if service_present else '无或未确认'}",
            f"- 驱动：{len(driver_items)}",
            f"- 目录：{len(directory_items)}",
            "- 说明：检测到软件存在不等于恶意，所有线索均需结合用户用途人工确认。",
            "",
        ])
        _security_vendor_installed_table(lines, installed_items)
        _security_vendor_driver_table(lines, driver_items)
        _security_vendor_directory_table(lines, directory_items)
        _security_vendor_finding_summary(lines, finding_items)


def _group_security_vendor_report_items(
    installed: list[dict[str, Any]],
    drivers: list[dict[str, Any]],
    directories: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}

    def group(vendor: Any) -> dict[str, list[dict[str, Any]]] | None:
        name = str(vendor or "").strip()
        if not name:
            return None
        return grouped.setdefault(name, {
            "installed_programs": [],
            "drivers": [],
            "directories": [],
            "findings": [],
        })

    for vendor in _as_list(summary.get("vendors_detected")):
        group(vendor)
    for item in installed:
        target = group(item.get("matched_vendor"))
        if target is not None:
            target["installed_programs"].append(item)
    for item in drivers:
        target = group(item.get("matched_vendor"))
        if target is not None:
            target["drivers"].append(item)
    for item in directories:
        target = group(item.get("matched_vendor"))
        if target is not None:
            target["directories"].append(item)
    for item in findings:
        target = group(_dict(item.get("evidence")).get("vendor"))
        if target is not None:
            target["findings"].append(item)
    return grouped


def _security_vendor_installed_table(lines: list[str], items: list[dict[str, Any]]) -> None:
    if not items:
        return
    lines.extend([
        "#### 已安装程序",
        "",
        "| 产品名称 | 版本 | 发布者 | 安装位置 | 匹配厂商 | 匹配关键词 |",
        "|---|---|---|---|---|---|",
    ])
    for item in items[:SECURITY_VENDOR_DETAIL_LIMIT]:
        lines.append(
            f"| {_cell(item.get('display_name'))} | {_cell(item.get('display_version'))} | "
            f"{_cell(item.get('publisher'))} | {_cell(item.get('install_location'))} | "
            f"{_cell(item.get('matched_vendor'))} | {_cell(item.get('matched_keyword'))} |"
        )
    _security_vendor_overflow(lines, len(items))
    lines.append("")


def _security_vendor_driver_table(lines: list[str], items: list[dict[str, Any]]) -> None:
    if not items:
        return
    lines.extend([
        "#### 相关驱动",
        "",
        "检测到安全软件相关驱动不等于异常。驱动可能是正常在用组件，也可能是卸载残留；不建议自动删除，需要确认签名、状态、启动类型及文件路径。",
        "",
        "| 名称 | 显示名称 | 状态 | 启动模式 | 驱动路径 | 匹配厂商 |",
        "|---|---|---|---|---|---|",
    ])
    for item in items[:SECURITY_VENDOR_DETAIL_LIMIT]:
        lines.append(
            f"| {_cell(item.get('name'))} | {_cell(item.get('display_name'))} | {_cell(item.get('state'))} | "
            f"{_cell(item.get('start_mode'))} | {_cell(item.get('path_name'))} | "
            f"{_cell(item.get('matched_vendor'))} |"
        )
    _security_vendor_overflow(lines, len(items))
    lines.append("")


def _security_vendor_directory_table(lines: list[str], items: list[dict[str, Any]]) -> None:
    if not items:
        return
    lines.extend([
        "#### 目录辅助证据",
        "",
        "单独目录存在不等于软件仍在运行。空目录、日志目录或缓存目录不应直接判为 Warning，目录只作为辅助证据。",
        "",
        "| 路径 | 匹配厂商 | 匹配关键词 |",
        "|---|---|---|",
    ])
    for item in items[:SECURITY_VENDOR_DETAIL_LIMIT]:
        lines.append(
            f"| {_cell(item.get('path'))} | {_cell(item.get('matched_vendor'))} | "
            f"{_cell(item.get('matched_keyword'))} |"
        )
    _security_vendor_overflow(lines, len(items))
    lines.append("")


def _security_vendor_finding_summary(lines: list[str], items: list[dict[str, Any]]) -> None:
    if not items:
        return
    lines.extend(["#### 风险判断", ""])
    for item in items:
        review = "是" if item.get("needs_human_review") is True else "否"
        lines.extend([
            f"- {_finding_severity(item)}：{_value(item.get('title') or item.get('name'))}",
            f"  - 简短描述：{_short(item.get('description'), 200)}",
            f"  - 需要人工复核：{review}",
            f"  - 验证检查点：{_short(item.get('verification_checkpoint'), 200)}",
        ])
    lines.append("")


def _security_vendor_errors(lines: list[str], errors: Any) -> None:
    items = _as_list(errors)
    if not items:
        return
    lines.extend(["### 采集限制", ""])
    for item in items[:SECURITY_VENDOR_ERROR_LIMIT]:
        if isinstance(item, dict):
            source = _safe_error_text(item.get("source"), 40)
            status = _safe_error_text(item.get("status"), 40)
            message = _safe_error_text(item.get("message"), 180)
            lines.append(f"- {_value(source)} / {_value(status)}：{_value(message)}")
        else:
            lines.append(f"- {_safe_error_text(item, 180)}")
    if len(items) > SECURITY_VENDOR_ERROR_LIMIT:
        lines.append(f"- 另有 {len(items) - SECURITY_VENDOR_ERROR_LIMIT} 条错误未展开，请查看执行日志。")
    lines.append("")


def _security_vendor_overflow(lines: list[str], count: int) -> None:
    if count > SECURITY_VENDOR_DETAIL_LIMIT:
        lines.append(f"- 另有 {count - SECURITY_VENDOR_DETAIL_LIMIT} 条未展开，详见 raw 数据。")


def _safe_error_text(value: Any, limit: int) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    traceback_at = text.casefold().find("traceback")
    if traceback_at >= 0:
        text = text[:traceback_at].strip() or "错误详情已省略"
    text = re.sub(
        r"(?i)((?:/|--)(?:token|user|password|secret)|(?:token|password|secret)=)\s*[^\s]+",
        r"\1 [REDACTED]",
        text,
    )
    command_at = text.casefold().find("-command")
    if "powershell" in text.casefold() and command_at >= 0:
        text = f"{text[:command_at].strip()} -Command [已省略]"
    return text[:limit] + ("..." if len(text) > limit else "")


def _heading(value: Any) -> str:
    return _value(value).replace("\r", " ").replace("\n", " ").replace("#", "").strip()


def _firewall_rules_table(lines: list[str], title: str, rules: list[Any]) -> None:
    lines.append(f"### {title}")
    if not rules:
        lines.extend(["未采集到相关规则，需人工确认。", ""])
        return
    lines.append("| 显示名称 | Enabled | Direction | Action | Profile | Ports |")
    lines.append("|---|---:|---|---|---|---|")
    for item in rules[:MAX_DETAIL_ROWS]:
        row = _dict(item)
        lines.append(
            f"| {_cell(row.get('DisplayName') or row.get('Name'))} | {_cell(row.get('Enabled'))} | "
            f"{_cell(row.get('Direction'))} | {_cell(row.get('Action'))} | {_cell(row.get('Profile'))} | "
            f"{_cell(row.get('Ports'))} |"
        )
    if len(rules) > MAX_DETAIL_ROWS:
        lines.append(f"- 仅展示前 {MAX_DETAIL_ROWS} 条，完整数据见 raw。")
    lines.append("")


def _compact(value: Any) -> str:
    text = str(value).replace("\n", " ").replace("\r", " ")
    return text[:500] + ("..." if len(text) > 500 else "")


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _value(value: Any) -> str:
    if value is None or value == "":
        return "未确认"
    return str(value)


def _cell(value: Any) -> str:
    text = _value(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    return text


def _short(value: Any, limit: int) -> str:
    text = _value(value)
    return text[:limit] + ("..." if len(text) > limit else "")


def _bytes(value: Any) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "未确认"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.1f} {units[idx]}"


def _percent(value: Any) -> str:
    if value is None or value == "":
        return "未确认"
    try:
        return f"{float(value):.2f}%"
    except (TypeError, ValueError):
        return str(value)


def _join_clues(*groups: Any) -> str:
    clues: list[str] = []
    for group in groups:
        clues.extend(str(item) for item in _as_list(group) if item)
    return "; ".join(clues)
