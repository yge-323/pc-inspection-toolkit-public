from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from string import Formatter
from typing import Any

from i18n import normalize_language


class LocaleResourceError(RuntimeError):
    """Raised when a required built-in localization resource is missing or invalid."""


_TEXT = {
    "finding_source_note": ("规则文本按原文保留", "Rule text retained in its source language"),
    "severity.Critical": ("严重", "Critical"),
    "severity.Attention": ("重点关注", "Attention"),
    "severity.Warning": ("警告", "Warning"),
    "severity.Need Admin": ("需要管理员权限", "Need administrator"),
    "severity.Info": ("提示", "Informational"),
    "severity.OK": ("正常", "OK"),
    "severity.Skipped": ("已跳过", "Skipped"),
    "severity.Failed": ("失败", "Failed"),
    "severity.meaning.OK": ("正常或已确认符合预期的行为。", "Normal behavior or behavior confirmed as expected."),
    "severity.meaning.Info": ("提示性发现，无需立即采取行动。", "Informational finding; no immediate action is required."),
    "severity.meaning.Warning": ("需要人工确认，但不一定代表高风险。", "Requires manual confirmation but does not necessarily indicate high risk."),
    "severity.meaning.Attention": ("需要优先复核，因为可能影响安全、可用性或巡检结论。", "Requires priority review because it may affect security, availability, or the inspection conclusion."),
    "severity.meaning.Critical": ("存在明确的严重风险或高影响异常情况。", "A clear severe risk or high impact abnormal condition."),
    "severity.meaning.Need Admin": ("需要管理员权限才能获取更完整的数据；这不等同于 Critical。", "Administrator privileges are required for more complete data; this is not equivalent to Critical."),
    "severity.meaning.Skipped": ("不适用、不受支持、不可用或按计划跳过。", "Not applicable, unsupported, unavailable, or intentionally skipped."),
    "severity.meaning.Failed": ("采集或解析失败，需要复核。", "Collection or parsing failed and requires review."),
    "analysis.no_findings": ("没有生成确定性发现；未检查范围不代表安全。", "No deterministic findings were generated; unchecked areas are not confirmed safe."),
    "analysis.incomplete": ("分析不完整；缺失证据不代表未发现风险。", "Analysis is incomplete; missing evidence does not mean no risk was found."),
    "support.unavailable": ("生命周期规则不可用/未核实", "Lifecycle rules unavailable or unverified"),
    "support.unknown_coverage": ("版本覆盖未知，需人工核实", "Version coverage is unknown and requires manual review"),
    "support.unmatched": ("未匹配已核实生命周期记录；不代表仍受支持", "No verified lifecycle record matched; this does not mean the version is still supported"),
    "support.ended": ("常规支持已结束", "Standard support has ended"),
    "support.review": ("生命周期状态需人工核实", "Lifecycle status requires manual review"),
    "support.no_source": ("未匹配到准确版本的生命周期来源", "No lifecycle source matched the exact version"),
    "gap.none": ("无分析缺口记录", "No analysis gaps recorded"),
    "gap.no_findings": ("没有确定性发现；未检查范围不代表安全", "No deterministic findings; unchecked areas are not confirmed safe"),
    "report.title": ("PC 巡检证据分析报告", "PC Inspection Evidence Analysis Report"),
    "report.analysis_status": ("分析状态", "Analysis status"),
    "report.asset_alias": ("资产代号", "Asset alias"),
    "report.bundle": ("证据包", "Evidence bundle"),
    "report.target": ("目标", "Target"),
    "report.untrusted": ("证据均视为不可信输入。SHA-256 只能检查封装后的字节是否变化，不能证明来源真实性。", "Treat evidence as untrusted input. SHA-256 can detect changes to packaged bytes but cannot prove source authenticity."),
    "report.platform_support": ("平台支持状态", "Platform support status"),
    "report.hardware": ("硬件与采集摘要", "Hardware and collection summary"),
    "summary.group.硬件": ("硬件", "Hardware"),
    "summary.group.系统安全事实": ("系统安全事实", "System security facts"),
    "summary.group.Windows安全配置": ("Windows安全配置", "Windows security configuration"),
    "summary.group.磁盘容量与剩余空间": ("磁盘容量与剩余空间", "Disk capacity and free space"),
    "summary.group.进程与服务": ("进程与服务", "Processes and services"),
    "summary.group.设备": ("设备", "Device"),
    "summary.group.采集状态": ("采集状态", "Collection status"),
    "summary.group.账户与启动项": ("账户与启动项", "Accounts and startup items"),
    "summary.group.容量与服务": ("容量与服务", "Capacity and services"),
    "summary.group.进程与安全基线": ("进程与安全基线", "Processes and security baseline"),
    "summary.key.CPU": ("CPU", "CPU"),
    "summary.key.CPU数量": ("CPU数量", "Logical processors"),
    "summary.key.内存字节": ("内存字节", "Memory bytes"),
    "summary.key.内存KB": ("内存KB", "Memory KB"),
    "summary.key.显卡": ("显卡", "Graphics adapter"),
    "summary.key.显卡摘要": ("显卡摘要", "Graphics summary"),
    "summary.key.磁盘摘要": ("磁盘摘要", "Disk summary"),
    "summary.key.采集UID": ("采集UID", "Collected UID"),
    "summary.key.安全状态": ("安全状态", "Security status"),
    "summary.key.RDP拒绝连接标志": ("RDP拒绝连接标志", "RDP deny-connections flag"),
    "summary.key.RDP要求NLA": ("RDP要求NLA", "RDP requires NLA"),
    "summary.key.SMB1显式配置": ("SMB1显式配置", "Explicit SMB1 configuration"),
    "summary.key.自动登录标志": ("自动登录标志", "Autologon flag"),
    "summary.key.内置Guest启用": ("内置Guest启用", "Built-in Guest enabled"),
    "summary.key.最小密码长度": ("最小密码长度", "Minimum password length"),
    "summary.key.密码复杂度": ("密码复杂度", "Password complexity"),
    "summary.key.账户锁定阈值": ("账户锁定阈值", "Account lockout threshold"),
    "summary.key.密码策略读取状态": ("密码策略读取状态", "Password policy read status"),
    "summary.key.防火墙配置文件": ("防火墙配置文件", "Firewall profiles"),
    "summary.key.卷数": ("卷数", "Volume count"),
    "summary.key.卷剩余空间": ("卷剩余空间", "Volume free space"),
    "summary.key.进程采集记录数": ("进程采集记录数", "Process records collected"),
    "summary.key.内存占用靠前进程": ("内存占用靠前进程", "Processes using the most memory"),
    "summary.key.服务采集记录数": ("服务采集记录数", "Service records collected"),
    "summary.key.操作系统": ("操作系统", "Operating system"),
    "summary.key.版本": ("版本", "Version"),
    "summary.key.内部版本号": ("内部版本号", "Build number"),
    "summary.key.CPU型号": ("CPU型号", "CPU model"),
    "summary.key.CPU逻辑处理器": ("CPU逻辑处理器", "Logical processors"),
    "summary.key.账户数": ("账户数", "Account count"),
    "summary.key.管理员组成员数": ("管理员组成员数", "Administrators group members"),
    "summary.key.启动项数量": ("启动项数量", "Startup item count"),
    "summary.key.磁盘卷数量": ("磁盘卷数量", "Disk volume count"),
    "summary.key.服务数量": ("服务数量", "Service count"),
    "summary.key.网络端口记录数量": ("网络端口记录数量", "Network port records"),
    "summary.key.磁盘剩余空间": ("磁盘剩余空间", "Disk free space"),
    "summary.key.进程记录数": ("进程记录数", "Process records"),
    "summary.key.RDP启用": ("RDP启用", "RDP enabled"),
    "summary.key.RDP要求NLA": ("RDP要求NLA", "RDP requires NLA"),
    "summary.key.SMB1启用": ("SMB1启用", "SMB1 enabled"),
    "summary.key.自动登录启用": ("自动登录启用", "Autologon enabled"),
    "summary.key.本地账户数": ("本地账户数", "Local account count"),
    "summary.key.密码最小长度/复杂度/锁定阈值": ("密码最小长度/复杂度/锁定阈值", "Password minimum length / complexity / lockout threshold"),
    "report.coverage": ("证据覆盖", "Evidence coverage"),
    "report.item": ("项目", "Item"),
    "report.status": ("状态", "Status"),
    "report.exit_code": ("退出码", "Exit code"),
    "report.reason": ("说明", "Reason"),
    "report.source_note": ("原文提示", "Source text note"),
    "support_status": ("平台支持状态", "Platform support status"),
    "category": ("分类", "Category"),
    "report.findings": ("风险发现与整改", "Findings and remediation"),
    "report.description": ("描述", "Description"),
    "report.finding_id": ("编号", "Finding ID"),
    "report.finding_title": ("发现", "Finding"),
    "report.severity": ("等级", "Severity"),
    "report.severity_meaning": ("等级说明", "Severity meaning"),
    "report.evidence": ("证据", "Evidence"),
    "report.precheck": ("整改前核查", "Pre-change checks"),
    "report.applicability": ("适用条件", "Applicability"),
    "report.impact": ("影响与条件", "Impact and conditions"),
    "report.recommendation": ("整改步骤", "Recommended steps"),
    "report.rollback": ("回滚", "Rollback"),
    "report.verification": ("复查", "Verification"),
    "report.references": ("资料来源", "References"),
    "report.gaps": ("证据缺口", "Evidence gaps"),
    "report.ai": ("AI辅助建议（非正式结论）", "AI-assisted suggestions (not an official conclusion)"),
    "report.ai_separation": ("AI文本与确定性发现分开；不会改变分析状态或风险等级。", "AI text is separate from deterministic findings and does not change analysis status or severity."),
    "report.ai_reason": ("原因", "Reason"),
    "report.ai_refs": ("引用", "References"),
    "report.no_source": ("未匹配到准确版本来源", "No source matched the exact version"),
    "report.fallback_precheck": ("实施前核对影响范围、维护窗口与备份", "Review impact scope, maintenance window, and backups before implementation"),
    "report.fallback_applicability": ("平台/版本未核实", "Platform or version unverified"),
    "report.fallback_impact": ("需要人工复核", "Manual review required"),
    "report.fallback_recommendation": ("补充证据并人工检查", "Gather more evidence and review manually"),
    "report.fallback_rollback": ("未修改系统；获批变更前保留原始配置", "No system changes were made; preserve the original configuration before an approved change"),
    "report.fallback_verification": ("重新采集并比较证据", "Collect evidence again and compare"),
    "report.fallback_not_provided": ("未提供", "Not provided"),
    "report.html_badge": ("发现与整改建议", "Findings and recommendations"),
    "report.ai_status": ("建议与确定性发现分开，不改变分析结论。", "Suggestions remain separate from deterministic findings and do not change the analysis conclusion."),
    "legacy.title": ("Windows 巡检报告", "Windows Inspection Report"),
    "legacy.status_heading": ("Analysis Status", "Analysis Status"),
    "legacy.status": ("Analysis Status", "Analysis Status"),
    "legacy.incomplete": ("风险分析未完整完成；本报告不能作为完整的无风险结论。", "Risk analysis is incomplete; this report cannot be treated as a complete no-risk conclusion."),
    "legacy.failed": ("风险分析失败；仅可使用已保留的采集证据进行人工复核。", "Risk analysis failed; retained collection evidence is for manual review only."),
    "legacy.configuration": ("配置", "Configuration"),
    "legacy.default_registry": ("默认规则注册表", "Default registry"),
    "legacy.user_override": ("用户覆盖", "User override"),
    "legacy.local_profile": ("本机配置", "Local profile"),
    "legacy.error": ("错误", "Error"),
    "legacy.warning": ("警告", "Warning"),
    "legacy.additional_errors": ("另有 {count} 条错误未展开", "{count} additional errors omitted"),
    "legacy.basic": ("1. 基本信息", "1. Basic information"),
    "legacy.hostname": ("主机名", "Hostname"),
    "legacy.os": ("操作系统", "Operating system"),
    "legacy.user": ("当前用户", "Current user"),
    "legacy.admin": ("是否管理员", "Administrator"),
    "legacy.time": ("巡检时间", "Inspection time"),
    "legacy.summary": ("2. 总体风险摘要", "2. Risk summary"),
    "legacy.level": ("等级", "Severity"),
    "legacy.count": ("数量", "Count"),
    "legacy.key_findings": ("关键发现", "Findings"),
    "legacy.focus": ("3. 重点风险", "3. Findings requiring attention"),
    "legacy.no_findings": ("未发现需要优先展示的风险。", "No findings require priority display."),
    "legacy.incomplete_findings": ("风险分析未完整执行，不能据此判断为未发现风险。", "Risk analysis was incomplete; this does not establish that no risks were found."),
    "legacy.finding_id": ("发现编号", "Finding ID"),
    "legacy.severity": ("风险等级", "Severity"),
    "legacy.severity_meaning": ("等级说明", "Severity meaning"),
    "legacy.base_severity": ("原始风险等级", "Original severity"),
    "legacy.profile_note": ("本机配置审计注释", "Local profile audit note"),
    "legacy.match_type": ("本机配置匹配类型", "Local profile match type"),
    "legacy.category": ("分类", "Category"),
    "legacy.component": ("组件", "Component"),
    "legacy.description": ("描述", "Description"),
    "legacy.precheck": ("整改前核查", "Pre-change checks"),
    "legacy.applicability": ("适用条件", "Applicability"),
    "legacy.impact": ("可能影响", "Potential impact"),
    "legacy.recommendation": ("建议下一步检查", "Recommended next checks"),
    "legacy.rollback": ("回滚方法", "Rollback"),
    "legacy.verification": ("验证检查点", "Verification checkpoint"),
    "legacy.manual_review": ("需人工确认", "Manual review required"),
    "legacy.auto_fix": ("是否自动修复", "Automatic remediation"),
    "legacy.true": ("是", "Yes"),
    "legacy.false": ("否", "No"),
    "legacy.system_info": ("4. 系统信息", "4. System information"),
    "legacy.users": ("5. 用户与权限", "5. Users and permissions"),
    "legacy.services": ("6. 服务", "6. Services"),
    "legacy.ports": ("7. 网络端口", "7. Network ports"),
    "legacy.tasks": ("8. 计划任务", "8. Scheduled tasks"),
    "legacy.startup": ("启动项", "Startup items"),
    "legacy.security_vendors": ("安全软件与电脑管家组件", "Security software and system utilities"),
    "legacy.firewall": ("防火墙", "Firewall"),
    "legacy.rdp": ("远程桌面", "Remote Desktop"),
    "legacy.firewall_status": ("防火墙状态", "Firewall status"),
    "legacy.remote_desktop_status": ("远程桌面状态", "Remote Desktop status"),
    "legacy.shares": ("共享目录", "Shared folders"),
    "legacy.disks": ("磁盘与卷", "Disks and volumes"),
    "legacy.events": ("13. 事件日志摘要", "13. Event log summary"),
    "legacy.raw": ("14. 原始数据位置", "14. Raw data location"),
    "legacy.limitations": ("15. 本次巡检限制与不确定项", "15. Inspection limits and uncertainties"),
    "legacy.readonly": ("本工具只读采集并提示风险，不自动修复。", "This tool collects read-only evidence and reports risks; it does not remediate automatically."),
    "legacy.admin_gap": ("普通权限下部分信息可能缺失。", "Some information may be unavailable without administrator privileges."),
    "legacy.manual_context": ("端口、账号、计划任务等发现需要结合业务背景人工确认。", "Findings about ports, accounts, and scheduled tasks require review in business context."),
    "legacy.raw_detail": ("报告只展示关键摘要和前若干条明细，完整结构化数据见 raw。", "This report shows key summaries and a limited number of details; see raw for complete structured data."),
    "legacy.no_collector": ("未执行此项检查", "Not collected"),
    "legacy.partial": ("部分完成", "Partial"),
    "legacy.need_admin": ("需要管理员权限", "Administrator privileges required"),
    "legacy.skipped": ("已跳过", "Skipped"),
    "legacy.collect_failed": ("采集失败", "Collection failed"),
    "legacy.not_confirmed": ("未确认", "Unconfirmed"),
    "legacy.unconfirmed": ("未确认", "Unconfirmed"),
    "legacy.not_collected": ("未采集", "Not collected"),
    "legacy.not_collected_skipped": ("未采集 / Skipped", "Not collected / Skipped"),
    "legacy.not_run": ("未执行此项检查", "This check was not run"),
    "legacy.no_data": ("无数据。", "No data."),
    "legacy.collector_absent": ("该 collector 未出现在本次结果中。", "This collector is absent from the current results."),
    "legacy.not_detected": ("未检测到", "Not detected"),
    "legacy.installed": ("已安装", "Installed"),
    "legacy.suspected_residue": ("疑似残留", "Possible residue"),
    "legacy.driver_clue": ("相关驱动线索", "Related driver evidence"),
    "legacy.directory_trace": ("仅目录痕迹", "Directory evidence only"),
    "legacy.startup_details": ("启动项明细", "Startup item details"),
    "legacy.security_summary": ("检测摘要", "Detection summary"),
    "legacy.share_details": ("共享明细", "Share details"),
    "legacy.listener_summary": ("RDP 监听摘要", "RDP listener summary"),
    "legacy.bitlocker": ("BitLocker 状态", "BitLocker status"),
    "legacy.logical_disks": ("逻辑盘与空间", "Logical disks and space"),
    "legacy.physical_health": ("物理磁盘健康状态", "Physical disk health"),
    "legacy.vendor_installed": ("已安装程序", "Installed programs"),
    "legacy.related_drivers": ("相关驱动", "Related drivers"),
    "legacy.directory_evidence": ("目录辅助证据", "Directory evidence"),
    "legacy.risk_judgement": ("风险判断", "Risk assessment"),
    "legacy.collection_limit": ("采集限制", "Collection limits"),
    "legacy.status_label": ("采集状态", "Collection status"),
    "legacy.system_summary": ("系统信息", "System information"),
    "legacy.review_clue": ("人工复核", "Manual review"),
    "legacy.evidence_label": ("证据", "Evidence"),
    "legacy.name": ("名称", "Name"),
    "legacy.path": ("路径", "Path"),
    "legacy.type": ("类型", "Type"),
    "legacy.state": ("状态", "State"),
    "legacy.source": ("来源", "Source"),
    "legacy.result": ("结果", "Result"),
    "legacy.detail": ("明细", "Details"),
    "legacy.service_status": ("服务状态", "Service status"),
    "legacy.enabled": ("是否启用", "Enabled"),
    "legacy.port": ("端口", "Port"),
    "legacy.count_label": ("数量", "Count"),
    "legacy.share_count": ("共享数量", "Share count"),
    "legacy.default_share_count": ("默认管理共享数量", "Default administrative shares"),
    "legacy.nondefault_share_count": ("非默认共享数量", "Non-default shares"),
    "legacy.broad_access": ("Everyone / Guest / Anonymous 权限线索", "Everyone / Guest / Anonymous access evidence"),
    "legacy.used_fallback": ("是否使用 fallback", "Fallback used"),
    "legacy.no_scope": ("未采集到逻辑盘空间摘要，需人工确认。", "No logical disk space summary was collected; manual review is required."),
    "legacy.no_physical": ("未采集到物理磁盘健康状态，需人工确认。", "No physical disk health status was collected; manual review is required."),
    "legacy.bitlocker_need_admin": ("BitLocker 状态需要管理员权限复查。", "BitLocker status requires administrator review."),
    "legacy.bitlocker_missing": ("未采集到 BitLocker 信息，可能为不支持、未启用或权限不足。", "No BitLocker information was collected; it may be unsupported, disabled, or unavailable due to permissions."),
    "legacy.startup_risk_source": ("风险判断：统一由 AnalysisResult Findings 提供，本节仅展示 Collector 事实。", "Risk assessment is provided by AnalysisResult findings; this section shows collector facts only."),
    "legacy.no_security_vendor": ("未检测到已知安全软件或电脑管家组件。", "No known security software or system utility components were detected."),
    "legacy.profile_summary": ("配置文件摘要", "Profile summary"),
    "legacy.no_profile": ("未采集到 Profile 信息，需人工确认。", "No profile information was collected; manual review is required."),
    "legacy.smb_summary": ("SMB-In / 文件和打印共享相关摘要", "SMB-In / File and Printer Sharing summary"),
    "legacy.no_smb": ("未采集到共享规则，需人工确认。", "No sharing rules were collected; manual review is required."),
    "legacy.rdp_summary_heading": ("远程桌面相关摘要", "Remote Desktop summary"),
    "legacy.no_rdp": ("未采集到远程桌面规则，需人工确认。", "No Remote Desktop rules were collected; manual review is required."),
    "legacy.term_service_status": ("TermService 状态", "TermService state"),
    "legacy.term_service_start": ("TermService 启动类型", "TermService start type"),
    "legacy.rdp_firewall_uncertain": ("RDP 状态未启用或未采集，入站防火墙和监听状态需人工确认。", "RDP state is disabled or unavailable; inbound firewall and listener state require manual review."),
    "legacy.rdp_firewall_heading": ("远程桌面防火墙规则摘要", "Remote Desktop firewall rule summary"),
    "legacy.no_rdp_rules": ("未采集到远程桌面防火墙规则，需人工确认。", "No Remote Desktop firewall rules were collected; manual review is required."),
    "legacy.not_configured": ("未配置", "Not configured"),
    "legacy.default_inbound": ("默认入站", "Default inbound"),
    "legacy.default_outbound": ("默认出站", "Default outbound"),
    "legacy.display_name": ("显示名称", "Display name"),
    "legacy.ports": ("端口", "Ports"),
    "legacy.volume": ("卷", "Volume"),
    "legacy.volume_status": ("卷状态", "Volume status"),
    "legacy.protection_status": ("保护状态", "Protection status"),
    "legacy.lock_status": ("锁定状态", "Lock status"),
    "legacy.encryption_progress": ("加密进度", "Encryption progress"),
    "legacy.capacity": ("容量", "Capacity"),
    "legacy.name_model": ("名称/型号", "Name/model"),
    "legacy.no_known_vendor": ("未检测到已知安全软件或电脑管家组件。", "No known security software or system utility components were detected."),
    "legacy.profile_summary": ("Profile 摘要", "Profile summary"),
    "legacy.no_profile_info": ("未采集到 Profile 信息，需人工确认。", "No profile information was collected; manual review is required."),
    "legacy.smb_rules": ("SMB-In / File and Printer Sharing 相关规则摘要", "SMB-In / File and Printer Sharing rule summary"),
    "legacy.rdp_rules": ("Remote Desktop 相关规则摘要", "Remote Desktop rule summary"),
    "legacy.no_related_rules": ("未采集到相关规则，需人工确认。", "No related rules were collected; manual review is required."),
    "legacy.rdp_listener_unknown": ("RDP 监听：未发现或未采集到，需结合防火墙和服务状态人工确认。", "RDP listener: none found or not collected; review firewall and service state manually."),
    "legacy.no_broad_access": ("未发现", "Not found"),
    "legacy.broad_access_found": ("发现，需人工确认", "Found; manual review required"),
    "legacy.rdp_listener_not_found": ("未发现或未采集到，需结合防火墙和服务状态人工确认。", "none found or not collected; review firewall and service state manually."),
    "legacy.rdp_firewall_mixed_heading": ("Remote Desktop 防火墙规则摘要", "Remote Desktop firewall rule summary"),
    "legacy.rdp_listener_label": ("RDP 监听", "RDP listener"),
    "legacy.startup_risk_source_body": ("统一由 AnalysisResult Findings 提供，本节仅展示 Collector 事实。", "is provided by AnalysisResult findings; this section shows collector facts only."),
    "legacy.no_startup": ("未采集到启动项或当前环境无启动项。", "No startup items were collected or found in this environment."),
    "legacy.vendor_presence_note": ("检测到安全软件或电脑管家组件不等于恶意。本章节用于确认已安装软件、相关驱动和卸载残留线索，不会自动卸载、删除或修改系统设置。", "Detecting security software or system utility components does not mean they are malicious. This section reviews installed software, related drivers, and uninstall residue; it does not uninstall, delete, or change system settings."),
    "legacy.vendor_finding_note": ("检测到安全软件相关驱动不等于异常。驱动可能是正常在用组件，也可能是卸载残留；不建议自动删除，需要确认签名、状态、启动类型及文件路径。", "A security software-related driver is not necessarily abnormal. It may be in normal use or be uninstall residue; do not delete it automatically. Verify its signature, state, start mode, and path."),
    "legacy.directory_note": ("单独目录存在不等于软件仍在运行。空目录、日志目录或缓存目录不应直接判为 Warning，目录只作为辅助证据。", "A directory alone does not mean software is running. Empty, log, or cache directories should not be classified as Warning by themselves; treat them as supporting evidence only."),
    "legacy.multiple_security": ("检测到多个安全软件或电脑管家组件，可能存在功能重复或资源占用，需要结合用户实际用途确认。", "Multiple security or system utility components may duplicate functions or consume resources; confirm their purpose with the user."),
    "legacy.no_vendor": ("未获得可聚合的厂商明细。", "No vendor details could be grouped."),
    "legacy.no_structured_share": ("未采集到结构化共享明细；如使用 fallback，请查看 raw。", "No structured share details were collected; check raw data if a fallback was used."),
    "legacy.no_rdp_listener": ("- RDP 监听：未发现或未采集到，需结合防火墙和服务状态人工确认。", "- RDP listener: none found or collected; review firewall and service state manually."),
    "legacy.rdp_summary": ("Remote Desktop 是否启用", "Remote Desktop enabled"),
    "legacy.rdp_port": ("RDP 端口", "RDP port"),
    "legacy.rdp_count": ("RDP 端口监听数量", "RDP listener count"),
    "legacy.used_fallback_short": ("是否使用 fallback", "Fallback used"),
    "legacy.startup_count": ("启动项总数", "Total startup items"),
    "legacy.scope": ("范围", "Scope"),
    "legacy.command_target": ("命令/目标", "Command/target"),
    "legacy.share_name": ("名称", "Name"),
    "legacy.filesystem": ("文件系统", "File system"),
    "legacy.total_capacity": ("总容量", "Total capacity"),
    "legacy.free_space": ("剩余空间", "Free space"),
    "legacy.free_percent": ("剩余百分比", "Free percent"),
    "legacy.drive": ("盘符", "Drive"),
    "legacy.media": ("介质", "Media"),
    "legacy.interface": ("接口", "Interface"),
    "legacy.health": ("健康状态", "Health status"),
    "legacy.operational_state": ("运行状态", "Operational state"),
    "legacy.risk_label": ("风险判断", "Risk assessment"),
    "legacy.meaning": ("说明", "Description"),
    "legacy.exit_code": ("退出码", "Exit code"),
    "legacy.cpu": ("CPU", "CPU"),
    "legacy.summary_row": ("摘要", "Summary"),
    "legacy.user_scope": ("用户", "User"),
    "legacy.default_admin_share": ("默认管理共享", "Default administrative share"),
    "legacy.broad_access_clue": ("宽泛权限线索", "Broad access evidence"),
    "legacy.disk_clue": ("磁盘线索", "Disk evidence"),
    "legacy.listener_count": ("监听数量", "Listener count"),
    "legacy.address": ("地址", "Address"),
    "legacy.process": ("进程", "Process"),
    "legacy.pid": ("PID", "PID"),
    "legacy.profile": ("配置文件", "Profile"),
    "legacy.direction": ("方向", "Direction"),
    "legacy.action": ("操作", "Action"),
    "legacy.ports_column": ("端口", "Ports"),
}


# Each value is the exact built-in source form and its reviewed translation.
# Runtime rule overrides and third-party text never enter this catalog.
_FINDINGS: dict[str, dict[str, tuple[str, str]]] = {
    "REDIS_WILDCARD_BIND_REVIEW": {
        "description": ("确定性规则仅匹配明确采集到的证据；适用性仍受版本范围限制。", "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."),
    },
    "WIN_PORT_22_REVIEW": {
        "title": ("SSH 常用端口外部监听审查", "Review external listener on the common SSH port"),
        "description": ("配置的 SSH 检查端口正在 0.0.0.0 或 :: 上监听。此项只检查监听状态，不验证进程是否为 sshd，也不判断该访问是否符合预期。", "A configured SSH review port is listening on 0.0.0.0 or ::. This listener-only check does not verify that the process is sshd or that the access is expected."),
        "impact": ("对外监听的 SSH 常用端口可能扩大远程访问面，但仅凭端口监听不能确认服务身份或是否属于预期配置。", "An externally listening SSH port may expand remote access, but the listener alone does not establish service identity or whether the configuration is expected."),
        "recommendation": ("先由资产负责人确认SSH用途和监听进程。若属于获批维护通道，保留22端口并仅按批准来源范围收紧有效防火墙规则；若确认不再需要，按维护窗口通过受支持的服务/策略入口调整具体服务和规则。不要仅凭端口命中停止未知进程或阻断22。", "Have the asset owner confirm the SSH purpose and listening process. Keep port 22 for an approved maintenance channel and scope effective firewall rules to approved sources. If it is no longer needed, adjust the identified service and rules through supported management controls during a maintenance window. Do not stop an unknown process or block port 22 based only on this match."),
    },
    "WIN_SMB_445_ALLOWED": {
        "title": ("SMB 常用端口外部监听审查", "Review external listener on the common SMB port"),
        "description": ("配置的 SMB 检查端口正在 0.0.0.0 或 :: 上监听。此项只检查监听状态，不验证防火墙允许规则或共享权限。", "A configured SMB review port is listening on 0.0.0.0 or ::. This listener-only check does not verify firewall Allow rules or share permissions."),
        "impact": ("对外监听的 SMB 常用端口可能形成文件共享访问面，但仅凭监听不能确认防火墙是否允许入站或共享权限是否宽泛。", "An externally listening SMB port may expose a file-sharing surface, but the listener alone does not establish inbound firewall allowance or broad share permissions."),
        "recommendation": ("由业务所有者确认445对应的共享用途和授权。若承载获批文件、打印、备份、虚拟化或集群业务，保留必要通道并核对共享/NTFS最小权限及防火墙来源范围；只有确认无依赖后，才按变更流程通过Windows受支持管理入口禁用不需要的共享服务或收紧规则。不要仅凭端口监听直接封锁445。", "Have the service owner confirm the purpose and authorization for port 445. Preserve required channels for approved file, print, backup, virtualization, or cluster workloads and review least-privilege share/NTFS permissions and firewall source scope. Only after confirming there are no dependencies, use supported Windows controls and change procedures to disable an unneeded service or tighten rules. Do not block port 445 based only on the listener."),
    },
    "WIN_RDP_EXPOSED_REVIEW": {
        "title": ("RDP 常用端口外部监听审查", "Review external listener on the common RDP port"),
        "description": ("配置的 RDP 检查端口正在 0.0.0.0 或 :: 上监听。此项只检查监听状态，不判断远程桌面启用状态或入站防火墙可达性。", "A configured RDP review port is listening on 0.0.0.0 or ::. This listener-only check does not determine the Remote Desktop enablement state or inbound firewall reachability."),
        "impact": ("对外监听的 RDP 常用端口可能形成远程登录访问面，但仅凭监听不能确认远程桌面状态或防火墙是否允许入站。", "An externally listening RDP port may expose a remote logon surface, but the listener alone does not establish Remote Desktop state or inbound firewall allowance."),
        "recommendation": ("人工确认监听进程及 RDP 使用意图，并另行核对远程桌面状态、防火墙配置、允许来源和账户安全；本 Finding 不代表已确认 RDP 启用或入站允许。", "Confirm the listening process and intended RDP use. Separately review Remote Desktop state, firewall configuration, allowed sources, and account security. This finding does not confirm that RDP is enabled or inbound access is allowed."),
    },
    "WIN_BITLOCKER_NEED_ADMIN": {
        "title": ("BitLocker 状态需要管理员权限确认", "BitLocker status requires administrator review"),
        "description": ("当前权限不足，无法完整确认 BitLocker 状态。", "Insufficient permissions to fully verify BitLocker status."),
        "impact": ("无法判断磁盘加密状态，需管理员权限复核。", "Disk encryption status cannot be determined and requires administrator review."),
        "recommendation": ("由获批管理员以只读方式核对 BitLocker 卷状态；若权限暂不可用，保留此证据缺口并交接复核，不要为巡检启停加密或请求工具自动提权。", "An authorized administrator should verify BitLocker volume status in read-only mode. If access is unavailable, retain this evidence gap for follow-up; do not enable or disable encryption or request automatic elevation for inspection."),
    },
    "WIN_PROXY_PORT_EXPOSED": {
        "title": ("代理相关端口需要复核", "Review proxy-related listener"),
        "description": ("7890-7899 范围内的端口正在 0.0.0.0 或 :: 上监听。仅回环监听的 Clash Verge 或 mihomo 端口可能是本地代理提示；全接口监听需要复核。", "A port in the 7890-7899 range is listening on 0.0.0.0 or ::. Loopback-only Clash Verge or mihomo listeners may be local proxy information; all-interface listeners require review."),
        "impact": ("代理端口如对局域网开放可能带来访问风险。", "A proxy port exposed to the local network may create an access risk."),
        "recommendation": ("确认是否有意向局域网开放；如非预期，请检查代理应用的绑定地址和访问控制。", "Confirm whether LAN exposure is intended. If it is not, review the proxy application's bind address and access controls."),
    },
    "WIN_ADMINISTRATOR_COUNT_REVIEW": {
        "title": ("管理员组成员较多", "Large number of Administrators group members"),
        "description": ("管理员组成员超过了配置的复核阈值。", "The Administrators group contains more members than the configured review threshold."),
        "impact": ("管理员面扩大，误用或滥用风险增加。", "A larger administrator group increases the risk of accidental or unauthorized use."),
        "recommendation": ("人工复核管理员组成员是否均为预期账户。", "Manually verify that every Administrators group member is expected."),
    },
    "WIN_SERVICE_SUSPICIOUS_PATH": {
        "title": ("可疑自启动服务路径", "Review a suspicious auto-start service path"),
        "description": ("自动启动服务的二进制路径包含配置的高关注路径片段。", "An automatic service binary path contains a configured high-attention path substring."),
        "impact": ("用户目录或临时目录中的自启动服务需要高度关注。", "An auto-start service located in a user or temporary directory requires close review."),
        "recommendation": ("复核服务路径、签名、创建时间和业务来源。", "Review the service path, signature, creation time, and business origin."),
    },
    "WIN_SCHEDULED_TASK_SUSPICIOUS_PATH": {
        "title": ("计划任务路径需要复核", "Review a scheduled task path"),
        "description": ("计划任务操作包含配置的高关注路径片段。", "A scheduled task action contains a configured high-attention path substring."),
        "impact": ("用户目录或临时目录中的启动项可能是持久化线索。", "A startup action in a user or temporary directory may indicate persistence."),
        "recommendation": ("人工复核任务 Action 路径、签名和创建来源。", "Manually review the task action path, signature, and creation source."),
    },
    "WIN_EVENT_LOG_ERROR_VOLUME": {
        "title": ("近期系统事件异常较多", "High volume of recent system events"),
        "description": ("当前事件日志采集窗口中存在严重事件，或达到配置的错误数量阈值。", "The current event-log collection window contains a critical event or reaches the configured error-count threshold."),
        "impact": ("系统稳定性或驱动/服务可能存在异常。", "System stability or a driver or service may be affected."),
        "recommendation": ("查看事件日志详情，按 Provider 和 Event ID 继续定位。", "Review event log details and investigate by provider and event ID."),
    },
    "WIN_STARTUP_SUSPICIOUS_PATH": {
        "title": ("启动项存在高关注路径或脚本解释器线索", "Startup item contains a high-attention path or script interpreter clue"),
        "description": ("检测到启动项路径或命令包含需要人工复核的持久化线索。", "A startup path or command contains a persistence clue that requires manual review."),
        "impact": ("该启动项可能是正常软件，也可能是异常持久化入口，需要结合签名、来源和用户确认判断。", "The startup item may be legitimate software or an unexpected persistence entry; review its signature, origin, and user intent."),
        "recommendation": ("人工确认启动项来源；如不认识该项，进一步检查文件签名、创建时间和父目录。", "Confirm the startup item's origin. If it is unfamiliar, inspect the file signature, creation time, and parent directory."),
    },
    "WIN_SECURITY_VENDOR_PRESENT": {
        "title": ("检测到安全软件或电脑管家组件", "Security software or system utility detected"),
        "description": ("检测到相关安全软件或电脑管家组件，存在不等于恶意，需要确认是否为用户主动安装以及是否与其他安全软件冲突。", "Related security software or system utility components were detected. Their presence does not mean they are malicious; confirm whether the user installed them and whether they conflict with other security software."),
        "impact": ("多个安全防护或管家组件可能产生资源占用、拦截冲突或配置覆盖，但单独存在不表示异常。", "Multiple security or system utility components may consume resources, conflict in blocking, or override settings, but their presence alone is not abnormal."),
        "recommendation": ("确认相关产品是否为用户主动安装、是否仍在使用，以及是否与其他安全软件存在冲突；不要自动卸载或删除。", "Confirm whether the product was intentionally installed, is still used, or conflicts with other security software. Do not uninstall or delete it automatically."),
        "verification_checkpoint": ("核对已安装程序、厂商信息和用户使用意图，确认保留或按厂商官方流程人工处理。", "Review installed programs, vendor information, and user intent to decide whether to retain the product or handle it manually through the vendor's official process."),
    },
    "WIN_SECURITY_VENDOR_RESIDUE": {
        "title": ("检测到安全软件卸载残留", "Possible security software uninstall residue detected"),
        "description": ("卸载项中未发现对应产品，但仍存在服务、驱动、计划任务、启动项等残留线索，需要人工确认。", "The product was not found in uninstall entries, but service, driver, scheduled task, or startup evidence remains and requires manual review."),
        "impact": ("残留组件可能继续启动、占用资源或影响系统与其他安全软件，但仅凭该线索不能判断为恶意。", "Residual components may continue to run, consume resources, or affect the system and other security software; this evidence alone does not establish malicious activity."),
        "recommendation": ("先确认产品是否仍安装、注册或承担防护职责；若确属卸载残留，由资产负责人确认替代防护已就绪，再使用该产品厂商发布的对应版本卸载/清理流程。不要手工删除驱动、服务、注册表项或目录；完成后检查Windows安全中心显示的提供程序与状态。", "First confirm whether the product is still installed, registered, or providing protection. If it is uninstall residue, have the asset owner confirm replacement protection is ready, then use the vendor's removal procedure for the matching version. Do not manually delete drivers, services, registry entries, or directories. Afterward, check providers and status in Windows Security."),
    },
    "WIN_SECURITY_VENDOR_DRIVER_REVIEW": {
        "title": ("检测到安全软件相关驱动", "Security software-related driver detected"),
        "description": ("检测到安全软件相关驱动或驱动残留，驱动存在不等于异常，不建议自动删除，需要确认签名、状态、启动类型和文件路径。", "A security software-related driver or residual driver was detected. Its presence alone is not abnormal; do not delete it automatically. Verify its signature, state, start mode, and path."),
        "impact": ("相关驱动可能参与文件、网络或系统启动过滤，错误处置可能影响系统稳定性。", "The driver may filter files, network traffic, or system startup; incorrect handling may affect system stability."),
        "recommendation": ("请人工确认驱动签名、运行状态、启动类型、文件路径和对应产品状态，不要自动删除或禁用。", "Manually verify the driver signature, running state, start mode, file path, and associated product state. Do not delete or disable it automatically."),
        "verification_checkpoint": ("通过受信任的系统工具核对驱动签名和服务状态，并在厂商官方卸载后复跑巡检。", "Use trusted system tools to verify the driver signature and service state, then rerun the inspection after an official vendor uninstall."),
    },
    "WIN_BASELINE_RDP_NLA_DISABLED": {
        "title": ("已启用远程桌面但未要求网络级别身份验证", "Remote Desktop is enabled without requiring Network Level Authentication"),
        "description": ("采集到 RDP 已启用且 NLA 未启用；此项不判断防火墙是否允许入站或外部网络是否可达。", "RDP is enabled and NLA is disabled in the collected evidence; this check does not determine inbound firewall allowance or external reachability."),
        "impact": ("启用 RDP 会提供远程登录入口；关闭 NLA 会降低会话建立前的身份验证保护。旧客户端兼容性和业务依赖可能影响处置方式。", "RDP provides a remote logon entry point, and disabling NLA reduces authentication protection before session establishment. Legacy client compatibility and business dependencies may affect remediation."),
        "recommendation": ("1. 若业务不需要 RDP，在确认带外/本地管理通道和依赖后关闭远程桌面。2. 若业务需要 RDP，按组织策略启用 NLA，并确认所有运维客户端兼容。3. 复核允许的远程账户和防火墙来源范围；不要把本 Finding 当作网络可达性测试。", "1. If RDP is not needed, confirm out-of-band or local administration and dependencies before disabling Remote Desktop. 2. If it is required, enable NLA according to policy and verify management client compatibility. 3. Review permitted remote accounts and firewall source scope; this finding is not a reachability test."),
    },
    "WIN_BASELINE_SMB1_ENABLED": {
        "title": ("检测到 SMB 1.0 显式启用", "SMB 1.0 is explicitly enabled"),
        "description": ("LanmanServer SMB1 注册表设置明确为启用；缺失该值不会被当作关闭或开启。", "The LanmanServer SMB1 registry setting is explicitly enabled; a missing value is not treated as enabled or disabled."),
        "impact": ("SMBv1 是旧协议，启用可能增加文件共享攻击面；移除前必须核实旧设备、应用和备份依赖。", "SMBv1 is an obsolete protocol and may increase file-sharing exposure; verify dependencies of legacy devices, applications, and backups before removing it."),
        "recommendation": ("1. 盘点 NAS、旧 Windows、扫描/备份设备和应用的 SMB 方言依赖。2. 在目标系统版本对应的 Windows Features/Server Manager 中按 Microsoft 指南移除或禁用 SMBv1；执行前确认变更窗口和重启要求。3. 不要仅为消除此项直接改写注册表。", "1. Inventory SMB dialect dependencies for NAS, legacy Windows systems, scanning or backup devices, and applications. 2. Follow Microsoft guidance for the target OS version to remove or disable SMBv1 through Windows Features or Server Manager; confirm the change window and restart requirements first. 3. Do not directly edit the registry just to clear this finding."),
    },
    "WIN_BASELINE_AUTOLOGON_ENABLED": {
        "title": ("Windows 自动登录已启用", "Windows automatic logon is enabled"),
        "description": ("Winlogon AutoAdminLogon 标志为 1；采集器不读取或导出自动登录凭据。", "The Winlogon AutoAdminLogon flag is 1; the collector does not read or export automatic logon credentials."),
        "impact": ("自动登录可能让能接触设备的人直接进入配置账户的桌面及其可访问资源。", "Automatic logon may let someone with physical access enter the configured account's desktop and access its resources."),
        "recommendation": ("1. 确认该设备是否确需无人值守登录及其物理/机房访问控制。2. 若无明确业务授权，由账户/凭据负责人通过组织批准的自动登录管理方式关闭，并轮换可能用于自动登录的凭据。3. 不要把密码复制到工单、命令行或巡检报告。", "1. Confirm whether unattended logon is needed and review physical access controls. 2. Without explicit business approval, have the account owner disable it through an approved method and rotate any credentials used for automatic logon. 3. Do not copy passwords into tickets, command lines, or inspection reports."),
    },
    "WIN_BASELINE_GUEST_ENABLED": {
        "title": ("内置 Guest 账户已启用", "Built-in Guest account is enabled"),
        "description": ("本地账户摘要中 SID 末尾为 -501 的内置 Guest 账户处于启用状态；不会导出账户名或 SID。", "The local account summary reports the built-in Guest account ending in SID -501 as enabled; account names and SIDs are not exported."),
        "impact": ("访客账户可能扩大本地或共享访问面；Guest Only 共享模型等旧配置也可能依赖它。", "A guest account may broaden local or share access; legacy configurations such as the Guest Only sharing model may depend on it."),
        "recommendation": ("1. 核对 Guest 账户是否被共享、服务或旧版本地账户模式依赖。2. 若无批准用途，在本地用户管理或组织安全策略中禁用内置 Guest。3. 复核 SMB 共享权限和访问日志，确认没有将 Guest 当作业务账户使用。", "1. Check whether shares, services, or legacy local-account settings depend on Guest. 2. If it has no approved purpose, disable the built-in Guest account through Local Users or organizational security policy. 3. Review SMB share permissions and access logs to confirm Guest is not used as a business account."),
    },
    "WIN_BASELINE_FIREWALL_PROFILE_DISABLED": {
        "title": ("至少一个 Windows 防火墙配置文件已关闭", "At least one Windows Firewall profile is disabled"),
        "description": ("至少一个 Domain、Private/Standard 或 Public 防火墙配置文件的显式 EnableFirewall 值为 0。", "At least one Domain, Private/Standard, or Public firewall profile has an explicit EnableFirewall value of 0."),
        "impact": ("关闭中的配置文件可能缺少对应入站/出站规则保护；本项不推断其他配置文件状态或网络边界设备控制。", "A disabled profile may lack its inbound or outbound rule protections; this finding does not infer other profile states or network perimeter controls."),
        "recommendation": ("1. 确认当前网络配置文件、管理入口和已批准的入站例外。2. 由防火墙策略负责人检查组策略及业务例外；无批准例外时在 Windows Defender 防火墙高级安全管理中恢复对应配置文件。3. 先验证运维通道和关键业务连接，不要一键重置全部规则。", "1. Confirm the active network profile, management access, and approved inbound exceptions. 2. Have the firewall policy owner review Group Policy and business exceptions; if none are approved, restore the profile through Windows Defender Firewall with Advanced Security. 3. Verify management access and critical business connections first; do not reset all rules at once."),
    },
    "WIN_BASELINE_PASSWORD_COMPLEXITY_DISABLED": {
        "title": ("有效密码策略未启用复杂性要求", "Effective password policy does not require complexity"),
        "description": ("secedit 合并策略显示 PasswordComplexity=0；仅评估当前导出的系统策略，不审计账户口令本身。", "The secedit merged policy reports PasswordComplexity=0; this evaluates only the exported system policy and does not audit account passwords."),
        "impact": ("新设密码可能不受 Windows 复杂性规则约束，容易采用较弱模式；组织可有经批准的其他认证控制。", "New passwords may not be subject to Windows complexity rules and could use weaker patterns; an organization may have other approved authentication controls."),
        "recommendation": ("1. 与身份/域策略负责人确认本机、域 GPO 和细粒度密码策略的实际适用范围。2. 若组织基线要求，在组策略或本地安全策略的“账户策略 → 密码策略”中启用复杂性要求，并先验证旧系统/服务账户兼容性。3. 结合组织批准的最小长度要求，不自动重置现有密码。", "1. Confirm the applicable local, domain GPO, and fine-grained password policies with the identity or domain policy owner. 2. If required by policy, enable complexity in Group Policy or Local Security Policy under Account Policies → Password Policy, after checking legacy system and service account compatibility. 3. Follow the approved minimum length; do not reset existing passwords automatically."),
    },
    "WIN_BASELINE_PASSWORD_MINIMUM_LENGTH_LOW": {
        "title": ("有效密码最小长度低于 Microsoft 指引值", "Effective minimum password length is below Microsoft guidance"),
        "description": ("secedit 合并策略显示 MinimumPasswordLength 小于 8；该比较是维护提示，不代表法规或组织测评结论。", "The secedit merged policy reports MinimumPasswordLength below 8; this is a maintenance prompt, not a regulatory or organizational audit conclusion."),
        "impact": ("较短或允许空口令的本地密码更容易被猜测；提高要求也可能增加锁定和兼容支持成本。", "Short local passwords or permitted empty passwords may be easier to guess; stronger requirements can also increase lockout and compatibility support costs."),
        "recommendation": ("1. 与身份负责人核对域、细粒度策略和系统用途。2. 若适用的组织基线要求至少 8 位，在策略管理入口提高最小长度；结合口令短语培训并评估服务账户/旧应用影响。3. 不要把任意数字当作所有环境的合规线。", "1. Review domain and fine-grained policies and system use with the identity owner. 2. If the applicable organizational baseline requires at least 8 characters, raise the minimum through policy management; provide passphrase guidance and assess service account and legacy application impact. 3. Do not treat an arbitrary number as a universal compliance threshold."),
    },
    "WIN_BASELINE_ACCOUNT_LOCKOUT_DISABLED": {
        "title": ("有效账户锁定策略未启用阈值", "Effective account lockout policy has no threshold"),
        "description": ("secedit 合并策略显示 LockoutBadCount=0；工具不替组织选择锁定阈值或持续时间。", "The secedit merged policy reports LockoutBadCount=0; the tool does not select a lockout threshold or duration for the organization."),
        "impact": ("失败登录次数不会按本策略阈值触发锁定响应，可能增加密码猜测机会；阈值设置过低也会造成误锁定和拒绝服务。", "Failed logons will not trigger lockout under this policy threshold, which may increase guessing opportunities; a threshold set too low can also cause false lockouts and denial of service."),
        "recommendation": ("1. 由身份负责人评估暴露面、服务账户、帮助台解锁能力和域策略。2. 按组织批准的阈值、持续时间及计数器重置时间配置账户锁定策略。3. 先在测试范围验证监控、解锁流程和自动化账户影响。", "1. Have the identity owner assess exposure, service accounts, help desk unlock capacity, and domain policy. 2. Configure the approved lockout threshold, duration, and counter reset period. 3. Validate monitoring, unlock procedures, and automated account impact in a test scope first."),
    },
    "GENERIC_WILDCARD_LISTENER_REVIEW": {
        "title": ("未被专属规则覆盖的通配地址监听需要人工确认", "Manually review wildcard listener without a specific rule"),
        "description": ("确定性规则仅匹配明确采集到的证据；适用性仍受版本范围限制。", "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."),
        "impact": ("其他专属候选规则未覆盖的通配监听，仍需结合防火墙、路由和业务依赖确认；监听本身不能证明网络可达。", "A wildcard listener not covered by a specific candidate rule requires review with firewall, routing, and business dependencies; listening alone does not prove network reachability."),
        "recommendation": ("确认监听进程、授权访问范围、防火墙规则及业务依赖，再按该软件精确版本评估收敛范围。", "Confirm the listening process, authorized access scope, firewall rules, and business dependencies. Then assess a narrower scope for the exact software version."),
    },
    "REDIS_WILDCARD_BIND_REVIEW": {
        "title": ("Redis 配置存在通配 bind 值", "Redis configuration uses a wildcard bind value"),
        "description": ("确定性规则仅匹配明确采集到的证据；适用性仍取决于具体版本。", "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."),
        "impact": ("监听范围可能超过业务所需；配置值本身不能证明网络可达。", "The listening scope may exceed business needs; the configuration value alone does not prove network reachability."),
        "recommendation": ("在维护窗口核对客户端来源、防火墙和版本能力，审批后仅保留业务所需绑定地址；不套用其他版本的 ACL 命令。", "During a maintenance window, review client sources, firewall controls, and version capabilities. After approval, keep only required bind addresses; do not apply ACL commands from other versions."),
    },
    "MYSQL_WILDCARD_BIND_REVIEW": {
        "title": ("MySQL 配置存在通配 bind-address", "MySQL configuration uses a wildcard bind address"),
        "description": ("确定性规则仅匹配明确采集到的证据；适用性仍取决于具体版本。", "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."),
        "impact": ("服务可能接受超出业务所需网络范围的连接请求；不等同已暴露或可登录。", "The service may accept connection requests beyond business needs; this does not establish exposure or successful login."),
        "recommendation": ("先核对连接来源与防火墙，审批后配置所需监听范围；不得仅凭此证据修改生产数据库。", "Review connection sources and firewall controls first. After approval, configure the required listening scope; do not modify a production database based only on this evidence."),
    },
    "NGINX_LEGACY_TLS_CONFIG_REVIEW": {
        "title": ("Nginx 配置包含旧 TLS 协议标识", "Nginx configuration includes a legacy TLS protocol marker"),
        "description": ("确定性规则仅匹配明确采集到的证据；适用性仍取决于具体版本。", "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."),
        "impact": ("旧协议可能不符合当前组织策略；实际可协商协议仍需端到端验证。", "Legacy protocols may not meet current policy; the protocols actually negotiated require end-to-end verification."),
        "recommendation": ("核对完整 include 链、Nginx/OpenSSL 构建与客户端要求，审批后制定兼容升级方案。", "Review the full include chain, Nginx/OpenSSL build, and client requirements; after approval, plan a compatible upgrade."),
    },
    "TOMCAT_CONNECTOR_TLS_DISABLED_REVIEW": {
        "title": ("Tomcat Connector 显式关闭 TLS", "Tomcat Connector explicitly disables TLS"),
        "description": ("确定性规则仅匹配明确采集到的证据；适用性仍取决于具体版本。", "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."),
        "impact": ("此单项配置不能证明业务流量明文传输或外部可达。", "This single configuration does not prove that business traffic is unencrypted or externally reachable."),
        "recommendation": ("核对反向代理到 Tomcat 的传输保护、Connector 绑定范围和业务拓扑，再决定是否调整。", "Review transport protection from the reverse proxy to Tomcat, Connector bind scope, and business topology before deciding on a change."),
    },
    "WAS_SECURITY_DISABLED_REVIEW": {
        "title": ("WebSphere 配置显式关闭安全设置", "WebSphere configuration explicitly disables a security setting"),
        "description": ("确定性规则仅匹配明确采集到的证据；适用性仍取决于具体版本。", "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."),
        "impact": ("该配置线索可能影响管理或传输安全；单个 XML 片段不能确定生效配置。", "This configuration clue may affect management or transport security; a single XML fragment does not establish the effective configuration."),
        "recommendation": ("由 WebSphere 管理员确认生效 cell/profile、同步状态和安全策略，再制定维护窗口内的人工整改。", "Have the WebSphere administrator confirm the effective cell/profile, synchronization state, and security policy before planning manual remediation during a maintenance window."),
    },
    "ORACLE_VALID_NODE_CHECK_DISABLED_REVIEW": {
        "title": ("Oracle Listener 配置关闭节点来源限制", "Oracle Listener configuration disables valid-node source checks"),
        "description": ("确定性规则仅匹配明确采集到的证据；适用性仍取决于具体版本。", "Deterministic rule matched only explicit collected evidence; applicability remains version-bound."),
        "impact": ("如果单位依赖此控制进行来源限制，配置可能不符合策略；防火墙及其他控制尚未检查。", "If the organization relies on this control to restrict sources, the configuration may not meet policy; firewalls and other controls have not been checked."),
        "recommendation": ("核对数据库团队批准的网络访问模型及准确版本文档；不得仅凭该文件直接重启 Listener 或改动生产配置。", "Review the database team's approved network access model and documentation for the exact version; do not restart the Listener or change production configuration based only on this file."),
    },
    "WIN_DISK_LOW_SPACE": {
        "title": ("磁盘剩余空间偏低", "Low disk space"),
        "description": ("检测到磁盘或卷剩余空间偏低，可能影响系统更新、日志写入、应用运行或故障排查留存能力。", "Low free space was detected on a disk or volume. This may affect system updates, log writes, applications, or retention of troubleshooting evidence."),
        "impact": ("剩余空间过低可能导致系统更新失败、应用写日志失败、数据库或中间件异常、排障证据丢失，严重时可能影响服务稳定性。", "Very low free space can cause update failures, failed application logging, database or middleware errors, loss of troubleshooting evidence, and in severe cases reduced service stability."),
        "recommendation": ("请人工确认受影响卷是否为系统盘或应用日志盘，并结合剩余空间百分比和绝对剩余容量评估；必要时清理无用文件、迁移日志或备份、扩容磁盘或调整保留策略。不要在未确认业务用途前自动删除文件。", "Confirm whether the affected volume holds the system or application logs, then assess both free-space percentage and absolute capacity. If needed, remove confirmed unnecessary files, move logs or backups, expand storage, or adjust retention. Do not automatically delete files before confirming their purpose."),
    },
    "LNX_EMPTY_PASSWORD_ACCOUNTS": {
        "title": ("存在空口令账户摘要线索", "Evidence summary indicates accounts with empty passwords"),
        "description": ("在可读 shadow 的前提下，摘要显示空口令字段数量大于 0；需人工核实账户与锁定状态。", "If shadow data was readable, the summary indicates one or more empty-password fields; manually verify the accounts and lock state."),
        "impact": ("空口令账户可能允许无需口令的登录尝试，实际可用性和访问范围需结合账户状态与服务配置确认。", "An account with an empty password may permit login attempts without a password; actual access depends on account state and service configuration."),
        "recommendation": ("以 root 核对空口令账户，确认是否锁定/禁用；按单位策略设置口令或锁定，禁止在未批准窗口批量改密。", "As root, verify accounts with empty passwords and whether they are locked or disabled. Set passwords or lock accounts according to policy; do not perform bulk password changes outside an approved window."),
        "applicability": ("仅依据已采集的摘要字段；精确发行版与配置生效状态需人工核实。", "Based only on collected summary fields; verify the exact distribution and effective configuration manually."),
        "rollback": ("变更前备份 shadow；登录异常时按单位流程恢复。", "Back up shadow before changes; if logons fail, restore it under organizational procedures."),
        "verification_checkpoint": ("复采账户摘要，EMPTY_PASSWORD_COUNT 应为 0 或已解释的例外。", "Recollect the account summary; EMPTY_PASSWORD_COUNT should be 0 or a documented exception."),
    },
    "LNX_MULTIPLE_UID0_ACCOUNTS": {
        "title": ("存在多个 UID 0 账户", "Multiple UID 0 accounts detected"),
        "description": ("采集摘要显示超过一个 UID 0 账户；不等于已确认后门，但需要核实。", "The collection summary reports more than one UID 0 account; this does not confirm a backdoor but requires review."),
        "impact": ("采集摘要显示超过一个 UID 0 账户；不等于已确认后门，但需要核实。", "The collection summary reports more than one UID 0 account; this does not confirm a backdoor but requires review."),
        "recommendation": ("核对 /etc/passwd 中 UID 0 账户用途；非必要的 root 等价账户应在维护窗口按单位流程处理。", "Review the purpose of UID 0 accounts in /etc/passwd. Handle unnecessary root-equivalent accounts during a maintenance window under organizational procedures."),
        "applicability": ("仅依据已采集的摘要字段；精确发行版与配置生效状态需人工核实。", "Based only on collected summary fields; verify the exact distribution and effective configuration manually."),
        "rollback": ("变更前备份 passwd/shadow 及相关授权；访问异常时按单位流程恢复。", "Back up passwd, shadow, and related authorization before changes; if access fails, restore them under organizational procedures."),
        "verification_checkpoint": ("复采账户摘要，确认 UID0_COUNT 与业务批准名单一致。", "Recollect the account summary and confirm UID0_COUNT matches the business-approved account list."),
    },
    "LNX_SSH_ROOT_LOGIN_PERMITTED": {
        "title": ("SSH 允许 root 相关登录", "SSH permits root-related logon"),
        "description": ("sshd_config 摘要显示 PermitRootLogin={value}。", "The sshd_config summary reports PermitRootLogin={value}."),
        "impact": ("SSH 直接允许 root 相关登录会扩大高权限远程访问面，具体效果需结合认证与网络控制核实。", "Allowing root-related SSH logon expands privileged remote access; the effective exposure depends on authentication and network controls."),
        "recommendation": ("确认已有可用的普通运维账户与 sudo；审批后在维护窗口将 PermitRootLogin 设为 no，执行 sshd -t 后 reload，不断开现有会话直到验证完成。", "Confirm a working unprivileged administration account and sudo. After approval, set PermitRootLogin to no during a maintenance window, run sshd -t, then reload. Keep the current session open until verification succeeds."),
        "applicability": ("仅依据已采集的摘要字段；精确发行版与配置生效状态需人工核实。", "Based only on collected summary fields; verify the exact distribution and effective configuration manually."),
        "rollback": ("恢复 sshd_config 备份并 reload；验证管理通道。", "Restore the sshd_config backup and reload; verify the administration channel."),
        "verification_checkpoint": ("复采 security_status，确认 SSH_PERMIT_ROOT_LOGIN=no，并用普通账户验证登录。", "Recollect security_status, confirm SSH_PERMIT_ROOT_LOGIN=no, and verify login with a regular account."),
    },
    "LNX_SSH_EMPTY_PASSWORDS_PERMITTED": {
        "title": ("SSH 允许空口令", "SSH permits empty passwords"),
        "description": ("sshd_config 摘要显示 PermitEmptyPasswords=yes。", "The sshd_config summary reports PermitEmptyPasswords=yes."),
        "impact": ("若账户及其他访问控制允许，空口令可能使远程认证保护不足。", "If accounts and other access controls permit it, empty passwords may weaken remote authentication."),
        "recommendation": ("审批后改为 no，语法检查并 reload；同步检查账户空口令情况。", "After approval, set it to no, validate the configuration, and reload; also check for accounts with empty passwords."),
        "applicability": ("仅依据已采集的摘要字段；精确发行版与配置生效状态需人工核实。", "Based only on collected summary fields; verify the exact distribution and effective configuration manually."),
        "rollback": ("恢复原配置并 reload。", "Restore the original configuration and reload."),
        "verification_checkpoint": ("复采确认 SSH_PERMIT_EMPTY_PASSWORDS=no。", "Recollect and confirm SSH_PERMIT_EMPTY_PASSWORDS=no."),
    },
    "LNX_PASSWORD_MAX_DAYS_WEAK": {
        "title": ("口令最长有效期过长或未实质限制", "Password maximum age is very long or effectively unlimited"),
        "description": ("login.defs 摘要 PASS_MAX_DAYS={value}。", "The login.defs summary reports PASS_MAX_DAYS={value}."),
        "impact": ("过长的有效期可能延长已泄露口令的可用时间；实际 PAM 策略及组织例外需另行核实。", "A very long maximum age may extend the time a compromised password remains usable; verify effective PAM policy and organizational exceptions."),
        "recommendation": ("按单位口令策略评估；审批后调整 PASS_MAX_DAYS 并明确现有账户生效方式，避免未通知用户导致批量锁定。", "Review against organizational password policy. After approval, adjust PASS_MAX_DAYS and define how it applies to existing accounts to avoid mass lockouts without user notice."),
        "applicability": ("仅依据已采集的摘要字段；精确发行版与配置生效状态需人工核实。", "Based only on collected summary fields; verify the exact distribution and effective configuration manually."),
        "rollback": ("恢复 login.defs 备份；确认现有账户策略未意外收紧。", "Restore the login.defs backup; confirm existing account policy was not unintentionally tightened."),
        "verification_checkpoint": ("复采 security_status 并抽查代表性账户的口令老化设置。", "Recollect security_status and sample representative accounts to verify password aging settings."),
    },
    "LNX_PASSWORD_MIN_LEN_WEAK": {
        "title": ("口令最小长度偏短", "Minimum password length is short"),
        "description": ("login.defs 摘要 PASS_MIN_LEN={value}；PAM 实际策略可能更严或更松。", "The login.defs summary reports PASS_MIN_LEN={value}; effective PAM policy may be stricter or weaker."),
        "impact": ("较短的口令可能更容易被猜测；PAM 实际生效策略需要交叉核实。", "Short passwords may be easier to guess; cross-check the effective PAM policy."),
        "recommendation": ("核对 PAM/密码质量模块实际生效策略后再调整；不要只改 login.defs。", "Verify the effective PAM and password-quality module policy before making changes; do not change login.defs alone."),
        "applicability": ("仅依据已采集的摘要字段；精确发行版与配置生效状态需人工核实。", "Based only on collected summary fields; verify the exact distribution and effective configuration manually."),
        "rollback": ("恢复原配置。", "Restore the original configuration."),
        "verification_checkpoint": ("复采并与 PAM 配置交叉核实。", "Recollect and cross-check against the PAM configuration."),
    },
    "OS_LIFECYCLE_REVIEW": {
        "title": ("{product} {version} 生命周期支持已结束", "{product} {version} lifecycle support has ended"),
        "description": ("Collected OS identity matches a lifecycle record whose normal support has ended. This is a version-support and migration-planning review, not a security finding or proof of exposure.", "采集到的操作系统身份匹配常规支持已结束的生命周期记录。此项用于版本支持与迁移规划，不是安全发现，也不证明存在暴露。"),
        "applicability": ("仅依据所列采集事实和策略快照；付费扩展支持资格、合同和当前覆盖范围均未核实。", "Based only on the listed collected facts and policy snapshot; paid extended-support eligibility, contract, and current coverage are unverified."),
        "impact": ("常规支持结束意味着后续更新与支持范围可能受限；本结果不判断该设备是否存在漏洞或合规违规。", "End of standard support may limit future updates and support; this result does not determine whether the device has vulnerabilities or compliance violations."),
        "recommendation": ("人工盘点应用架构、驱动、外设、业务依赖和数据迁移；核对厂商/组织支持计划与备份恢复方案，在试点环境验证迁移，再安排维护窗口并复查业务、驱动及安全更新状态。国内合规要求应依据组织适用标准及实际国产操作系统测试确认，本工具不自动判定。", "Inventory application architecture, drivers, peripherals, business dependencies, and data migration. Review vendor or organizational support plans and backup recovery, validate migration in a pilot, then schedule a maintenance window and verify business operation, drivers, and security updates. Assess local compliance against applicable standards and tested target systems; this tool does not determine compliance."),
        "rollback": ("本发现不执行变更。迁移前形成经审批的备份和回退方案；试点或正式切换失败时按批准方案恢复原环境并复核业务。", "This finding makes no changes. Prepare an approved backup and rollback plan before migration; if a pilot or cutover fails, restore the original environment under the approved plan and verify business operation."),
        "verification_checkpoint": ("由资产负责人核对操作系统版本、扩展支持合同、目标平台兼容性、备份恢复演练和迁移后更新状态。", "Have the asset owner verify the OS version, extended-support contract, target platform compatibility, backup recovery test, and post-migration update state."),
    },
    "OS_LIFECYCLE_COVERAGE": {
        "title": ("操作系统生命周期覆盖未确认", "Operating system lifecycle coverage is unconfirmed"),
        "applicability": ("无法依据当前采集事实确认受支持或已结束支持；这不是安全通过结论。", "Current collected facts cannot establish whether support is active or ended; this is not a security pass."),
        "impact": ("生命周期覆盖未知时，不能据此推断仍受支持或无风险。", "Unknown lifecycle coverage does not establish that the system remains supported or is risk-free."),
        "recommendation": ("从可信采集结果核实操作系统产品与版本，并补充经审核的生命周期策略记录后重新分析。", "Verify the operating system product and version from trusted collection results, add an audited lifecycle policy record, and analyze again."),
        "rollback": ("本发现不执行变更。", "This finding makes no changes."),
        "verification_checkpoint": ("复核 OS 采集来源、产品和版本，并确认策略快照覆盖该身份。", "Review the OS collection source, product, and version, and confirm the policy snapshot covers this identity."),
    },
}

from locales.listener_translations import LISTENER_FINDINGS
from locales.rule_translations import RULE_FINDINGS

for _translation_source in (LISTENER_FINDINGS, RULE_FINDINGS):
    for _rule_id, _fields in _translation_source.items():
        _catalog_fields = _FINDINGS.setdefault(_rule_id, {})
        for _field, _pair in _fields.items():
            existing = _catalog_fields.get(_field)
            # The analyzer supplies this exact description independently of the
            # bundled rule JSON. Keep its dedicated source mapping when merging
            # richer bundled-rule fields.
            if (_field == "description" and existing and
                    "Deterministic rule matched only explicit collected evidence; applicability remains version-bound." in existing):
                continue
            _catalog_fields[_field] = _pair

_DISPLAY_FIELDS = ("title", "description", "impact", "recommendation", "verification_checkpoint", "precheck", "applicability", "rollback")
# The inventory digest makes accidental deletion of a fixed report key visible.
# Update it only when deliberately adding or retiring a report resource key.
_TEXT_KEY_COUNT = 319
_TEXT_KEY_SHA256 = "d7db37905d26acfb6d2d4001b489fef064642cdb458595f51391efdbd6dc72b9"
_FINDING_KEY_SHA256 = "8b795d0f6f726ae6559b75ca634b781c1bec9a814b968826387901041e6a2cf8"


def text(key: str, language: str = "zh-CN") -> str:
    locale = normalize_language(language)
    pair = _TEXT.get(key)
    if (not isinstance(pair, tuple) or len(pair) != 2
            or any(not isinstance(item, str) or not item.strip() for item in pair)):
        raise LocaleResourceError(f"Required locale resource is missing or invalid: {key}")
    try:
        zh_fields = {field for _, field, _, _ in Formatter().parse(pair[0]) if field}
        en_fields = {field for _, field, _, _ in Formatter().parse(pair[1]) if field}
    except ValueError as exc:
        raise LocaleResourceError(f"Required locale resource has an invalid template: {key}") from exc
    if zh_fields != en_fields:
        raise LocaleResourceError(f"Required locale resource has inconsistent templates: {key}")
    return pair[0 if locale == "zh-CN" else 1]


def validate_resources() -> None:
    """Validate required labels and all bundled built-in finding translations."""
    problems: list[str] = []

    def valid_pair(resource_key: str, pair: Any) -> None:
        if not isinstance(pair, tuple) or len(pair) != 2 or any(not isinstance(value, str) or not value.strip() for value in pair):
            problems.append(f"{resource_key}: expected non-empty (zh-CN, en-US) strings")
            return
        try:
            zh_fields = {field for _, field, _, _ in Formatter().parse(pair[0]) if field}
            en_fields = {field for _, field, _, _ in Formatter().parse(pair[1]) if field}
        except ValueError as exc:
            problems.append(f"{resource_key}: malformed format template ({exc})")
            return
        if zh_fields != en_fields:
            problems.append(f"{resource_key}: zh-CN/en-US template placeholders differ")

    key_inventory = "\n".join(sorted(_TEXT)).encode("utf-8")
    key_count = len(_TEXT)
    key_digest = sha256(key_inventory).hexdigest()
    if key_count != _TEXT_KEY_COUNT or key_digest != _TEXT_KEY_SHA256:
        problems.append(f"text: required report resource inventory is incomplete or changed ({key_count}, {key_digest})")
    for key, pair in _TEXT.items():
        valid_pair(f"text:{key}", pair)
    for rule_id, fields in _FINDINGS.items():
        if not isinstance(fields, Mapping) or not fields:
            problems.append(f"finding:{rule_id}: missing field catalog")
            continue
        for field in _DISPLAY_FIELDS:
            if field in fields:
                valid_pair(f"finding:{rule_id}.{field}", fields[field])

    finding_keys = "\n".join(sorted(f"{rule_id}.{field}" for rule_id, fields in _FINDINGS.items() for field in fields)).encode("utf-8")
    if sha256(finding_keys).hexdigest() != _FINDING_KEY_SHA256:
        problems.append("finding: required built-in translation inventory is incomplete or changed")

    analyzer_rules = (
        "GENERIC_WILDCARD_LISTENER_REVIEW", "REDIS_WILDCARD_BIND_REVIEW",
        "LNX_EMPTY_PASSWORD_ACCOUNTS", "LNX_MULTIPLE_UID0_ACCOUNTS",
        "LNX_SSH_ROOT_LOGIN_PERMITTED", "LNX_SSH_EMPTY_PASSWORDS_PERMITTED",
        "LNX_PASSWORD_MAX_DAYS_WEAK", "LNX_PASSWORD_MIN_LEN_WEAK",
        "OS_LIFECYCLE_REVIEW", "OS_LIFECYCLE_COVERAGE",
    )
    for rule_id in analyzer_rules:
        if not _FINDINGS.get(rule_id):
            problems.append(f"finding:{rule_id}: analyzer-owned built-in resource is missing")

    if problems:
        raise LocaleResourceError("Localization resource validation failed:\n- " + "\n- ".join(problems))


def display_summary(summary: Any, language: str = "zh-CN") -> dict[str, Any]:
    """Localize app-owned summary labels and fixed derived text, preserving evidence values."""
    import re

    locale = normalize_language(language)
    if not isinstance(summary, Mapping):
        return {}

    fixed_values = {
        "未确认": ("未确认", "Unconfirmed"),
        "未检查": ("未检查", "Not checked"),
        "未知": ("未知", "Unknown"),
        "百分比未知": ("百分比未知", "Percentage unknown"),
        "未确认（空结果不代表无账户）": ("未确认（空结果不代表无账户）", "Unconfirmed (an empty result does not mean there are no accounts)"),
        "未确认（空结果不代表无成员）": ("未确认（空结果不代表无成员）", "Unconfirmed (an empty result does not mean there are no members)"),
        "未确认（空结果不代表无启动项）": ("未确认（空结果不代表无启动项）", "Unconfirmed (an empty result does not mean there are no startup items)"),
        "未确认（空结果不代表无磁盘）": ("未确认（空结果不代表无磁盘）", "Unconfirmed (an empty result does not mean there are no disks)"),
    }
    derived_fields = {
        "卷数", "卷剩余空间", "进程采集记录数", "内存占用靠前进程", "服务采集记录数",
        "账户数", "管理员组成员数", "启动项数量", "磁盘卷数量", "服务数量",
        "网络端口记录数量", "磁盘剩余空间", "进程记录数", "采集状态",
        "RDP启用", "RDP要求NLA", "SMB1启用", "自动登录启用", "本地账户数",
        "内置Guest启用", "防火墙配置文件", "密码策略读取状态",
        "密码最小长度/复杂度/锁定阈值",
    }

    def show_value(group: str, key: str, value: Any) -> Any:
        if group == "采集状态" and isinstance(value, str):
            statuses = {"ok": ("正常", "OK"), "partial": ("部分完成", "Partial"),
                        "need_admin": ("需要管理员权限", "Need administrator"), "failed": ("失败", "Failed"),
                        "skipped": ("已跳过", "Skipped"), "unknown": ("未知", "Unknown")}
            return statuses.get(value.casefold(), (value, value))[0 if locale == "zh-CN" else 1]
        if key in derived_fields and isinstance(value, str):
            pair = fixed_values.get(value)
            if pair:
                return pair[0 if locale == "zh-CN" else 1]
            count = re.fullmatch(r"未确认（空结果不代表无(账户|成员|启动项|磁盘)）", value)
            if count:
                phrase = {"账户": ("账户", "accounts"), "成员": ("成员", "members"), "启动项": ("启动项", "startup items"), "磁盘": ("磁盘", "disks")}[count.group(1)]
                return value if locale == "zh-CN" else f"Unconfirmed (an empty result does not mean there are no {phrase[1]})"
            # This sentence is generated by the CLI summary formatter. Preserve drive
            # identifiers and numeric measurements while translating only its syntax.
            disk = re.fullmatch(r"(.+?)：(.+?) 可用 / (.+?) 总量（([^（）]+)）", value)
            if disk:
                drive, free, total, percent = disk.groups()
                if locale == "en-US":
                    unit = lambda item: "Unknown" if item == "未知" else item
                    percent_text = "percentage unknown" if percent.rstrip("%") == "百分比未知" else percent
                    drive_text = "Unknown drive" if drive == "未知盘符" else drive.rstrip(':：')
                    return f"{drive_text}: {unit(free)} free / {unit(total)} total ({percent_text})"
            # Per-volume summaries can join multiple generated rows with Chinese semicolons.
            if "；" in value and key in {"卷剩余空间", "磁盘剩余空间"}:
                parts = value.split("；")
                rendered = [show_value(group, key, part) for part in parts]
                return ("; " if locale == "en-US" else "；").join(rendered)
            if key == "密码最小长度/复杂度/锁定阈值" and value == "未知/未知/未知" and locale == "en-US":
                return "Unknown / Unknown / Unknown"
        return value

    result: dict[str, Any] = {}
    for group, facts in summary.items():
        group_label = "summary.group." + str(group)
        group_text = text(group_label, locale) if group_label in _TEXT else str(group)
        if not isinstance(facts, Mapping):
            result[group_text] = facts
            continue
        localized_facts: dict[str, Any] = {}
        for key, value in facts.items():
            key_label = "summary.key." + str(key)
            key_text = text(key_label, locale) if key_label in _TEXT else str(key)
            localized_facts[key_text] = show_value(str(group), str(key), value)
        result[group_text] = localized_facts
    return result


def gap_text(value: Any, language: str = "zh-CN") -> str:
    """Translate fixed analyzer gap codes while retaining unknown messages verbatim."""
    raw = str(value or "")
    locale = normalize_language(language)
    if not raw:
        return ""
    controlled_families = {
        "REQUIRED_EVIDENCE_MISSING": ("缺少必需的证据文件", "Required evidence file is missing"),
        "EVIDENCE_PARTIAL": ("证据文件仅部分采集", "Evidence file was only partially collected"),
        "EVIDENCE_READ_FAILED": ("证据文件读取失败", "Evidence file could not be read"),
        "EVIDENCE_MISSING": ("证据文件缺失", "Evidence file is missing"),
        "EVIDENCE_TRUNCATED": ("证据文件已截断", "Evidence file was truncated"),
        "EVIDENCE_PERMISSION_DENIED": ("当前账户无权读取证据文件", "Current account could not read the evidence file"),
        "EVIDENCE_TOOL_UNAVAILABLE": ("采集所需原生命令不可用", "Required native collection command is unavailable"),
        "EVIDENCE_NOT_CHECKED": ("证据项未检查", "Evidence item was not checked"),
        "EVIDENCE_PARSE_FAILED": ("证据解析失败", "Evidence parsing failed"),
        "EVIDENCE_FAILED": ("证据采集失败", "Evidence collection failed"),
        "WINDOWS_ADMINISTRATOR_COUNT_UNKNOWN": ("管理员组成员数量未知", "Administrator group member count is unknown"),
        "WINDOWS_STARTUP_RECORD_COUNT_UNKNOWN": ("启动项记录数量未知", "Startup item record count is unknown"),
        "WINDOWS_STARTUP_EVIDENCE_TRUNCATED": ("启动项证据已截断", "Startup item evidence was truncated"),
        "WINDOWS_STARTUP_RECORD_COUNT_MISMATCH": ("启动项声明数量与采集记录不一致", "Declared startup item count does not match collected records"),
        "WINDOWS_STARTUP_FACTS_MISSING_OR_UNKNOWN": ("启动项事实缺失或未知", "Startup item facts are missing or unknown"),
        "WINDOWS_STARTUP_ROW_FORMAT_INVALID": ("启动项记录格式无效", "Startup item row format is invalid"),
        "WINDOWS_STARTUP_IMAGE_PATH_UNKNOWN": ("启动项映像路径未知", "Startup item image path is unknown"),
        "WINDOWS_SERVICE_FACTS_INCOMPLETE": ("Windows 服务事实不完整", "Windows service facts are incomplete"),
        "WINDOWS_SERVICE_MULTIPLE_EVIDENCE_FILES": ("存在多个 Windows 服务证据文件", "Multiple Windows service evidence files were found"),
        "WINDOWS_SECURITY_MULTIPLE_EVIDENCE_FILES": ("存在多个 Windows 安全证据文件", "Multiple Windows security evidence files were found"),
        "WINDOWS_SECURITY_FACTS_INCOMPLETE": ("Windows 安全事实不完整", "Windows security facts are incomplete"),
        "WINDOWS_DISK_MULTIPLE_EVIDENCE_FILES": ("存在多个 Windows 磁盘证据文件", "Multiple Windows disk evidence files were found"),
        "WINDOWS_ACCOUNT_MULTIPLE_EVIDENCE_FILES": ("存在多个 Windows 账户证据文件", "Multiple Windows account evidence files were found"),
        "WINDOWS_DISK_SIZE_UNKNOWN": ("磁盘总容量未知", "Disk total size is unknown"),
        "WINDOWS_DISK_FREE_SPACE_UNKNOWN": ("磁盘剩余空间未知", "Disk free space is unknown"),
        "WINDOWS_DISK_PERCENT_FORMAT_INVALID": ("磁盘剩余百分比格式无效", "Disk free percentage format is invalid"),
        "WINDOWS_DISK_ROW_FORMAT_INVALID": ("磁盘记录格式无效", "Disk row format is invalid"),
        "WINDOWS_DISK_VOLUME_ID_UNKNOWN": ("磁盘卷身份未知", "Disk volume identity is unknown"),
        "WINDOWS_DISK_VOLUME_ID_CONFLICT": ("磁盘卷身份存在冲突", "Disk volume identity conflicts"),
        "CONFIG_SCHEMA_INVALID": ("配置证据结构无效", "Configuration evidence schema is invalid"),
        "CONFIG_PARSE_FAILED": ("配置证据解析失败", "Configuration evidence could not be parsed"),
        "CONFIG_INCLUDE_SCOPE_UNCHECKED": ("配置 include 范围尚未检查", "Configuration include scope has not been checked"),
        "CONFIG_DUPLICATE_PRODUCT_INSTANCE": ("同一产品实例存在重复配置证据", "Duplicate configuration evidence exists for the same product instance"),
        "PRODUCT_VERSION_APPLICABILITY_UNVERIFIED": ("产品版本适用性未核实", "Product version applicability is unverified"),
        "REQUIRED_COMPONENT_EVIDENCE_MISSING": ("缺少所请求组件的配置证据", "Requested component configuration evidence is missing"),
        "REQUESTED_SCOPE_UNSUPPORTED": ("请求的分析范围不受支持", "Requested analysis scope is unsupported"),
        "NETWORK_COLLECTOR_STATUS": ("网络采集器状态", "Network collector status"),
        "PLATFORM_RULES_INVALID_OR_UNAVAILABLE": ("平台规则无效或不可用", "Platform rules are invalid or unavailable"),
        "WINDOWS_RISK_RULES_INVALID_OR_UNAVAILABLE": ("Windows 风险规则无效或不可用", "Windows risk rules are invalid or unavailable"),
        "FINDING_ID_CONFLICT": ("发现编号冲突，分析结果已拒绝", "Finding ID conflict; analysis results were rejected"),
        "LINUX_SECURITY_SUMMARY_NOT_CHECKED": ("Linux 安全摘要未执行检查", "Linux security summary was not checked"),
        "LISTENER_KNOWLEDGE_MISSING": ("监听规则知识库缺失", "Listener knowledge base is missing"),
        "LISTENER_KNOWLEDGE_TOO_LARGE": ("监听规则知识库超过资源限制", "Listener knowledge base exceeds the resource limit"),
        "LISTENER_KNOWLEDGE_JSON_INVALID": ("监听规则知识库 JSON 无效", "Listener knowledge base JSON is invalid"),
        "LISTENER_KNOWLEDGE_JSON_RESOURCE_LIMIT": ("监听规则知识库 JSON 超过资源限制", "Listener knowledge base JSON exceeds the resource limit"),
        "LISTENER_KNOWLEDGE_ENCODING_INVALID": ("监听规则知识库编码无效", "Listener knowledge base encoding is invalid"),
        "LISTENER_KNOWLEDGE_SCHEMA_INVALID": ("监听规则知识库结构无效", "Listener knowledge base schema is invalid"),
        "LISTENER_KNOWLEDGE_SCHEMA_UNSUPPORTED": ("监听规则知识库结构版本不受支持", "Listener knowledge base schema version is unsupported"),
        "LISTENER_KNOWLEDGE_RULE_INVALID": ("监听规则知识库中的规则无效", "A rule in the listener knowledge base is invalid"),
        "LISTENER_KNOWLEDGE_PORT_PROTOCOL_DUPLICATE": ("监听知识库中存在重复端口与协议规则", "Duplicate port and protocol rule in listener knowledge base"),
        "LISTENER_KNOWLEDGE_DUPLICATE_JSON_KEY": ("监听规则知识库 JSON 含有重复键", "Listener knowledge base JSON contains a duplicate key"),
        "LISTENER_KNOWLEDGE_UNAVAILABLE": ("监听规则知识库不可用", "Listener knowledge base is unavailable"),
        "LISTENER_KNOWLEDGE_INVALID": ("监听规则知识库无效", "Listener knowledge base is invalid"),
    }
    for prefix, pair in controlled_families.items():
        if raw == prefix or raw.startswith(prefix + ":"):
            suffix = raw[len(prefix):]
            detail = suffix[1:] if suffix.startswith(":") else ""
            label = pair[0 if locale == "zh-CN" else 1]
            if prefix == "NETWORK_COLLECTOR_STATUS" and detail:
                label = ("网络采集器状态" if locale == "zh-CN" else "Network collector status") + f": {detail}"
            elif detail:
                label += f": {detail}"
            # Keep the machine code and dynamic suffix visible for support triage.
            return f"{label} [{raw}]"
    codes = {
        "LISTENER_EVIDENCE_TRUNCATED": ("监听证据已截断", "Listener evidence was truncated"),
        "LISTENER_COLLECTOR_STATUS_UNKNOWN": ("监听采集状态未知", "Listener collection status is unknown"),
        "LISTENER_EVIDENCE_EMPTY_CONFIRMED": ("已确认监听证据为空", "Listener evidence was confirmed empty"),
        "LISTENER_LINE_UNRECOGNIZED": ("存在无法识别的监听记录", "Some listener records could not be parsed"),
        "LISTENER_ENDPOINT_INVALID_OR_UNKNOWN": ("监听端点无效或未知", "Listener endpoint is invalid or unknown"),
        "LISTENER_STATE_UNKNOWN": ("监听状态未知", "Listener state is unknown"),
        "LISTENER_FACTS_INVALID": ("监听事实无效", "Listener facts are invalid"),
        "LISTENER_PROTOCOL_UNKNOWN": ("监听协议未知", "Listener protocol is unknown"),
        "LISTENER_PORT_INVALID_OR_UNKNOWN": ("监听端口无效或未知", "Listener port is invalid or unknown"),
        "LISTENER_ADDRESS_INVALID_OR_UNKNOWN": ("监听地址无效或未知", "Listener address is invalid or unknown"),
        "LISTENER_PROCESS_UNKNOWN": ("监听进程未知", "Listener process is unknown"),
        "WINDOWS_DISK_FACTS_MISSING_OR_UNKNOWN": ("Windows 磁盘事实缺失或未知", "Windows disk facts are missing or unknown"),
        "WINDOWS_SECURITY_FACTS_MISSING_OR_UNKNOWN": ("Windows 安全事实缺失或未知", "Windows security facts are missing or unknown"),
        "WINDOWS_SERVICE_FACTS_MISSING_OR_UNKNOWN": ("Windows 服务事实缺失或未知", "Windows service facts are missing or unknown"),
        "WINDOWS_ACCOUNT_FACTS_MISSING_OR_UNKNOWN": ("Windows 账户事实缺失或未知", "Windows account facts are missing or unknown"),
        "WINDOWS_STARTUP_FACTS_MISSING_OR_UNKNOWN": ("Windows 启动项事实缺失或未知", "Windows startup facts are missing or unknown"),
        "TARGET_VERSION_APPLICABILITY_UNVERIFIED": ("目标版本适用性未核实", "Target version applicability is unverified"),
        "TARGET_ARCHITECTURE_UNVERIFIED": ("目标体系结构未核实", "Target architecture is unverified"),
        "OS_LIFECYCLE_EVIDENCE_CONTRADICTION": ("操作系统采集证据相互矛盾", "OS lifecycle evidence contains conflicting identities"),
        "OS_LIFECYCLE_COVERAGE_UNSUPPORTED": ("操作系统生命周期覆盖不受支持或身份未识别", "OS lifecycle coverage is unsupported or the identity is unrecognized"),
        "OS_LIFECYCLE_IDENTITY_CONTRADICTION": ("目标信息与采集到的操作系统身份冲突", "Target metadata conflicts with the collected OS identity"),
        "OS_LIFECYCLE_RECORD_UNAVAILABLE": ("验证后的策略中没有该操作系统身份的生命周期记录", "No lifecycle record for this OS identity exists in the validated policy"),
        "OS_LIFECYCLE_STATUS_UNSUPPORTED": ("生命周期记录未标记为支持结束；本模块不据此判断安全", "The lifecycle record is not classified as ended; this module makes no safety claim"),
        "OS_LIFECYCLE_POLICY_INVALID_OR_UNAVAILABLE": ("生命周期策略无效或不可用", "Lifecycle policy is invalid or unavailable"),
        "LINUX_ACCOUNT_SUMMARY_MISSING": ("Linux 账户摘要缺失", "Linux account summary is missing"),
        "LINUX_ACCOUNT_SUMMARY_NOT_CHECKED": ("Linux 账户摘要未执行检查", "Linux account summary was not checked"),
        "LINUX_SECURITY_SUMMARY_MISSING": ("Linux 安全摘要缺失", "Linux security summary is missing"),
        "LINUX_SECURITY_SUMMARY_NOT_CHECKED": ("Linux 安全摘要未执行检查", "Linux security summary was not checked"),
        "LINUX_UID0_COUNT_UNPARSED": ("Linux UID 0 账户数量无法解析", "Linux UID 0 account count could not be parsed"),
        "LINUX_EMPTY_PASSWORD_UNPARSED": ("Linux 空口令字段数量无法解析", "Linux empty password field count could not be parsed"),
        "LINUX_SHADOW_NOT_READABLE": ("Linux shadow 数据不可读", "Linux shadow data is not readable"),
        "LINUX_SSH_PERMIT_ROOT_LOGIN_DEFAULT_UNCONFIRMED": ("SSH root 登录默认值未核实", "The default SSH root login setting is unverified"),
        "LINUX_SSHD_CONFIG_NOT_READABLE": ("sshd 配置不可读", "The sshd configuration is not readable"),
        "Required evidence coverage is incomplete; an empty result is not a pass.": ("必需证据覆盖不完整；空结果不代表检查通过。", "Required evidence coverage is incomplete; an empty result is not a pass."),
        "No evidence files were supplied.": ("未提供证据文件。", "No evidence files were supplied."),
        "Risk analysis did not run because no valid registry was available.": ("没有可用的有效规则注册表，风险分析未运行。", "Risk analysis did not run because no valid registry was available."),
        "Exit status sidecar is malformed.": ("退出状态 sidecar 格式无效。", "Exit status sidecar is malformed."),
        "The bounded collector timed out.": ("受限采集器执行超时。", "The bounded collector timed out."),
        "The collector failed while gathering evidence.": ("采集器收集证据时失败。", "The collector failed while gathering evidence."),
        "The bounded collector exceeded its output limit.": ("受限采集器输出超过限制。", "The bounded collector exceeded its output limit."),
        "The bounded collector could not confirm child-process cleanup.": ("受限采集器无法确认子进程已清理。", "The bounded collector could not confirm child-process cleanup."),
        "Bounded capture runner reported a non-success status.": ("受限采集运行器报告了非成功状态。", "Bounded capture runner reported a non-success status."),
        "Evidence text is empty or whitespace-only.": ("证据文本为空或仅包含空白字符。", "Evidence text is empty or whitespace-only."),
        "The required native command was unavailable.": ("所需的系统原生命令不可用。", "The required native command was unavailable."),
        "The current account could not read this evidence; retry only with authorized administrator access.": ("当前账户无法读取此证据；仅在获得授权的管理员权限后重试。", "The current account could not read this evidence; retry only with authorized administrator access."),
        "The collector returned partial facts; see its notes and do not treat missing fields as passing.": ("采集器仅返回部分事实；请查看采集说明，缺失字段不能视为检查通过。", "The collector returned partial facts; see its notes and do not treat missing fields as passing."),
        "The collector reported partial status without usable facts.": ("采集器报告部分状态，但没有可用事实。", "The collector reported partial status without usable facts."),
        "Collector explicitly marked this evidence unavailable or excluded.": ("采集器明确标记此证据不可用或已排除。", "Collector explicitly marked this evidence unavailable or excluded."),
        "Collector could not safely identify the native output encoding.": ("采集器无法安全识别原生命令输出编码。", "Collector could not safely identify the native output encoding."),
        "Unsupported collector status marker.": ("采集器状态标记不受支持。", "Unsupported collector status marker."),
        "Evidence text encoding is unknown or invalid; content was not decoded.": ("证据文本编码未知或无效；未解码其内容。", "Evidence text encoding is unknown or invalid; content was not decoded."),
        "The bounded native command failed, timed out, exceeded output limit, or did not record an exit code.": ("受限原生命令失败、超时、输出超限或未记录退出码。", "The bounded native command failed, timed out, exceeded output limit, or did not record an exit code."),
        "Unsupported evidence type.": ("证据类型不受支持。", "Unsupported evidence type."),
        "local AI is opt-in and was not requested": ("本地 AI 为可选功能，且本次未请求。", "Local AI is opt-in and was not requested"),
        "Local AI is opt-in and was not requested.": ("本地 AI 为可选功能，且本次未请求。", "Local AI is opt-in and was not requested."),
        "provider, endpoint, and model are all required": ("必须同时提供 provider、endpoint 和 model。", "Provider, endpoint, and model are all required"),
    }
    for code, pair in codes.items():
        if raw == code or raw.startswith(code + ":"):
            suffix = raw[len(code):]
            return pair[0 if locale == "zh-CN" else 1] + suffix
    import re
    ai_error = re.fullmatch(r"([^:]+): request or response rejected", raw)
    if ai_error:
        message = "请求或响应被拒绝" if locale == "zh-CN" else "request or response rejected"
        return f"{ai_error.group(1)}: {message}"
    return raw + "（原文保留）" if locale == "zh-CN" else raw + " (source text retained)"


def display_reason(reason: Any, language: str = "zh-CN") -> str:
    """Localize exact built-in reason text and mark unknown source text verbatim."""
    return gap_text(reason, language)


def severity_display(value: Any, language: str = "zh-CN") -> str:
    raw = str(value or "Info")
    known = {"Critical", "Attention", "Warning", "Need Admin", "Info", "OK", "Skipped", "Failed"}
    localized = text("severity." + (raw if raw in known else "Info"), language)
    return raw if localized in {raw, "severity." + raw} else f"{raw} ({localized})"


def severity_explanation(value: Any, language: str = "zh-CN") -> str:
    raw = str(value or "Info")
    known = {"Critical", "Attention", "Warning", "Need Admin", "Info", "OK", "Skipped", "Failed"}
    return text("severity.meaning." + (raw if raw in known else "Info"), language)


def localize_legacy_report(lines: list[str], language: str) -> list[str]:
    """Translate known static legacy-report labels while leaving data cells verbatim."""
    locale = normalize_language(language)
    if locale == "zh-CN":
        return lines
    pairs = {zh: en for key, (zh, en) in _TEXT.items() if key.startswith("legacy.") or key.startswith("report.")}
    pairs.update({en: en for key, (zh, en) in _TEXT.items() if key.startswith("legacy.") or key.startswith("report.")})
    fixed_lines = {
        "- 状态：未采集 / Skipped": "- State: Not collected / Skipped",
        "- 说明：该 collector 未出现在本次结果中。": "- Description: This collector is absent from the current results.",
        "- 采集状态：未执行此项检查": "- Collection status: This check was not run",
        "- 风险判断：统一由 AnalysisResult Findings 提供，本节仅展示 Collector 事实。": "- Risk assessment is provided by AnalysisResult findings; this section shows collector facts only.",
        "- 说明：检测到软件存在不等于恶意，所有线索均需结合用户用途人工确认。": "- Note: Software presence does not mean malicious activity; review all clues in the user's context.",
        "- 未检测到已知安全软件或电脑管家组件。": "- No known security software or system utility components were detected.",
    }
    output: list[str] = []
    in_evidence = False
    for index, line in enumerate(lines):
        if in_evidence and line.startswith("  - "):
            output.append(line)
            continue
        in_evidence = False
        line = fixed_lines.get(line, line)
        is_evidence_heading = line in {"- 证据：", "- Evidence:"}
        if line.startswith(("## ", "### ")):
            prefix, heading = line.split(" ", 1)
            line = prefix + " " + pairs.get(heading, heading)
        elif line.startswith("|-") or (line.startswith("|---") and set(line.strip("|-").replace(":", "")) == set()):
            pass
        elif line.startswith("|") and index + 1 < len(lines) and lines[index + 1].startswith("|-"):
            cells = line.split("|")
            line = "|".join(pairs.get(cell.strip(), cell.strip()) if cell.strip() else "" for cell in cells)
        elif line.startswith("- ") or line.startswith("  - "):
            lead, rest = line.rsplit("- ", 1) if line.startswith("  - ") else ("", line[2:])
            for separator in ("：", ": "):
                if separator in rest:
                    label, value = rest.split(separator, 1)
                    if label in pairs:
                        rest = pairs[label] + ": " + value
                    elif value in pairs:
                        rest = label + separator + pairs[value]
                    break
            rest = pairs.get(rest, rest)
            line = lead + "- " + rest
        elif not line.startswith("|"):
            line = pairs.get(line, line)
        output.append(line)
        in_evidence = is_evidence_heading
    return output


def display_finding(finding: Mapping[str, Any], language: str) -> dict[str, Any]:
    """Return a display copy, translating only exact curated text for a stable rule id."""
    locale = normalize_language(language)
    display = dict(finding)
    known_lifecycle_description = False
    identity = str(finding.get("rule_id") or finding.get("finding_id") or "")
    # Instance-qualified findings (for example disk IDs and evidence products) retain
    # their stable rule identity while preserving the dynamic suffix in the finding.
    catalog = _FINDINGS.get(identity)
    if catalog is None:
        catalog = _FINDINGS.get(identity.split(":", 1)[0])
    if catalog:
        target_index = 0 if locale == "zh-CN" else 1
        source_index = 1 - target_index
        for field in _DISPLAY_FIELDS:
            value = finding.get(field)
            pair = catalog.get(field)
            if isinstance(value, str) and pair and value in pair:
                display[field] = pair[target_index]
            elif isinstance(value, str) and pair:
                translated = _translate_template(value, pair, target_index)
                if translated is None and field == "applicability":
                    translated = _translate_applicability_suffix(value, pair, target_index)
                if translated is not None:
                    display[field] = translated
    if identity in {"OS_LIFECYCLE_COVERAGE", "OS_LIFECYCLE_REVIEW"}:
        description_pairs = {
            "Collected OS evidence contains conflicting recognized product/version identities.": "采集到的操作系统证据包含相互冲突的已识别产品/版本身份。",
            "OS lifecycle coverage is unsupported or the collected OS identity is unrecognized.": "操作系统生命周期覆盖不受支持，或采集到的操作系统身份未识别。",
            "Declared target metadata conflicts with collected OS identity; lifecycle applicability is unresolved.": "声明的目标元数据与采集到的操作系统身份冲突；生命周期适用性尚未确定。",
            "Collected OS identity has no lifecycle record in the validated policy; support is unknown.": "验证后的策略中没有该操作系统身份的生命周期记录；支持状态未知。",
            "Lifecycle record is not classified as ended; this module makes no support-safety claim.": "生命周期记录未分类为支持结束；本模块不作支持状态或安全性结论。",
        }
        description = finding.get("description")
        translated = description_pairs.get(description) if isinstance(description, str) else None
        if translated:
            known_lifecycle_description = True
            display["description"] = translated if locale == "zh-CN" else description
    if identity == "OS_LIFECYCLE_REVIEW" and isinstance(finding.get("evidence"), dict):
        evidence = finding["evidence"]
        product = evidence.get("observed_product")
        version = evidence.get("observed_version")
        if product and version:
            expected = _FINDINGS[identity]["title"]
            if any(finding.get("title") == pair.format(product=product, version=version) for pair in expected):
                display["title"] = expected[0 if locale == "zh-CN" else 1].format(product=product, version=version)
    # If any prose field remains outside the curated exact source pairs, it may be
    # a local override or third-party rule. Preserve it and mark the source language.
    unresolved = any(
        isinstance(finding.get(field), str)
        and bool(finding[field])
        and not (field == "description" and known_lifecycle_description)
        and (not catalog or field not in catalog or (finding[field] not in catalog[field]
             and _translate_template(finding[field], catalog[field], 0 if locale == "zh-CN" else 1) is None
             and not (field == "applicability" and _translate_applicability_suffix(finding[field], catalog[field], 0 if locale == "zh-CN" else 1) is not None)))
        for field in _DISPLAY_FIELDS
    )
    if unresolved:
        display["_locale_source_note"] = text("finding_source_note", locale)
    return display


def _translate_template(value: str, pair: tuple[str, str], target_index: int) -> str | None:
    """Match only a full anchored template; preserve the captured dynamic value."""
    import re

    for source_index, source in enumerate(pair):
        if "{" not in source or "}" not in source:
            continue
        parts = re.split(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", source)
        pattern = "^" + "".join(re.escape(part) if index % 2 == 0 else "(?P<" + part + ">.+?)" for index, part in enumerate(parts)) + "$"
        match = re.fullmatch(pattern, value)
        if match:
            target = pair[target_index]
            try:
                return target.format(**match.groupdict())
            except (KeyError, ValueError):
                return None
    return None


def _translate_applicability_suffix(value: str, pair: tuple[str, str], target_index: int) -> str | None:
    """Translate only exact suffixes added by the analyzer to rule applicability."""
    import re
    for source in pair:
        if not value.startswith(source):
            continue
        suffix = value[len(source):]
        if suffix == "；组件准确版本未核实":
            return pair[target_index] + ("；组件准确版本未核实" if target_index == 0 else "; component's exact version is unverified")
        match = re.fullmatch(r"；配置声明版本：(.{1,100})（尚未独立核实）", suffix)
        if match:
            return pair[target_index] + (f"；配置声明版本：{match.group(1)}（尚未独立核实）" if target_index == 0 else f"; declared configuration version: {match.group(1)} (not independently verified)")
        match = re.fullmatch(r"; declared configuration version: (.{1,100}) \(not independently verified\)", suffix)
        if match:
            return pair[target_index] + (f"；配置声明版本：{match.group(1)}（尚未独立核实）" if target_index == 0 else f"; declared configuration version: {match.group(1)} (not independently verified)")
        if suffix == "; component exact version is unverified":
            return pair[target_index] + ("；组件准确版本未核实" if target_index == 0 else "; component's exact version is unverified")
    return None
