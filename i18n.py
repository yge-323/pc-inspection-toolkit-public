"""Explicit application language helpers; machine-readable contracts stay unchanged."""
from __future__ import annotations

import json
import hashlib
import os
import secrets
import stat
import string
from pathlib import Path
from typing import Any

DEFAULT_LANGUAGE = "zh-CN"
LANGUAGES = ("zh-CN", "en-US")
_LANGUAGE_ALIASES = {
    "zh": "zh-CN", "zh-cn": "zh-CN", "zh-hans": "zh-CN", "chinese": "zh-CN",
    "en": "en-US", "en-us": "en-US", "english": "en-US",
}

# Keys are complete, application-authored source phrases. Unknown user, rule, and
# evidence text is returned as-is; this module never rewrites substrings.
_ZH_EN = {
    "巡检工作台": "Inspection workspace",
    "从本机只读采集或导入现场证据开始": "Start with a read-only local inspection or import field evidence",
    "本机只读巡检": "Read-only local inspection",
    "仅检查当前 Windows 设备；需要你明确确认授权": "Checks this Windows device only; your explicit authorization is required",
    "现场证据导入": "Field evidence import",
    "校验原生采集目录、EvidenceBundle 或 SecureCRT / 4A 粘贴证据": "Validate a native capture folder, EvidenceBundle, or SecureCRT / 4A paste evidence",
    "分析与报告": "Analysis and reports",
    "按真实 analysis.json 展示确定性发现、证据缺口与独立的 AI 辅助建议": "Show deterministic findings, evidence gaps, and separate AI assistance from the selected analysis.json",
    "复查与交付": "Review and handoff",
    "导出脱敏交付文件，或按现有规则比较整改前后分析": "Export a redacted handoff or compare analyses before and after remediation using the existing rules",
    "概览": "Overview", "本机巡检": "Local inspection", "证据导入": "Import evidence",
    "复查与交付": "Review and handoff", "取消当前操作": "Cancel current operation",
    "现场巡检与证据分析": "Field inspection and evidence analysis",
    "现场巡检与分析": "Field inspection and analysis",
    "现场维护工具": "Field maintenance toolkit", "Windows 本地工具": "Windows desktop toolkit",
    "工作空间": "Workspace", "安全原则": "Safety principles", "V3 离线巡检": "V3 offline inspection",
    "第一步：安全授权后再开始": "Step 1: confirm authorization before starting",
    "在本机执行只读巡检，或将现场采集证据带回分析。": "Run a read-only inspection locally, or bring field evidence back for analysis.",
    "当前操作不会自动提权；不会自动联网或请求 AI；不会自动执行修改。": "This app does not elevate privileges, connect to the network, request AI, or apply changes automatically.",
    "开始本机巡检": "Start local inspection", "导入现场证据": "Import field evidence",
    "本机权限 · Windows 维护": "Local permissions · Windows maintenance",
    "设备当前状态": "Current device status", "尚无本会话实例": "No session instance yet",
    "选择场景": "Select a scenario", "本机检查": "Local inspection",
    "现场证据目录": "Field evidence folder", "只读取证据，不写回目标": "Read evidence only; do not write to the target",
    "我已获得当前设备、当前权限范围内的只读巡检授权": "I have authorization for a read-only inspection of this device within the current permission scope",
    "可见范围": "Visible scope", "以当前权限和证据缺口为准。": "Scope depends on current permissions and evidence gaps.",
    "缺少权限不会自动提升到管理员权限，也不会把未检查项标为安全。": "The app will not elevate to administrator; unchecked items are not marked safe.",
    "执行进度与日志": "Progress and logs", "本机只读巡检": "Read-only local inspection",
    "尚未确认授权，当前不会启动采集。": "Authorization is not confirmed; collection will not start.",
    "巡检只读运行。权限不足与证据缺失会记录为缺口；PARTIAL 不表示检查通过。": "Inspection is read-only. Missing permissions and evidence are recorded as gaps; PARTIAL does not mean a pass.",
    "选择证据来源": "Choose evidence source", "导入前先检查目录边界、来源完整性和目标绑定结果。": "Before import, check directory boundaries, source integrity, and target binding.",
    "U 盘目录 / EvidenceBundle": "USB folder / EvidenceBundle", "SecureCRT / 4A 粘贴文件": "SecureCRT / 4A paste file",
    "报告保存目录": "Report output folder", "本地 AI 辅助建议": "Local AI suggestions",
    "默认关闭": "Off by default", "启用 Ollama 本地建议": "Enable Ollama local suggestions",
    "AI 设置…": "AI settings…", "启用前需确认 Ollama cloud 功能关闭；AI 请求仅在明确启用后发出。": "Confirm Ollama cloud is off first; AI requests are sent only after explicit opt-in.",
    "分析状态": "Analysis status", "只有证据导入成功后才能启动分析。": "Analysis can start only after evidence is imported successfully.",
    "校验并安全导入": "Validate and import safely", "打开分析结果": "Open analysis results",
    "源目录不会被修改；这里只会把选中的数据复制到新的隔离案例目录并执行脚本。": "The source folder is not modified; selected data is copied to a new isolated case folder before scripts run.",
    "当前分析结果": "Current analysis results", "分析详情": "Analysis details",
    "Finding 详情": "Finding details", "展示分析文件中的原始字段，不会使用预设示例内容。": "Shows fields from the analysis file; no example content is substituted.",
    "证据缺口与状态说明": "Evidence gaps and status notes", "AI 辅助建议（非正式结论）": "AI assistance (not a formal finding)",
    "准确的 Finding 规则结论不会被 AI 文本替代，也不会改变等级和状态。": "AI text does not replace deterministic Finding rules or change severity or status.",
    "报告文件": "Report files", "打开报告目录": "Open report folder", "选择 analysis.json…": "Choose analysis.json…",
    "当前交付": "Current handoff", "前后分析比较遵循同一规则摘要；证据不足不能解释为已解决。": "Before/after comparison uses the same rule summary; missing evidence does not mean resolved.",
    "Codex 脱敏交付": "Redacted Codex handoff", "使用当前已加载的 analysis.json？\n选择“否”以另选文件。": "Use the currently loaded analysis.json?\nChoose No to select another file.",
    "选择一份 analysis.json，导出仅含白名单摘要的交付文件。": "Select an analysis.json to export a handoff containing only allow-listed summaries.",
    "生成脱敏交付文件…": "Create redacted handoff…", "整改前后比较": "Before/after comparison",
    "同一资产和规则摘要下比较整改前后；变化的规则不当作已解决。": "Compare before and after for the same asset and rule summary; changed rules are not treated as resolved.",
    "比较 analysis.json…": "Compare analysis.json…", "返回分析与报告": "Back to analysis and reports",
    "提供者": "Provider", "Ollama（当前支持）": "Ollama (currently supported)",
    "启用前必须确认 Ollama cloud 功能已关闭": "Confirm Ollama cloud is off before enabling",
    "服务调用位置不能仅由回环地址证明。AI 建议与规则结论分开。": "A loopback address alone does not prove where a service runs. AI suggestions remain separate from rule findings.",
    "取消": "Cancel", "保存本次设置": "Save these settings",
    "当前会话尚无比较结果。": "There is no comparison result in this session yet.",
    "未开始": "Not started", "未加载": "Not loaded", "请选择已有 analysis.json，或完成一次分析。": "Choose an existing analysis.json or complete an analysis.",
    "尚未加载分析。请选择真实 analysis.json；不会使用示例数据填充。": "No analysis loaded. Choose a real analysis.json; example data is never inserted.",
    "未加载分析文件。选择真实 analysis.json 后，这里展示对应 Finding 字段。": "No analysis loaded. Choose a real analysis.json to display its Finding fields here.",
    "未加载分析文件。": "No analysis loaded.",
    "AI 默认关闭；加载真实分析文件后显示该分析实际记录的 AI 状态与建议。": "AI is off by default. Load a real analysis file to see its recorded AI status and suggestions.",
    "请选择证据缺口，单击查看下方原始解释。": "Select an evidence gap to view its original explanation below.",
    "请选择证据目录或完整的粘贴导出文件。": "Select an evidence folder or a complete paste export file.",
    "请选择粘贴证据对应的实际用途。": "Choose the actual use case for the pasted evidence.",
    "原生证据目录尚未封装；请选择实际用途。": "The native evidence folder has not been sealed; choose its actual use case.",
    "请先确认当前设备及当前权限范围内的只读巡检授权。工具不会自动提权。": "Confirm read-only inspection authorization for this device and permission scope. The app will not elevate privileges.",
    "请选择巡检场景。": "Select an inspection scenario.",
    "项目代号和设备代号必须是 1–80 位 ASCII 字母、数字、点、下划线或连字符。": "Project and asset aliases must be 1–80 ASCII letters, digits, dots, underscores, or hyphens.",
    "启用 AI 前必须确认 Ollama cloud 功能已关闭。": "Confirm Ollama cloud is off before enabling AI.",
    "请填写本地服务 Endpoint、模型名称和 1–1800 秒的超时。": "Enter the local service endpoint, model name, and a timeout from 1 to 1800 seconds.",
    "AI 超时必须是 1–1800 秒的整数。": "The AI timeout must be an integer from 1 to 1800 seconds.",
    "等待确认": "Awaiting confirmation", "尚未开始": "Not started", "等待证据": "Awaiting evidence", "等待分析": "Awaiting analysis",
    "已确认只读授权": "Read-only authorization confirmed", "已分析证据": "Evidence analyzed", "报告已生成": "Report generated", "已加载分析文件": "Analysis file loaded",
    "报告目录": "Report folder", "状态": "Status", "确定性发现": "Deterministic findings", "证据缺口 / 警告": "Evidence gaps / warnings",
    "分析未完整；缺失证据不代表未发现问题。": "Analysis is incomplete; missing evidence does not mean no issues were found.",
    "本机 AI 建议": "Local AI suggestions", "服务商": "Provider", "Endpoint": "Endpoint", "模型": "Model", "超时": "Timeout",
    "当前已设置": "Configured for this session", "已启用": "Enabled", "已关闭": "Off",
    "选择已有 analysis.json": "Choose an existing analysis.json", "选择报告的 analysis.json": "Choose an analysis.json for the report",
    "选择整改前 analysis.json": "Choose the before-remediation analysis.json", "选择整改后 analysis.json": "Choose the after-remediation analysis.json",
    "确认授权": "Confirm authorization", "采集或导入": "Collect or import", "规则分析": "Rule analysis", "报告与复查": "Reports and review",
    "打开最近报告目录": "Open latest report folder", "打开报告目录": "Open report folder", "查看日志": "View logs",
    "暂无风险发现；未检查范围不代表安全。": "No risk findings were generated; unchecked scope does not mean safe.",
    "未加载分析。": "No analysis loaded.", "本次会话还没有可查看的报告目录。": "No report folder is available in this session yet.",
    "尚无本会话报告。请先完成分析或加载分析文件。": "There is no report for this session yet. Complete an analysis or load an analysis file.",
    "报告文件不存在：{name}": "Report file not found: {name}",
    "无法加载分析文件：{error}": "Could not load analysis file: {error}",
    "无法加载分析文件：{error_type}: {error}": "Could not load analysis file: {error_type}: {error}",
    "操作仍在运行": "Operation is still running", "取消当前操作并关闭窗口？": "Cancel the current operation and close the window?",
    "当前操作仍在运行，请等待完成或先取消。": "An operation is still running. Wait for it to finish or cancel it first.",
    "本次会话还没有可查看的报告目录。": "No report folder is available in this session yet.",
    "就绪。未检查不代表安全；工具不会自动提权或修改目标配置。": "Ready. Unchecked scope is not safe by default; the app will not elevate or modify target configuration.",
    "实际采集与导入需显式授权。": "Collection and import require explicit authorization.",
}
_ZH_EN.update({
    "已加载分析文件": "Analysis file loaded",
    "选择已有 analysis.json": "Choose an existing analysis.json",
    "选择报告的 analysis.json": "Choose an analysis.json for the report",
    "选择整改前 analysis.json": "Choose the before-remediation analysis.json",
    "选择整改后 analysis.json": "Choose the after-remediation analysis.json",
    "保存脱敏交付文件": "Save redacted handoff file",
    "分析 JSON": "Analysis JSON",
    "使用当前已加载的 analysis.json？\n选择“否”以另选文件。": "Use the currently loaded analysis.json?\nChoose No to select another file.",
    "Codex 脱敏交付": "Codex redacted handoff",
    "命令退出码 {code}；请检查上方安全错误信息。": "Command exited with code {code}; review the safety error above.",
    "报告文件不存在：{name}": "Report file does not exist: {name}",
    "无法打开所选报告：{error_type}: {error}": "Could not open the selected report: {error_type}: {error}",
    "结果文件无法安全显示：": "The result file could not be displayed safely: ",
    "取消当前操作并关闭窗口？": "Cancel the current operation and close the window?",
    "保存这些设置": "Save these settings",
    "粘贴通道使用现有 paste-import 校验；选择完整的 SecureCRT / 4A 导出文本，不执行其中内容。": "The paste flow uses the existing paste-import validation. Choose a complete SecureCRT / 4A export; its contents are not executed.",
    "支持固定采集器输出目录及 EvidenceBundle；仅复制并解析允许的证据文件。": "Supports fixed collector output folders and EvidenceBundle; only allow-listed evidence files are copied and parsed.",
    "巡检工具": "Inspection Toolkit",
    "未检查不代表安全": "Unchecked does not mean safe",
    "证据缺口与分析状态说明显示在下方区域。": "Evidence gaps and analysis status are shown below.",
    "已选择“证据缺口”。请查看下方的原始警告与错误列表。": "Evidence gaps are selected. See the original warnings and errors below.",
    "尚未加载分析。请选择真实 analysis.json；不会使用示例数据填充。": "No analysis loaded. Choose a real analysis.json; example data is never inserted.",
    "当前筛选条件下没有待复核 Finding；这不改变分析状态。": "No findings need review under this filter; the analysis status is unchanged.",
    "分析中没有规则 Finding；证据缺口和状态仍需单独查看。": "The analysis has no rule findings; evidence gaps and status still need separate review.",
    "分析文件未记录警告或错误。该信息不代表已检查范围外的安全状态。": "The analysis records no warnings or errors. This says nothing about areas outside the checked scope.",
    "分析文件": "Analysis file",
    "本机只读巡检": "Local read-only inspection",
    "证据导入与分析": "Evidence import and analysis",
    "Codex 脱敏导出": "Codex redacted export",
    "复查比较": "Review comparison",
    "证据已分析": "Evidence analyzed",
    "报告已生成": "Report generated",
    "已加载分析文件": "Analysis file loaded",
    "正在进行本机只读巡检": "Running a local read-only inspection",
    "正在校验证据并进行规则分析": "Validating evidence and running rule analysis",
    "正在生成脱敏交付文件": "Generating a redacted handoff file",
    "正在按正式比较规则核对两份分析": "Comparing the two analyses under the formal comparison rules",
    "未加载": "Not loaded", "未知": "Unknown",
    "状态": "Status", "警告 / 证据缺口": "Warnings / evidence gaps", "分析错误": "Analysis errors",
    "严重": "Critical", "高": "High", "警告": "Warning", "提示": "Information",
    "项目代号和设备代号必须是 1–80 位 ASCII 字母、数字、点、下划线或连字符。": "Project and asset aliases must be 1–80 ASCII letters, digits, dots, underscores, or hyphens.",
    "无法打开所选报告：{error_type}: {error}": "Could not open the selected report: {error_type}: {error}",
    "命令退出码 {code}；请检查上方安全错误信息。": "Command exited with code {code}; review the safety error above.",
    "分析已生成，但结果文件未能安全加载；未显示为成功。": "Analysis was generated, but its result file could not be safely loaded; it is not shown as successful.",
    "已完成（需以分析状态为准）": "Completed (check the analysis status)",
    "操作已取消，未标记成功。": "Operation cancelled; it is not marked as successful.",
    "操作未完成；已有确定性报告（若已生成）仍可查看。": "Operation did not complete; any deterministic report already generated remains available.",
    "已结束。PARTIAL / FAILED 不表示检查通过。": "finished. PARTIAL / FAILED do not mean a pass.",
    "；界面可继续响应，也可请求取消。": "; the interface remains responsive and you can cancel.",
    "操作未完成：": "Operation did not complete: ",
    "正在请求取消，并清理本程序启动的子进程……": "Requesting cancellation and stopping child processes started by this app…",
    "正在结束当前子进程；请等待窗口关闭。": "Stopping the current child process; wait for the window to close.",
    "操作仍在运行": "Operation is still running",
    "选择完整的 SecureCRT / 4A 粘贴导出文件": "Choose a complete SecureCRT / 4A paste export file",
    "所选证据目录不存在。": "The selected evidence folder does not exist.",
    "所选粘贴导出文件不存在。": "The selected paste export file does not exist.",
    "现有 paste-import 命令未返回已导入案例路径。": "The existing paste-import command did not return the imported case path.",
    "分析结果结构不正确。": "The analysis result has an invalid structure.",
    "项目代号": "Project alias", "设备代号": "Asset alias", "检查场景": "Inspection scenario",
    "案例保存目录": "Case storage folder", "报告输出目录": "Report output folder",
    "系统、CPU、内存与磁盘摘要": "System, CPU, memory, and disk summary",
    "监听端口、防火墙与共享线索": "Listening ports, firewall, and sharing indicators",
    "服务、启动项与计划任务": "Services, startup items, and scheduled tasks",
    "账户摘要及安全软件状态": "Account summary and security software status",
    "权限差异与采集缺口记录": "Permission differences and collection gaps",
    "固定文件与目录白名单": "Fixed file and directory allow-list",
    "真实采集时间及版本检查": "Collection time and version checks",
    "完整性校验与目标绑定": "Integrity and target binding checks",
    "缺失或冲突时保留缺口，不伪装完整": "Keep gaps for missing or conflicting data; never imply completeness",
    "用途（原生目录及粘贴证据必填）": "Use case (required for native folders and pasted evidence)",
    "Ollama 辅助建议设置": "Ollama assistance settings",
    "本地服务 Endpoint": "Local service endpoint", "模型名称": "Model name", "请求超时（秒）": "Request timeout (seconds)",
    "启用前需确认 Ollama cloud 功能关闭；AI 请求仅在明确启用后发出。": "Confirm Ollama cloud is off first; AI requests are sent only after explicit opt-in.",
    "仅在导入分析时启用；Ollama cloud 功能必须由你确认已关闭。": "Used only during analysis; confirm Ollama cloud is disabled first.",
    "AI 对话标题": "AI conversation title", "本地 AI 辅助建议": "Local AI suggestions",
    "规则 Finding": "Rule findings", "证据缺口 / 错误": "Evidence gaps / errors",
    "证据目录或粘贴文件": "Evidence folder or paste file", "证据缺口": "Evidence gaps",
    "已加载分析": "Analysis loaded", "未命名": "Untitled",
    "全部": "All", "待复核": "Needs review",
    "系统、CPU、内存与磁盘摘要": "System, CPU, memory, and disk summary",
    "系统、CPU、内存与磁盘摘要": "System, CPU, memory, and disk summary",
    "案例保存目录": "Case storage folder",
    "已有操作正在运行，请等待完成或先取消。": "An operation is already running; wait for it to finish or cancel it first.",
    "分析已生成，但结果文件未能安全加载；未显示为成功。": "Analysis was generated, but the result file could not be loaded safely; it is not shown as successful.",
    "复查比较文件：": "Comparison report: ", "已导入案例：": "Imported case: ",
    "操作未完成：": "Operation did not complete: ",
    "分析状态异常：": "Analysis status error: ",
    "读取分析结果失败：": "Could not read analysis result: ",
    "正在请求取消，并清理本程序启动的子进程……": "Requesting cancellation and stopping child processes started by this app…",
    "正在结束当前子进程；请等待窗口关闭。": "Stopping the current child process; wait for the window to close.",
    "无效的 analysis.json 结果结构。": "Invalid analysis.json result structure.",
    "已加载分析：": "Analysis loaded: ",
    "操作未完成；已有确定性报告（若已生成）仍可查看。": "Operation did not complete; any deterministic report already generated remains available.",
    "请选择列表中的实际用途。": "Choose an actual use case from the list.",
    "V3 桌面巡检": "V3 desktop inspection",
    "Windows 桌面工具": "Windows desktop tool",
    "保存复查结果": "Save review results",
    "保存脱敏交付文件": "Save redacted handoff file",
    "尚无本会话报告。": "No report has been created in this session yet.",
    "本会话尚无比较结果。": "No comparison result is available in this session yet.",
    "未知/其他": "Unknown / other",
    "检查项目 / Finding": "Check / Finding",
    "级别": "Severity",
    "证据摘要": "Evidence summary",
    "选择完整的 SecureCRT / 4A 粘贴导出文件": "Choose a complete SecureCRT / 4A paste export file",
    "选择文件…": "Choose file…",
    "选择目录…": "Choose folder…",
    "规则 ID": "Rule ID", "检查项目": "Check", "风险等级": "Severity",
    "类别": "Category", "对象": "Subject", "描述": "Description",
    "原始证据": "Raw evidence", "整改前核查": "Pre-change checks",
    "适用性": "Applicability", "影响与条件": "Impact and conditions",
    "整改建议": "Recommended action", "回滚": "Rollback",
    "复查要点": "Verification points", "警告 / 证据缺口": "Warnings / evidence gaps",
    "分析错误": "Analysis errors", "Finding 详情": "Finding details",
    "保存复查结果": "Save review results",
    "检查本机 Windows 设备": "Inspect this Windows device",
    "PC Inspection Toolkit · 现场巡检与证据分析": "PC Inspection Toolkit · Field inspection and evidence analysis",
    "语言选项无效。": "Invalid language option.",
    "不支持所选语言。": "The selected language is not supported.",
    "仅支持内部 --startup-check 选项。": "Only the internal --startup-check option is accepted.",
    "Tkinter 不可用；请使用 inspection_cli.py。": "Tkinter is unavailable; use inspection_cli.py.",
    "偏好设置读取失败，已使用简体中文。": "The preference could not be read; Simplified Chinese is being used.",
    "语言偏好保存失败；已恢复此前语言。": "The language preference could not be saved; the previous language was restored.",
    "English": "English",
    "简体中文": "Simplified Chinese",
    "从一次安全、可追溯的巡检开始": "Start with a safe, traceable inspection",
    "在本机执行只读巡检，或把现场采集的证据带回工具分析。": "Run a read-only inspection locally, or bring collected field evidence back for analysis.",
    "所有操作均需人工发起；不会自动提权、修改配置或执行修复。": "Every operation is started by a person; the app will not elevate privileges, change configuration, or apply fixes automatically.",
    "离线优先 · Windows 维护端": "Offline-first · Windows maintenance workstation",
    "作业流程": "Workflow", "各步骤只显示本会话实际状态": "Each step shows the actual state of this session",
    "选择任务": "Choose a task", "能力与边界": "Capabilities and boundaries",
    "检查本机 Windows 设备": "Inspect this Windows device",
    "填写设备代号、选择目录并确认授权后启动只读采集。": "Enter an asset alias, choose a folder, and confirm authorization to start read-only collection.",
    "打开巡检": "Open inspection", "打开巡检  ›": "Open inspection  ›",
    "界面语言": "Interface language",
    "报告语言": "Report language",
    "跟随界面": "Follow interface",
    "简体中文报告": "Chinese report",
    "英文报告": "English report",
    "语言资源缺失或无效；已保留此前语言。": "A required language resource is missing or invalid; the previous language was kept.",
    "文本文件": "Text files",
    "所有文件": "All files",
    "只读操作 · 不修改目标": "Read-only actions · target is not modified",
    "不会自动提权或执行修复": "No automatic elevation or remediation",
    "分析外部设备证据": "Analyze evidence from another device",
    "导入 EvidenceBundle、固定采集器目录或 SecureCRT / 4A 粘贴结果。": "Import an EvidenceBundle, a fixed collector folder, or SecureCRT / 4A paste output.",
    "打开导入": "Open import", "打开导入  ›": "Open import  ›",
    "规则 Finding 与证据缺口展示": "Rule findings and evidence gaps",
    "Markdown / HTML / CSV / JSON 报告": "Markdown / HTML / CSV / JSON reports",
    "Codex 脱敏交付与前后复查": "Redacted Codex handoff and before/after review",
    "Ollama 建议为可选功能，默认关闭": "Ollama suggestions are optional and off by default",
    "任务配置": "Task configuration", "只填写脱敏标识；证据由本机只读采集产生。": "Enter redacted aliases only; evidence is collected locally in read-only mode.",
    "我已获得当前设备及当前权限范围内的只读巡检授权": "I am authorized to inspect this device within the current permission scope in read-only mode",
    "采集范围": "Collection scope", "具体可用性以现场运行结果及权限为准。": "Actual coverage depends on runtime results and permissions.",
    "缺少权限不会自动申请管理员权限，也不会把未检查项目标记为安全。": "The app will not request administrator access; unchecked items are not marked safe.",
    "执行进度与日志": "Progress and logs", "启动后显示真实采集日志、退出状态和分析输出。": "After start, this shows actual collection logs, exit status, and analysis output.",
    "开始只读巡检": "Start read-only inspection", "取消当前操作": "Cancel current operation",
    "必须先确认授权；运行中可取消。": "Confirm authorization first; you can cancel while it runs.",
    "巡检只读运行。权限不足或证据缺失会记录为缺口，PARTIAL 不代表检查通过。": "Inspection runs read-only. Missing permissions or evidence are recorded as gaps; PARTIAL does not mean a pass.",
    "浏览…": "Browse…", "执行日志": "Execution log", "显示本会话中的 CLI 输出；不会写入 Git 或自动上传。": "Shows CLI output from this session; nothing is written to Git or uploaded automatically.",
    "选择证据来源": "Choose evidence source", "导入前执行白名单、元数据、完整性和目标绑定检查。": "Import checks the allow-list, metadata, integrity, and target binding first.",
    "U 盘目录 / EvidenceBundle": "USB folder / EvidenceBundle", "SecureCRT / 4A 粘贴文件": "SecureCRT / 4A paste file",
    "导入保护规则": "Import safeguards", "只提交 Finding 白名单摘要；建议不会改写规则结论或分析状态。": "Only allow-listed Finding summaries are sent; suggestions do not rewrite rule findings or analysis status.",
    "启用 Ollama 辅助建议": "Enable Ollama suggestions", "导入状态": "Import status", "只有证据导入成功后才会启动分析。": "Analysis starts only after evidence imports successfully.",
    "源目录不会被修改；导入包中的内容按不可信数据解析，不执行脚本。": "The source folder is not modified; imported content is treated as untrusted data and scripts are not executed.",
    "当前分析案例": "Current analysis case", "检查结果明细": "Inspection details",
    "展示分析文件中的原始字段，不重新推导风险。": "Shows original fields from the analysis file without deriving risk again.",
    "证据缺口与状态说明": "Evidence gaps and status notes", "与确定性 Finding 分区显示；不会改变 Finding、风险等级或分析状态。": "Shown separately from deterministic findings; does not change findings, severity, or analysis status.",
    "当前报告": "Current report", "复查要求目标身份与规则摘要符合比较契约；证据不足不会标记为已解除。": "Review requires matching target identity and rule summary; missing evidence is not marked resolved.",
    "打开最近报告目录": "Open latest report folder", "由正式 CLI 生成；请在分享前复核脱敏结果。": "Generated by the official CLI; review redaction before sharing.",
    "导出脱敏交付文件…": "Export redacted handoff…", "同一项目资产与规则身份下比较；变化的规则不会当作已解决。": "Compare the same project asset and rule identity; changed rules are not treated as resolved.",
    "比较 analysis.json…": "Compare analysis.json…", "本地模型设置": "Local model settings", "仅在导入分析时启用；Ollama cloud 功能必须由你确认已关闭。": "Used only during analysis; confirm Ollama cloud is disabled first.",
    "提供方": "Provider", "Ollama（当前支持）": "Ollama (currently supported)",
    "我已确认 Ollama cloud 功能关闭": "I confirm Ollama cloud is disabled",
    "服务身份与推理位置不能仅由回环地址证明。AI 建议与规则结论分开。": "A loopback address alone cannot prove service identity or inference location. AI suggestions remain separate from rule findings.",
    "保存本次设置": "Save these settings", "已选择“证据缺口”。请查看下方的原始警告与错误列表。": "Evidence gaps selected. See the original warnings and errors below.",
    "当前筛选条件下没有待复核 Finding；这不改变分析状态。": "No findings need review under this filter; analysis status is unchanged.",
    "分析中没有规则 Finding；证据缺口和状态仍需单独查看。": "No rule findings are present; evidence gaps and status still need separate review.",
    "该 Finding 没有可显示的详情字段。": "This finding has no detail fields to display.",
    "分析文件未记录警告或错误。该信息不代表已检查范围外的安全状态。": "The analysis file records no warnings or errors. This says nothing about unchecked scope.",
    "当前分析没有 AI 辅助建议字段。AI 默认关闭，且不会改变确定性 Finding。": "This analysis has no AI suggestions. AI is off by default and does not change deterministic findings.",
    "AI 内容仅为辅助建议，不是确定性风险结论。": "AI text is advisory and is not a deterministic risk finding.",
    "AI 状态：": "AI status: ", "原因：": "Reason: ", "（引用：": " (references: ", "未提供": "Not provided",
    "报告目录": "Report folder", "采集状态": "Collection status",
    "无法加载分析文件：{error_type}: {error}": "Could not load analysis file: {error_type}: {error}",
    "文件夹尚未准备就绪。": "The folder is not ready yet.",
    "analysis.json 不存在。": "analysis.json does not exist.",
    "analysis.json 超出 20 MiB 安全读取上限。": "analysis.json exceeds the 20 MiB safe read limit.",
    "证据导入与分析": "Evidence import and analysis", "正在校验证据并运行规则分析": "Validating evidence and running rule analysis",
    "无法启动操作": "Could not start operation", "正在进行本机只读巡检": "Running a read-only local inspection",
    "正在导入和分析证据": "Importing and analyzing evidence", "正在导出脱敏交付": "Exporting a redacted handoff",
    "正在比较整改前后分析": "Comparing before/after analyses", "已完成": "Completed", "失败": "Failed",
    "已取消": "Cancelled", "正在运行": "Running", "等待中": "Waiting", "完成": "Complete",
})
_EN_ZH = {english: chinese for chinese, english in _ZH_EN.items()}
_EN_ZH["Local inspection"] = "本机巡检"
_SEVERITY_EXPLANATIONS = {
    "Critical": ("严重风险，需立即由授权人员复核。", "Critical risk; authorized personnel should review it immediately."),
    "High": ("高风险，需优先由授权人员复核。", "High risk; authorized personnel should prioritize review."),
    "Warning": ("需要关注并结合证据人工核实。", "Review the evidence and verify the condition manually."),
    "Info": ("信息项，不表示已确认风险。", "Informational; this does not confirm a risk."),
}

# Fixed inventory for application-owned phrases. Update deliberately when a
# built-in translation key is added or removed.
UI_RESOURCE_KEY_COUNT = 342
UI_RESOURCE_KEY_DIGEST = "80bf41188f627ad9f40328e113ef90a84337e0c82b09cd7ee146adfbed87e4cf"


class LanguagePreferenceError(ValueError):
    """The saved language preference is unsafe or invalid."""


class LocaleResourceError(ValueError):
    """A required application-owned locale resource is missing or malformed."""


def validate_ui_resources(language: str | None = None) -> None:
    """Fail clearly when a registered, application-owned UI translation is invalid.

    Unknown runtime strings (paths, logs, custom rules, and user evidence) are
    intentionally outside this inventory and remain untouched by ``tr``.
    """
    locale = normalize_language(language)
    key_digest = hashlib.sha256("\n".join(sorted(_ZH_EN)).encode("utf-8")).hexdigest()
    if len(_ZH_EN) != UI_RESOURCE_KEY_COUNT or key_digest != UI_RESOURCE_KEY_DIGEST:
        raise LocaleResourceError(
            f"The built-in UI resource inventory is incomplete or changed for {locale}."
        )
    formatter = string.Formatter()
    for source, translation in _ZH_EN.items():
        if not source.strip() or not isinstance(translation, str) or not translation.strip():
            raise LocaleResourceError(f"Empty UI locale resource for {locale}: {source!r}")
        try:
            source_fields = {field for _, field, _, _ in formatter.parse(source) if field}
            translation_fields = {field for _, field, _, _ in formatter.parse(translation) if field}
        except ValueError as exc:
            raise LocaleResourceError(f"Malformed UI locale placeholder for {locale}: {source!r}") from exc
        if source_fields != translation_fields:
            raise LocaleResourceError(f"UI locale placeholders do not match for {locale}: {source!r}")
    # Keep reverse lookup aligned with the same fixed inventory.
    for source, translated in _EN_ZH.items():
        if not source.strip() or not translated.strip():
            raise LocaleResourceError(f"Empty UI locale resource for {locale}: {source!r}")


def normalize_language(value: str | None = None) -> str:
    """Return one canonical locale; None and blank select the Chinese default."""
    if value is None or not str(value).strip():
        return DEFAULT_LANGUAGE
    raw = str(value).strip()
    if raw in LANGUAGES:
        return raw
    normalized = _LANGUAGE_ALIASES.get(raw.casefold())
    if normalized is None:
        raise ValueError(f"Unsupported language: {raw}")
    return normalized


def tr(text: str, language: str | None = None, **values: Any) -> str:
    """Translate an exact application-authored phrase and format known fields."""
    locale = normalize_language(language)
    source = str(text)
    translated = source
    if locale == "en-US":
        translated = _ZH_EN.get(source, source)
    else:
        translated = _EN_ZH.get(source, source)
    if values:
        try:
            return translated.format(**values)
        except (KeyError, ValueError, IndexError):
            return translated
    return translated


def severity_explanation(severity: str, language: str | None = None) -> str:
    pair = _SEVERITY_EXPLANATIONS.get(str(severity))
    if pair is None:
        return ""
    return pair[1 if normalize_language(language) == "en-US" else 0]


def _reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attrs = getattr(info, "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def preference_path() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if not base:
            raise LanguagePreferenceError("The per-user roaming configuration directory is unavailable.")
        return Path(base) / "PC Inspection Toolkit" / "preferences.json"
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "pc-inspection-toolkit" / "preferences.json"


def load_language_preference(path: Path | None = None) -> tuple[str, str | None]:
    try:
        target = path or preference_path()
        current = target.parent
        while current != current.parent:
            if current.exists() and _reparse(current):
                return DEFAULT_LANGUAGE, "Saved language preference path contains a link or reparse point."
            current = current.parent
        if _reparse(target):
            return DEFAULT_LANGUAGE, "Saved language preference is a link or reparse point and was ignored."
        if not target.exists():
            return DEFAULT_LANGUAGE, None
        if not target.is_file() or target.stat().st_size > 4096:
            raise LanguagePreferenceError("Saved language preference is not a small regular file.")
        data = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) != {"schema_version", "language"} or data["schema_version"] != 1:
            raise LanguagePreferenceError("Saved language preference has an unsupported schema.")
        return normalize_language(data["language"]), None
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return DEFAULT_LANGUAGE, f"Saved language preference was ignored ({type(exc).__name__})."


def save_language_preference(language: str, path: Path | None = None) -> None:
    try:
        locale = normalize_language(language)
    except ValueError as exc:
        raise LanguagePreferenceError("The selected language is not supported.") from exc
    target = path or preference_path()
    parent = target.parent
    current = parent
    while current != current.parent:
        if current.exists() and _reparse(current):
            raise LanguagePreferenceError("The language preference path contains a link or reparse point.")
        current = current.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    if _reparse(parent) or not parent.is_dir():
        raise LanguagePreferenceError("The language preference directory is unsafe.")
    if target.exists() and (_reparse(target) or not target.is_file()):
        raise LanguagePreferenceError("The language preference target is not a regular file.")
    temporary = parent / f".preferences-{secrets.token_hex(8)}.tmp"
    payload = json.dumps({"schema_version": 1, "language": locale}, ensure_ascii=False, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if target.exists() and (_reparse(target) or not target.is_file()):
            raise LanguagePreferenceError("The language preference target changed during save.")
        os.replace(temporary, target)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
