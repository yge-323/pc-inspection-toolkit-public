from __future__ import annotations

import csv
import html
import io
import json
import re
from pathlib import Path
from typing import Any

from models.analysis import AnalysisResult


def _safe(value: Any) -> str:
    text = str(value if value is not None else "")
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)[:4000]


def _md(value: Any) -> str:
    text = _safe(value).replace("\r", " ").replace("\n", " ")
    for char in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!", "|"):
        text = text.replace(char, "\\" + char)
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _support_summary(result: AnalysisResult) -> tuple[str, str]:
    lifecycle = result.config_evidence.get("os_lifecycle", {})
    if not isinstance(lifecycle, dict) or lifecycle.get("status") != "loaded":
        return "生命周期规则不可用/未核实", ""
    finding = next((item for item in result.findings if item.get("rule_id") == "OS_LIFECYCLE_REVIEW" and isinstance(item.get("evidence"), dict)), None)
    if not finding:
        if any("OS_LIFECYCLE_COVERAGE_UNSUPPORTED" in warning or "OS_LIFECYCLE_RECORD_UNAVAILABLE" in warning for warning in result.warnings):
            return "版本覆盖未知，需人工核实", ""
        return "未匹配已核实生命周期记录；不代表仍受支持", ""
    evidence = finding["evidence"]
    status = "常规支持已结束" if evidence.get("support_status") == "ended" else "生命周期状态需人工核实"
    sources = evidence.get("sources", [])
    source_text = "; ".join(x for x in sources if isinstance(x, str)) if isinstance(sources, list) else ""
    return status, source_text


def render_markdown(result: AnalysisResult, metadata: dict[str, Any]) -> str:
    lines = ["# PC 巡检证据分析报告", "", f"- 分析状态：**{result.status}**",
             f"- 资产代号：{_md(metadata.get('asset_alias'))}", f"- 证据包：{_md(metadata.get('bundle_id'))}",
             f"- 目标：{_md(metadata.get('target'))}", "",
             "证据均视为不可信输入。SHA-256 只能检查封装后的字节是否变化，不能证明来源真实性。", "",
             "## 平台支持状态", ""]
    support_status, support_source = _support_summary(result)
    lines.append(f"- 状态：{_md(support_status)}")
    lines.append(f"- 来源：{_md(support_source or '未匹配到准确版本的生命周期来源')}")
    lines.extend(["", "## 硬件与采集摘要", ""])
    summary = metadata.get("evidence_summary", {})
    if isinstance(summary, dict):
        for group, facts in summary.items():
            if isinstance(facts, dict):
                lines.append(f"- **{_md(group)}:** " + "; ".join(f"{_md(k)}={_md(v)}" for k, v in facts.items()))
    lines.extend(["", "## 证据覆盖", "", "| 项目 | 状态 | 退出码 | 说明 |", "|---|---|---:|---|"])
    evidence_rows = metadata.get("evidence_items", [])
    for item in evidence_rows if isinstance(evidence_rows, list) else []:
        if isinstance(item, dict):
            lines.append(f"| {_md(item.get('name'))} | {_md(item.get('status'))} | {_md(item.get('exit_code'))} | {_md(item.get('reason'))} |")
    lines.extend(["", "## 风险发现与整改", ""])
    if not result.findings:
        lines.append("没有生成确定性发现；未检查范围不代表安全。")
    for finding in result.findings:
        lines.extend([f"### {_md(finding.get('title'))}", f"- 编号：{_md(finding.get('finding_id'))}",
                      f"- 等级：{_md(finding.get('severity'))}", f"- 证据：{_md(json.dumps(finding.get('evidence', {}), ensure_ascii=False))}",
                      f"- 整改前核查：{_md(finding.get('precheck', '实施前核对影响范围、维护窗口与备份'))}",
                      f"- 适用版本：{_md(finding.get('applicability', '平台/版本未核实'))}",
                      f"- 影响与条件：{_md(finding.get('impact', '需要人工复核'))}",
                      f"- 整改步骤：{_md(finding.get('recommendation', '补充证据并人工检查'))}",
                      f"- 回滚：{_md(finding.get('rollback', '未修改系统；获批变更前保留原始配置'))}",
                      f"- 复查：{_md(finding.get('verification_checkpoint', '重新采集并比较证据'))}",
                      f"- 资料来源：{_md('; '.join(str(value) for value in finding.get('references', [])) if isinstance(finding.get('references'), list) else finding.get('references', ''))}", ""])
    if result.status != "OK":
        lines.extend(["## 证据缺口", "", "分析不完整；缺失证据不代表未发现风险。", *[f"- {_md(x)}" for x in result.warnings + result.errors], ""])
    advisory = metadata.get("ai_advisory")
    if isinstance(advisory, dict):
        lines.extend(["## AI辅助建议（非正式结论）", "", f"- 状态：{_md(advisory.get('status'))}",
                      "- AI文本与确定性发现分开；不会改变分析状态或风险等级。"])
        if advisory.get("reason"):
            lines.append(f"- 原因：{_md(advisory['reason'])}")
        for suggestion in advisory.get("suggestions", []) if isinstance(advisory.get("suggestions"), list) else []:
            if isinstance(suggestion, dict):
                lines.append(f"- {_md(suggestion.get('text'))}（引用：{_md(', '.join(suggestion.get('evidence_refs', [])))}）")
        lines.append("")
    return "\n".join(lines)


def render_html(result: AnalysisResult, metadata: dict[str, Any]) -> str:
    support_status, support_source = _support_summary(result)
    rows = []
    for item in result.findings:
        defaults = {"applicability": "版本/适用条件需人工核实", "impact": "实施前评估服务影响及变更窗口",
                    "recommendation": "依据证据核实配置后，由获批人员实施变更",
                    "rollback": "本工具未修改系统；获批变更前备份原配置并准备恢复步骤",
                    "verification_checkpoint": "按同一规则版本重新采集并人工复核"}
        cells = [item.get(k, defaults.get(k, "未提供")) for k in
                 ("finding_id", "title", "severity", "evidence", "precheck", "applicability",
                  "impact", "recommendation", "rollback", "verification_checkpoint", "references")]
        rows.append("<tr>" + "".join(f"<td>{html.escape(_safe(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v))}</td>" for v in cells) + "</tr>")
    warnings = "".join(f"<li>{html.escape(_safe(v))}</li>" for v in result.warnings + result.errors)
    summary_html = ""
    summary = metadata.get("evidence_summary", {})
    if isinstance(summary, dict):
        summary_html = "<ul>" + "".join(f"<li><strong>{html.escape(_safe(group))}:</strong> " + html.escape("; ".join(f"{k}={v}" for k, v in facts.items())) + "</li>" for group, facts in summary.items() if isinstance(facts, dict)) + "</ul>"
    coverage_html = "".join(f"<tr><td>{html.escape(_safe(x.get('name')))}</td><td>{html.escape(_safe(x.get('status')))}</td><td>{html.escape(_safe(x.get('exit_code')))}</td><td>{html.escape(_safe(x.get('reason')))}</td></tr>" for x in metadata.get("evidence_items", []) if isinstance(x, dict))
    return ("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>巡检证据分析报告</title>"
            "<style>body{font:16px system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #bbb;padding:.5rem;text-align:left;overflow-wrap:anywhere;white-space:pre-wrap;vertical-align:top}th{background:#eee}.status{font-weight:bold}</style><body>"
            f"<h1>PC 巡检证据分析报告</h1><p class=\"status\">分析状态：{html.escape(result.status)}</p><p>资产代号：{html.escape(_safe(metadata.get('asset_alias')))} · Bundle：{html.escape(_safe(metadata.get('bundle_id')))}</p>"
            + "<p>证据包内容均按不可信输入处理。SHA-256 只校验封装后的字节一致性，不证明来源真实性。</p>"
            + f"<h2>平台支持状态</h2><p>{html.escape(_safe(support_status))} · {html.escape(_safe(support_source or '未匹配到准确版本来源'))}</p><h2>硬件与采集摘要</h2>" + summary_html
            + "<h2>证据覆盖</h2><table><thead><tr><th>项目</th><th>状态</th><th>退出码</th><th>说明</th></tr></thead><tbody>" + coverage_html + "</tbody></table>"
            "<h2>发现与整改建议</h2><table><thead><tr><th>编号</th><th>发现</th><th>等级</th><th>证据</th><th>整改前核查</th><th>适用性</th><th>影响与条件</th><th>步骤</th><th>回滚</th><th>复查</th><th>资料来源</th></tr></thead><tbody>"
            + "".join(rows) + f"</tbody></table><h2>证据缺口与警告</h2><ul>{warnings}</ul>"
            + _ai_html(metadata.get("ai_advisory")) + "</body></html>")


def render_csv(result: AnalysisResult) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=["analysis_status", "row_type", "gaps", "support_status", "finding_id", "title", "severity", "category", "precheck", "applicability", "evidence", "impact", "recommendation", "rollback", "verification_checkpoint", "references"])
    writer.writeheader()
    gaps = "; ".join(result.warnings + result.errors)
    support_status, _support_source_text = _support_summary(result)
    writer.writerow({"analysis_status": result.status, "row_type": "analysis_summary", "gaps": gaps or "无分析缺口记录", "support_status": support_status})
    if not result.findings:
        writer.writerow({"analysis_status": result.status, "row_type": "finding_summary", "gaps": "没有确定性发现；未检查范围不代表安全"})
    for finding in result.findings:
        row = {key: finding.get(key, "") for key in writer.fieldnames}
        row.update({"applicability": row["applicability"] or "版本/适用条件需人工核实",
                    "impact": row["impact"] or "实施前评估服务影响及变更窗口",
                    "recommendation": row["recommendation"] or "依据证据核实配置后，由获批人员实施变更",
                    "rollback": row["rollback"] or "本工具未修改系统；获批变更前备份原配置并准备恢复步骤",
                    "verification_checkpoint": row["verification_checkpoint"] or "按同一规则版本重新采集并人工复核"})
        row.update({"analysis_status": result.status, "row_type": "finding", "gaps": gaps})
        row["support_status"] = support_status
        row["evidence"] = json.dumps(row["evidence"], ensure_ascii=False)
        row["references"] = "; ".join(str(value) for value in row["references"]) if isinstance(row["references"], list) else row["references"]
        writer.writerow({key: _csv_safe(value) for key, value in row.items()})
    return output.getvalue()


def _csv_safe(value: Any) -> str:
    text = _safe(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text


def _ai_html(advisory: Any) -> str:
    if not isinstance(advisory, dict):
        return ""
    rows = [f"<li>{html.escape(_safe(x.get('text')))} (refs: {html.escape(', '.join(x.get('evidence_refs', [])))})</li>"
            for x in advisory.get("suggestions", []) if isinstance(x, dict)] if isinstance(advisory.get("suggestions"), list) else []
    reason = f"<p>{html.escape(_safe(advisory['reason']))}</p>" if advisory.get("reason") else ""
    return f"<h2>AI辅助建议（非正式结论）</h2><p>状态：{html.escape(_safe(advisory.get('status')))}。建议与确定性发现分开，不改变分析结论。</p>{reason}<ul>{''.join(rows)}</ul>"


def write_reports(base: Path, result: AnalysisResult, metadata: dict[str, Any]) -> dict[str, Path]:
    base.mkdir(parents=True, exist_ok=False)
    outputs = {"md": base / "report.md", "html": base / "report.html", "csv": base / "findings.csv", "json": base / "analysis.json"}
    outputs["md"].write_text(render_markdown(result, metadata), encoding="utf-8")
    outputs["html"].write_text(render_html(result, metadata), encoding="utf-8")
    outputs["csv"].write_text(render_csv(result), encoding="utf-8-sig", newline="")
    outputs["json"].write_text(json.dumps({"status": result.status, "metadata": metadata, **result.to_dict()}, ensure_ascii=False, indent=2), encoding="utf-8")
    return outputs
