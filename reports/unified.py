from __future__ import annotations

import csv
import html
import io
import json
import re
from pathlib import Path
from typing import Any

from models.analysis import AnalysisResult
from locales import display_finding, display_reason, display_summary, text, validate_resources
from locales.findings import gap_text, severity_display, severity_explanation


def _safe(value: Any) -> str:
    text = str(value if value is not None else "")
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)[:4000]


def _md(value: Any) -> str:
    text = _safe(value).replace("\r", " ").replace("\n", " ")
    for char in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!", "|"):
        text = text.replace(char, "\\" + char)
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _support_summary(result: AnalysisResult, language: str = "zh-CN") -> tuple[str, str]:
    lifecycle = result.config_evidence.get("os_lifecycle", {})
    if not isinstance(lifecycle, dict) or lifecycle.get("status") != "loaded":
        return text("support.unavailable", language), ""
    finding = next((item for item in result.findings if item.get("rule_id") == "OS_LIFECYCLE_REVIEW" and isinstance(item.get("evidence"), dict)), None)
    if not finding:
        if any("OS_LIFECYCLE_COVERAGE_UNSUPPORTED" in warning or "OS_LIFECYCLE_RECORD_UNAVAILABLE" in warning for warning in result.warnings):
            return text("support.unknown_coverage", language), ""
        return text("support.unmatched", language), ""
    evidence = finding["evidence"]
    status = text("support.ended" if evidence.get("support_status") == "ended" else "support.review", language)
    sources = evidence.get("sources", [])
    source_text = "; ".join(x for x in sources if isinstance(x, str)) if isinstance(sources, list) else ""
    return status, source_text


def render_markdown(result: AnalysisResult, metadata: dict[str, Any], language: str = "zh-CN") -> str:
    validate_resources()
    t = lambda key: text(key, language)
    sep = ": " if t("report.title").startswith("PC Inspection") else "："
    lines = [f"# {t('report.title')}", "", f"- {t('report.analysis_status')}{sep}**{result.status}**",
             f"- {t('report.asset_alias')}{sep}{_md(metadata.get('asset_alias'))}", f"- {t('report.bundle')}{sep}{_md(metadata.get('bundle_id'))}",
             f"- {t('report.target')}{sep}{_md(metadata.get('target'))}", "", t("report.untrusted"), "",
             f"## {t('report.platform_support')}", ""]
    support_status, support_source = _support_summary(result, language)
    lines.append(f"- {t('report.status')}{sep}{_md(support_status)}")
    lines.append(f"- {t('report.references')}{sep}{_md(support_source or t('report.no_source'))}")
    lines.extend(["", f"## {t('report.hardware')}", ""])
    summary = display_summary(metadata.get("evidence_summary", {}), language)
    if isinstance(summary, dict):
        for group, facts in summary.items():
            if isinstance(facts, dict):
                lines.append(f"- **{_md(group)}:** " + "; ".join(f"{_md(k)}={_md(v)}" for k, v in facts.items()))
    lines.extend(["", f"## {t('report.coverage')}", "", f"| {t('report.item')} | {t('report.status')} | {t('report.exit_code')} | {t('report.reason')} |", "|---|---|---:|---|"])
    evidence_rows = metadata.get("evidence_items", [])
    for item in evidence_rows if isinstance(evidence_rows, list) else []:
        if isinstance(item, dict):
            lines.append(f"| {_md(item.get('name'))} | {_md(item.get('status'))} | {_md(item.get('exit_code'))} | {_md(gap_text(item.get('reason'), language))} |")
    lines.extend(["", f"## {t('report.findings')}", ""])
    if not result.findings:
        lines.append(t("analysis.no_findings"))
    for finding in result.findings:
        item = display_finding(finding, language)
        fields = (("report.finding_id", finding.get("finding_id")), ("report.severity", severity_display(finding.get("severity"), language)), ("report.severity_meaning", severity_explanation(finding.get("severity"), language)), ("report.evidence", json.dumps(finding.get("evidence", {}), ensure_ascii=False)),
                  ("report.precheck", item.get("precheck", t("report.fallback_precheck"))), ("report.applicability", item.get("applicability", t("report.fallback_applicability"))),
                  ("report.impact", item.get("impact", t("report.fallback_impact"))), ("report.recommendation", item.get("recommendation", t("report.fallback_recommendation"))),
                  ("report.rollback", item.get("rollback", t("report.fallback_rollback"))), ("report.verification", item.get("verification_checkpoint", t("report.fallback_verification"))))
        lines.append(f"### {_md(item.get('title'))}")
        if item.get("_locale_source_note"):
            lines.append(f"- {_md(item['_locale_source_note'])}")
        if item.get("description"):
            lines.append(f"- {_md(t('legacy.description'))}{sep}{_md(item['description'])}")
        lines.extend(f"- {t(label)}{sep}{_md(value)}" for label, value in fields)
        references = finding.get("references", [])
        lines.append(f"- {t('report.references')}{sep}{_md('; '.join(str(value) for value in references) if isinstance(references, list) else references)}".rstrip())
        lines.append("")
    if result.status != "OK":
        lines.extend([f"## {t('report.gaps')}", "", t("analysis.incomplete"), *[f"- {_md(gap_text(x, language))}" for x in result.warnings + result.errors], ""])
    advisory = metadata.get("ai_advisory")
    if isinstance(advisory, dict):
        lines.extend([f"## {t('report.ai')}", "", f"- {t('report.status')}：{_md(advisory.get('status'))}", f"- {t('report.ai_separation')}"])
        if advisory.get("reason"):
            lines.append(f"- {t('report.ai_reason')}：{_md(display_reason(advisory['reason'], language))}")
        for suggestion in advisory.get("suggestions", []) if isinstance(advisory.get("suggestions"), list) else []:
            if isinstance(suggestion, dict):
                lines.append(f"- {_md(suggestion.get('text'))}（{t('report.ai_refs')}：{_md(', '.join(suggestion.get('evidence_refs', [])))}）")
        lines.append("")
    return "\n".join(lines)


def render_html(result: AnalysisResult, metadata: dict[str, Any], language: str = "zh-CN") -> str:
    validate_resources()
    t = lambda key: text(key, language)
    support_status, support_source = _support_summary(result, language)
    rows = []
    for item in result.findings:
        display = display_finding(item, language)
        cells = [item.get("finding_id"), display.get("title"), severity_display(item.get("severity"), language), severity_explanation(item.get("severity"), language), display.get("description", ""), item.get("evidence"),
                 display.get("precheck", t("report.fallback_precheck")), display.get("applicability", t("report.fallback_applicability")),
                 display.get("impact", t("report.fallback_impact")), display.get("recommendation", t("report.fallback_recommendation")),
                 display.get("rollback", t("report.fallback_rollback")), display.get("verification_checkpoint", t("report.fallback_verification")), item.get("references"), display.get("_locale_source_note", "")]
        rows.append("<tr>" + "".join(f"<td>{html.escape(_safe(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v))}</td>" for v in cells) + "</tr>")
    warnings = "".join(f"<li>{html.escape(_safe(gap_text(v, language)))}</li>" for v in result.warnings + result.errors)
    summary_html = ""
    summary = display_summary(metadata.get("evidence_summary", {}), language)
    if isinstance(summary, dict):
        summary_html = "<ul>" + "".join(f"<li><strong>{html.escape(_safe(group))}:</strong> " + html.escape("; ".join(f"{k}={v}" for k, v in facts.items())) + "</li>" for group, facts in summary.items() if isinstance(facts, dict)) + "</ul>"
    coverage_html = "".join(f"<tr><td>{html.escape(_safe(x.get('name')))}</td><td>{html.escape(_safe(x.get('status')))}</td><td>{html.escape(_safe(x.get('exit_code')))}</td><td>{html.escape(_safe(gap_text(x.get('reason'), language)))}</td></tr>" for x in metadata.get("evidence_items", []) if isinstance(x, dict))
    language_tag = "zh-CN" if text("report.title", language).startswith("PC 巡检") else "en-US"
    labels = [t(k) for k in ("report.finding_id", "report.finding_title", "report.severity", "report.severity_meaning", "report.description", "report.evidence", "report.precheck", "report.applicability", "report.impact", "report.recommendation", "report.rollback", "report.verification", "report.references")]
    return (f"<!doctype html><html lang=\"{language_tag}\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{html.escape(t('report.title'))}</title>"
            "<style>body{font:16px system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #bbb;padding:.5rem;text-align:left;overflow-wrap:anywhere;white-space:pre-wrap;vertical-align:top}th{background:#eee}.status{font-weight:bold}</style><body>"
            f"<h1>{html.escape(t('report.title'))}</h1><p class=\"status\">{html.escape(t('report.analysis_status'))}: {html.escape(result.status)}</p><p>{html.escape(t('report.asset_alias'))}: {html.escape(_safe(metadata.get('asset_alias')))} · {html.escape(t('report.bundle'))}: {html.escape(_safe(metadata.get('bundle_id')))}</p>"
            + f"<p>{html.escape(t('report.untrusted'))}</p>"
            + f"<h2>{html.escape(t('report.platform_support'))}</h2><p>{html.escape(_safe(support_status))} · {html.escape(_safe(support_source or t('report.no_source')))}</p><h2>{html.escape(t('report.hardware'))}</h2>" + summary_html
            + f"<h2>{html.escape(t('report.coverage'))}</h2><table><thead><tr><th>{html.escape(t('report.item'))}</th><th>{html.escape(t('report.status'))}</th><th>{html.escape(t('report.exit_code'))}</th><th>{html.escape(t('report.reason'))}</th></tr></thead><tbody>" + coverage_html + "</tbody></table>"
            f"<h2>{html.escape(t('report.html_badge'))}</h2><table><thead><tr>" + "".join(f"<th>{html.escape(label)}</th>" for label in labels) + f"<th>{html.escape(t('report.source_note'))}</th></tr></thead><tbody>"
            + "".join(rows) + f"</tbody></table><h2>{html.escape(t('report.gaps'))}</h2><ul>{warnings}</ul>"
            + _ai_html(metadata.get("ai_advisory"), language) + "</body></html>")


def render_csv(result: AnalysisResult, language: str = "zh-CN") -> str:
    validate_resources()
    output = io.StringIO(newline="")
    fields = ["analysis_status", "row_type", "gaps", "support_status", "finding_id", "title", "severity", "severity_label", "category", "description", "precheck", "applicability", "evidence", "impact", "recommendation", "rollback", "verification_checkpoint", "references", "translation_note"]
    headers = [text("report.analysis_status", language), "row_type", text("report.gaps", language), text("support_status", language), text("report.finding_id", language), text("report.finding_title", language), text("report.severity", language), text("report.severity_meaning", language), text("category", language), text("report.description", language), text("report.precheck", language), text("report.applicability", language), text("report.evidence", language), text("report.impact", language), text("report.recommendation", language), text("report.rollback", language), text("report.verification", language), text("report.references", language), text("report.source_note", language)]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writerow(dict(zip(fields, headers)))
    gaps = "; ".join(gap_text(x, language) for x in result.warnings + result.errors)
    support_status, _support_source_text = _support_summary(result, language)
    writer.writerow({"analysis_status": result.status, "row_type": "analysis_summary", "gaps": gaps or text("gap.none", language), "support_status": support_status})
    if not result.findings:
        writer.writerow({"analysis_status": result.status, "row_type": "finding_summary", "gaps": text("gap.no_findings", language)})
    for finding in result.findings:
        display = display_finding(finding, language)
        row = {key: finding.get(key, "") for key in fields}
        for field in ("title", "description", "impact", "recommendation", "verification_checkpoint", "precheck", "applicability", "rollback"):
            if field in display:
                row[field] = display[field]
        row["translation_note"] = display.get("_locale_source_note", "")
        row["severity_label"] = severity_explanation(finding.get("severity"), language)
        for key, fallback in (("applicability", "report.fallback_applicability"), ("impact", "report.fallback_impact"), ("recommendation", "report.fallback_recommendation"), ("rollback", "report.fallback_rollback"), ("verification_checkpoint", "report.fallback_verification")):
            row[key] = row[key] or text(fallback, language)
        row.update({"analysis_status": result.status, "row_type": "finding", "gaps": gaps, "support_status": support_status})
        row["evidence"] = json.dumps(row["evidence"], ensure_ascii=False)
        row["references"] = "; ".join(str(value) for value in row["references"]) if isinstance(row["references"], list) else row["references"]
        writer.writerow({key: _csv_safe(value) for key, value in row.items()})
    return output.getvalue()


def _csv_safe(value: Any) -> str:
    text = _safe(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text


def _ai_html(advisory: Any, language: str = "zh-CN") -> str:
    if not isinstance(advisory, dict):
        return ""
    rows = [f"<li>{html.escape(_safe(x.get('text')))} (refs: {html.escape(', '.join(x.get('evidence_refs', [])))})</li>"
            for x in advisory.get("suggestions", []) if isinstance(x, dict)] if isinstance(advisory.get("suggestions"), list) else []
    reason = f"<p>{html.escape(_safe(display_reason(advisory['reason'], language)))}</p>" if advisory.get("reason") else ""
    return f"<h2>{html.escape(text('report.ai', language))}</h2><p>{html.escape(text('report.status', language))}: {html.escape(_safe(advisory.get('status')))}. {html.escape(text('report.ai_status', language))}</p>{reason}<ul>{''.join(rows)}</ul>"


def write_reports(base: Path, result: AnalysisResult, metadata: dict[str, Any], language: str = "zh-CN") -> dict[str, Path]:
    validate_resources()
    base.mkdir(parents=True, exist_ok=False)
    outputs = {"md": base / "report.md", "html": base / "report.html", "csv": base / "findings.csv", "json": base / "analysis.json"}
    outputs["md"].write_text(render_markdown(result, metadata, language), encoding="utf-8")
    outputs["html"].write_text(render_html(result, metadata, language), encoding="utf-8")
    outputs["csv"].write_text(render_csv(result, language), encoding="utf-8-sig", newline="")
    outputs["json"].write_text(json.dumps({"status": result.status, "metadata": metadata, **result.to_dict()}, ensure_ascii=False, indent=2), encoding="utf-8")
    return outputs
