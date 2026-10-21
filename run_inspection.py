from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from functools import partial
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Sequence

from analyzers.risk_analyzer import analyze
from collectors import (
    disks,
    event_logs,
    firewall,
    network_ports,
    processes,
    remote_desktop,
    scheduled_tasks,
    security_vendors,
    services,
    shares,
    startup_items,
    system_info,
    users,
    windows_security,
)
from collectors.common import base_result, utc_now
from i18n import normalize_language
from locales.cli import argument_parser_class, cli_text
from models.analysis import AnalysisResult
from reports.markdown_report import render_report
from rules.loader import RuleResolution, resolve_rule_configuration

VERSION = "0.1.0-mvp"


COLLECTORS = [
    system_info.collect,
    users.collect,
    firewall.collect,
    remote_desktop.collect,
    shares.collect,
    disks.collect,
    services.collect,
    network_ports.collect,
    processes.collect,
    scheduled_tasks.collect,
    startup_items.collect,
    security_vendors.collect,
    event_logs.collect,
    windows_security.collect,
]

Collector = Callable[[], dict[str, Any]]
Analyzer = Callable[..., AnalysisResult | list[dict[str, Any]]]


def _language_from_argv(argv: list[str], default: str) -> str:
    for index, item in enumerate(argv):
        if item in {"--lang", "--language"} and index + 1 < len(argv):
            try:
                return normalize_language(argv[index + 1])
            except ValueError:
                return default
        if item.startswith("--lang=") or item.startswith("--language="):
            try:
                return normalize_language(item.split("=", 1)[1])
            except ValueError:
                return default
    return default


def application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def run_collection_pipeline(
    collector_functions: Sequence[Collector] | None = None,
    analyzer: Analyzer = analyze,
    *,
    resolution: RuleResolution | None = None,
    listener_knowledge: dict[str, Any] | None = None,
    listener_knowledge_evidence: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], AnalysisResult]:
    resolution = resolution or resolve_rule_configuration(application_root())
    collector_results: dict[str, Any] = {}
    active_collectors = (
        collector_functions
        if collector_functions is not None
        else _configured_collectors(resolution.registry)
    )
    for collect in active_collectors:
        collector_name = _collector_name(collect)
        try:
            item = collect()
            if not isinstance(item, dict) or not item.get("collector"):
                raise ValueError(f"Collector {collector_name} returned an invalid result.")
        except Exception as exc:  # noqa: BLE001
            item = base_result(collector_name)
            item["status"] = "failed"
            item["errors"].append(str(exc))
            logging.exception("collector=%s failed", collector_name)
        collector_results[str(item["collector"])] = item
        logging.info("collector=%s status=%s errors=%s", item["collector"], item["status"], item["errors"])
    collection_status, collection_warnings, has_usable_collection = _collector_integrity(
        collector_results
    )
    try:
        if analyzer is analyze:
            if not resolution.can_analyze:
                analysis_result = AnalysisResult(
                    status="PARTIAL" if has_usable_collection else "FAILED",
                    findings=[],
                    config_evidence=resolution.config_evidence,
                    warnings=list(resolution.warnings),
                    errors=list(resolution.errors),
                )
            else:
                analysis_result = analyze(
                    collector_results,
                    resolution.registry,
                    local_profile=resolution.local_profile,
                    config_evidence=resolution.config_evidence,
                    config_status=resolution.status,
                    listener_knowledge=listener_knowledge,
                    listener_knowledge_evidence=listener_knowledge_evidence,
                    warnings=resolution.warnings,
                    errors=resolution.errors,
                )
        else:
            custom_result = analyzer(collector_results)
            analysis_result = (
                custom_result
                if isinstance(custom_result, AnalysisResult)
                else AnalysisResult(status="OK", findings=list(custom_result))
            )
    except Exception as exc:  # noqa: BLE001
        exception_type = type(exc).__name__
        logging.error("analyzer failed type=%s", exception_type)
        analysis_result = AnalysisResult(
            status="PARTIAL" if has_usable_collection else "FAILED",
            findings=[],
            config_evidence=resolution.config_evidence,
            warnings=list(resolution.warnings),
            errors=[*resolution.errors, f"ANALYZER_EXCEPTION:{exception_type}"],
        )
    analysis_result.status = _combine_analysis_status(analysis_result.status, collection_status)
    analysis_result.warnings = _unique_messages(
        [*analysis_result.warnings, *collection_warnings]
    )
    return collector_results, analysis_result


def _configured_collectors(registry: dict[str, Any] | None) -> list[Collector]:
    active: list[Collector] = []
    for collect in COLLECTORS:
        if collect is not security_vendors.collect:
            active.append(collect)
            continue
        if registry is None:
            active.append(_unconfigured_security_vendor_collector)
            continue
        configured = partial(
            security_vendors.collect,
            registry["vendor_patterns"],
        )
        configured.collector_name = "security_vendors"  # type: ignore[attr-defined]
        active.append(configured)
    return active


def _unconfigured_security_vendor_collector() -> dict[str, Any]:
    result = base_result("security_vendors")
    result["status"] = "failed"
    result["errors"].append("Security vendor collection requires a valid default registry.")
    return result


def _collector_integrity(
    collector_results: dict[str, Any],
) -> tuple[str, list[str], bool]:
    if not collector_results:
        return "FAILED", ["COLLECTION_INCOMPLETE:no_collectors"], False

    incomplete: list[tuple[str, str]] = []
    has_usable_collection = False
    all_safely_skipped = True
    for collector_name, item in collector_results.items():
        status = str(item.get("status") or "unknown").strip().casefold()
        if status == "ok":
            has_usable_collection = True
            all_safely_skipped = False
        elif status in {"partial", "need_admin"}:
            has_usable_collection = True
            all_safely_skipped = False
            incomplete.append((collector_name, status))
        elif status == "skipped":
            continue
        else:
            all_safely_skipped = False
            incomplete.append((collector_name, "failed" if status == "failed" else "unknown"))

    if all_safely_skipped:
        return "FAILED", ["COLLECTION_INCOMPLETE:all_collectors_skipped:无有效采集证据"], False
    warnings = [
        f"COLLECTOR_INCOMPLETE:{_safe_collector_label(name)}:{status}"
        for name, status in incomplete
    ]
    if incomplete:
        return ("PARTIAL" if has_usable_collection else "FAILED"), warnings, has_usable_collection
    return "OK", [], has_usable_collection


def _combine_analysis_status(analysis_status: str, collection_status: str) -> str:
    rank = {"OK": 0, "PARTIAL": 1, "FAILED": 2}
    return max((analysis_status, collection_status), key=lambda value: rank[value])


def _safe_collector_label(value: Any) -> str:
    text = str(value or "unknown")
    return "".join(character for character in text if character.isalnum() or character in {"_", "-"})[:64] or "unknown"


def _unique_messages(messages: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(message) for message in messages))


def analysis_exit_code(result: AnalysisResult) -> int:
    return 0 if result.status == "OK" else 4


def _collector_name(collect: Collector) -> str:
    explicit_name = getattr(collect, "collector_name", None)
    if explicit_name:
        return str(explicit_name)
    module_name = str(getattr(collect, "__module__", ""))
    if module_name.startswith("collectors."):
        return module_name.rsplit(".", 1)[-1]
    return str(getattr(collect, "__name__", "collector"))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    display_language = _language_from_argv(argv, "zh-CN")
    parser_type = argument_parser_class(display_language)
    parser = parser_type(description=cli_text("Windows local inspection tool", display_language), language=display_language)
    parser.add_argument("--version", action="version", version=VERSION,
                        help=cli_text("Show program version and exit", display_language))
    parser.add_argument("--output-dir", default="reports/output", help=cli_text("Report output directory", display_language))
    parser.add_argument("--raw-dir", default="data/raw", help=cli_text("Raw normalized data directory", display_language))
    parser.add_argument("--lang", "--language", dest="language", type=normalize_language,
                        default="zh-CN", metavar="zh-CN|en-US|zh|en",
                        help=cli_text("Select the report and human message language", display_language))
    report_lang_help = ("Select the report language; defaults to --lang" if display_language == "en-US"
                        else "选择报告语言；默认沿用 --lang")
    parser.add_argument("--report-lang", "--report-language", dest="report_language",
                        type=normalize_language, default=None, metavar="zh-CN|en-US|zh|en",
                        help=report_lang_help)
    args = parser.parse_args(argv)
    language = normalize_language(args.language)
    report_language = normalize_language(args.report_language or language)

    root = application_root()
    resolution = resolve_rule_configuration(root)
    output_dir = (root / args.output_dir).resolve()
    raw_dir = (root / args.raw_dir).resolve()
    log_dir = root / "logs" / "execution"
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = log_dir / f"execution-{stamp}.log"
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )
    started = utc_now()
    t0 = perf_counter()
    logging.info("start version=%s args=%s", VERSION, vars(args))

    collector_results, analysis_result = run_collection_pipeline(resolution=resolution)
    findings = analysis_result.findings
    results: dict[str, Any] = {
        "version": VERSION,
        "started_at": started,
        "collectors": collector_results,
    }
    results["findings"] = findings
    results["analysis"] = analysis_result.to_dict()

    raw_json = raw_dir / f"inspection-data-{stamp}.json"
    raw_json.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    report_path = output_dir / f"windows-inspection-report-{stamp}.md"
    render_report(
        results["collectors"] | {"started_at": started},
        analysis_result,
        report_path,
        raw_dir,
        language=report_language,
    )

    elapsed = perf_counter() - t0
    logging.info("report=%s raw=%s elapsed=%.2fs version=%s", report_path, raw_json, elapsed, VERSION)
    print(f"{cli_text('Report', language)}: {report_path}")
    print(f"{cli_text('Raw data', language)}: {raw_json}")
    print(f"{cli_text('Execution log', language)}: {log_path}")
    if analysis_result.status != "OK":
        print(cli_text("The analysis is incomplete; review its evidence gaps.", language))
    return analysis_exit_code(analysis_result)


if __name__ == "__main__":
    raise SystemExit(main())
