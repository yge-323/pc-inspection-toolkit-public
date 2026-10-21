from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import os
import platform
import uuid
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzers.evidence_analyzer import analyze_evidence
from analyzers.listener_risk import DEFAULT_KNOWLEDGE as DEFAULT_LISTENER_KNOWLEDGE, ListenerKnowledgeError, listener_knowledge_error_reason, load_knowledge as load_listener_knowledge
from analyzers.local_ai import LocalAIError, request_suggestions
from i18n import normalize_language
from locales.cli import argument_parser_class, cli_text
from analyzers.windows_security_rules import native_service_facts
from analyzers.windows_disk_rules import parse_native_disk_facts
from evidence.bundle import BundleError, import_bundle, validate_bundle, write_manifest
from evidence.config_sanitizer import ConfigSanitizationError, sanitize_config
from evidence.paste import PasteError, import_paste_text
from evidence.transports import TransportError, capture_ssh_bundle, capture_winrm_bundle
from evidence.bundle import _decode_text
from models.analysis import AnalysisResult
from reports.unified import write_reports

VERSION = "0.3.0-landable"


def application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object.")
    return value


def _load_analysis(path: Path) -> tuple[AnalysisResult, dict[str, Any]]:
    value = _json_object(path)
    metadata = value.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    findings, evidence = value.get("findings", []), value.get("config_evidence", {})
    warnings, errors = value.get("warnings", []), value.get("errors", [])
    if (not isinstance(findings, list) or any(not isinstance(x, dict) or not isinstance(x.get("finding_id"), str)
                                               or any(k in x and not isinstance(x[k], str) for k in ("title", "severity", "category", "description", "impact", "recommendation", "rollback", "verification_checkpoint", "applicability"))
                                               or ("evidence" in x and not isinstance(x["evidence"], dict)) for x in findings)
            or not isinstance(evidence, dict) or not isinstance(warnings, list) or not isinstance(errors, list)
            or any(not isinstance(x, str) for x in warnings + errors)):
        raise ValueError("Analysis document fields are malformed.")
    identifiers = [x["finding_id"] for x in findings]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Analysis document contains duplicate Finding IDs.")
    result = AnalysisResult(status=value.get("status"), findings=findings,
                            config_evidence=evidence, warnings=warnings, errors=errors)
    return result, metadata


def _write_new(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="") as stream:
        stream.write(value)


def _canonical_rules_binding(resolution: Any, lifecycle_policy: Any, listener_knowledge: Any = None,
                             listener_knowledge_evidence: Any = None) -> tuple[str, str]:
    """Bind the effective in-memory rules without exporting their contents or paths."""
    registry = resolution.registry if isinstance(resolution.registry, dict) else {}
    payload = {"registry": registry, "local_profile": resolution.local_profile, "os_lifecycle": lifecycle_policy,
               "listener_knowledge": listener_knowledge,
               "listener_knowledge_source_sha256": listener_knowledge_evidence.get("sha256")
               if isinstance(listener_knowledge_evidence, dict) else None}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    default_evidence = resolution.config_evidence.get("default_registry", {})
    version = str(default_evidence.get("registry_version") or registry.get("registry_version") or "unknown")
    lifecycle_version = str(lifecycle_policy.get("rules_version", "unknown")) if isinstance(lifecycle_policy, dict) else "unknown"
    listener_version = str(listener_knowledge.get("rules_version", "unknown")) if isinstance(listener_knowledge, dict) else "unknown"
    return f"{version}+oslife-{lifecycle_version}+listeners-{listener_version}", hashlib.sha256(canonical).hexdigest()


def _safe_id(value: Any) -> str:
    text = str(value or "")
    return text[:100] if re.fullmatch(r"[A-Za-z0-9_.@:-]{1,100}", text) else "redacted-id"


def _redact_text(value: Any) -> str:
    text = str(value or "")[:2000]
    for pattern in (r"(?i)(password|passwd|secret|token|credential|api[_-]?key|requirepass)\s*[:=]?\s*[^\s,;]+",
                    r"(?i)(?:[A-Z]:\\Users\\|/home/|/Users/)[^\s]+",
                    r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
                    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"):
        text = re.sub(pattern, "[已脱敏]", text)
    return text


def _format_bytes(value: int) -> str:
    size = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return "未确认"


def _summary_bytes(value: Any) -> str:
    try:
        number = float(value)
        if not (number >= 0 and number < float("inf")):
            return "未知"
        return _format_bytes(int(number))
    except (TypeError, ValueError):
        return "未知"


def _safe_codex(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k)[:80]: _safe_codex(v) for k, v in list(value.items())[:40] if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", str(k))}
    if isinstance(value, list):
        return [_safe_codex(x) for x in value[:100]]
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return "[已省略]"


def _evidence_summary(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Extract only bounded, explicitly selected non-identity facts for reports."""
    files = {Path(item["path"]).name.casefold(): item for item in manifest["items"] if item["status"] == "collected"}
    specs = {
        "硬件": {"cpu.txt": (r"(?im)^Name=(.+)$", "CPU"), "cpu_count.txt": (r"(?im)^([0-9]+)$", "CPU数量"),
                 "memory.txt": (r"(?im)^TotalPhysicalMemory=(\d+)$", "内存字节"), "memory_summary.txt": (r"(?im)^MemTotal_kB=(\d+)$", "内存KB"),
                 "graphics.txt": (r"(?im)^Name=(.+)$", "显卡"), "graphics_summary.txt": (r"(?im)^(?:[^\r\n]{1,100})$", "显卡摘要"), "disks.txt": (r"(?im)^([^\r\n]{1,160})$", "磁盘摘要")},
        "系统安全事实": {"privilege.txt": (r"(?m)^([0-9]+)$", "采集UID"), "security_status.txt": (r"(?m)^(?:COLLECTOR_STATUS=[A-Z_]+|[A-Za-z0-9_. -]{1,80})$", "安全状态")}
    }
    output: dict[str, Any] = {}
    for group, entries in specs.items():
        facts = {}
        for filename, (pattern, label) in entries.items():
            item = files.get(filename)
            if not item:
                continue
            try:
                text = _decode_text((root / Path(item["path"])).read_bytes())[:65536]
            except (OSError, UnicodeError):
                continue
            match = re.search(pattern, text)
            if match:
                value = _redact_text((match.group(1) if match.lastindex else match.group(0)).strip())
                if value:
                    facts[label] = value[:160]
        if facts:
            output[group] = facts
    if str(manifest.get("target", {}).get("os_family", "")).casefold() == "windows":
        process_item = files.get("processes.txt")
        service_item = files.get("services.txt")
        process_lines: list[str] = []
        service_lines: list[str] = []
        for item, target in ((process_item, process_lines), (service_item, service_lines)):
            if not item:
                continue
            try:
                target.extend(_decode_text((root / Path(item["path"])).read_bytes())[:262144].splitlines())
            except (OSError, UnicodeError):
                continue
        process_rows: list[tuple[str, str, int]] = []
        for line in process_lines:
            match = re.match(r"^Name=([^;]{1,180});ProcessId=(\d+);[^;]*;WorkingSetBytes=(\d+)", line)
            if match:
                process_rows.append((match.group(1), match.group(2), int(match.group(3))))
        top_processes = sorted(process_rows, key=lambda row: row[2], reverse=True)[:8]
        process_count = re.search(r"(?m)^RecordCount=(\d+)$", "\n".join(process_lines))
        security_item = files.get("security_status.txt")
        security_lines: list[str] = []
        if security_item:
            try:
                security_lines = _decode_text((root / Path(security_item["path"])).read_bytes())[:65536].splitlines()
            except (OSError, UnicodeError):
                pass
        security_values: dict[str, list[str]] = {}
        for line in security_lines:
            if "=" in line:
                key, value = line.split("=", 1)
                security_values.setdefault(key.strip(), []).append(value.strip())
        security_labels = {
            "RdpDisabled": "RDP拒绝连接标志",
            "RdpNlaRequired": "RDP要求NLA",
            "Smb1ExplicitValue": "SMB1显式配置",
            "AutoAdminLogonEnabled": "自动登录标志",
            "GuestEnabled": "内置Guest启用",
            "MinimumPasswordLength": "最小密码长度",
            "PasswordComplexity": "密码复杂度",
            "LockoutBadCount": "账户锁定阈值",
            "PasswordPolicyStatus": "密码策略读取状态",
        }
        security_summary = {
            label: (values[0] if len(values) == 1 else "UNKNOWN")
            for key, label in security_labels.items()
            for values in [security_values.get(key, [])]
        }
        firewall_profiles = security_values.get("FirewallProfile", [])
        if firewall_profiles:
            security_summary["防火墙配置文件"] = "；".join(firewall_profiles[:3])
        if security_summary:
            output["Windows安全配置"] = security_summary
        native_disk_rows: list[dict[str, Any]] = []
        disk_item = files.get("disks.txt")
        if disk_item:
            try:
                disk_text = _decode_text((root / Path(disk_item["path"])).read_bytes())[:65536]
                native_disk_rows, _disk_gaps = parse_native_disk_facts(disk_text)
            except (OSError, UnicodeError):
                pass
        output["磁盘容量与剩余空间"] = {
            "卷数": len(native_disk_rows) if native_disk_rows else "未确认",
            "卷剩余空间": "；".join(
                f"{row.get('Drive') or '未知盘符'}：{_format_bytes(int(row['Free']))} 可用 / "
                f"{_format_bytes(int(row['Size']))} 总量（{row.get('FreePercent') if row.get('FreePercent') is not None else '百分比未知'}%）"
                for row in native_disk_rows
                if isinstance(row.get("Free"), (int, float)) and isinstance(row.get("Size"), (int, float))
            ) or "未确认",
        }
        service_rows = native_service_facts("\n".join(service_lines))
        output["进程与服务"] = {
            "进程采集记录数": process_count.group(1) if process_count else "未确认",
            "内存占用靠前进程": "；".join(
                f"{_redact_text(name)} (PID {pid}, {_format_bytes(memory)})"
                for name, pid, memory in top_processes
            ) or "未确认",
            "服务采集记录数": len(service_rows) if service_rows else "未确认",
        }
    return output


def _local_summary(collectors: dict[str, Any]) -> dict[str, Any]:
    """Only expose counts and selected hardware facts, never raw collector payloads."""
    def data(name: str) -> Any:
        item = collectors.get(name, {})
        return item.get("data") if isinstance(item, dict) and item.get("status") in {"ok", "partial", "need_admin"} else None
    system = data("system_info") or {}
    cpu = data("cpu") or {}
    disks = data("disks") or {}
    services = data("services") or []
    listeners = data("network_ports") or []
    users = data("users") or {}
    startup = data("startup_items") or {}
    processes = data("processes") or {}
    windows_security = data("windows_security") or {}
    password_policy = windows_security.get("PasswordPolicy") if isinstance(windows_security, dict) else None
    password_policy = password_policy if isinstance(password_policy, dict) else {}
    password_values = password_policy.get("Values")
    password_values = password_values if isinstance(password_values, dict) else {}
    summary: dict[str, Any] = {"设备": {}, "采集状态": {}, "账户与启动项": {}, "进程与安全基线": {}}
    safe_system = {"操作系统": system.get("os"), "版本": system.get("version"), "内部版本号": system.get("build"),
                   "CPU型号": cpu.get("name") or platform.processor(), "CPU逻辑处理器": cpu.get("logical_processors") or os.cpu_count(), "内存字节": system.get("total_memory_bytes")}
    summary["设备"].update({k: _redact_text(v) for k, v in safe_system.items() if isinstance(v, (str, int, float)) and v != ""})
    user_rows = users.get("Users") if isinstance(users, dict) else None
    admin_rows = users.get("Administrators") if isinstance(users, dict) else None
    startup_rows = startup.get("Items") if isinstance(startup, dict) else None
    summary["账户与启动项"] = {"账户数": len(user_rows) if isinstance(user_rows, list) and user_rows else "未确认（空结果不代表无账户）",
                           "管理员组成员数": len(admin_rows) if isinstance(admin_rows, list) and admin_rows else "未确认（空结果不代表无成员）",
                           "启动项数量": len(startup_rows) if isinstance(startup_rows, list) and startup_rows else "未确认（空结果不代表无启动项）"}
    summary["采集状态"] = {name: str(value.get("status", "unknown"))[:40] for name, value in list(collectors.items())[:40] if isinstance(value, dict)}
    disk_rows = disks.get("VolumeSummary") if isinstance(disks, dict) else None
    summary["容量与服务"] = {"磁盘卷数量": len(disk_rows) if isinstance(disk_rows, list) and disk_rows else "未确认（空结果不代表无磁盘）",
                         "服务数量": len(services) if isinstance(services, list) else "未检查",
                         "网络端口记录数量": len(listeners) if isinstance(listeners, list) else "未检查"}
    if isinstance(disk_rows, list) and disk_rows:
        summary["容量与服务"]["磁盘剩余空间"] = "；".join(
            f"{row.get('Drive') or '未知盘符'}："
            f"{_summary_bytes(row.get('Free'))} 可用 / "
            f"{_summary_bytes(row.get('Size'))} 总量"
            f"（{row.get('FreePercent') if row.get('FreePercent') is not None else '百分比未知'}%）"
            for row in disk_rows if isinstance(row, dict)
        )
    process_rows = processes.get("Items") if isinstance(processes, dict) else None
    process_rows = process_rows if isinstance(process_rows, list) else []
    def working_set(row: dict[str, Any]) -> int:
        try:
            return max(0, int(row.get("WorkingSetSize") or 0))
        except (TypeError, ValueError):
            return 0
    top_processes = sorted((row for row in process_rows if isinstance(row, dict)),
                           key=working_set, reverse=True)[:8]
    summary["进程与安全基线"] = {
        "进程记录数": processes.get("TotalCount", len(process_rows)) if isinstance(processes, dict) else "未检查",
        "内存占用靠前进程": ", ".join(
            f"{_redact_text(row.get('Name'))} (PID {row.get('ProcessId')})" for row in top_processes
        ) or "未确认",
        "RDP启用": (windows_security.get("Rdp") or {}).get("Enabled", "未知") if isinstance(windows_security, dict) else "未检查",
        "RDP要求NLA": (windows_security.get("Rdp") or {}).get("NlaRequired", "未知") if isinstance(windows_security, dict) else "未检查",
        "SMB1启用": (windows_security.get("Smb1") or {}).get("Enabled", "未知") if isinstance(windows_security, dict) else "未检查",
        "自动登录启用": (windows_security.get("AutoLogon") or {}).get("Enabled", "未知") if isinstance(windows_security, dict) else "未检查",
        "本地账户数": (windows_security.get("LocalAccounts") or {}).get("Total", "未知") if isinstance(windows_security, dict) else "未检查",
        "内置Guest启用": (windows_security.get("LocalAccounts") or {}).get("GuestEnabled", "未知") if isinstance(windows_security, dict) else "未检查",
        "防火墙配置文件": "；".join(
            f"{row.get('Name')}={row.get('Enabled')}" for row in
            (windows_security.get("FirewallProfiles", []) if isinstance(windows_security, dict) else [])
            if isinstance(row, dict)
        ) or "未知",
        "密码策略读取状态": password_policy.get("Status", "未知") if isinstance(windows_security, dict) else "未检查",
        "密码最小长度/复杂度/锁定阈值": "/".join(
            str(value) for value in (
                password_values.get("MinimumPasswordLength"),
                password_values.get("PasswordComplexity"),
                password_values.get("LockoutBadCount"),
            )
        ) if isinstance(windows_security, dict) else "未检查",
    }
    return summary


def _compare(before: AnalysisResult, after: AnalysisResult, before_meta: dict[str, Any], after_meta: dict[str, Any]) -> dict[str, Any]:
    old_target, new_target = before_meta.get("target_identity"), after_meta.get("target_identity")
    if not isinstance(old_target, dict) or not isinstance(new_target, dict):
        raise ValueError("Comparison requires target identity metadata.")
    if before_meta.get("project_alias") != after_meta.get("project_alias") or before_meta.get("asset_alias") != after_meta.get("asset_alias"):
        raise ValueError("Comparison rejected: bundles do not identify the same project and asset alias.")
    if not before_meta.get("project_alias") or not before_meta.get("asset_alias"):
        raise ValueError("Comparison rejected: stable project and asset aliases are required.")
    same_target = all(old_target.get(key) == new_target.get(key) for key in ("os_family", "product", "version", "architecture", "scope"))
    same_rules = (before_meta.get("rules_version") == after_meta.get("rules_version")
                  and before_meta.get("rules_sha256") == after_meta.get("rules_sha256"))
    old = {str(x.get("finding_id")): x for x in before.findings if x.get("finding_id")}
    new = {str(x.get("finding_id")): x for x in after.findings if x.get("finding_id")}
    previous_complete = before.status == "OK"
    current_complete = after.status == "OK"
    rows = []
    for key in sorted(old.keys() | new.keys()):
        if not (same_rules and same_target):
            state = "not_comparable"
        elif key in old and key in new:
            state = "still_present"
        elif key in new:
            state = "new"
        elif previous_complete and current_complete and same_rules and same_target:
            state = "resolved"
        else:
            state = "not_checked"
        rows.append({"finding_id": key, "state": state,
                     "before_rules_version": before_meta.get("rules_version", "unknown"),
                     "after_rules_version": after_meta.get("rules_version", "unknown")})
    comparable = previous_complete and current_complete and same_rules and same_target
    return {"status": "OK" if comparable else "PARTIAL",
            "before_status": before.status, "after_status": after.status,
            "same_target": same_target, "rules_changed": not same_rules, "items": rows,
            "note": "Missing evidence or incomplete analysis is not_checked. Target/rule changes make absent findings not_comparable, never resolved."}


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


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    language = _language_from_argv(argv, "zh-CN")
    parser_type = argument_parser_class(language)
    parser = parser_type(description=cli_text("Offline evidence inspection and reporting tool", language), language=language)
    parser.add_argument("--lang", "--language", dest="language", type=normalize_language,
                        default="zh-CN", metavar="zh-CN|en-US|zh|en",
                        help=cli_text("Select the report and human message language", language))
    report_lang_help = ("Select the report language; defaults to --lang" if language == "en-US"
                        else "选择报告语言；默认沿用 --lang")
    parser.add_argument("--report-lang", "--report-language", dest="report_language",
                        type=normalize_language, default=None, metavar="zh-CN|en-US|zh|en",
                        help=report_lang_help)
    parser.add_argument("--version", action="version", version=VERSION,
                        help=cli_text("Show program version and exit", language))
    sub = parser.add_subparsers(dest="command", required=True, parser_class=parser_type)
    seal = sub.add_parser("seal", help=cli_text("Create a manifest for a reviewed native evidence directory", language),
                          description=cli_text("Create a manifest for a reviewed native evidence directory", language))
    seal.add_argument("directory", type=Path); seal.add_argument("--project-alias", required=True); seal.add_argument("--asset-alias", required=True)
    seal.add_argument("--target", required=True, type=Path, help=cli_text("JSON containing exactly: os_family, product, version, architecture, use_case, scope", language))
    seal.add_argument("--collection", required=True, type=Path, help=cli_text("JSON containing exactly: started_at, finished_at, timezone, privilege, collector_version, command_catalog", language))
    root = application_root()
    imp = sub.add_parser("import", help=cli_text("Validate and import a bundle into a new case directory", language),
                         description=cli_text("Validate and import a bundle into a new case directory", language))
    imp.add_argument("bundle", type=Path); imp.add_argument("--cases", type=Path, default=root / "data" / "raw" / "cases")
    analyze = sub.add_parser("analyze", help=cli_text("Analyze one validated, already imported bundle", language),
                             description=cli_text("Analyze one validated, already imported bundle", language))
    analyze.add_argument("case", type=Path); analyze.add_argument("--output", type=Path, default=root / "reports" / "output")
    analyze.add_argument("--listener-knowledge", type=Path, default=DEFAULT_LISTENER_KNOWLEDGE,
                         help=cli_text("Use a validated listener knowledge JSON file (defaults to the bundled example).", language))
    analyze.add_argument("--ai-provider", choices=["ollama"]); analyze.add_argument("--ai-endpoint")
    analyze.add_argument("--ai-model"); analyze.add_argument("--ai-cloud-disabled-ack", action="store_true", help=cli_text("Assert Ollama cloud features were disabled before use", language))
    analyze.add_argument("--ai-timeout", type=float, default=15.0)
    local = sub.add_parser("analyze-local", help=cli_text("Run authorized current-Windows collectors and render the same unified reports", language),
                           description=cli_text("Run authorized current-Windows collectors and render the same unified reports", language))
    local.add_argument("--output", type=Path, default=root / "reports" / "output")
    local.add_argument("--project-alias", required=True)
    local.add_argument("--asset-alias", required=True)
    local.add_argument("--listener-knowledge", type=Path, default=DEFAULT_LISTENER_KNOWLEDGE,
                       help=cli_text("Use a validated listener knowledge JSON file (defaults to the bundled example).", language))
    cmp = sub.add_parser("compare", help=cli_text("Compare two analysis.json files", language), description=cli_text("Compare two analysis.json files", language))
    cmp.add_argument("before", type=Path); cmp.add_argument("after", type=Path); cmp.add_argument("--output", type=Path, required=True)
    handoff = sub.add_parser("codex-export", help=cli_text("Write a redacted summary for Codex conversation analysis", language), description=cli_text("Write a redacted summary for Codex conversation analysis", language))
    handoff.add_argument("analysis", type=Path); handoff.add_argument("--output", type=Path, required=True)
    sanitize = sub.add_parser("sanitize-config", help=cli_text("Export selected allow-listed config facts after redaction", language), description=cli_text("Export selected allow-listed config facts after redaction", language))
    sanitize.add_argument("--product", choices=["nginx", "tomcat", "redis", "mysql", "oracle", "was"], required=True)
    sanitize.add_argument("--source", type=Path, required=True); sanitize.add_argument("--output-dir", type=Path, required=True)
    sanitize.add_argument("--instance-id", default="instance-1"); sanitize.add_argument("--product-version", default="unknown")
    remote = sub.add_parser("capture-ssh", help=cli_text("Capture one explicitly authorized POSIX target using pinned OpenSSH host keys", language), description=cli_text("Capture one explicitly authorized POSIX target using pinned OpenSSH host keys", language))
    remote.add_argument("--host", required=True); remote.add_argument("--user", required=True); remote.add_argument("--port", type=int, default=22)
    remote.add_argument("--known-hosts", type=Path, required=True); remote.add_argument("--timeout", type=int, default=600)
    remote.add_argument("--agent-auth", action="store_true", help=cli_text("Explicitly authorize using the already running SSH agent only; private-key files are never read", language))
    remote.add_argument("--project-alias", required=True); remote.add_argument("--asset-alias", required=True)
    remote.add_argument("--target", required=True, type=Path); remote.add_argument("--collection", required=True, type=Path)
    remote.add_argument("--cases", type=Path, default=root / "data" / "raw" / "cases")
    winrm_cmd = sub.add_parser("capture-winrm", help=cli_text("Capture one explicitly authorized Windows target through HTTPS WinRM", language), description=cli_text("Capture one explicitly authorized Windows target through HTTPS WinRM", language))
    winrm_cmd.add_argument("--host", required=True); winrm_cmd.add_argument("--port", type=int, default=5986)
    winrm_cmd.add_argument("--user-env", required=True, help=cli_text("Environment variable name containing the WinRM username", language))
    winrm_cmd.add_argument("--password-env", required=True, help=cli_text("Environment variable name containing the WinRM password", language))
    winrm_cmd.add_argument("--project-alias", required=True); winrm_cmd.add_argument("--asset-alias", required=True)
    winrm_cmd.add_argument("--target", required=True, type=Path); winrm_cmd.add_argument("--collection", required=True, type=Path)
    winrm_cmd.add_argument("--cases", type=Path, default=root / "data" / "raw" / "cases")
    paste = sub.add_parser("paste-import", help=cli_text("Import bastion/SecureCRT paste block produced by platforms/posix_paste_export.sh", language), description=cli_text("Import bastion/SecureCRT paste block produced by platforms/posix_paste_export.sh", language))
    paste.add_argument("paste_file", type=Path, help=cli_text("Text file containing the full BEGIN/END paste block", language))
    paste.add_argument("--project-alias", required=True)
    paste.add_argument("--asset-alias", required=True)
    paste.add_argument("--use-case", required=True, choices=["home_pc", "office_pc", "office_server", "unknown"])
    paste.add_argument("--cases", type=Path, default=root / "data" / "raw" / "cases")
    paste.add_argument("--output", type=Path, default=root / "reports" / "output")
    paste.add_argument("--analyze", action="store_true", help=cli_text("Continue to analyze after import", language))
    paste.add_argument("--listener-knowledge", type=Path, default=DEFAULT_LISTENER_KNOWLEDGE)
    local_any = sub.add_parser("inspect-local", help=cli_text("One-shot authorized local capture→seal→import→analyze (POSIX or Windows)", language), description=cli_text("One-shot authorized local capture→seal→import→analyze (POSIX or Windows)", language))
    local_any.add_argument("--project-alias", required=True)
    local_any.add_argument("--asset-alias", required=True)
    local_any.add_argument("--use-case", required=True, choices=["home_pc", "office_pc", "office_server", "unknown"])
    local_any.add_argument("--cases", type=Path, default=root / "data" / "raw" / "cases")
    local_any.add_argument("--output", type=Path, default=root / "reports" / "output")
    local_any.add_argument("--listener-knowledge", type=Path, default=DEFAULT_LISTENER_KNOWLEDGE)
    subparsers_action = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    for child_parser in subparsers_action.choices.values():
        child_parser.add_argument("--lang", "--language", dest="language", type=normalize_language,
                                  default=argparse.SUPPRESS, metavar="zh-CN|en-US|zh|en",
                                  help=cli_text("Select the report and human message language", language))
        child_parser.add_argument("--report-lang", "--report-language", dest="report_language",
                                  type=normalize_language, default=argparse.SUPPRESS,
                                  metavar="zh-CN|en-US|zh|en", help=report_lang_help)
    args = parser.parse_args(argv)
    language = normalize_language(args.language)
    report_language = normalize_language(getattr(args, "report_language", None) or language)
    try:
        if args.command == "seal":
            path = write_manifest(args.directory, project_alias=args.project_alias, asset_alias=args.asset_alias, target=_json_object(args.target), collection=_json_object(args.collection))
            print(f"SEALED={path}")
            return 0
        if args.command == "import":
            path = import_bundle(args.bundle, args.cases)
            print(f"CASE={path}")
            return 0
        if args.command == "analyze":
            manifest = validate_bundle(args.case)
            result = analyze_evidence(args.case, manifest, listener_knowledge_path=args.listener_knowledge)
            rules_evidence = result.config_evidence.get("platform_rules", {})
            lifecycle_evidence = result.config_evidence.get("os_lifecycle", {})
            listener_evidence = result.config_evidence.get("listener_knowledge", {})
            windows_rules_evidence = result.config_evidence.get("windows_risk_registry", {})
            rules_hash = hashlib.sha256((str(rules_evidence.get("sha256", "")) + str(lifecycle_evidence.get("sha256", ""))
                                         + str(listener_evidence.get("sha256", ""))
                                         + str(windows_rules_evidence.get("sha256", ""))).encode("ascii", errors="ignore")).hexdigest()
            metadata: dict[str, Any] = {"project_alias": manifest["project_alias"], "asset_alias": manifest["asset_alias"], "bundle_id": manifest["bundle_id"],
                                        "target": " / ".join(str(x) for x in manifest["target"].values()),
                                        "target_identity": manifest["target"], "rules_version": f"{rules_evidence.get('rules_version', 'unknown')}+oslife-{lifecycle_evidence.get('rules_version', 'unknown')}+listeners-{listener_evidence.get('rules_version', 'unknown')}+windows-{windows_rules_evidence.get('rules_version', 'not_applicable')}",
                                        "rules_sha256": rules_hash, "tool_version": VERSION,
                                        "evidence_count": len(manifest["items"]), "sha256_authenticates_source": False,
                                        "evidence_items": [{"name": Path(x["path"]).name, "status": x["status"], "exit_code": x["exit_code"], "reason": x["reason"]} for x in manifest["items"]],
                                        "evidence_summary": _evidence_summary(args.case, manifest)}
            requested_ai = [args.ai_provider, args.ai_endpoint, args.ai_model]
            if any(requested_ai):
                if not all(requested_ai):
                    metadata["ai_advisory"] = {"status": "AI_NOT_RUN", "reason": "provider, endpoint, and model are all required"}
                else:
                    try:
                        metadata["ai_advisory"] = request_suggestions(provider=args.ai_provider, endpoint=args.ai_endpoint,
                                                                       model=args.ai_model, findings=result.findings,
                                                                       cloud_disabled_acknowledged=args.ai_cloud_disabled_ack,
                                                                        timeout=args.ai_timeout, language=report_language)
                    except (LocalAIError, OSError, TimeoutError, ValueError) as exc:
                        metadata["ai_advisory"] = {"status": "AI_FAILED", "reason": f"{type(exc).__name__}: request or response rejected"}
            else:
                metadata["ai_advisory"] = {"status": "AI_NOT_RUN", "reason": "local AI is opt-in and was not requested"}
            report_dir = args.output / str(manifest["bundle_id"])
            outputs = write_reports(report_dir, result, metadata, report_language)
            print("\n".join(f"{key.upper()}={value}" for key, value in outputs.items()))
            print(f"ANALYSIS_STATUS={result.status}")
            print(f"AI_STATUS={metadata['ai_advisory']['status']}")
            print("INFO: " + cli_text("Report files were created.", language))
            if metadata["ai_advisory"]["status"] == "AI_NOT_RUN":
                print("INFO: " + cli_text("Local AI was not requested; no AI request was sent.", language))
            return 0 if result.status == "OK" else 4
        if args.command == "compare":
            before, before_meta = _load_analysis(args.before); after, after_meta = _load_analysis(args.after)
            value = _compare(before, after, before_meta, after_meta)
            _write_new(args.output, json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            print(f"COMPARISON={args.output}")
            return 0 if value["status"] == "OK" else 4
        if args.command == "sanitize-config":
            path = sanitize_config(args.product, args.source, args.output_dir, instance_id=args.instance_id, version=args.product_version)
            print(f"SANITIZED_EVIDENCE={path}")
            return 0
        if args.command == "analyze-local":
            from run_inspection import application_root as inspection_application_root, run_collection_pipeline
            from rules.loader import resolve_rule_configuration
            resolution = resolve_rule_configuration(inspection_application_root())
            try:
                listener_knowledge, listener_evidence = load_listener_knowledge(args.listener_knowledge)
            except (OSError, UnicodeError, json.JSONDecodeError, ListenerKnowledgeError) as exc:
                reason = listener_knowledge_error_reason(exc)
                listener_knowledge, listener_evidence = None, {"status": "failed", "reason": reason}
                collectors = {}
                result = AnalysisResult(status="FAILED", config_evidence={"listener_knowledge": listener_evidence},
                                        errors=[reason])
            else:
                collectors, result = run_collection_pipeline(resolution=resolution, listener_knowledge=listener_knowledge,
                                                             listener_knowledge_evidence=listener_evidence)
            from analyzers.lifecycle import DEFAULT_POLICY, analyze_lifecycle
            system_item = collectors.get("system_info", {})
            system_facts = system_item.get("data", {}) if isinstance(system_item, dict) else {}
            target = {"os_family": "windows", "product": str(system_facts.get("os", "unknown")), "version": str(system_facts.get("version", "unknown"))}
            os_evidence = {"os_detail.txt": f"Caption={target['product']}\nVersion={target['version']}\n"}
            try:
                lifecycle_bytes = DEFAULT_POLICY.read_bytes()
                lifecycle_policy = json.loads(lifecycle_bytes.decode("utf-8"))
                if not isinstance(lifecycle_policy, dict):
                    lifecycle_policy = {"unavailable_sha256": hashlib.sha256(lifecycle_bytes).hexdigest()}
                args.output.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(prefix=".policy-", dir=args.output) as policy_tmp:
                    policy_copy = Path(policy_tmp) / "os-lifecycle.json"
                    policy_copy.write_bytes(lifecycle_bytes)
                    lifecycle_findings, lifecycle_warnings = analyze_lifecycle(target, os_evidence, policy_copy)
            except (OSError, UnicodeError, json.JSONDecodeError):
                lifecycle_bytes = b""
                lifecycle_policy = {"unavailable_sha256": hashlib.sha256(lifecycle_bytes).hexdigest()}
                lifecycle_findings, lifecycle_warnings = analyze_lifecycle(target, os_evidence, DEFAULT_POLICY.parent / "missing-policy.json")
            result.findings.extend(lifecycle_findings)
            result.warnings = list(dict.fromkeys(result.warnings + lifecycle_warnings))
            if lifecycle_warnings and result.status == "OK":
                result.status = "PARTIAL"
            lifecycle_hash = hashlib.sha256(lifecycle_bytes).hexdigest() if lifecycle_bytes else "not_available"
            lifecycle_version = str(lifecycle_policy.get("rules_version", "unknown"))
            policy_invalid = "OS_LIFECYCLE_POLICY_INVALID_OR_UNAVAILABLE" in lifecycle_warnings
            result.config_evidence["os_lifecycle"] = {"status": "failed" if policy_invalid else "loaded", "rules_version": lifecycle_version, "sha256": lifecycle_hash}
            if not args.project_alias or not args.asset_alias:
                raise ValueError("Stable project and asset aliases are required for local analysis.")
            platform_rules = resolution.registry if isinstance(resolution.registry, dict) else {}
            combined_rules_version, rules_hash = _canonical_rules_binding(resolution, lifecycle_policy, listener_knowledge,
                                                                          listener_evidence)
            target_identity = {"os_family": "windows", "product": target["product"], "version": target["version"],
                               "architecture": str(system_facts.get("architecture") or platform.machine() or "unknown"), "scope": "basic"}
            metadata = {"project_alias": args.project_alias, "asset_alias": args.asset_alias,
                        "bundle_id": "local-" + uuid.uuid4().hex, "target": " / ".join(target_identity.values()),
                        "target_identity": target_identity, "rules_version": combined_rules_version,
                        "rules_sha256": rules_hash, "tool_version": VERSION,
                        "support_assessment": "See rule-bound OS lifecycle Finding; paid/contract entitlement is not inferred.",
                        "evidence_summary": _local_summary(collectors), "ai_advisory": {"status": "AI_NOT_RUN", "reason": "Local AI is opt-in and was not requested."}}
            outputs = write_reports(args.output / datetime.now(timezone.utc).strftime("local-%Y%m%dT%H%M%SZ"), result, metadata, report_language)
            print("\n".join(f"{key.upper()}={value}" for key, value in outputs.items()))
            print(f"ANALYSIS_STATUS={result.status}")
            print("INFO: " + cli_text("Report files were created.", language))
            return 0 if result.status == "OK" else 4
        if args.command == "capture-ssh":
            path = capture_ssh_bundle(host=args.host, user=args.user, port=args.port, known_hosts=args.known_hosts,
                                      cases_dir=args.cases, project_alias=args.project_alias, asset_alias=args.asset_alias,
                                      target=_json_object(args.target), collection=_json_object(args.collection), timeout=args.timeout,
                                      agent_auth=args.agent_auth)
            print(f"BUNDLE={path}")
            return 0
        if args.command == "capture-winrm":
            path = capture_winrm_bundle(host=args.host, port=args.port, user_env=args.user_env, password_env=args.password_env,
                                        cases_dir=args.cases, project_alias=args.project_alias, asset_alias=args.asset_alias,
                                        target=_json_object(args.target), collection=_json_object(args.collection))
            print(f"BUNDLE={path}")
            return 0
        if args.command == "paste-import":
            text = args.paste_file.read_text(encoding="utf-8", errors="strict")
            staging = import_paste_text(text, args.cases / ".paste-staging")
            print(f"EVIDENCE={staging}")
            import desktop_app
            target, collection = desktop_app.derive_native_metadata(staging, args.use_case)
            sealed = write_manifest(staging, project_alias=args.project_alias, asset_alias=args.asset_alias,
                                    target=target, collection=collection)
            print(f"SEALED={sealed}")
            case = import_bundle(staging, args.cases)
            print(f"CASE={case}")
            if not args.analyze:
                return 0
            return main(["--lang", language, "--report-lang", report_language,
                         "analyze", str(case), "--output", str(args.output),
                         "--listener-knowledge", str(args.listener_knowledge)])
        if args.command == "inspect-local":
            return _inspect_local(args, root, language, report_language)
        result, metadata = _load_analysis(args.analysis)
        safe_metadata = {"target": _safe_codex(metadata.get("target_identity", {})), "rules_version": metadata.get("rules_version"),
                         "rules_sha256": metadata.get("rules_sha256"), "evidence_summary": _safe_codex(metadata.get("evidence_summary", {}))}
        handoff_data = {"label": "Redacted Codex conversation handoff; not a source of authoritative findings",
                        "status": result.status, "metadata": safe_metadata, "findings": [
                            {"finding_id": _safe_id(item.get("finding_id")), **{k: _redact_text(item.get(k, "")) for k in ("title", "severity", "category", "description", "impact", "recommendation", "verification_checkpoint")},
                             "evidence": _safe_codex(item.get("evidence", {})), "applicability": _redact_text(item.get("applicability", "")),
                             "rollback": _redact_text(item.get("rollback", ""))}
                            for item in result.findings],
                        "warnings": [_redact_text(x) for x in result.warnings], "errors": [_redact_text(x) for x in result.errors],
                        "instruction": "Use only supplied facts. Do not infer missing evidence or replace deterministic risk status."}
        _write_new(args.output, json.dumps(handoff_data, ensure_ascii=False, indent=2) + "\n")
        print(f"CODEX_HANDOFF={args.output}")
        return 0
    except (BundleError, ConfigSanitizationError, PasteError, TransportError, OSError, UnicodeError, json.JSONDecodeError, ValueError, RuntimeError, FileNotFoundError) as exc:
        detail = str(exc).strip().replace("\n", " ")
        if len(detail) > 240:
            detail = detail[:237] + "..."
        print(f"ERROR={type(exc).__name__}: {detail or 'operation rejected'}", file=sys.stderr)
        if "language" in locals():
            print("INFO: " + cli_text("The operation failed. Review the error details.", language), file=sys.stderr)
        return 2


def _inspect_local(args: argparse.Namespace, root: Path,
                   language: str | None = None, report_language: str | None = None) -> int:
    import desktop_app
    import shutil
    import subprocess

    evidence = root / "data" / "raw" / f"local-capture-{uuid.uuid4().hex}"
    if evidence.exists():
        raise ValueError("Local capture path already exists.")
    system = platform.system().casefold()
    if system in {"linux", "darwin"}:
        script = root / "platforms" / "posix_capture.sh"
        if not script.is_file():
            raise FileNotFoundError("posix_capture.sh missing")
        completed = subprocess.run(["sh", str(script), str(evidence)], cwd=str(root), check=False)
        # PARTIAL capture (exit 4) is acceptable and still analyzable.
        if completed.returncode not in {0, 4}:
            if evidence.exists():
                shutil.rmtree(evidence, ignore_errors=True)
            raise RuntimeError(f"POSIX capture failed with exit {completed.returncode}")
    elif system == "windows":
        script = root / "platforms" / "windows_capture.cmd"
        completed = subprocess.run(["cmd.exe", "/d", "/c", str(script), str(evidence)], cwd=str(root), check=False)
        if completed.returncode not in {0, 4}:
            if evidence.exists():
                shutil.rmtree(evidence, ignore_errors=True)
            raise RuntimeError(f"Windows capture failed with exit {completed.returncode}")
    else:
        raise RuntimeError(f"Unsupported local platform: {system}")
    print(f"EVIDENCE={evidence}")
    target, collection = desktop_app.derive_native_metadata(evidence, args.use_case)
    sealed = write_manifest(evidence, project_alias=args.project_alias, asset_alias=args.asset_alias,
                            target=target, collection=collection)
    print(f"SEALED={sealed}")
    case = import_bundle(evidence, args.cases)
    print(f"CASE={case}")
    human_language = normalize_language(language or args.language)
    selected_report_language = normalize_language(report_language or getattr(args, "report_language", None) or human_language)
    return main(["--lang", human_language, "--report-lang", selected_report_language,
                 "analyze", str(case), "--output", str(args.output),
                 "--listener-knowledge", str(args.listener_knowledge)])


if __name__ == "__main__":
    raise SystemExit(main())
