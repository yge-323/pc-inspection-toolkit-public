from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Any

from collectors.security_vendors import match_vendor
from analyzers.listener_risk import analyze_facts as analyze_listener_facts, normalize_collector_rows
from analyzers.windows_security_rules import (
    analyze_windows_administrator_count,
    analyze_windows_security_facts,
    analyze_windows_service_facts,
    analyze_windows_startup_facts,
    local_security_facts,
)
from analyzers.windows_disk_rules import analyze_windows_disk_facts, windows_disk_identity_state
from models.analysis import AnalysisResult
from models.finding import Finding
from rules.loader import rule_map

def analyze(
    results: dict[str, Any],
    registry: dict[str, Any] | None,
    *,
    local_profile: dict[str, Any] | None = None,
    config_evidence: dict[str, dict[str, Any]] | None = None,
    config_status: str = "OK",
    listener_knowledge: dict[str, Any] | None = None,
    listener_knowledge_evidence: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
) -> AnalysisResult:
    warnings = list(warnings or [])
    errors = list(errors or [])
    if registry is None:
        return AnalysisResult(
            status="PARTIAL" if results else "FAILED",
            findings=[],
            config_evidence=config_evidence or {},
            warnings=warnings,
            errors=errors or ["Risk analysis did not run because no valid registry was available."],
        )

    rules = rule_map(registry)
    findings: list[dict[str, Any]] = []
    network_result = results.get("network_ports", {}) if isinstance(results.get("network_ports"), dict) else {}
    network_present = "network_ports" in results
    collector_status_explicit = "status" in network_result
    collector_status = str(network_result.get("status") or "not_checked").casefold()
    # Preserve direct legacy analyzer callers that supplied facts before collector statuses
    # became part of this interface. The real collection pipeline always supplies a status.
    valid_fact_status = collector_status in {"ok", "partial", "need_admin"} or not collector_status_explicit
    network_rows = network_result.get("data") if valid_fact_status else []
    listener_facts, listener_gaps = normalize_collector_rows(network_rows)
    # Legacy Windows rules still own their existing IDs and override semantics, but consume
    # the same validated facts so malformed ports cannot abort or bypass shared analysis.
    legacy_rows = [{"LocalPort": item["port"], "LocalAddress": item["address"],
                    "ProcessName": item.get("process", "unknown")}
                   for item in listener_facts if item["protocol"] == "tcp"]
    findings.extend(_network_findings(legacy_rows, registry, rules))
    if listener_knowledge is not None:
        findings.extend(analyze_listener_facts(listener_facts, listener_knowledge))
        for warning in listener_gaps:
            if warning not in warnings:
                warnings.append(warning)
        if (listener_gaps or collector_status in {"partial", "need_admin"} or not valid_fact_status) and config_status == "OK":
            config_status = "PARTIAL"
        if not collector_status_explicit:
            if "NETWORK_COLLECTOR_STATUS_UNKNOWN" not in warnings:
                warnings.append("NETWORK_COLLECTOR_STATUS_UNKNOWN")
            if config_status == "OK":
                config_status = "PARTIAL"
    if not valid_fact_status and (network_present or listener_knowledge is not None):
        warning = f"NETWORK_COLLECTOR_STATUS_{collector_status.upper()}"
        if warning not in warnings:
            warnings.append(warning)
        if config_status == "OK":
            config_status = "PARTIAL"
    elif collector_status in {"partial", "need_admin"} and config_status == "OK":
        config_status = "PARTIAL"
    findings.extend(_user_findings(results.get("users", {}).get("data", {}), registry, rules))
    findings.extend(_service_findings(results.get("services", {}).get("data", []), registry, rules))
    findings.extend(_task_findings(results.get("scheduled_tasks", {}).get("data", []), registry, rules))
    findings.extend(_bitlocker_need_admin_findings(results.get("disks", {}), rules))
    disk_result = results.get("disks", {}) if isinstance(results.get("disks"), dict) else {}
    disk_data = disk_result.get("data") if isinstance(disk_result.get("data"), dict) else {}
    disk_volumes = _as_list(disk_data.get("VolumeSummary") or disk_data.get("Volumes") or disk_data.get("LogicalDisks"))
    disk_identity_gaps, _disk_conflicts = windows_disk_identity_state(disk_volumes)
    for warning in disk_identity_gaps:
        if warning not in warnings:
            warnings.append(warning)
    if disk_identity_gaps and config_status == "OK":
        config_status = "PARTIAL"
    findings.extend(_disk_low_space_findings(disk_result, registry, rules))
    findings.extend(_startup_suspicious_path_findings(results.get("startup_items", {}), registry, rules))
    findings.extend(_security_vendor_findings(results, registry, rules))
    security_collector = results.get("windows_security", {})
    if isinstance(security_collector, dict) and security_collector.get("status") in {"ok", "partial", "need_admin"}:
        findings.extend(analyze_windows_security_facts(
            local_security_facts(security_collector.get("data")), registry
        ))
    findings.extend(_event_log_findings(results.get("event_logs", {}).get("data", []), registry, rules))
    findings = _apply_local_profile_annotations(findings, results, local_profile, rules, config_evidence)
    listener_ids = {str(rule.get("id")) for rule in (listener_knowledge or {}).get("rules", []) if isinstance(rule, dict)}
    finding_ids = [str(item.get("finding_id") or "") for item in findings]
    if any(finding_ids.count(rule_id) > 1 for rule_id in listener_ids):
        duplicate_config = {**(config_evidence or {}), **({"listener_knowledge": listener_knowledge_evidence} if listener_knowledge_evidence else {})}
        return AnalysisResult(status="FAILED", findings=[], config_evidence=duplicate_config,
                              warnings=warnings, errors=errors + ["FINDING_ID_CONFLICT"])
    return AnalysisResult(
        status="PARTIAL" if config_status == "PARTIAL" else "OK",
        findings=sorted(findings, key=lambda f: _rank(f["severity"])),
        config_evidence={**(config_evidence or {}), **({"listener_knowledge": listener_knowledge_evidence} if listener_knowledge_evidence else {})},
        warnings=warnings,
        errors=errors,
    )


def _finding_dict(finding: Finding) -> dict[str, Any]:
    item = finding.to_dict()
    item.update({
        "name": finding.title,
        "level": finding.severity,
        "impact": finding.impact,
        "recommendation": finding.recommendation,
        "auto_fix": "否",
    })
    return item


def _bitlocker_need_admin_findings(
    disks: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(disks, dict):
        return []

    status = str(disks.get("status") or "").lower()
    errors = _as_list(disks.get("errors"))
    data = disks.get("data") if isinstance(disks.get("data"), dict) else {}
    errors.extend(_as_list(data.get("Errors")))
    error_text = " ".join(str(item) for item in errors).lower()

    bitlocker_related = "bitlocker" in error_text or "get-bitlockervolume" in error_text
    permission_related = any(token in error_text for token in ("access denied", "permission denied", "拒绝访问"))
    if status != "need_admin" and not (bitlocker_related and permission_related):
        return []

    rule = _active_rule(rules, "WIN_BITLOCKER_NEED_ADMIN")
    if rule is None:
        return []
    return [_configured_finding(
        rule,
        {
            "collector": disks.get("collector", "disks"),
            "collector_status": disks.get("status"),
            "errors": errors,
            "bitlocker": data.get("BitLocker"),
        },
        "disks",
    )]


def _disk_low_space_findings(
    disks: dict[str, Any],
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(disks, dict):
        return []

    data = disks.get("data") if isinstance(disks.get("data"), dict) else {}
    volumes = _as_list(data.get("VolumeSummary") or data.get("Volumes") or data.get("LogicalDisks"))
    return analyze_windows_disk_facts(volumes, registry, rules)


def _startup_suspicious_path_findings(
    startup_items: dict[str, Any],
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(startup_items, dict):
        return []
    data = startup_items.get("data") if isinstance(startup_items.get("data"), dict) else {}
    items = _as_list(data.get("Items"))
    return analyze_windows_startup_facts(
        items, registry, rules, collector=str(startup_items.get("collector") or "startup_items")
    )


def _security_vendor_findings(
    results: dict[str, Any],
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(results, dict):
        return []

    collector = results.get("security_vendors")
    collector = collector if isinstance(collector, dict) else {}
    data = collector.get("data") if isinstance(collector.get("data"), dict) else {}
    inventory_available = str(collector.get("status") or "").casefold() in {"ok", "partial"}

    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
    vendor_patterns = registry["vendor_patterns"]
    _group_vendor_items(grouped, _as_list(data.get("installed_programs")), "installed_program", vendor_patterns)
    _group_vendor_items(grouped, _as_list(data.get("drivers")), "driver", vendor_patterns)
    _group_vendor_items(grouped, _as_list(data.get("directories")), "directory", vendor_patterns)
    _group_vendor_items(grouped, _collector_data_list(results.get("services")), "service", vendor_patterns)
    _group_vendor_items(
        grouped,
        _collector_data_list(results.get("scheduled_tasks")),
        "scheduled_task",
        vendor_patterns,
    )

    startup_collector = results.get("startup_items")
    startup_collector = startup_collector if isinstance(startup_collector, dict) else {}
    startup_data = startup_collector.get("data") if isinstance(startup_collector.get("data"), dict) else {}
    _group_vendor_items(grouped, _as_list(startup_data.get("Items")), "startup_item", vendor_patterns)

    findings: list[dict[str, Any]] = []
    for vendor in sorted(grouped):
        sources = grouped[vendor]
        uninstall_present = bool(sources["installed_program"])
        driver_present = bool(sources["driver"])
        residue_present = any(sources[key] for key in ("service", "driver", "scheduled_task", "startup_item"))
        running_service_present = any(_service_is_running(item) for item in sources["service"])

        if uninstall_present or (not inventory_available and running_service_present):
            finding = _security_vendor_present_finding(vendor, sources, rules)
            if finding is not None:
                findings.append(finding)
        elif inventory_available and residue_present:
            finding = _security_vendor_residue_finding(vendor, sources, rules)
            if finding is not None:
                findings.append(finding)

        if driver_present:
            finding = _security_vendor_driver_finding(vendor, sources, rules)
            if finding is not None:
                findings.append(finding)

    return findings


def _service_is_running(item: dict[str, Any]) -> bool:
    state = _first_present(item, "status", "state", "State")
    return str(state or "").casefold() in {"running", "active"}


def _collector_data_list(value: Any) -> list[Any]:
    collector = value if isinstance(value, dict) else {}
    data = collector.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _group_vendor_items(
    grouped: dict[str, dict[str, list[dict[str, Any]]]],
    items: list[Any],
    source_type: str,
    vendor_patterns: dict[str, Any],
) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        match = _security_vendor_match(item, source_type, vendor_patterns)
        if match is None:
            continue
        vendor, matched_keyword = match
        sources = grouped.setdefault(vendor, {
            "installed_program": [],
            "service": [],
            "driver": [],
            "scheduled_task": [],
            "startup_item": [],
            "directory": [],
        })
        summary = dict(item)
        summary["matched_vendor"] = vendor
        summary["matched_keyword"] = str(item.get("matched_keyword") or matched_keyword)
        summary["source_type"] = source_type
        sources[source_type].append(summary)


def _security_vendor_match(
    item: dict[str, Any],
    source_type: str,
    vendor_patterns: dict[str, Any],
) -> tuple[str, str] | None:
    explicit_vendor = str(item.get("matched_vendor") or "").strip()
    if explicit_vendor:
        canonical_match = match_vendor({"vendor": explicit_vendor}, ("vendor",), vendor_patterns)
        canonical = canonical_match["matched_vendor"] if canonical_match else explicit_vendor
        matched_keyword = item.get("matched_keyword")
        if not matched_keyword and canonical_match:
            matched_keyword = canonical_match["matched_keyword"]
        return canonical, str(matched_keyword or explicit_vendor)

    if source_type in {"installed_program", "driver", "directory"}:
        return None

    field_map = {
        "service": ("Name", "name", "DisplayName", "display_name", "PathName", "binary_path"),
        "scheduled_task": (
            "TaskName",
            "task_name",
            "TaskPath",
            "task_path",
            "Actions",
            "actions",
            "ScriptPaths",
            "script_paths",
            "executable",
            "command",
        ),
        "startup_item": (
            "Name", "name", "Command", "command", "ImagePath", "image_path",
            "ScriptPath", "script_path", "Path", "path", "Location", "location",
        ),
    }
    shared_match = match_vendor(item, field_map.get(source_type, ()), vendor_patterns)
    if shared_match is None:
        return None
    return shared_match["matched_vendor"], shared_match["matched_keyword"]


def _security_vendor_evidence(
    vendor: str,
    sources: dict[str, list[dict[str, Any]]],
    preferred_sources: tuple[str, ...],
) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for source_type in preferred_sources:
        if sources[source_type]:
            selected = sources[source_type][0]
            break

    related_item_count = sum(len(items) for items in sources.values())
    return {
        "vendor": vendor,
        "matched_keyword": selected.get("matched_keyword"),
        "source_type": selected.get("source_type"),
        "name": _first_present(selected, "name", "Name", "TaskName"),
        "display_name": _first_present(selected, "display_name", "DisplayName"),
        "path": _first_present(
            selected,
            "path",
            "path_name",
            "PathName",
            "binary_path",
            "install_location",
            "ImagePath",
            "image_path",
            "ScriptPath",
            "script_path",
            "ScriptPaths",
            "script_paths",
            "Command",
            "Actions",
        ),
        "status": _first_present(selected, "status", "state", "State"),
        "start_type": _first_present(selected, "start_mode", "StartMode"),
        "uninstall_present": bool(sources["installed_program"]),
        "service_present": bool(sources["service"]),
        "driver_present": bool(sources["driver"]),
        "task_present": bool(sources["scheduled_task"]),
        "startup_present": bool(sources["startup_item"]),
        "directory_present": bool(sources["directory"]),
        "related_item_count": related_item_count,
    }


def _security_vendor_present_finding(
    vendor: str,
    sources: dict[str, list[dict[str, Any]]],
    rules: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    rule = _active_rule(rules, "WIN_SECURITY_VENDOR_PRESENT")
    if rule is None:
        return None
    finding = Finding(
        finding_id="WIN_SECURITY_VENDOR_PRESENT",
        title=str(rule["name"]),
        severity=str(rule["severity"]),
        category=str(rule["category"]),
        component="security_vendors",
        description=str(rule["condition_description"]),
        evidence=_security_vendor_evidence(vendor, sources, ("installed_program", "service")),
        impact=str(rule["risk"]),
        recommendation=str(rule["recommendation"]),
        verification_checkpoint="核对已安装程序、厂商信息和用户使用意图，确认保留或按厂商官方流程人工处理。",
        needs_human_review=True,
    )
    return _finding_dict(finding)


def _security_vendor_residue_finding(
    vendor: str,
    sources: dict[str, list[dict[str, Any]]],
    rules: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    rule = _active_rule(rules, "WIN_SECURITY_VENDOR_RESIDUE")
    if rule is None:
        return None
    return _configured_finding(
        rule,
        _security_vendor_evidence(
            vendor,
            sources,
            ("driver", "service", "scheduled_task", "startup_item"),
        ),
        "security_vendors",
    )


def _security_vendor_driver_finding(
    vendor: str,
    sources: dict[str, list[dict[str, Any]]],
    rules: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    rule = _active_rule(rules, "WIN_SECURITY_VENDOR_DRIVER_REVIEW")
    if rule is None:
        return None
    finding = Finding(
        finding_id="WIN_SECURITY_VENDOR_DRIVER_REVIEW",
        title=str(rule["name"]),
        severity=str(rule["severity"]),
        category=str(rule["category"]),
        component="security_vendors",
        description=str(rule["condition_description"]),
        evidence=_security_vendor_evidence(vendor, sources, ("driver",)),
        impact=str(rule["risk"]),
        recommendation=str(rule["recommendation"]),
        verification_checkpoint="通过受信任的系统工具核对驱动签名和服务状态，并在厂商官方卸载后复跑巡检。",
        needs_human_review=True,
    )
    return _finding_dict(finding)


def _active_rule(
    rules: dict[str, dict[str, Any]],
    rule_id: str,
) -> dict[str, Any] | None:
    rule = rules.get(rule_id)
    if not rule or rule.get("enabled") is not True:
        return None
    return rule


def _rule_file_path() -> Path:
    if getattr(sys, "frozen", False):
        application_root = Path(sys.executable).resolve().parent
    else:
        application_root = Path(__file__).resolve().parents[1]

    external_path = application_root / "rules" / "windows_risk_rules.example.json"
    if external_path.is_file():
        return external_path

    bundle_root = Path(getattr(sys, "_MEIPASS", application_root))
    bundled_path = bundle_root / "rules" / "windows_risk_rules.example.json"
    return bundled_path if bundled_path.is_file() else external_path


def _network_findings(
    ports: list[dict[str, Any]],
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ssh_listeners: dict[tuple[int, str], dict[str, Any]] = {}
    port_registry = registry["ports"]
    ssh_ports = set(port_registry["ssh"])
    smb_ports = set(port_registry["smb"])
    rdp_ports = set(port_registry["rdp"])
    proxy_ranges = [tuple(item) for item in port_registry["proxy_ranges"]]
    proxy_processes = {str(item).casefold() for item in port_registry["proxy_loopback_processes"]}
    for item in ports:
        port = int(item.get("LocalPort") or 0)
        address = str(item.get("LocalAddress") or "")
        process = str(item.get("ProcessName") or "")
        external = address in {"0.0.0.0", "::"}
        evidence = {"address": address, "port": port, "process": process, "protocol": "tcp"}
        if port in smb_ports and external:
            finding = _registry_finding(
                rules,
                "WIN_SMB_445_ALLOWED",
                evidence,
                "network_ports",
            )
            if finding is not None:
                findings.append(finding)
        elif port in rdp_ports and external:
            finding = _registry_finding(
                rules,
                "WIN_RDP_EXPOSED_REVIEW",
                evidence,
                "network_ports",
            )
            if finding is not None:
                findings.append(finding)
        elif port in ssh_ports and external:
            key = (port, process.casefold())
            listener = ssh_listeners.setdefault(key, {"process": process, "addresses": []})
            if address not in listener["addresses"]:
                listener["addresses"].append(address)
        elif any(start <= port <= end for start, end in proxy_ranges):
            if address in {"127.0.0.1", "::1"} and process.casefold() in proxy_processes:
                continue
            finding = _registry_finding(
                rules,
                "WIN_PROXY_PORT_EXPOSED",
                evidence,
                "network_ports",
            )
            if finding is not None:
                findings.append(finding)

    for (port, _), listener in ssh_listeners.items():
        process = listener["process"]
        evidence = {
            "addresses": listener["addresses"],
            "port": port,
            "process": process,
            "protocol": "tcp",
        }
        finding = _registry_finding(
            rules,
            "WIN_PORT_22_REVIEW",
            evidence,
            "network_ports",
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _registry_finding(
    rules: dict[str, dict[str, Any]],
    rule_id: str,
    evidence: dict[str, Any],
    component: str,
) -> dict[str, Any] | None:
    rule = _active_rule(rules, rule_id)
    if rule is None:
        return None
    addresses = evidence.get("addresses") or ([evidence.get("address")] if evidence.get("address") else [])
    endpoints = [
        f"[{address}]:{evidence.get('port')}" if ":" in str(address) else f"{address}:{evidence.get('port')}"
        for address in addresses
    ]
    display_evidence = f"{', '.join(endpoints)} {evidence.get('process') or ''}".strip()
    item = _configured_finding(rule, display_evidence, component)
    item["evidence_data"] = evidence
    return item


def _configured_finding(
    rule: dict[str, Any],
    evidence: Any,
    component: str,
) -> dict[str, Any]:
    severity = str(rule["severity"])
    item = {
        "finding_id": str(rule["id"]),
        "title": str(rule["name"]),
        "name": str(rule["name"]),
        "severity": severity,
        "level": severity,
        "category": str(rule["category"]),
        "component": component,
        "description": str(rule["condition_description"]),
        "evidence": evidence,
        "impact": str(rule["risk"]),
        "risk": str(rule["risk"]),
        "recommendation": str(rule["recommendation"]),
        "needs_human_review": True,
        "auto_fix": "否",
    }
    for field in ("precheck", "applicability", "rollback", "verification_checkpoint", "references"):
        if field in rule:
            item[field] = rule[field]
    return item


def _user_findings(
    data: Any,
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    admins = data.get("Administrators", []) if isinstance(data, dict) else []
    if isinstance(admins, dict):
        admins = [admins]
    return analyze_windows_administrator_count(len(admins), registry, rules)


def _service_findings(
    services: list[dict[str, Any]],
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    return analyze_windows_service_facts(services, registry)


def _task_findings(
    tasks: list[dict[str, Any]],
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rule = _active_rule(rules, "WIN_SCHEDULED_TASK_SUSPICIOUS_PATH")
    if rule is None:
        return []
    patterns = [str(item).casefold() for item in registry["path_patterns"]["scheduled_task_suspicious_substrings"]]
    suspicious = []
    for task in tasks:
        actions = " ".join([
            str(task.get("Actions") or ""),
            *[str(item) for item in _as_list(task.get("ScriptPaths"))],
        ]).casefold()
        if any(pattern in actions for pattern in patterns):
            suspicious.append(str(task.get("TaskName") or "unknown"))
    if not suspicious:
        return []
    return [_configured_finding(
        rule,
        {"tasks": suspicious[:10], "matched_count": len(suspicious)},
        "scheduled_tasks",
    )]


def _event_log_findings(
    events: list[dict[str, Any]],
    registry: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rule = _active_rule(rules, "WIN_EVENT_LOG_ERROR_VOLUME")
    if rule is None:
        return []
    levels = Counter(str(e.get("LevelDisplayName") or "") for e in events)
    critical = levels.get("Critical", 0)
    error = levels.get("Error", 0)
    critical_threshold = int(registry["thresholds"]["event_log_critical_count_warning_at_least"])
    error_threshold = int(registry["thresholds"]["event_log_error_count_warning_at_least"])
    if critical < critical_threshold and error < error_threshold:
        return []
    return [_configured_finding(
        rule,
        {
            "critical_count": critical,
            "error_count": error,
            "thresholds": {"critical_at_least": critical_threshold, "error_at_least": error_threshold},
        },
        "event_logs",
    )]


def _apply_local_profile_annotations(
    findings: list[dict[str, Any]],
    results: dict[str, Any],
    local_profile: dict[str, Any] | None,
    rules: dict[str, dict[str, Any]],
    config_evidence: dict[str, dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if local_profile is None:
        return findings

    system = results.get("system_info") if isinstance(results.get("system_info"), dict) else {}
    system_data = system.get("data") if isinstance(system.get("data"), dict) else {}
    hostname = str(system_data.get("hostname") or system_data.get("ComputerName") or "").casefold()
    expected_hostnames = {
        str(item).casefold()
        for item in local_profile.get("machine_match", {}).get("hostnames", [])
        if isinstance(item, str)
    }
    if not hostname or hostname not in expected_hostnames:
        return findings

    if config_evidence is not None and isinstance(config_evidence.get("local_profile"), dict):
        config_evidence["local_profile"]["applied"] = True

    for finding in findings:
        rule_id = str(finding.get("rule_id") or finding.get("finding_id") or "")
        rule = rules.get(rule_id)
        if rule is None:
            continue
        evidence = (
            finding.get("evidence_data")
            if isinstance(finding.get("evidence_data"), dict)
            else finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        )
        annotations: list[dict[str, Any]] = []

        for exception in local_profile.get("rule_exceptions", []):
            if exception.get("rule_id") != rule_id:
                continue
            match = exception.get("match")
            if isinstance(match, dict) and _exact_evidence_match(evidence, match):
                annotations.append({"match_type": "rule_exception", "matched_fields": sorted(match)})

        port = evidence.get("port")
        process = str(evidence.get("process") or "")
        addresses = evidence.get("addresses") or ([evidence.get("address")] if evidence.get("address") else [])
        for listener in local_profile.get("expected_listeners", []):
            if not isinstance(listener, dict) or listener.get("port") != port:
                continue
            if _normalized_identity(listener.get("process")) != _normalized_identity(process):
                continue
            if _normalized_identity(listener.get("protocol")) != _normalized_identity(evidence.get("protocol")):
                continue
            allowed_rule_ids = listener.get("rule_ids") or []
            if allowed_rule_ids and rule_id not in allowed_rule_ids:
                continue
            expected_addresses = {_normalized_identity(item) for item in listener.get("addresses", [])}
            actual_addresses = {_normalized_identity(item) for item in addresses}
            if expected_addresses != actual_addresses:
                continue
            annotations.append({
                "match_type": "expected_listener",
                "matched_fields": ["addresses", "port", "process", "protocol"],
            })

        expected_processes = {str(item).casefold() for item in local_profile.get("expected_processes", [])}
        if process and process.casefold() in expected_processes:
            annotations.append({"match_type": "expected_process", "matched_fields": ["process"]})

        account = str(evidence.get("account") or evidence.get("username") or "")
        expected_accounts = {str(item).casefold() for item in local_profile.get("expected_accounts", [])}
        if account and account.casefold() in expected_accounts:
            annotations.append({"match_type": "expected_account", "matched_fields": ["account"]})

        if not annotations:
            continue
        base_severity = finding.get("severity")
        disposition = (
            "expected"
            if rule.get("local_override_policy") == "allow_exact_expected"
            and finding.get("severity") != "Critical"
            else "context_only"
        )
        finding["base_severity"] = base_severity
        finding["local_profile_disposition"] = disposition
        finding["local_profile_annotations"] = [
            {
                "match_type": annotation["match_type"],
                "matched_fields": annotation["matched_fields"],
                "disposition": disposition,
                "base_severity": base_severity,
            }
            for annotation in annotations
        ]
    return findings


def _exact_evidence_match(evidence: dict[str, Any], expected: dict[str, Any]) -> bool:
    for key, expected_value in expected.items():
        if key not in evidence or expected_value is None:
            return False
        actual = evidence[key]
        if isinstance(expected_value, str) and isinstance(actual, str):
            if _normalized_identity(actual) != _normalized_identity(expected_value):
                return False
        elif type(actual) is not type(expected_value) or actual != expected_value:
            return False
    return True


def _normalized_identity(value: Any) -> str:
    return str(value or "").strip().casefold()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_present(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return None


def _normalize_legacy_severity(value: Any) -> str:
    # HIGH/MEDIUM/LOW are accepted only for legacy compatibility; new findings use standard severity.
    key = str(value or "").strip().replace("_", " ").replace("-", " ").casefold()
    return {
        "critical": "Critical",
        "high": "Critical",
        "attention": "Attention",
        "medium": "Attention",
        "warning": "Warning",
        "low": "Warning",
        "need admin": "Need Admin",
        "info": "Info",
        "ok": "OK",
        "skipped": "Skipped",
        "failed": "Failed",
    }.get(key, "Info")


def _rank(level: str) -> int:
    severity = _normalize_legacy_severity(level)
    return {
        "Critical": 0,
        "Attention": 1,
        "Warning": 2,
        "Need Admin": 3,
        "Info": 4,
        "OK": 5,
        "Skipped": 6,
        "Failed": 7,
    }.get(severity, 9)
