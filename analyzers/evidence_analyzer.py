from __future__ import annotations

import json
import re
import hashlib
import ipaddress
from pathlib import Path
from typing import Any

from models.analysis import AnalysisResult
from analyzers.lifecycle import DEFAULT_POLICY as DEFAULT_LIFECYCLE_POLICY, analyze_lifecycle
from analyzers.listener_risk import DEFAULT_KNOWLEDGE as DEFAULT_LISTENER_KNOWLEDGE, ListenerKnowledgeError, analyze_facts as analyze_listener_facts, listener_knowledge_error_reason, load_knowledge as load_listener_knowledge, parse_listener_text
from analyzers.windows_security_rules import (
    analyze_windows_administrator_count,
    analyze_windows_security_facts,
    analyze_windows_service_facts,
    analyze_windows_startup_facts,
    native_security_facts,
    native_service_facts,
    parse_native_administrator_count,
    parse_native_startup_facts,
)
from analyzers.windows_disk_rules import analyze_windows_disk_facts, parse_native_disk_facts
from analyzers.linux_baseline import analyze_linux_baseline
from evidence.config_sanitizer import ALLOW, PRODUCT_FILES, XML_TAGS
from rules.loader import validate_registry

DEFAULT_RULES = Path(__file__).resolve().parents[1] / "rules" / "platform_risk_rules.example.json"
DEFAULT_WINDOWS_RULES = Path(__file__).resolve().parents[1] / "rules" / "windows_risk_rules.example.json"
REQUIRED_FILES = {
    "windows": {"os.txt", "os_detail.txt", "cpu.txt", "memory.txt", "graphics.txt", "disks.txt", "processes.txt", "services.txt", "listeners.txt", "firewall.txt", "privilege.txt", "accounts.txt", "startup_items.txt", "security_status.txt"},
    "linux": {"os.txt", "os_release.txt", "architecture.txt", "cpu_count.txt", "memory_summary.txt", "graphics_summary.txt", "disks.txt", "services.txt", "listeners.txt", "firewall.txt", "privilege.txt", "accounts.txt", "startup_items.txt", "security_status.txt"},
    "macos": {"os.txt", "os_release.txt", "architecture.txt", "cpu_count.txt", "memory_summary.txt", "graphics_summary.txt", "disks.txt", "services.txt", "listeners.txt", "privilege.txt", "accounts.txt", "startup_items.txt", "security_status.txt"},
}


def analyze_evidence(root: Path, manifest: dict[str, Any], rules_path: Path = DEFAULT_RULES,
                     listener_knowledge_path: Path = DEFAULT_LISTENER_KNOWLEDGE) -> AnalysisResult:
    family = str(manifest["target"].get("os_family", "unknown")).casefold()
    items = manifest["items"]
    if not items:
        return AnalysisResult(status="FAILED", warnings=["No evidence files were supplied."])
    policy, policy_error = load_platform_policy(rules_path)
    if policy_error.get("status") != "loaded":
        return AnalysisResult(status="FAILED", config_evidence={"platform_rules": policy_error}, errors=["PLATFORM_RULES_INVALID_OR_UNAVAILABLE"])
    try:
        listener_knowledge, listener_evidence = load_listener_knowledge(listener_knowledge_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ListenerKnowledgeError) as exc:
        return AnalysisResult(status="FAILED", config_evidence={"platform_rules": policy_error,
                                                                  "listener_knowledge": {"status": "failed", "reason": listener_knowledge_error_reason(exc)}},
                              errors=[listener_knowledge_error_reason(exc)])
    windows_registry: dict[str, Any] | None = None
    windows_registry_evidence: dict[str, Any] = {"status": "not_applicable"}
    if family == "windows":
        windows_registry, windows_registry_evidence = load_windows_risk_registry(DEFAULT_WINDOWS_RULES)
        if windows_registry is None:
            return AnalysisResult(
                status="FAILED",
                config_evidence={"platform_rules": policy_error, "listener_knowledge": listener_evidence,
                                 "windows_risk_registry": windows_registry_evidence},
                errors=["WINDOWS_RISK_RULES_INVALID_OR_UNAVAILABLE"],
            )
    statuses = {str(item["path"]): str(item["status"]) for item in items}
    required = REQUIRED_FILES.get(family, set())
    present_names = {Path(p).name for p in statuses}
    gaps = [f"REQUIRED_EVIDENCE_MISSING:{name}" for name in sorted(required - present_names)]
    gaps.extend(f"EVIDENCE_{status.upper()}:{path}" for path, status in statuses.items() if status != "collected")
    gaps.extend(f"EVIDENCE_PARTIAL:{item['path']}" for item in items
                if item.get("status") == "collected" and item.get("reason"))
    text_by_name: dict[str, str] = {}
    for item in items:
        if item["status"] != "collected":
            continue
        p = root.joinpath(*Path(item["path"]).parts)
        try:
            text_by_name[str(item["path"]).casefold()] = _read_text(p)[:MAX_TEXT]
        except (OSError, UnicodeError):
            gaps.append(f"EVIDENCE_READ_FAILED:{item['path']}")
    findings: list[dict[str, Any]] = []
    specific_wildcard_facts: set[tuple[str, int, str]] = set()
    lifecycle_findings, lifecycle_warnings = analyze_lifecycle(manifest["target"], text_by_name, DEFAULT_LIFECYCLE_POLICY)
    findings.extend(lifecycle_findings)
    if family == "windows":
        security_files = [(name, content) for name, content in text_by_name.items()
                          if Path(name).name.casefold() == "security_status.txt"]
        if not security_files:
            gaps.append("WINDOWS_SECURITY_FACTS_MISSING_OR_UNKNOWN")
        else:
            if len(security_files) > 1:
                gaps.append("WINDOWS_SECURITY_MULTIPLE_EVIDENCE_FILES")
            security_text = security_files[0][1]
            security_facts = native_security_facts(security_text)
            fact_names = (
                "rdp_enabled", "rdp_nla_required", "smb1_enabled", "autologon_enabled",
                "guest_enabled", "password_complexity", "minimum_password_length",
                "lockout_threshold",
            )
            if any(security_facts.get(name) is None for name in fact_names) or not security_facts.get("firewall_disabled_profiles") and "FirewallProfile=" not in security_text:
                gaps.append("WINDOWS_SECURITY_FACTS_INCOMPLETE")
            findings.extend(analyze_windows_security_facts(security_facts, windows_registry or {}))
        service_files = [(name, content) for name, content in text_by_name.items()
                         if Path(name).name.casefold() == "services.txt"]
        if not service_files:
            gaps.append("WINDOWS_SERVICE_FACTS_MISSING_OR_UNKNOWN")
        else:
            if len(service_files) > 1:
                gaps.append("WINDOWS_SERVICE_MULTIPLE_EVIDENCE_FILES")
            service_facts = native_service_facts(service_files[0][1])
            if not service_facts:
                gaps.append("WINDOWS_SERVICE_FACTS_INCOMPLETE")
            findings.extend(analyze_windows_service_facts(service_facts, windows_registry or {}))
        disk_files = [(name, content) for name, content in text_by_name.items()
                      if Path(name).name.casefold() == "disks.txt"]
        if not disk_files:
            gaps.append("WINDOWS_DISK_FACTS_MISSING_OR_UNKNOWN")
        else:
            if len(disk_files) > 1:
                gaps.append("WINDOWS_DISK_MULTIPLE_EVIDENCE_FILES")
            disk_facts, disk_gaps = parse_native_disk_facts(disk_files[0][1])
            gaps.extend(disk_gaps)
            findings.extend(analyze_windows_disk_facts(disk_facts, windows_registry or {}))
        account_files = [(name, content) for name, content in text_by_name.items()
                         if Path(name).name.casefold() == "accounts.txt"]
        if not account_files:
            gaps.append("WINDOWS_ACCOUNT_FACTS_MISSING_OR_UNKNOWN")
        else:
            if len(account_files) > 1:
                gaps.append("WINDOWS_ACCOUNT_MULTIPLE_EVIDENCE_FILES")
            administrator_count, account_gaps = parse_native_administrator_count(account_files[0][1])
            gaps.extend(account_gaps)
            findings.extend(analyze_windows_administrator_count(administrator_count, windows_registry or {}))
        startup_files = [(name, content) for name, content in text_by_name.items()
                         if Path(name).name.casefold() == "startup_items.txt"]
        if not startup_files:
            gaps.append("WINDOWS_STARTUP_FACTS_MISSING_OR_UNKNOWN")
        else:
            if len(startup_files) > 1:
                gaps.append("WINDOWS_STARTUP_MULTIPLE_EVIDENCE_FILES")
            startup_facts, startup_gaps = parse_native_startup_facts(startup_files[0][1])
            gaps.extend(startup_gaps)
            findings.extend(analyze_windows_startup_facts(startup_facts, windows_registry or {}))
    if required and not required.issubset({Path(p).name for p in statuses}):
        gaps.append("Required evidence coverage is incomplete; an empty result is not a pass.")
    target = manifest["target"]
    if not target.get("product") or _unknown(target.get("version")):
        gaps.append("TARGET_VERSION_APPLICABILITY_UNVERIFIED")
    if not target.get("architecture") or _unknown(target.get("architecture")):
        gaps.append("TARGET_ARCHITECTURE_UNVERIFIED")
    config_candidates: list[tuple[str, dict[str, Any], str]] = []
    config_identity_paths: dict[tuple[str, str], list[str]] = {}
    for path, content in text_by_name.items():
        if Path(path).name.casefold().endswith("-config.json"):
            try:
                item = json.loads(content)
                if (isinstance(item, dict) and item.get("product") in PRODUCT_FILES
                        and isinstance(item.get("instance_id"), str)
                        and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", item["instance_id"])):
                    config_identity_paths.setdefault((item["product"], item["instance_id"]), []).append(str(path))
                if not _validate_sanitized_config(item, Path(path).name):
                    gaps.append(f"CONFIG_SCHEMA_INVALID:{Path(path).name}")
                    continue
                if _unknown(item["version"]):
                    gaps.append(f"PRODUCT_VERSION_APPLICABILITY_UNVERIFIED:{item['product']}:{item['instance_id']}")
                gaps.append(f"CONFIG_INCLUDE_SCOPE_UNCHECKED:{item['product']}:{item['instance_id']}")
                config_candidates.append((str(path), item, content))
            except (json.JSONDecodeError, AttributeError, TypeError, KeyError):
                gaps.append(f"CONFIG_PARSE_FAILED:{Path(path).name}")
    duplicate_paths = {path for paths in config_identity_paths.values() if len(paths) > 1 for path in paths}
    for identity, paths in config_identity_paths.items():
        if len(paths) > 1:
            gaps.append(f"CONFIG_DUPLICATE_PRODUCT_INSTANCE:{identity[0]}:{identity[1]}")
    matcher_texts = {path: content for path, content in text_by_name.items()
                     if not Path(path).name.casefold().endswith("-config.json")}
    config_products: set[str] = set()
    for path, item, content in config_candidates:
        if path not in duplicate_paths:
            matcher_texts[path] = content
            config_products.add(item["product"])
    listener_files = [(name, value) for name, value in text_by_name.items() if Path(name).name.casefold() == "listeners.txt"]
    listener_facts: list[dict[str, Any]] = []
    if not listener_files:
        gaps.append("LISTENER_FACTS_MISSING_OR_UNKNOWN")
    else:
        if len(listener_files) > 1:
            gaps.append("LISTENER_MULTIPLE_EVIDENCE_FILES")
        listener_facts: list[dict[str, Any]] = []
        listener_gaps: list[str] = []
        confirmed_empty = False
        for source, listener_text in listener_files:
            source_facts, source_gaps = parse_listener_text(listener_text, source=source)
            listener_facts.extend(source_facts)
            listener_gaps.extend(source_gaps)
            confirmed_empty = confirmed_empty or "LISTENER_EVIDENCE_EMPTY_CONFIRMED" in source_gaps
        gaps.extend(item for item in listener_gaps if item != "LISTENER_EVIDENCE_EMPTY_CONFIRMED")
        if not listener_facts and not confirmed_empty:
            gaps.append("LISTENER_FACTS_MISSING_OR_UNKNOWN")
    specific_listener_findings = analyze_listener_facts(listener_facts, listener_knowledge)
    emitted_listener_keys = {
        (finding["evidence"]["port"], protocol)
        for finding in specific_listener_findings
        for protocol in finding["evidence"]["protocols"]
    }
    specific_wildcard_facts = {
        (fact["protocol"], fact["port"], fact["address"])
        for fact in listener_facts
        if fact.get("scope") == "wildcard"
        and (fact.get("port"), fact.get("protocol")) in emitted_listener_keys
    }
    for rule in policy["rules"]:
        findings.extend(_match_rule(rule, family, manifest, matcher_texts,
                                    listener_facts=listener_facts,
                                    covered_listener_facts=specific_wildcard_facts))
    findings.extend(specific_listener_findings)
    if family in {"linux", "macos"}:
        linux_findings, linux_gaps = analyze_linux_baseline(text_by_name)
        findings.extend(linux_findings)
        gaps.extend(linux_gaps)
    requested = {part.strip().casefold() for part in str(target.get("scope", "basic")).split(";") if part.strip()}
    supported = {"basic", "nginx", "tomcat", "redis", "was", "oracle", "mysql"}
    gaps.extend(f"REQUESTED_SCOPE_UNSUPPORTED:{part}" for part in sorted(requested - supported))
    gaps.extend(f"REQUIRED_COMPONENT_EVIDENCE_MISSING:{part}" for part in sorted((requested & supported) - {"basic"} - config_products))
    lifecycle_raw = DEFAULT_LIFECYCLE_POLICY.read_bytes() if DEFAULT_LIFECYCLE_POLICY.is_file() else b""
    lifecycle_digest = hashlib.sha256(lifecycle_raw).hexdigest() if lifecycle_raw else "not_available"
    try:
        lifecycle_version = str(json.loads(lifecycle_raw.decode("utf-8")).get("rules_version", "unknown"))
    except (UnicodeError, json.JSONDecodeError, AttributeError):
        lifecycle_version = "unknown"
    gaps.extend(lifecycle_warnings)
    status = "FAILED" if "OS_LIFECYCLE_POLICY_INVALID_OR_UNAVAILABLE" in lifecycle_warnings or not any(x["status"] == "collected" for x in items) else ("PARTIAL" if gaps else "OK")
    listener_ids = {str(rule.get("id")) for rule in listener_knowledge.get("rules", []) if isinstance(rule, dict)}
    finding_ids = [str(item.get("finding_id") or "") for item in findings]
    if any(finding_ids.count(rule_id) > 1 for rule_id in listener_ids):
        return AnalysisResult(status="FAILED", findings=[],
                              config_evidence={"platform_rules": {"status": "loaded", "rules_version": policy["rules_version"], "sha256": policy_error["sha256"]},
                                               "listener_knowledge": listener_evidence,
                                                "windows_risk_registry": windows_registry_evidence,
                                               "os_lifecycle": {"status": "failed" if "OS_LIFECYCLE_POLICY_INVALID_OR_UNAVAILABLE" in lifecycle_warnings else "loaded",
                                                                "rules_version": lifecycle_version, "sha256": lifecycle_digest}},
                              warnings=list(dict.fromkeys(gaps)), errors=["FINDING_ID_CONFLICT"])
    return AnalysisResult(status=status, findings=findings,
                          config_evidence={"platform_rules": {"status": "loaded", "rules_version": policy["rules_version"], "sha256": policy_error["sha256"]},
                                           "listener_knowledge": listener_evidence,
                                            "windows_risk_registry": windows_registry_evidence,
                                           "os_lifecycle": {"status": "failed" if "OS_LIFECYCLE_POLICY_INVALID_OR_UNAVAILABLE" in lifecycle_warnings else "loaded",
                                                            "rules_version": lifecycle_version, "sha256": lifecycle_digest}},
                          warnings=list(dict.fromkeys(gaps)))


def load_windows_risk_registry(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    digest = "not_available"
    try:
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        registry = json.loads(raw.decode("utf-8"))
        if validate_registry(registry):
            return None, {"status": "failed", "sha256": digest}
        return registry, {"status": "loaded", "rules_version": registry["registry_version"], "sha256": digest}
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        return None, {"status": "failed", "sha256": digest}


def load_platform_policy(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    digest = ""
    try:
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        policy = json.loads(raw.decode("utf-8"))
        if not isinstance(policy, dict) or set(policy) != {"schema_version", "rules_version", "rules"}:
            raise ValueError
        if not isinstance(policy["schema_version"], int) or isinstance(policy["schema_version"], bool) or policy["schema_version"] != 1 or not isinstance(policy["rules_version"], str) or not policy["rules_version"].strip():
            raise ValueError
        rules = policy["rules"]
        if not isinstance(rules, list) or not rules:
            raise ValueError
        identifiers: set[str] = set()
        platforms = {"windows", "linux", "macos"}
        products = {"nginx", "tomcat", "redis", "mysql", "oracle", "was"}
        severities = {"Critical", "Attention", "Warning", "Info"}
        for rule in rules:
            allowed = {"id", "title", "severity", "platforms", "products", "match", "applicability", "impact", "recommendation", "rollback", "verification_checkpoint"}
            if not isinstance(rule, dict) or set(rule) - allowed or not {"id", "title", "severity", "platforms", "match", "applicability", "impact", "recommendation", "rollback", "verification_checkpoint"}.issubset(rule):
                raise ValueError
            rid = rule["id"]
            if not isinstance(rid, str) or not re.fullmatch(r"[A-Z0-9_]{1,80}", rid) or rid in identifiers:
                raise ValueError
            identifiers.add(rid)
            if rule["severity"] not in severities or not isinstance(rule["title"], str) or not rule["title"]:
                raise ValueError
            if not isinstance(rule["platforms"], list) or not rule["platforms"] or any(x not in platforms for x in rule["platforms"]):
                raise ValueError
            if "products" in rule and (not isinstance(rule["products"], list) or not rule["products"] or any(x not in products for x in rule["products"])):
                raise ValueError
            matcher = rule["match"]
            if not isinstance(matcher, dict):
                raise ValueError
            kind = matcher.get("kind")
            if kind == "wildcard_listener":
                if set(matcher) != {"kind"} or "products" in rule:
                    raise ValueError
            elif kind in {"config_value_any", "config_value_contains", "config_value_tokens_any"}:
                if set(matcher) != {"kind", "key", "values"} or not isinstance(matcher["key"], str) or not matcher["key"] or not isinstance(matcher["values"], list) or not matcher["values"] or any(not isinstance(x, str) for x in matcher["values"]) or "products" not in rule:
                    raise ValueError
            else:
                raise ValueError
            for field in ("applicability", "impact", "recommendation", "rollback", "verification_checkpoint"):
                if not isinstance(rule[field], str) or not rule[field].strip():
                    raise ValueError
        return policy, {"status": "loaded", "sha256": digest}
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, KeyError):
        return {}, {"status": "failed", "sha256": digest or "not_available"}


def _unknown(value: Any) -> bool:
    return str(value or "").strip().casefold() in {"", "unknown", "not provided", "not_confirmed", "未确认", "未知"}


def _validate_sanitized_config(value: Any, evidence_filename: str) -> bool:
    fields = {"schema_version", "product", "instance_id", "version", "config_basename", "status", "facts", "limitations"}
    if not isinstance(value, dict) or set(value) != fields or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        return False
    product, instance = value.get("product"), value.get("instance_id")
    if product not in PRODUCT_FILES or not isinstance(instance, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", instance):
        return False
    if evidence_filename.casefold() != f"{product}-{instance}-config.json".casefold():
        return False
    if value.get("status") != "sanitized" or not isinstance(value.get("version"), str) or len(value["version"]) > 100:
        return False
    if not isinstance(value.get("config_basename"), str) or value["config_basename"].casefold() not in {x.casefold() for x in PRODUCT_FILES[product]}:
        return False
    facts, limitations = value.get("facts"), value.get("limitations")
    if not isinstance(facts, list) or len(facts) > 1000 or not isinstance(limitations, list) or len(limitations) > 20 or any(not isinstance(x, str) or len(x) > 300 for x in limitations):
        return False
    xml_fields = {"element", "key", "value", "source"}
    directive_fields = {"key", "value", "line", "source"}
    for fact in facts:
        if not isinstance(fact, dict) or not isinstance(fact.get("value"), str) or len(fact["value"]) > 200 or fact.get("source") != "selected_file":
            return False
        if set(fact) == directive_fields:
            key = fact.get("key")
            if not isinstance(key, str) or key.casefold() not in ALLOW.get(product, set()) or type(fact.get("line")) is not int or fact["line"] < 1:
                return False
            if not _safe_config_value(key.casefold(), fact["value"]):
                return False
        elif set(fact) in (xml_fields - {"key"}, xml_fields):
            element = fact.get("element")
            key = fact.get("key")
            if not isinstance(element, str) or element not in XML_TAGS.get(product, {}):
                return False
            if key is not None and (not isinstance(key, str) or key not in XML_TAGS[product][element] or not _safe_config_value(key.casefold(), fact["value"])):
                return False
            if key is None and fact["value"] != "present_redacted":
                return False
        else:
            return False
    return True


def _safe_config_value(key: str, value: str) -> bool:
    placeholders = {"configured_redacted", "present_redacted", "configured_unparsed", "invalid_or_unparsed",
                    "listener_configured_unparsed", "ipv6_listener_configured"}
    if value in placeholders:
        return True
    if key in {"bind", "bind-address"}:
        parts = value.split()
        if not parts or len(parts) > 8:
            return False
        try:
            return all(part == "*" or ipaddress.ip_address(part.split("%", 1)[0]) for part in parts)
        except ValueError:
            return False
    if key in {"port", "tls-port", "redirectport"}:
        return value.isdigit() and 1 <= int(value) <= 65535
    if key in {"ssl_protocols", "sslenabledprotocols"}:
        allowed = {"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
        tokens = value.replace(",", " ").split()
        return bool(tokens) and all(token in allowed for token in tokens)
    if key in {"client_max_body_size", "maxthreads"}:
        return bool(re.fullmatch(r"[0-9]{1,6}(?:[kKmMgG])?", value))
    if key in {"listen"}:
        return bool(re.fullmatch(r"[0-9]{1,5}(?:\s+ssl)?", value))
    if key == "protocol":
        return value in {"HTTP/1.1", "AJP/1.3", "org.apache.coyote.http11.Http11Protocol",
                         "org.apache.coyote.http11.Http11NioProtocol", "org.apache.coyote.http11.Http11Nio2Protocol",
                         "org.apache.coyote.http11.Http11AprProtocol", "org.apache.coyote.ajp.AjpProtocol",
                         "org.apache.coyote.ajp.AjpNioProtocol", "org.apache.coyote.ajp.AjpNio2Protocol",
                         "org.apache.coyote.ajp.AjpAprProtocol"}
    if key in {"type", "scheme", "name"}:
        return bool(re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", value))
    if key in {"protected-mode", "tls-auth-clients", "skip-networking", "local-infile", "require_secure_transport", "skip_name_resolve", "ssl_prefer_server_ciphers", "ssl_session_tickets", "admin_restrictions", "tcp.validnode_checking", "sslenabled", "secure", "enabled"}:
        return value.casefold() in {"yes", "no", "on", "off", "true", "false", "0", "1", "required", "requested", "accepted", "rejected", "desired"}
    return False


def _match_rule(rule: dict[str, Any], family: str, manifest: dict[str, Any], text_by_name: dict[str, str], *,
                listener_facts: list[dict[str, Any]] | None = None,
                covered_listener_facts: set[tuple[str, int, str]] | None = None) -> list[dict[str, Any]]:
    if family not in rule["platforms"]:
        return []
    matcher = rule["match"]
    results: list[dict[str, Any]] = []
    kind = matcher.get("kind") if isinstance(matcher, dict) else None
    if kind == "wildcard_listener":
        listener_sources = [(name, value) for name, value in text_by_name.items()
                            if Path(name).name.casefold() == "listeners.txt"]
        if listener_facts is None:
            listeners = "\n".join(value for _, value in listener_sources)
            lines = _wildcard_listeners(listeners)
        else:
            covered = covered_listener_facts if rule.get("severity") == "Info" else None
            lines = _wildcard_listeners("", facts=listener_facts, covered_facts=covered)
        if lines:
            visible_lines = lines[:20]
            sources = list(dict.fromkeys(line["source"] for line in visible_lines if line.get("source")))
            results.append(_finding(rule, "general", {"sources": sources, "lines": visible_lines}, None))
    elif kind in {"config_value_any", "config_value_contains", "config_value_tokens_any"}:
        for path, content in text_by_name.items():
            filename = Path(path).name
            if not filename.endswith("-config.json"):
                continue
            try:
                config = json.loads(content)
            except json.JSONDecodeError:
                continue
            if not isinstance(config, dict):
                continue
            product = str(config.get("product", "")).casefold()
            if product not in rule.get("products", []) or not isinstance(config.get("facts"), list):
                continue
            matches = []
            for fact in config["facts"]:
                if not isinstance(fact, dict) or str(fact.get("key", "")).casefold() != str(matcher.get("key", "")).casefold():
                    continue
                value = str(fact.get("value", "")).casefold()
                expected = [str(x).casefold() for x in matcher.get("values", [])]
                tokens = {x for x in re.split(r"[\s,]+", value) if x}
                if ((kind == "config_value_any" and value in expected)
                        or (kind == "config_value_contains" and any(x in value for x in expected))
                        or (kind == "config_value_tokens_any" and bool(tokens & set(expected)))):
                    matches.append(fact)
            if matches:
                evidence = {"source": filename, "facts": matches[:20], "instance_id": config.get("instance_id", "unknown")}
                results.append(_finding(rule, product, evidence, config.get("version")))
    return results


def _finding(rule: dict[str, Any], product: str, evidence: dict[str, Any], product_version: Any) -> dict[str, Any]:
    instance = evidence.get("instance_id")
    suffix = f"@{instance}" if instance else ""
    applicability = str(rule["applicability"])
    if product_version and not _unknown(product_version):
        applicability += f"；配置声明版本：{str(product_version)[:100]}（尚未独立核实）"
    else:
        applicability += "；组件准确版本未核实"
    return {"finding_id": f"{rule['id']}{suffix}", "rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"], "category": product or "general",
            "component": product, "description": "Deterministic rule matched only explicit collected evidence; applicability remains version-bound.",
            "evidence": evidence, "applicability": applicability, "impact": rule["impact"],
            "recommendation": rule["recommendation"], "rollback": rule["rollback"],
            "verification_checkpoint": rule["verification_checkpoint"], "needs_human_review": True, "auto_fix": "否"}


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="strict")
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le", errors="strict")
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be", errors="strict")
    return data.decode("utf-8", errors="strict")


def _wildcard_listeners(text: str, *, facts: list[dict[str, Any]] | None = None,
                        covered_facts: set[tuple[str, int, str]] | None = None) -> list[dict[str, str]]:
    if facts is None:
        from analyzers.listener_risk import parse_listener_text
        facts, _gaps = parse_listener_text(text)
    visible = []
    for fact in facts:
        if fact.get("protocol") != "tcp" or fact.get("scope") != "wildcard":
            continue
        key = (fact.get("protocol"), fact.get("port"), fact.get("address"))
        if covered_facts is not None and key in covered_facts:
            continue
        visible.append({"protocol": str(fact["protocol"]), "local_bind": f"{fact['address']}:{fact['port']}",
                        "state": "listening", "source": str(fact.get("source", "unknown"))})
        if len(visible) >= 100:
            break
    return visible


MAX_TEXT = 8 * 1024 * 1024
