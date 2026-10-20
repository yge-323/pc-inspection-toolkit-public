from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any


DEFAULT_KNOWLEDGE = Path(__file__).resolve().parents[1] / "rules" / "listener_knowledge.example.json"
MAX_LISTENER_LINES = 1000
MAX_LISTENER_INPUT_LINES = 100_000
MAX_LISTENER_TEXT_CHARS = 8 * 1024 * 1024
MAX_LISTENER_ROWS = 100_000
MAX_KNOWLEDGE_BYTES = 256 * 1024


class ListenerKnowledgeError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def load_knowledge(path: Path = DEFAULT_KNOWLEDGE) -> tuple[dict[str, Any], dict[str, str]]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_KNOWLEDGE_BYTES + 1)
    if len(raw) > MAX_KNOWLEDGE_BYTES:
        raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_TOO_LARGE")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except ListenerKnowledgeError:
        raise
    except UnicodeError as exc:
        raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_ENCODING_INVALID") from exc
    except json.JSONDecodeError as exc:
        raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_JSON_INVALID") from exc
    except (RecursionError, ValueError, OverflowError, MemoryError) as exc:
        raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_JSON_RESOURCE_LIMIT") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "rules_version", "rules"}:
        raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_SCHEMA_INVALID")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_SCHEMA_UNSUPPORTED")
    if (not isinstance(value.get("rules_version"), str) or not value["rules_version"].strip()
            or not isinstance(value.get("rules"), list) or not value["rules"]):
        raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_SCHEMA_INVALID")
    ids: set[str] = set()
    seen: set[tuple[int, str]] = set()
    required = {"id", "port", "protocols", "title", "severity", "impact", "recommendation", "rollback", "verification_checkpoint", "source"}
    for rule in value["rules"]:
        if not isinstance(rule, dict) or set(rule) != required:
            raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_RULE_INVALID")
        if (not isinstance(rule["id"], str) or not rule["id"].startswith("LISTENER_")
                or not re.fullmatch(r"[A-Z0-9_]{1,80}", rule["id"])
                or rule["id"] in ids or type(rule["port"]) is not int or not 1 <= rule["port"] <= 65535
                or not isinstance(rule["severity"], str) or rule["severity"] not in {"Attention", "Warning", "Info"}
                or not isinstance(rule["protocols"], list) or not rule["protocols"]
                or any(not isinstance(proto, str) or proto not in {"tcp", "udp"} for proto in rule["protocols"])
                or len(set(rule["protocols"])) != len(rule["protocols"])
                or not all(isinstance(rule[key], str) and rule[key].strip() for key in ("title", "impact", "recommendation", "rollback", "verification_checkpoint", "source"))):
                raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_RULE_INVALID")
        for proto in rule["protocols"]:
            key = (rule["port"], proto)
            if key in seen:
                raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_PORT_PROTOCOL_DUPLICATE")
            seen.add(key)
        ids.add(rule["id"])
    return value, {"status": "loaded", "rules_version": value["rules_version"], "sha256": digest}


def parse_listener_text(text: str, *, source: str = "listeners.txt") -> tuple[list[dict[str, Any]], list[str]]:
    facts: list[dict[str, Any]] = []
    gaps: list[str] = []
    if not isinstance(text, str):
        return [], ["LISTENER_FACTS_MISSING_OR_UNKNOWN"]
    char_limited = len(text) > MAX_LISTENER_TEXT_CHARS
    scan_text = text[:MAX_LISTENER_TEXT_CHARS] if char_limited else text
    if char_limited:
        # A character cap may land inside a row. Only process rows terminated
        # within the cap; never turn a clipped endpoint into a listener fact.
        last_newline = scan_text.rfind("\n")
        scan_text = scan_text[:last_newline + 1] if last_newline >= 0 else ""
        gaps.append("LISTENER_EVIDENCE_TRUNCATED")
    index = 0
    start = 0
    while start < len(scan_text):
        end = scan_text.find("\n", start)
        if end < 0:
            line = scan_text[start:]
            start = len(scan_text)
        else:
            line = scan_text[start:end].removesuffix("\r")
            start = end + 1
        index += 1
        if index > MAX_LISTENER_INPUT_LINES:
            gaps.append("LISTENER_EVIDENCE_TRUNCATED")
            break
        fields = line.split()
        if not fields:
            continue
        proto = fields[0].casefold()
        if proto.startswith("collector_status="):
            if proto != "collector_status=ok":
                gaps.append("LISTENER_COLLECTOR_STATUS_UNKNOWN")
            continue
        if proto in {"proto", "protocol", "active", "netid", "state", "协议", "协议类型", "活动连接"}:
            continue
        if line.casefold().startswith(("there are no entries", "no entries", "没有项目")):
            gaps.append("LISTENER_EVIDENCE_EMPTY_CONFIRMED")
            continue
        if proto in {"no_listeners", "listeners=0", "listener_count=0", "监听数量=0"}:
            gaps.append("LISTENER_EVIDENCE_EMPTY_CONFIRMED")
            continue
        if proto in {"raw", "raw4", "raw6", "unix", "unix_stream", "unix_dgram", "unix_seqpacket", "icmp", "icmp6"}:
            continue
        if line.casefold().startswith(("active internet connections", "active unix domain sockets", "proto recv-q", "netid state")):
            continue
        ss_state_only = proto in {"listen", "unconn"}
        is_ss_netid = proto in {"tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"} and len(fields) > 1 and fields[1].casefold() in {"listen", "unconn"}
        is_transport = proto in {"tcp", "tcp4", "tcp6", "tcp46", "udp", "udp4", "udp6", "udp46"}
        if not ss_state_only and not is_transport:
            gaps.append("LISTENER_LINE_UNRECOGNIZED")
            continue
        protocol = "udp" if proto.startswith("udp") or proto == "unconn" else "tcp"
        endpoint: str | None = None
        state = "unknown"
        # ss without -t/-u emits state first; with a netid it emits proto then state.
        if ss_state_only and len(fields) >= 5:
            endpoint = fields[3]
            state = proto
        elif is_ss_netid and len(fields) >= 6:
            endpoint = fields[4]
            state = fields[1].casefold()
        elif protocol == "udp" and len(fields) >= 4 and _looks_like_endpoint(fields[1]):
            # Windows netstat -ano: UDP Local Foreign PID.
            endpoint = fields[1]
            state = "udp"
        elif protocol == "udp" and len(fields) >= 5 and fields[1].isdigit() and fields[2].isdigit() and _looks_like_endpoint(fields[3]):
            # POSIX netstat -an: udp Recv-Q Send-Q Local Foreign.
            endpoint = fields[3]
            state = "udp"
        elif protocol == "tcp" and len(fields) >= 4 and _looks_like_endpoint(fields[1]):
            # Windows netstat -ano: TCP Local Foreign State PID.
            endpoint = fields[1]
            state = _first_listener_state(fields[2:])
        elif protocol == "tcp" and len(fields) >= 6 and fields[1].isdigit() and fields[2].isdigit() and _looks_like_endpoint(fields[3]):
            # POSIX netstat -an may append PID/Program after its state.
            endpoint = fields[3]
            state = _first_listener_state(fields[5:])
        elif is_transport:
            gaps.append("LISTENER_ENDPOINT_INVALID_OR_UNKNOWN")
        if endpoint is None:
            if state == "unknown":
                gaps.append("LISTENER_ENDPOINT_INVALID_OR_UNKNOWN")
            continue
        if protocol == "tcp" and state not in {"listen", "listening"}:
            if state == "unknown":
                gaps.append("LISTENER_STATE_UNKNOWN")
            continue
        fact, error = _endpoint_fact(endpoint, protocol, source, index, line)
        if error:
            gaps.append(error)
        elif fact:
            if len(facts) < MAX_LISTENER_LINES:
                facts.append(fact)
            else:
                gaps.append("LISTENER_EVIDENCE_TRUNCATED")
                break
    return facts, list(dict.fromkeys(gaps))


def normalize_collector_rows(rows: Any) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(rows, list):
        return [], ["LISTENER_FACTS_MISSING_OR_UNKNOWN"]
    facts: list[dict[str, Any]] = []
    gaps: list[str] = []
    scan_count = min(len(rows), MAX_LISTENER_ROWS)
    for index in range(scan_count):
        row = rows[index]
        line_no = index + 1
        if not isinstance(row, dict):
            gaps.append("LISTENER_FACTS_INVALID")
            continue
        raw_protocol = row.get("Protocol", row.get("protocol", "tcp"))
        if not isinstance(raw_protocol, str):
            gaps.append("LISTENER_PROTOCOL_UNKNOWN")
            continue
        protocol = raw_protocol.casefold()
        if protocol not in {"tcp", "udp"}:
            gaps.append("LISTENER_PROTOCOL_UNKNOWN")
            continue
        raw_state = row.get("State", row.get("state", "listen"))
        if not isinstance(raw_state, str):
            gaps.append("LISTENER_STATE_UNKNOWN")
            continue
        state = raw_state.casefold()
        if protocol == "tcp" and state not in {"listen", "listening"}:
            if state in {"established", "syn_sent", "syn_received", "fin_wait_1", "fin_wait_2", "time_wait", "close", "close_wait", "last_ack", "closing", "delete_tcb"}:
                continue
            gaps.append("LISTENER_STATE_UNKNOWN")
            continue
        address = row.get("LocalAddress", row.get("local_address", row.get("address")))
        port = row.get("LocalPort", row.get("local_port", row.get("port")))
        if isinstance(port, bool):
            gaps.append("LISTENER_PORT_INVALID_OR_UNKNOWN")
            continue
        if type(port) is int:
            number = port
        elif isinstance(port, str) and re.fullmatch(r"[0-9]{1,5}", port.strip()):
            number = int(port.strip())
        else:
            gaps.append("LISTENER_PORT_INVALID_OR_UNKNOWN")
            continue
        if not 1 <= number <= 65535 or not isinstance(address, str) or not address.strip():
            gaps.append("LISTENER_ENDPOINT_INVALID_OR_UNKNOWN")
            continue
        fact = _address_fact(address, number, protocol)
        if not fact:
            gaps.append("LISTENER_ADDRESS_INVALID_OR_UNKNOWN")
            continue
        process = row.get("ProcessName", row.get("process", "unknown"))
        if not isinstance(process, str):
            gaps.append("LISTENER_PROCESS_UNKNOWN")
            process = "unknown"
        fact.update({"source": "network_ports", "line": line_no, "process": process[:100]})
        if len(facts) < MAX_LISTENER_LINES:
            facts.append(fact)
        else:
            gaps.append("LISTENER_EVIDENCE_TRUNCATED")
            break
    if len(rows) > MAX_LISTENER_ROWS:
        gaps.append("LISTENER_EVIDENCE_TRUNCATED")
    return facts, list(dict.fromkeys(gaps))


def analyze_facts(facts: list[dict[str, Any]], knowledge: dict[str, Any]) -> list[dict[str, Any]]:
    rules = {(rule["port"], proto): rule for rule in knowledge["rules"] for proto in rule["protocols"]}
    grouped: dict[tuple[str, int], dict[str, Any]] = {}
    for fact in facts:
        if fact.get("scope") == "loopback":
            continue
        rule = rules.get((fact.get("port"), fact.get("protocol")))
        if not rule:
            continue
        key = (rule["id"], rule["port"])
        row = grouped.setdefault(key, {"rule": rule, "addresses": [], "protocols": [], "processes": [], "sources": []})
        for field, value in (("addresses", fact.get("address")), ("protocols", fact.get("protocol")),
                             ("processes", fact.get("process")), ("sources", fact.get("source"))):
            if value and value not in row[field]:
                row[field].append(value)
    findings = []
    for (rule_id, port), item in sorted(grouped.items()):
        rule = item["rule"]
        findings.append({
            "finding_id": rule_id, "rule_id": rule_id, "title": rule["title"], "severity": rule["severity"],
            "category": "network", "component": "listeners", "description": "仅表示采集到该端口在非回环地址监听；端口不能确认实际服务、认证、网络可达性或权限。",
            "evidence": {"port": port, "protocols": item["protocols"], "addresses": item["addresses"], "processes": item["processes"], "sources": item["sources"]},
            "applicability": f"候选端口规则 {knowledge['rules_version']}；需核实实际服务及版本。",
            "impact": rule["impact"], "recommendation": rule["recommendation"], "rollback": rule["rollback"],
            "verification_checkpoint": rule["verification_checkpoint"], "needs_human_review": True, "auto_fix": "否",
        })
    return findings


def _endpoint_fact(endpoint: str, protocol: str, source: str, line_no: int, raw: str) -> tuple[dict[str, Any] | None, str | None]:
    value = endpoint.strip()
    if value.startswith("[") and "]:" in value:
        address, port_text = value[1:].rsplit("]:", 1)
    elif "." in value and re.fullmatch(r"[0-9]{1,5}", value.rsplit(".", 1)[1]):
        # macOS netstat prints numeric endpoints with a dot before the port,
        # including IPv4/IPv6 addresses and wildcard `*.port`.
        address, port_text = value.rsplit(".", 1)
    elif ":" in value:
        address, port_text = value.rsplit(":", 1)
    else:
        return None, "LISTENER_ENDPOINT_INVALID_OR_UNKNOWN"
    if not re.fullmatch(r"[0-9]{1,5}", port_text):
        return None, "LISTENER_PORT_INVALID_OR_UNKNOWN"
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None, "LISTENER_PORT_INVALID_OR_UNKNOWN"
    fact = _address_fact(address, port, protocol)
    if not fact:
        return None, "LISTENER_ADDRESS_INVALID_OR_UNKNOWN"
    fact.update({"source": source, "line": line_no, "raw": raw[:300], "process": "unknown"})
    return fact, None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ListenerKnowledgeError("LISTENER_KNOWLEDGE_DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def _looks_like_endpoint(value: str) -> bool:
    if ":" in value and not value.endswith((":*", ":0")):
        return True
    if "." in value:
        address, _, port = value.rpartition(".")
        return bool(re.fullmatch(r"[0-9]{1,5}", port)) and (address == "*" or _valid_ip_address(address))
    return False


def _valid_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
        return True
    except ValueError:
        return False


def _first_listener_state(fields: list[str]) -> str:
    known = {"listen", "listening", "established", "syn_sent", "syn_received", "fin_wait_1", "fin_wait_2",
             "time_wait", "close", "close_wait", "last_ack", "closing", "delete_tcb"}
    return next((item.casefold() for item in fields if item.casefold() in known), "unknown")


def listener_knowledge_error_reason(exc: BaseException) -> str:
    if isinstance(exc, ListenerKnowledgeError):
        return exc.reason_code
    if isinstance(exc, FileNotFoundError):
        return "LISTENER_KNOWLEDGE_MISSING"
    if isinstance(exc, json.JSONDecodeError):
        return "LISTENER_KNOWLEDGE_JSON_INVALID"
    if isinstance(exc, UnicodeError):
        return "LISTENER_KNOWLEDGE_ENCODING_INVALID"
    if isinstance(exc, OSError):
        return "LISTENER_KNOWLEDGE_UNAVAILABLE"
    return "LISTENER_KNOWLEDGE_INVALID"


def _address_fact(address: str, port: int, protocol: str) -> dict[str, Any] | None:
    value = address.strip().strip("[]")
    if value in {"*", "0.0.0.0", "::", ":::"}:
        normalized, scope = value, "wildcard"
    else:
        try:
            parsed = ipaddress.ip_address(value.split("%", 1)[0])
        except ValueError:
            return None
        normalized = str(parsed)
        mapped = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
        scope = "loopback" if parsed.is_loopback or (mapped is not None and mapped.is_loopback) else "private" if parsed.is_private else "nonloopback"
    return {"protocol": protocol, "address": normalized, "port": port, "scope": scope}
