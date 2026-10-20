from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.listener_risk import (  # noqa: E402
    DEFAULT_KNOWLEDGE,
    MAX_LISTENER_INPUT_LINES,
    MAX_LISTENER_ROWS,
    MAX_LISTENER_TEXT_CHARS,
    ListenerKnowledgeError,
    analyze_facts,
    load_knowledge,
    normalize_collector_rows,
    parse_listener_text,
)


def _ids(findings: list[dict]) -> list[str]:
    return sorted(item["finding_id"] for item in findings)


def test_windows_linux_netstat_and_ss_have_same_shared_findings() -> None:
    samples = [
        "TCP 0.0.0.0:2375 0.0.0.0:0 LISTENING 42\r\nTCP [::]:2375 [::]:0 LISTENING 42\r\n",
        "tcp 0 128 0.0.0.0:2375 0.0.0.0:* LISTEN 123/dockerd\ntcp6 0 128 :::2375 :::* LISTEN 123/dockerd\n",
        "LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:((\"dockerd\",pid=42,fd=3))\nLISTEN 0 4096 [::]:2375 [::]:* users:((\"dockerd\",pid=42,fd=4))\n",
        "tcp LISTEN 0 128 0.0.0.0:2375 0.0.0.0:* users:((dockerd,pid=123,fd=1))\ntcp LISTEN 0 128 [::]:2375 [::]:* users:((dockerd,pid=123,fd=2))\n",
    ]
    knowledge, _ = load_knowledge(DEFAULT_KNOWLEDGE)
    outputs = []
    for sample in samples:
        facts, gaps = parse_listener_text(sample)
        assert not gaps, gaps
        outputs.append(analyze_facts(facts, knowledge))
    assert _ids(outputs[0]) == ["LISTENER_TCP_2375_REVIEW"]
    assert outputs[0] == outputs[1] == outputs[2] == outputs[3]
    assert len(outputs[0]) == 1
    assert outputs[0][0]["severity"] == "Attention"
    assert "不能确认 Docker" in outputs[0][0]["impact"]


def test_loopback_and_ipv4_mapped_loopback_do_not_match() -> None:
    sample = "TCP 127.0.0.1:2375 0.0.0.0:0 LISTENING 42\nTCP [::1]:2375 [::]:0 LISTENING 42\nTCP [::ffff:127.0.0.1]:2375 [::]:0 LISTENING 42\n"
    facts, gaps = parse_listener_text(sample)
    knowledge, _ = load_knowledge()
    assert not gaps, gaps
    assert len(facts) == 3
    assert all(item["scope"] == "loopback" for item in facts)
    assert analyze_facts(facts, knowledge) == []


def test_private_addresses_and_supported_udp_are_scoped_to_known_rules() -> None:
    sample = "TCP 10.4.2.7:6379 0.0.0.0:0 LISTENING 7\nUDP 0.0.0.0:11211 *:* 7\nUDP 10.0.0.2:9999 *:* 7\n"
    facts, gaps = parse_listener_text(sample)
    knowledge, _ = load_knowledge()
    findings = analyze_facts(facts, knowledge)
    assert not gaps, gaps
    assert _ids(findings) == ["LISTENER_TCP_6379_REVIEW", "LISTENER_TCP_UDP_11211_REVIEW"]
    assert all("9999" not in json.dumps(item) for item in findings)


def test_unknown_rows_and_bad_ports_remain_gaps() -> None:
    facts, gaps = parse_listener_text("nonsense listener output\nTCP *:not-a-port *:* LISTENING 1\n")
    assert facts == []
    assert "LISTENER_LINE_UNRECOGNIZED" in gaps
    assert "LISTENER_PORT_INVALID_OR_UNKNOWN" in gaps
    local_facts, local_gaps = normalize_collector_rows([{"LocalAddress": "0.0.0.0", "LocalPort": True}])
    assert local_facts == []
    assert local_gaps == ["LISTENER_PORT_INVALID_OR_UNKNOWN"]


def test_posix_netstat_skips_known_irrelevant_rows_but_unknown_states_are_gaps() -> None:
    sample = ("Active Internet connections (servers and established)\n"
              "Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n"
              "tcp 0 0 10.0.0.2:6379 0.0.0.0:* ESTABLISHED 12/redis\n"
              "udp 0 0 0.0.0.0:11211 0.0.0.0:* 13/memcached\n"
              "raw 0 0 0.0.0.0:9000 0.0.0.0:* 0/\n"
              "unix 2 [ ACC ] STREAM LISTENING 55 /run/example.sock\n"
              "tcp 0 0 10.0.0.2:23 0.0.0.0:* MYSTERY 4/process\n")
    facts, gaps = parse_listener_text(sample)
    assert [(fact["protocol"], fact["port"]) for fact in facts] == [("udp", 11211)]
    assert gaps == ["LISTENER_STATE_UNKNOWN"]


def test_busy_text_and_rows_scan_past_nonlisteners_to_tail_facts() -> None:
    knowledge, _ = load_knowledge()
    windows = "".join("TCP 10.0.0.2:40000 10.0.0.3:443 ESTABLISHED 12\n" for _ in range(1500))
    windows += "TCP [2001:db8::5]:2375 [::]:0 LISTENING 13\nUDP 10.0.0.4:11211 *:* 14\n"
    facts, gaps = parse_listener_text(windows)
    assert [(fact["protocol"], fact["port"]) for fact in facts] == [("tcp", 2375), ("udp", 11211)]
    assert not gaps, gaps
    assert _ids(analyze_facts(facts, knowledge)) == ["LISTENER_TCP_2375_REVIEW", "LISTENER_TCP_UDP_11211_REVIEW"]

    linux = "".join("tcp 0 0 10.0.0.2:40000 10.0.0.3:443 ESTABLISHED 12/client\n" for _ in range(1500))
    linux += "tcp6 0 128 2001:db8::5:2375 :::* LISTEN 13/service\n"
    facts, gaps = parse_listener_text(linux)
    assert [(fact["protocol"], fact["port"]) for fact in facts] == [("tcp", 2375)]
    assert not gaps, gaps
    assert _ids(analyze_facts(facts, knowledge)) == ["LISTENER_TCP_2375_REVIEW"]

    rows = [{"Protocol": "tcp", "State": "established", "LocalAddress": "10.0.0.2", "LocalPort": 40000}
            for _ in range(1500)]
    rows.extend([{"Protocol": "tcp", "State": "listen", "LocalAddress": "2001:db8::5", "LocalPort": 2375},
                 {"Protocol": "udp", "State": "unconn", "LocalAddress": "10.0.0.4", "LocalPort": 11211}])
    facts, gaps = normalize_collector_rows(rows)
    assert [(fact["protocol"], fact["port"]) for fact in facts] == [("tcp", 2375), ("udp", 11211)]
    assert not gaps, gaps
    assert _ids(analyze_facts(facts, knowledge)) == ["LISTENER_TCP_2375_REVIEW", "LISTENER_TCP_UDP_11211_REVIEW"]


def test_listener_budgets_count_effective_facts_and_bound_input() -> None:
    prefix = "TCP 0.0.0.0:2375 0.0.0.0:0 LISTENING 1\n"
    busy = "".join("TCP 10.0.0.2:40000 10.0.0.3:443 ESTABLISHED 12\n" for _ in range(MAX_LISTENER_INPUT_LINES - 1))
    facts, gaps = parse_listener_text(busy + prefix)
    assert [fact["port"] for fact in facts] == [2375]
    assert not gaps, gaps

    too_many = "".join(prefix for _ in range(1001))
    facts, gaps = parse_listener_text(too_many)
    assert len(facts) == 1000
    assert "LISTENER_EVIDENCE_TRUNCATED" in gaps

    rows = [{"LocalAddress": "10.0.0.2", "LocalPort": 40000, "State": "established"}
            for _ in range(1500)]
    rows.append({"LocalAddress": "0.0.0.0", "LocalPort": 2375})
    facts, gaps = normalize_collector_rows(rows)
    assert [fact["port"] for fact in facts] == [2375]
    assert not gaps, gaps

    bounded_rows = [{"LocalAddress": "10.0.0.2", "LocalPort": 40000, "State": "established"}
                    for _ in range(MAX_LISTENER_ROWS)]
    bounded_rows.append({"LocalAddress": "0.0.0.0", "LocalPort": 2375})
    facts, gaps = normalize_collector_rows(bounded_rows)
    assert facts == []
    assert "LISTENER_EVIDENCE_TRUNCATED" in gaps

    clipped = prefix + "x" * MAX_LISTENER_TEXT_CHARS
    facts, gaps = parse_listener_text(clipped)
    assert [fact["port"] for fact in facts] == [2375]
    assert "LISTENER_EVIDENCE_TRUNCATED" in gaps

    line_limited = "\n".join("tcp 0 0 10.0.0.2:40000 10.0.0.3:443 ESTABLISHED 12/client"
                              for _ in range(MAX_LISTENER_INPUT_LINES + 1))
    facts, gaps = parse_listener_text(line_limited)
    assert facts == []
    assert "LISTENER_EVIDENCE_TRUNCATED" in gaps


def test_macos_netstat_numeric_dot_endpoints_are_strict() -> None:
    # Format references: Apple netstat inet.c and inet6.c numeric endpoint output.
    # https://raw.githubusercontent.com/apple-oss-distributions/network_cmds/main/netstat.tproj/inet.c
    # https://raw.githubusercontent.com/apple-oss-distributions/network_cmds/main/netstat.tproj/inet6.c
    sample = ("tcp4 0 0 *.2375 *.* LISTEN\n"
              "tcp46 0 0 *.2376 *.* LISTEN\n"
              "tcp6 0 0 ::.2375 *.* LISTEN\n"
              "tcp6 0 0 ::1.2375 *.* LISTEN\n"
              "tcp4 0 0 192.168.1.20.6379 *.* LISTEN\n"
              "udp4 0 0 *.11211 *.*\n"
              "tcp6 0 0 *.70000 *.* LISTEN\n"
              "tcp6 0 0 *.not-a-port *.* LISTEN\n")
    facts, gaps = parse_listener_text(sample)
    assert [(fact["protocol"], fact["address"], fact["port"], fact["scope"])
            for fact in facts] == [
                ("tcp", "*", 2375, "wildcard"), ("tcp", "*", 2376, "wildcard"),
                ("tcp", "::", 2375, "wildcard"),
                ("tcp", "::1", 2375, "loopback"), ("tcp", "192.168.1.20", 6379, "private"),
                ("udp", "*", 11211, "wildcard")]
    assert "LISTENER_PORT_INVALID_OR_UNKNOWN" in gaps


def test_collector_port_types_are_strict_and_valid_rows_survive() -> None:
    values = [2375.5, -1, True, [], {}, "2375.5", "-1"]
    rows = [{"LocalAddress": "0.0.0.0", "LocalPort": value} for value in values]
    rows.append({"LocalAddress": "0.0.0.0", "LocalPort": 6379})
    facts, gaps = normalize_collector_rows(rows)
    assert [fact["port"] for fact in facts] == [6379]
    assert "LISTENER_PORT_INVALID_OR_UNKNOWN" in gaps


def test_invalid_and_duplicate_key_knowledge_fails_closed() -> None:
    value = json.loads(DEFAULT_KNOWLEDGE.read_text(encoding="utf-8"))
    value["rules"][0]["port"] = True
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "bad.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        try:
            load_knowledge(path)
        except ListenerKnowledgeError as exc:
            assert "RULE_INVALID" in str(exc)
        else:
            raise AssertionError("invalid boolean port was accepted")
        path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        try:
            load_knowledge(path)
        except ListenerKnowledgeError as exc:
            assert "DUPLICATE_JSON_KEY" in str(exc)
        else:
            raise AssertionError("duplicate JSON key was accepted")

        value = json.loads(DEFAULT_KNOWLEDGE.read_text(encoding="utf-8"))
        for malformed in (
            {"protocols": [{}]}, {"severity": []},
        ):
            path.write_text(json.dumps(value | {"rules": [value["rules"][0] | malformed]}), encoding="utf-8")
            try:
                load_knowledge(path)
            except ListenerKnowledgeError:
                pass
            else:
                raise AssertionError("malformed knowledge member was accepted")

        unsupported = value | {"schema_version": 2}
        path.write_text(json.dumps(unsupported), encoding="utf-8")
        try:
            load_knowledge(path)
        except ListenerKnowledgeError as exc:
            assert exc.reason_code == "LISTENER_KNOWLEDGE_SCHEMA_UNSUPPORTED"
        else:
            raise AssertionError("unsupported schema was accepted")

        path.write_text(json.dumps(value | {"rules": [value["rules"][0] | {"id": "WIN_RDP_EXPOSED_REVIEW"}]}), encoding="utf-8")
        try:
            load_knowledge(path)
        except ListenerKnowledgeError:
            pass
        else:
            raise AssertionError("un-namespaced finding id was accepted")


def test_deep_and_oversized_integer_json_fail_with_bounded_error() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "adversarial.json"
        path.write_text('{"nested":' + "[" * 20000 + "0" + "]" * 20000 + "}", encoding="ascii")
        try:
            load_knowledge(path)
        except ListenerKnowledgeError as exc:
            assert exc.reason_code == "LISTENER_KNOWLEDGE_JSON_RESOURCE_LIMIT"
        else:
            raise AssertionError("deep JSON was accepted")

        path.write_text('{"schema_version":' + "9" * 5000 + ',"rules_version":"x","rules":[]}', encoding="ascii")
        try:
            load_knowledge(path)
        except ListenerKnowledgeError as exc:
            assert exc.reason_code in {"LISTENER_KNOWLEDGE_JSON_RESOURCE_LIMIT", "LISTENER_KNOWLEDGE_SCHEMA_UNSUPPORTED"}
        else:
            raise AssertionError("oversized JSON integer was accepted")


if __name__ == "__main__":
    test_windows_linux_netstat_and_ss_have_same_shared_findings()
    test_loopback_and_ipv4_mapped_loopback_do_not_match()
    test_private_addresses_and_supported_udp_are_scoped_to_known_rules()
    test_unknown_rows_and_bad_ports_remain_gaps()
    test_posix_netstat_skips_known_irrelevant_rows_but_unknown_states_are_gaps()
    test_busy_text_and_rows_scan_past_nonlisteners_to_tail_facts()
    test_listener_budgets_count_effective_facts_and_bound_input()
    test_macos_netstat_numeric_dot_endpoints_are_strict()
    test_collector_port_types_are_strict_and_valid_rows_survive()
    test_invalid_and_duplicate_key_knowledge_fails_closed()
    test_deep_and_oversized_integer_json_fail_with_bounded_error()
    print("Listener risk tests passed.")
