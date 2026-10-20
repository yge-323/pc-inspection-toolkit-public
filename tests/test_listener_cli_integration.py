from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import run_inspection  # noqa: E402
import inspection_cli  # noqa: E402
from inspection_cli import main  # noqa: E402


def _invoke(argv: list[str]) -> tuple[int, str]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = main(argv)
    return status, output.getvalue()


def _artifacts(stdout: str) -> dict[str, Path]:
    return {line.split("=", 1)[0].lower(): Path(line.split("=", 1)[1])
            for line in stdout.splitlines() if "=" in line and line.split("=", 1)[0].lower() in {"md", "html", "csv", "json"}}


def test_cli_evidence_and_injected_local_pipeline_share_listener_finding_and_bind_knowledge() -> None:
    (ROOT / "work").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="listener-cli-", dir=ROOT / "work") as temporary:
        base = Path(temporary)
        source = base / "native"
        source.mkdir()
        target = {"os_family": "linux", "product": "Linux fixture", "version": "unknown", "architecture": "x86_64", "use_case": "server", "scope": "basic"}
        collection = {"started_at": "2026-10-11T00:00:00+00:00", "finished_at": "2026-10-11T00:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "fixture", "command_catalog": "synthetic"}
        files = {
            "os.txt": "Linux fixture\n", "os_release.txt": "NAME=Linux fixture\n", "architecture.txt": "x86_64\n",
            "cpu_count.txt": "4\n", "memory_summary.txt": "MemTotal_kB=4096\n", "graphics_summary.txt": "synthetic fixture\n",
            "disks.txt": "synthetic fixture\n", "services.txt": "synthetic fixture\n",
            "listeners.txt": ("TCP 10.0.0.2:40000 10.0.0.3:443 ESTABLISHED 40\n" * 1500
                              + "TCP 0.0.0.0:2375 0.0.0.0:0 LISTENING 40\n" * 120
                              + "TCP 0.0.0.0:2375 0.0.0.0:0 LISTENING 41\n"
                              + "TCP [::]:2375 [::]:0 LISTENING 42\n"
                              + "TCP 0.0.0.0:11211 0.0.0.0:0 LISTENING 43\n"
                              + "UDP 0.0.0.0:11211 *:* 43\n"),
            "firewall.txt": "synthetic fixture\n", "privilege.txt": "synthetic fixture\n",
            "accounts.txt": "synthetic fixture\n", "startup_items.txt": "synthetic fixture\n",
            "security_status.txt": "synthetic fixture\n",
        }
        for name, value in files.items():
            (source / name).write_text(value, encoding="utf-8")
            (source / f"{Path(name).stem}.exit-code.txt").write_text("0\n", encoding="ascii")
        nested_listener = source / "nested" / "listeners.txt"
        nested_listener.parent.mkdir()
        nested_listener.write_text("TCP 10.2.0.5:6379 0.0.0.0:0 LISTENING 52\n", encoding="utf-8")
        (nested_listener.parent / "listeners.exit-code.txt").write_text("0\n", encoding="ascii")
        for nested_name in ("nested-a", "nested-b"):
            extra_dir = source / nested_name
            extra_dir.mkdir()
            extra_lines = "TCP 0.0.0.0:2375 0.0.0.0:0 LISTENING 53\n" * 120
            extra_lines += "TCP 0.0.0.0:8443 0.0.0.0:0 LISTENING 54\n"
            (extra_dir / "listeners.txt").write_text(extra_lines, encoding="utf-8")
            (extra_dir / "listeners.exit-code.txt").write_text("0\n", encoding="ascii")
        limited_dir = source / "nested-c"
        limited_dir.mkdir()
        limited_lines = "".join(f"TCP 0.0.0.0:{port} 0.0.0.0:0 LISTENING 55\n" for port in range(8000, 8025))
        (limited_dir / "listeners.txt").write_text(limited_lines, encoding="utf-8")
        (limited_dir / "listeners.exit-code.txt").write_text("0\n", encoding="ascii")
        target_path, collection_path = base / "target.json", base / "collection.json"
        target_path.write_text(json.dumps(target), encoding="utf-8")
        collection_path.write_text(json.dumps(collection), encoding="utf-8")
        status, stdout = _invoke(["seal", str(source), "--project-alias", "fixture", "--asset-alias", "asset-1",
                                 "--target", str(target_path), "--collection", str(collection_path)])
        assert status == 0, stdout
        bundle = Path(stdout.strip().split("=", 1)[1]).parent
        cases = base / "cases"
        status, stdout = _invoke(["import", str(bundle), "--cases", str(cases)])
        assert status == 0, stdout
        case = Path(stdout.strip().split("=", 1)[1])

        evidence_reports = []
        evidence_results = []
        evidence_artifact_sets = []
        alternate_knowledge = json.loads((ROOT / "rules" / "listener_knowledge.example.json").read_text(encoding="utf-8"))
        alternate_knowledge["rules_version"] = "0.1.1-fixture"
        alternate_path = base / "listener-knowledge.json"
        alternate_path.write_text(json.dumps(alternate_knowledge), encoding="utf-8")
        for name in ("evidence-a", "evidence-b"):
            command = ["analyze", str(case), "--output", str(base / name)]
            if name == "evidence-b":
                command += ["--listener-knowledge", str(alternate_path)]
            status, stdout = _invoke(command)
            assert status in (0, 4), stdout
            artifacts = _artifacts(stdout)
            assert set(artifacts) == {"md", "html", "csv", "json"}
            evidence_artifact_sets.append(artifacts)
            payload = json.loads(artifacts["json"].read_text(encoding="utf-8"))
            evidence_results.append(payload)
            evidence_reports.append(artifacts["json"])
            ids = [item["finding_id"] for item in payload["findings"]]
            assert len(ids) == len(set(ids)), ids
            memcached = next(item for item in payload["findings"] if item["finding_id"] == "LISTENER_TCP_UDP_11211_REVIEW")
            assert set(memcached["evidence"]["protocols"]) == {"tcp", "udp"}
            redis = next(item for item in payload["findings"] if item["finding_id"] == "LISTENER_TCP_6379_REVIEW")
            assert "nested/listeners.txt" in redis["evidence"]["sources"]
            assert "LISTENER_EVIDENCE_TRUNCATED" not in payload["warnings"]
            generic = next(item for item in payload["findings"] if item["finding_id"] == "GENERIC_WILDCARD_LISTENER_REVIEW")
            assert len(generic["evidence"]["lines"]) == 20
            assert sum(line["local_bind"] == "0.0.0.0:8443" for line in generic["evidence"]["lines"]) == 2
            assert {line["source"] for line in generic["evidence"]["lines"] if line["local_bind"] == "0.0.0.0:8443"} == {
                "nested-a/listeners.txt", "nested-b/listeners.txt"}
            assert set(generic["evidence"]["sources"]) == {line["source"] for line in generic["evidence"]["lines"]}
        status, stdout = _invoke(["compare", str(evidence_reports[0]), str(evidence_reports[1]), "--output", str(base / "compare.json")])
        assert status == 4, stdout
        comparison = json.loads((base / "compare.json").read_text(encoding="utf-8"))
        assert all(item["state"] == "not_comparable" for item in comparison["items"])

        # A prior rules version kept generic wildcard rows alongside dedicated
        # listener findings. The policy version/hash change must keep old/new
        # reports from treating those presentation changes as resolved risk.
        old_policy = json.loads((ROOT / "rules" / "platform_risk_rules.example.json").read_text(encoding="utf-8"))
        old_policy["rules_version"] = "0.1.0"
        old_policy["rules"][0]["title"] = "通配地址监听需要人工确认"
        old_policy_path = base / "platform-rules-0.1.0.json"
        old_policy_path.write_text(json.dumps(old_policy, ensure_ascii=False), encoding="utf-8")
        old_output = base / "old-policy"
        actual_analyze = inspection_cli.analyze_evidence
        with patch.object(inspection_cli, "analyze_evidence",
                          side_effect=lambda path, manifest, listener_knowledge_path: actual_analyze(
                              path, manifest, rules_path=old_policy_path,
                              listener_knowledge_path=listener_knowledge_path)):
            old_status, old_stdout = _invoke(["analyze", str(case), "--output", str(old_output)])
        assert old_status in (0, 4), old_stdout
        old_report = _artifacts(old_stdout)["json"]
        old_payload = json.loads(old_report.read_text(encoding="utf-8"))
        assert "0.1.0" in old_payload["metadata"]["rules_version"]
        status, stdout = _invoke(["compare", str(old_report), str(evidence_reports[0]), "--output", str(base / "old-new-compare.json")])
        assert status == 4, stdout
        old_new = json.loads((base / "old-new-compare.json").read_text(encoding="utf-8"))
        assert all(item["state"] == "not_comparable" for item in old_new["items"])

        same_policy_output = base / "same-policy"
        same_status, same_stdout = _invoke(["analyze", str(case), "--output", str(same_policy_output)])
        assert same_status in (0, 4), same_stdout
        status, stdout = _invoke(["compare", str(evidence_reports[0]), str(_artifacts(same_stdout)["json"]),
                                 "--output", str(base / "same-policy-compare.json")])
        assert status in (0, 4), stdout
        same_policy_comparison = json.loads((base / "same-policy-compare.json").read_text(encoding="utf-8"))
        assert all(item["state"] != "not_comparable" for item in same_policy_comparison["items"])

        custom_policy = json.loads((ROOT / "rules" / "platform_risk_rules.example.json").read_text(encoding="utf-8"))
        custom_rule = dict(custom_policy["rules"][0])
        custom_rule.update({"id": "CUSTOM_CRITICAL_WILDCARD", "title": "自定义高优先级通配监听", "severity": "Critical"})
        custom_policy["rules"].append(custom_rule)
        custom_policy["rules_version"] = "0.1.2-fixture"
        custom_policy_path = base / "custom-critical-platform-rules.json"
        custom_policy_path.write_text(json.dumps(custom_policy, ensure_ascii=False), encoding="utf-8")
        custom_output = base / "custom-critical"
        with patch.object(inspection_cli, "analyze_evidence",
                          side_effect=lambda path, manifest, listener_knowledge_path: actual_analyze(
                              path, manifest, rules_path=custom_policy_path,
                              listener_knowledge_path=listener_knowledge_path)):
            custom_status, custom_stdout = _invoke(["analyze", str(case), "--output", str(custom_output)])
        assert custom_status in (0, 4), custom_stdout
        custom_payload = json.loads(_artifacts(custom_stdout)["json"].read_text(encoding="utf-8"))
        custom_findings = {item["finding_id"]: item for item in custom_payload["findings"]}
        assert "CUSTOM_CRITICAL_WILDCARD" in custom_findings
        assert "LISTENER_TCP_2375_REVIEW" in custom_findings
        assert custom_findings["CUSTOM_CRITICAL_WILDCARD"]["severity"] == "Critical"

        from analyzers.evidence_analyzer import _match_rule
        specific_text = "TCP 0.0.0.0:2375 0.0.0.0:0 LISTENING 1\n"
        from analyzers.listener_risk import parse_listener_text
        specific_facts, _ = parse_listener_text(specific_text)
        info_rule = next(rule for rule in json.loads((ROOT / "rules" / "platform_risk_rules.example.json").read_text(encoding="utf-8"))["rules"]
                         if rule["id"] == "GENERIC_WILDCARD_LISTENER_REVIEW")
        assert _match_rule(info_rule, "linux", {"target": target}, {"listeners.txt": specific_text},
                           listener_facts=specific_facts,
                           covered_listener_facts={("tcp", 2375, "0.0.0.0")}) == []
        status, stdout = _invoke(["codex-export", str(evidence_reports[0]), "--output", str(base / "codex.json")])
        assert status == 0, stdout
        codex_payload = json.loads((base / "codex.json").read_text(encoding="utf-8"))
        codex_ids = [item["finding_id"] for item in codex_payload["findings"]]
        assert len(codex_ids) == len(set(codex_ids)), codex_ids

        bad_knowledge = base / "invalid-listener-knowledge.json"
        bad_knowledge.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        status, stdout = _invoke(["analyze", str(case), "--output", str(base / "invalid-analysis"),
                                 "--listener-knowledge", str(bad_knowledge)])
        assert status == 4, stdout
        invalid_payload = json.loads(_artifacts(stdout)["json"].read_text(encoding="utf-8"))
        assert invalid_payload["status"] == "FAILED"
        assert invalid_payload["config_evidence"]["listener_knowledge"]["status"] == "failed"
        assert invalid_payload["config_evidence"]["listener_knowledge"]["reason"] == "LISTENER_KNOWLEDGE_DUPLICATE_JSON_KEY"

        malformed_knowledge = json.loads((ROOT / "rules" / "listener_knowledge.example.json").read_text(encoding="utf-8"))
        malformed_knowledge["rules"][0]["protocols"] = [{}]
        malformed_path = base / "malformed-listener-knowledge.json"
        malformed_path.write_text(json.dumps(malformed_knowledge), encoding="utf-8")
        status, stdout = _invoke(["analyze", str(case), "--output", str(base / "malformed-analysis"),
                                 "--listener-knowledge", str(malformed_path)])
        assert status == 4, stdout
        malformed_payload = json.loads(_artifacts(stdout)["json"].read_text(encoding="utf-8"))
        assert malformed_payload["config_evidence"]["listener_knowledge"]["reason"] == "LISTENER_KNOWLEDGE_RULE_INVALID"

        missing_path = base / "missing-listener-knowledge.json"
        status, stdout = _invoke(["analyze", str(case), "--output", str(base / "missing-analysis"),
                                 "--listener-knowledge", str(missing_path)])
        assert status == 4, stdout
        missing_payload = json.loads(_artifacts(stdout)["json"].read_text(encoding="utf-8"))
        assert missing_payload["config_evidence"]["listener_knowledge"]["reason"] == "LISTENER_KNOWLEDGE_MISSING"

        bounded_failures = {
            "deep": '{"nested":' + "[" * 20000 + "0" + "]" * 20000 + "}",
            "integer": '{"schema_version":' + "9" * 5000 + ',"rules_version":"x","rules":[]}',
        }
        for case_name, raw_knowledge in bounded_failures.items():
            bounded_path = base / f"{case_name}-knowledge.json"
            bounded_path.write_text(raw_knowledge, encoding="ascii")
            status, stdout = _invoke(["analyze", str(case), "--output", str(base / f"{case_name}-analysis"),
                                     "--listener-knowledge", str(bounded_path)])
            assert status == 4, stdout
            bounded_payload = json.loads(_artifacts(stdout)["json"].read_text(encoding="utf-8"))
            assert bounded_payload["status"] == "FAILED"
            assert bounded_payload["config_evidence"]["listener_knowledge"]["status"] == "failed"

        facts = [{"LocalAddress": "0.0.0.0", "LocalPort": 2375, "ProcessName": "unknown"},
                 {"LocalAddress": "::", "LocalPort": 2375, "ProcessName": "unknown"},
                 {"LocalAddress": "0.0.0.0", "LocalPort": 11211, "Protocol": "tcp"},
                 {"LocalAddress": "0.0.0.0", "LocalPort": 11211, "Protocol": "udp"},
                 {"LocalAddress": "0.0.0.0", "LocalPort": 2375.5, "Protocol": "tcp"}]
        synthetic_collector = {"collector": "network_ports", "status": "ok", "data": facts, "errors": []}
        with patch.object(run_inspection, "COLLECTORS", [lambda: synthetic_collector]):
            status, stdout = _invoke(["analyze-local", "--output", str(base / "local"), "--project-alias", "fixture", "--asset-alias", "asset-1"])
        assert status in (0, 4), stdout
        local_json = _artifacts(stdout)["json"]
        local_payload = json.loads(local_json.read_text(encoding="utf-8"))
        local_ids = [item["finding_id"] for item in local_payload["findings"]]
        assert len(local_ids) == len(set(local_ids)), local_ids
        local_memcached = next(item for item in local_payload["findings"] if item["finding_id"] == "LISTENER_TCP_UDP_11211_REVIEW")
        assert set(local_memcached["evidence"]["protocols"]) == {"tcp", "udp"}
        assert "LISTENER_PORT_INVALID_OR_UNKNOWN" in local_payload["warnings"]

        for collector_status in ("failed", "permission_denied", "not_checked"):
            residual_collector = {"collector": "network_ports", "status": collector_status,
                                  "data": [{"LocalAddress": "0.0.0.0", "LocalPort": 2375}], "errors": ["fixture"]}
            with patch.object(run_inspection, "COLLECTORS", [lambda: residual_collector]):
                failed_status, failed_stdout = _invoke(["analyze-local", "--output", str(base / f"{collector_status}-local"),
                                                       "--project-alias", "fixture", "--asset-alias", f"asset-{collector_status}"])
            assert failed_status == 4, failed_stdout
            failed_payload = json.loads(_artifacts(failed_stdout)["json"].read_text(encoding="utf-8"))
            assert "LISTENER_TCP_2375_REVIEW" not in {item["finding_id"] for item in failed_payload["findings"]}
            assert f"NETWORK_COLLECTOR_STATUS_{collector_status.upper()}" in failed_payload["warnings"]

        partial_collector = {"collector": "network_ports", "status": "need_admin",
                             "data": [{"LocalAddress": "0.0.0.0", "LocalPort": 2375}], "errors": ["fixture"]}
        with patch.object(run_inspection, "COLLECTORS", [lambda: partial_collector]):
            partial_status, partial_stdout = _invoke(["analyze-local", "--output", str(base / "need-admin-local"),
                                                      "--project-alias", "fixture", "--asset-alias", "asset-need-admin"])
        assert partial_status == 4, partial_stdout
        partial_payload = json.loads(_artifacts(partial_stdout)["json"].read_text(encoding="utf-8"))
        assert "LISTENER_TCP_2375_REVIEW" in {item["finding_id"] for item in partial_payload["findings"]}
        assert any("need_admin" in warning for warning in partial_payload["warnings"])

        def shared_finding(payload: dict) -> dict:
            return next(item for item in payload["findings"] if item["finding_id"] == "LISTENER_TCP_2375_REVIEW")

        evidence_finding, local_finding = shared_finding(evidence_results[0]), shared_finding(local_payload)
        for key in ("finding_id", "rule_id", "title", "severity", "impact", "recommendation", "rollback", "verification_checkpoint"):
            assert evidence_finding[key] == local_finding[key], key
        for artifact in evidence_artifact_sets[0].values():
            text = artifact.read_text(encoding="utf-8-sig").replace("\\_", "_")
            assert "LISTENER_TCP_2375_REVIEW" in text
        evidence_rule = evidence_results[0]["metadata"]
        local_rule = local_payload["metadata"]
        assert "listeners-0.2.0" in evidence_rule["rules_version"]
        assert "listeners-0.2.0" in local_rule["rules_version"]
        assert evidence_rule["rules_sha256"] != local_rule["rules_sha256"], "distinct channel rule scope must remain distinct"


if __name__ == "__main__":
    test_cli_evidence_and_injected_local_pipeline_share_listener_finding_and_bind_knowledge()
    print("Listener CLI integration tests passed.")
