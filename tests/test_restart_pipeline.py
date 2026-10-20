from __future__ import annotations

import json
import tempfile
import contextlib
import io
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.evidence_analyzer import analyze_evidence, load_platform_policy
from analyzers.local_ai import LocalAIError, _endpoint
from evidence.bundle import BundleError, import_bundle, parse_iso8601_timestamp, validate_bundle, write_manifest
from evidence.config_sanitizer import sanitize_config
from inspection_cli import _compare, main
from inspection_cli import _evidence_summary
from models.analysis import AnalysisResult
from reports.unified import render_csv, render_html, render_markdown


class RestartPipelineTests(unittest.TestCase):
    def test_collection_timestamp_validation_is_strict_and_ordered(self) -> None:
        self.assertEqual(parse_iso8601_timestamp("2026-10-05T02:05:00.1Z").microsecond, 100000)
        self.assertEqual(parse_iso8601_timestamp("2026-10-05T02:05:00.12Z").microsecond, 120000)
        self.assertEqual(parse_iso8601_timestamp("2026-10-05T02:05:00.1234Z").microsecond, 123400)
        self.assertEqual(parse_iso8601_timestamp("2026-10-05T02:05:00.12345Z").microsecond, 123450)
        self.assertEqual(parse_iso8601_timestamp("2026-10-05T02:05:00.1234567Z").microsecond, 123456)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bundle"
            root.mkdir()
            (root / "os.txt").write_text("Linux fixture\n", encoding="utf-8")
            (root / "os.exit-code.txt").write_text("0\n", encoding="ascii")
            target = {"os_family": "linux", "product": "Linux", "version": "fixture", "architecture": "x86_64", "use_case": "server", "scope": "basic"}
            collection = {"started_at": "2026-10-05T02:05:00.1234567+00:00", "finished_at": "2026-10-05T02:06:00.1234567+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "fixture", "command_catalog": "fixture"}
            write_manifest(root, project_alias="p", asset_alias="a", target=target, collection=collection)
            validate_bundle(root)
            collection["finished_at"] = "2026-10-05T02:04:00.1234567+00:00"
            with self.assertRaisesRegex(BundleError, "must not precede"):
                write_manifest(root, project_alias="p", asset_alias="a", target=target, collection=collection)
            collection["started_at"] = "2026-10-05T02:05:00+00:60"
            collection["finished_at"] = "2026-10-05T02:06:00Z"
            with self.assertRaises(BundleError):
                write_manifest(root, project_alias="p", asset_alias="a", target=target, collection=collection)

    def test_requirepass_arbitrary_value_never_reaches_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "redis.conf"
            source.write_text("requirepass Zx9qL2vN7pK4\nrename-command FLUSHALL hidden-command\nbind 127.0.0.1\n", encoding="utf-8")
            output = root / "out"
            result = sanitize_config("redis", source, output)
            text = result.read_text(encoding="utf-8")
            self.assertNotIn("Zx9qL2vN7pK4", text)
            payload = json.loads(text)
            self.assertEqual(payload["facts"][0]["value"], "configured_redacted")
            self.assertTrue(result.with_name(result.stem + ".exit-code.txt").exists())

    def test_invalid_or_duplicate_sanitized_config_never_reaches_matchers(self) -> None:
        target = {"os_family": "linux", "product": "CentOS", "version": "7", "architecture": "x86_64", "use_case": "server", "scope": "basic;redis"}
        collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "0.2", "command_catalog": "fixture"}
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config_source = base / "redis.conf"; config_source.write_text("bind 0.0.0.0\n", encoding="utf-8")
            root = base / "invalid"; root.mkdir()
            config = sanitize_config("redis", config_source, root, instance_id="cache1")
            value = json.loads(config.read_text(encoding="utf-8")); value["schema_version"] = 99
            config.write_text(json.dumps(value), encoding="utf-8")
            write_manifest(root, project_alias="p", asset_alias="a", target=target, collection=collection)
            result = analyze_evidence(root, validate_bundle(root))
            self.assertNotIn("REDIS_WILDCARD_BIND_REVIEW@cache1", {x["finding_id"] for x in result.findings})
            self.assertTrue(any(x.startswith("CONFIG_SCHEMA_INVALID:") for x in result.warnings))

            duplicate = base / "duplicate"; duplicate.mkdir()
            first = sanitize_config("redis", config_source, duplicate, instance_id="cache1")
            copy_dir = duplicate / "extra"; copy_dir.mkdir()
            duplicate_file = copy_dir / first.name; duplicate_file.write_bytes(first.read_bytes())
            duplicate_file.with_name(duplicate_file.stem + ".exit-code.txt").write_text("0\n", encoding="ascii")
            write_manifest(duplicate, project_alias="p", asset_alias="a", target=target, collection=collection)
            result = analyze_evidence(duplicate, validate_bundle(duplicate))
            self.assertNotIn("REDIS_WILDCARD_BIND_REVIEW@cache1", {x["finding_id"] for x in result.findings})
            self.assertIn("CONFIG_DUPLICATE_PRODUCT_INSTANCE:redis:cache1", result.warnings)

    def test_tomcat_protocol_value_is_a_fixed_enum_not_arbitrary_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / "server.xml"
            source.write_text('<Server><Service><Connector protocol="password123" /></Service></Server>', encoding="utf-8")
            output = sanitize_config("tomcat", source, root / "out")
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["facts"][0]["value"], "configured_redacted")
            self.assertNotIn("password123", output.read_text(encoding="utf-8"))

    def test_empty_required_evidence_and_orphan_sidecar_fail_closed_at_seal(self) -> None:
        target = {"os_family": "windows", "product": "Windows Server", "version": "2008", "architecture": "x64", "use_case": "server", "scope": "basic"}
        collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "0.2", "command_catalog": "fixture"}
        required = ("os.txt", "os_detail.txt", "cpu.txt", "memory.txt", "graphics.txt", "disks.txt", "services.txt", "listeners.txt", "firewall.txt", "privilege.txt", "accounts.txt", "startup_items.txt", "security_status.txt")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bundle"; root.mkdir()
            for name in required:
                text = "Caption=Windows Server 2008\r\nVersion=6.0\r\n" if name == "os_detail.txt" else "  \r\n"
                (root / name).write_text(text, encoding="utf-8")
                (root / (Path(name).stem + ".exit-code.txt")).write_text("0\n", encoding="ascii")
            write_manifest(root, project_alias="p", asset_alias="a", target=target, collection=collection)
            manifest = validate_bundle(root)
            self.assertNotEqual(analyze_evidence(root, manifest).status, "OK")
            self.assertTrue(all(item["status"] != "collected" for item in manifest["items"] if Path(item["path"]).name != "os_detail.txt"))
            orphan = Path(tmp) / "orphan"; orphan.mkdir()
            (orphan / "orphan.exit-code.txt").write_text("0\n", encoding="ascii")
            with self.assertRaises(BundleError):
                write_manifest(orphan, project_alias="p", asset_alias="a", target=target, collection=collection)

    def test_linux_host_analyzes_independent_middleware_configs_and_exact_tls_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); root = base / "bundle"; root.mkdir()
            (base / "redis.conf").write_text("bind 0.0.0.0\nrequirepass RandomNoKeyword99\n", encoding="utf-8")
            (base / "nginx.conf").write_text("ssl_protocols TLSv1.2 TLSv1.3;\n", encoding="utf-8")
            configs = [sanitize_config(product, base / f"{product}.conf", root, version="unknown")
                       for product in ("redis", "nginx")]
            items = []
            for name, text in (("os.txt", "Linux"), ("os_release.txt", "CentOS 7"), ("architecture.txt", "x86_64"),
                               ("cpu_count.txt", "4"), ("memory_summary.txt", "MemTotal_kB=4096"), ("graphics_summary.txt", "COLLECTOR_STATUS=NOT_CHECKED"),
                               ("disks.txt", "Filesystem 1024-blocks Used Available Capacity Mounted on"), ("services.txt", "COLLECTOR_STATUS=NOT_CHECKED"),
                               ("listeners.txt", "COLLECTOR_STATUS=NOT_CHECKED"), ("firewall.txt", "COLLECTOR_STATUS=NOT_CHECKED"),
                               ("privilege.txt", "COLLECTOR_STATUS=NOT_CHECKED"), ("accounts.txt", "COLLECTOR_STATUS=NOT_CHECKED"),
                               ("startup_items.txt", "COLLECTOR_STATUS=NOT_CHECKED"), ("security_status.txt", "COLLECTOR_STATUS=NOT_CHECKED")):
                (root / name).write_text(text + "\n", encoding="utf-8")
                (root / (Path(name).stem + ".exit-code.txt")).write_text("0\n", encoding="ascii")
            for path in configs:
                path.with_name(path.stem + ".exit-code.txt").write_text("0\n", encoding="ascii")
            target = {"os_family": "linux", "product": "CentOS", "version": "7", "architecture": "x86_64", "use_case": "server", "scope": "basic;redis;nginx"}
            collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "0.2", "command_catalog": "fixture"}
            write_manifest(root, project_alias="project-1", asset_alias="asset-1", target=target, collection=collection)
            manifest = validate_bundle(root)
            result = analyze_evidence(root, manifest)
            identifiers = {x["rule_id"] for x in result.findings}
            self.assertIn("REDIS_WILDCARD_BIND_REVIEW", identifiers)
            self.assertNotIn("NGINX_LEGACY_TLS_CONFIG_REVIEW", identifiers)
            self.assertTrue(any("PRODUCT_VERSION_APPLICABILITY_UNVERIFIED:redis" in x for x in result.warnings))

    def test_wildcard_listener_uses_local_address_and_listening_state(self) -> None:
        from analyzers.evidence_analyzer import _wildcard_listeners
        text = """TCP 127.0.0.1:8080 0.0.0.0:0 LISTENING 12
TCP 10.0.0.1:8080 0.0.0.0:0 ESTABLISHED 13
UDP 0.0.0.0:53 *:* 14
TCP 0.0.0.0:80 0.0.0.0:0 LISTENING 15
tcp6 0 0 :::443 :::* LISTEN
"""
        found = _wildcard_listeners(text)
        self.assertEqual(len(found), 2)
        self.assertEqual({x["local_bind"] for x in found}, {"0.0.0.0:80", ":::443"})

    def test_bundle_sidecar_requires_explicit_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); root = base / "bundle"; root.mkdir()
            (root / "os.txt").write_text("Linux\n", encoding="utf-8")
            (root / "os.exit-code.txt").write_text("EXIT_CODE=0\nSTATUS=OK\n", encoding="ascii")
            target = {"os_family": "linux", "product": "CentOS", "version": "7", "architecture": "x86_64", "use_case": "server", "scope": "basic"}
            collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "0.2", "command_catalog": "fixture"}
            write_manifest(root, project_alias="p", asset_alias="a", target=target, collection=collection)
            self.assertEqual(validate_bundle(root)["items"][0]["exit_code"], 0)
            imported = import_bundle(root, base / "cases")
            self.assertEqual(validate_bundle(imported)["items"][0]["status"], "collected")

    def test_partial_status_requires_a_fact_not_only_status_or_error_markers(self) -> None:
        target = {"os_family": "windows", "product": "Windows fixture", "version": "fixture", "architecture": "x64", "use_case": "unknown", "scope": "basic"}
        collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "0.2", "command_catalog": "fixture"}
        unusable_payloads = (
            "COLLECTOR_STATUS=PARTIAL\n",
            "COLLECTOR_STATUS=PARTIAL\nCOLLECTOR_STATUS=FAILED\n",
            "COLLECTOR_STATUS=PARTIAL\nCOLLECTOR_ERROR=FIXTURE\n",
            "COLLECTOR_STATUS=PARTIAL\nCOLLECTOR_NOTE=FIXTURE\n",
            "COLLECTOR_STATUS=PARTIAL\nCOLLECTION_TIMEOUT\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for index, payload in enumerate(unusable_payloads):
                root = base / f"bundle-{index}"
                root.mkdir()
                (root / "cpu.txt").write_text(payload, encoding="utf-8")
                (root / "cpu.exit-code.txt").write_text("EXIT_CODE=0\nSTATUS=COLLECTED\n", encoding="ascii")
                manifest_path = write_manifest(
                    root, project_alias="p", asset_alias="a", target=target, collection=collection
                )
                manifest = validate_bundle(root)
                item = manifest["items"][0]
                self.assertEqual(item["status"], "failed")

                sealed = json.loads(manifest_path.read_text(encoding="utf-8"))
                sealed["items"][0]["status"] = "collected"
                sealed["items"][0]["reason"] = ""
                manifest_path.write_text(json.dumps(sealed), encoding="utf-8")
                with self.assertRaisesRegex(BundleError, "usable text"):
                    validate_bundle(root)

    def test_bundle_analysis_summary_normalizes_crlf_and_utf16_bom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bundle"; root.mkdir()
            (root / "cpu.txt").write_bytes("Name=Fixture CPU\r\n".encode("utf-16"))
            (root / "cpu.exit-code.txt").write_text("0\n", encoding="ascii")
            for name, value in (("cpu_count.txt", "4\r\n"), ("memory_summary.txt", "MemTotal_kB=8192\r\n")):
                (root / name).write_bytes(value.encode("utf-8"))
                (root / (Path(name).stem + ".exit-code.txt")).write_text("0\n", encoding="ascii")
            target = {"os_family": "linux", "product": "CentOS", "version": "7", "architecture": "x86_64", "use_case": "server", "scope": "basic"}
            collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "0.2", "command_catalog": "fixture"}
            write_manifest(root, project_alias="p", asset_alias="a", target=target, collection=collection)
            manifest = validate_bundle(root)
            result = analyze_evidence(root, manifest)
            summary = _evidence_summary(root, manifest)
            self.assertEqual(summary["硬件"]["CPU"], "Fixture CPU")
            self.assertEqual(summary["硬件"]["CPU数量"], "4")
            self.assertEqual(summary["硬件"]["内存KB"], "8192")
            self.assertIn(result.status, {"PARTIAL", "FAILED"})

    def test_private_network_ai_endpoint_is_literal_and_bounded(self) -> None:
        self.assertEqual(_endpoint("http://127.0.0.1:11434")[3], True)
        self.assertEqual(_endpoint("http://192.168.20.10:11434")[3], False)
        for value in ("http://example.test:11434", "http://8.8.8.8:11434", "http://169.254.1.2:11434", "http://192.0.2.1:11434"):
            with self.assertRaises(LocalAIError):
                _endpoint(value)

    def test_report_outputs_preserve_partial_and_escape_untrusted_values(self) -> None:
        result = AnalysisResult(status="PARTIAL", warnings=["missing <script>alert(1)</script>"])
        metadata = {"asset_alias": "asset-1", "bundle_id": "bundle-1", "target": "CentOS", "evidence_summary": {"hardware": {"CPU": "4"}}}
        html = render_html(result, metadata)
        csv = render_csv(result)
        markdown = render_markdown(result, metadata)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("PARTIAL", csv)
        self.assertIn("missing", markdown)
        self.assertNotIn("<script>", html)

    def test_compare_does_not_resolve_when_rules_change_and_rejects_other_asset(self) -> None:
        before = AnalysisResult(status="OK", findings=[{"finding_id": "R1"}])
        after = AnalysisResult(status="OK")
        old = {"project_alias": "p", "asset_alias": "a", "target_identity": {"os_family": "linux", "product": "CentOS", "version": "7", "architecture": "x86_64", "scope": "basic"}, "rules_version": "1", "rules_sha256": "a"}
        changed = {**old, "rules_version": "2", "rules_sha256": "b"}
        self.assertEqual(_compare(before, after, old, changed)["items"][0]["state"], "not_comparable")
        with self.assertRaises(ValueError):
            _compare(before, after, old, {**changed, "asset_alias": "other"})

    def test_local_pc_entry_binds_identity_exports_and_compares_same_asset(self) -> None:
        import run_inspection
        collectors = {
            "system_info": {"status": "ok", "data": {"os": "Windows 10", "version": "22H2", "build": "19045", "architecture": "x64", "total_memory_bytes": 8589934592}},
            "cpu": {"status": "ok", "data": {"name": "Fixture CPU", "logical_processors": 8}},
            "users": {"status": "ok", "data": {"Users": [{"Name": "private-user"}], "Administrators": [{"Name": "private-admin"}]}},
            "startup_items": {"status": "ok", "data": {"Items": [{"Name": "private-startup-command"}]}},
            "disks": {"status": "ok", "data": {"VolumeSummary": [{"DeviceID": "C:"}]}},
            "services": {"status": "ok", "data": [{"name": "safe-service"}]},
            "network_ports": {"status": "ok", "data": []},
        }
        result = AnalysisResult(status="OK", findings=[{"finding_id": "FIXTURE", "title": "Fixture review", "severity": "Info", "evidence": {}}],
                                config_evidence={"platform_rules": {"rules_version": "test-v1", "sha256": "a" * 64}})
        def fake_pipeline(*, resolution=None, **_kwargs):
            self.assertIsNotNone(resolution)
            result.config_evidence = resolution.config_evidence
            return collectors, result

        with tempfile.TemporaryDirectory() as tmp, patch.object(run_inspection, "run_collection_pipeline", side_effect=fake_pipeline):
            output = Path(tmp) / "reports"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["analyze-local", "--output", str(output), "--project-alias", "proj", "--asset-alias", "workstation-1"])
            self.assertIn(status, (0, 4))
            report = next(output.glob("local-*/analysis.json"))
            payload = json.loads(report.read_text(encoding="utf-8"))
            meta = payload["metadata"]
            self.assertEqual(meta["asset_alias"], "workstation-1")
            self.assertTrue(meta["target_identity"]["product"].startswith("Windows"))
            self.assertIn("rules_sha256", meta)
            self.assertIn("CPU型号", meta["evidence_summary"]["设备"])
            self.assertNotIn("private-user", report.read_text(encoding="utf-8"))
            codex = Path(tmp) / "codex.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["codex-export", str(report), "--output", str(codex)]), 0)
            self.assertIn("Windows 10", codex.read_text(encoding="utf-8"))
            comparison = Path(tmp) / "compare.json"
            with contextlib.redirect_stdout(io.StringIO()):
                compare_status = main(["compare", str(report), str(report), "--output", str(comparison)])
            self.assertEqual(compare_status, 0 if payload["status"] == "OK" else 4)

    def test_local_rule_binding_uses_real_loader_registry_override_and_profile(self) -> None:
        import shutil
        import run_inspection
        from analyzers.lifecycle import DEFAULT_POLICY

        collectors = {"system_info": {"status": "ok", "data": {"os": "Windows 10", "version": "22H2", "architecture": "x64"}}}
        finding = {"finding_id": "SAME_FINDING", "title": "Fixture", "severity": "Warning", "evidence": {"fact": "same"}}
        metadata_by_case = {}
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            policy = base / "os_lifecycle.json"
            shutil.copyfile(DEFAULT_POLICY, policy)
            with patch("analyzers.lifecycle.DEFAULT_POLICY", policy):
                for case in ("base", "override", "profile"):
                    app = base / case
                    (app / "rules").mkdir(parents=True)
                    (app / "config").mkdir()
                    shutil.copyfile(ROOT / "rules" / "windows_risk_rules.example.json", app / "rules" / "windows_risk_rules.example.json")
                    shutil.copyfile(ROOT / "config" / "local-profile.example.json", app / "config" / "local-profile.json")
                    if case == "override":
                        registry = json.loads((app / "rules" / "windows_risk_rules.example.json").read_text(encoding="utf-8"))
                        rule_id = registry["rules"][0]["id"]
                        override = {"schema_version": 1, "base_registry_version": registry["registry_version"],
                                    "overrides": {"thresholds": {}, "ports": {}, "path_patterns": {}, "vendor_patterns": {},
                                                  "rules": {rule_id: {"severity": "Info"}}}}
                        (app / "config" / "windows-risk-rules.override.json").write_text(json.dumps(override), encoding="utf-8")
                    elif case == "profile":
                        profile_path = app / "config" / "local-profile.json"
                        profile = json.loads(profile_path.read_text(encoding="utf-8"))
                        profile["profile_id"] = "fixture-profile-2"
                        profile_path.write_text(json.dumps(profile), encoding="utf-8")

                    def fake_pipeline(*, resolution=None, **_kwargs):
                        self.assertIsNotNone(resolution)
                        self.assertEqual(resolution.status, "OK")
                        findings = [finding] if case == "base" else []
                        return collectors, AnalysisResult(status="OK", findings=findings, config_evidence=resolution.config_evidence)

                    with patch.object(run_inspection, "application_root", return_value=app), \
                         patch.object(run_inspection, "run_collection_pipeline", side_effect=fake_pipeline), \
                         patch("analyzers.lifecycle.analyze_lifecycle", return_value=([], [])):
                        output = base / f"reports-{case}"
                        with contextlib.redirect_stdout(io.StringIO()):
                            status = main(["analyze-local", "--output", str(output), "--project-alias", "p", "--asset-alias", "a"])
                        self.assertIn(status, (0, 4))
                        report = next(output.glob("local-*/analysis.json"))
                        metadata_by_case[case] = json.loads(report.read_text(encoding="utf-8"))["metadata"]

            self.assertEqual(metadata_by_case["base"]["rules_version"].split("+", 1)[0], "0.1.0")
            self.assertEqual(len({metadata_by_case[name]["rules_sha256"] for name in metadata_by_case}), 3)
            base_report = next((base / "reports-base").glob("local-*/analysis.json"))
            for case in ("override", "profile"):
                changed_report = next((base / f"reports-{case}").glob("local-*/analysis.json"))
                old, old_meta = __import__("inspection_cli")._load_analysis(base_report)
                new, new_meta = __import__("inspection_cli")._load_analysis(changed_report)
                comparison = _compare(old, new, old_meta, new_meta)
                self.assertTrue(comparison["rules_changed"])
                self.assertNotEqual(comparison["status"], "OK")
                self.assertEqual(comparison["items"][0]["state"], "not_comparable")


if __name__ == "__main__":
    unittest.main()
