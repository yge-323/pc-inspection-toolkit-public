from __future__ import annotations

import copy
import io
import json
import os
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers import local_ai
from evidence.transports import TransportCleanupError, TransportError, WINRM_COMMANDS, _extract_tar, _run_winrm_command, _ssh_arguments, _write_capture_file, capture_winrm_bundle


class TransportContractTests(unittest.TestCase):
    def test_ssh_requires_pinned_known_hosts_and_never_disables_host_key_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            known = Path(temporary) / "主机 keys"
            known.write_text("fixture ssh-ed25519 AAAA", encoding="ascii")
            with patch.dict(os.environ, {"SSH_AUTH_SOCK": "fixture-agent"}), patch("evidence.transports.shutil.which", return_value="ssh"):
                args = _ssh_arguments("192.168.4.10", "maint", 22, known, agent_auth=True)
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("-F", args)
            self.assertIn("IdentityAgent=SSH_AUTH_SOCK", args)
            self.assertIn("IdentityFile=none", args)
            self.assertTrue(any(str(x).startswith('UserKnownHostsFile="') and "主机 keys" in str(x) for x in args))
            self.assertNotIn("StrictHostKeyChecking=no", args)
            with self.assertRaises(TransportError):
                _ssh_arguments("-oProxyCommand=echo", "maint", 22, known, agent_auth=True)
            with self.assertRaises(TransportError):
                _ssh_arguments("192.168.4.10", "maint", 22, known)

    def test_ssh_archive_traversal_and_links_are_rejected(self) -> None:
        def archive(name: str, kind: bytes = b"data") -> bytes:
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as tar:
                entry = tarfile.TarInfo(name)
                entry.size = len(kind)
                tar.addfile(entry, io.BytesIO(kind))
            return output.getvalue()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(TransportError):
                _extract_tar(Path(temporary), archive("evidence/../../escape.txt"))

    def test_ssh_archive_decompressed_pax_header_has_a_total_budget(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
            entry = tarfile.TarInfo("evidence/small.txt")
            entry.pax_headers = {"comment": "x" * 8192}
            entry.size = 0
            tar.addfile(entry, io.BytesIO())
        with tempfile.TemporaryDirectory() as temporary, patch("evidence.transports.SSH_MAX_DECOMPRESSED_BYTES", 4096):
            with self.assertRaises(TransportError):
                _extract_tar(Path(temporary), output.getvalue())

    def test_winrm_requires_https_and_optional_dependency_without_fallback(self) -> None:
        target = {"os_family": "windows", "product": "Windows", "version": "unknown", "architecture": "x64", "use_case": "desktop", "scope": "basic"}
        collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "0.2", "command_catalog": "fixture"}
        with patch.dict(os.environ, {"FIXTURE_USER": "user", "FIXTURE_PASS": "secret-value"}, clear=False):
            with patch.dict("sys.modules", {"winrm": None}):
                with self.assertRaises(TransportError):
                    capture_winrm_bundle(host="host.example", port=5986, user_env="FIXTURE_USER", password_env="FIXTURE_PASS", cases_dir=Path("ignored"), project_alias="p", asset_alias="a", target=target, collection=collection)
            with self.assertRaises(TransportError):
                capture_winrm_bundle(host="host.example", port=5985, user_env="FIXTURE_USER", password_env="FIXTURE_PASS", cases_dir=Path("ignored"), project_alias="p", asset_alias="a", target=target, collection=collection)

    def test_winrm_raw_reader_bounds_output_and_always_cleans_up(self) -> None:
        class FakeProtocol:
            def __init__(self, fail_cleanup=False): self.cleaned = False; self.closed = False; self.fail_cleanup = fail_cleanup
            def open_shell(self, **kwargs): return "shell"
            def run_command(self, *args): return "command"
            def get_command_output_raw(self, *args): return b"12345", b"", 0, True
            def cleanup_command(self, *args):
                self.cleaned = True
                if self.fail_cleanup: raise RuntimeError("cleanup")
            def close_shell(self, *args): self.closed = True
        protocol = FakeProtocol()
        with self.assertRaises(TransportError):
            _run_winrm_command(protocol, "cmd.exe", [], timeout=1, max_bytes=4)
        self.assertTrue(protocol.cleaned and protocol.closed)
        protocol = FakeProtocol(fail_cleanup=True)
        with self.assertRaises(TransportCleanupError):
            _run_winrm_command(protocol, "cmd.exe", [], timeout=1, max_bytes=10)
        self.assertTrue(protocol.closed)

    def test_winrm_fixture_uses_validated_https_and_fixed_query_catalog(self) -> None:
        calls = []
        class FakeProtocol:
            def __init__(self, url, **kwargs):
                calls.append((url, kwargs))
                self.pending = {}
                self.transport = types.SimpleNamespace(session=None)
                def build_session():
                    if self.transport.session is None:
                        self.transport.session = types.SimpleNamespace(trust_env=True, proxies={"https": "proxy"}, verify=False, send=lambda *a, **k: None)
                        calls.append(("new_session", self.transport.session))
                    return self.transport.session
                self.transport.build_session = build_session
            def open_shell(self, **kwargs):
                self.transport.build_session()
                calls.append(("open", kwargs)); return "shell"
            def run_command(self, shell, executable, arguments):
                calls.append((executable, tuple(arguments)))
                command_id = str(len(self.pending))
                output = b"C:\\Windows\n" if executable.endswith("cmd.exe") and "echo %SystemRoot%" in arguments else b"fixture output\n"
                self.pending[command_id] = output
                return command_id
            def get_command_output_raw(self, shell, command_id):
                return self.pending[command_id], b"", 0, True
            def cleanup_command(self, shell, command): calls.append(("cleanup", command))
            def close_shell(self, shell):
                calls.append(("close", shell)); self.transport.session = None
        winrm_module = types.ModuleType("winrm"); winrm_module.__path__ = []
        protocol_module = types.ModuleType("winrm.protocol"); protocol_module.Protocol = FakeProtocol
        target = {"os_family": "windows", "product": "Windows", "version": "unknown", "architecture": "x64", "use_case": "desktop", "scope": "basic"}
        collection = {"started_at": "2026-10-03T10:00:00+00:00", "finished_at": "2026-10-03T10:01:00+00:00", "timezone": "UTC", "privilege": "ordinary", "collector_version": "0.2", "command_catalog": "fixture"}
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"FIXTURE_USER": "user", "FIXTURE_PASS": "never-log-this"}, clear=False), patch.dict("sys.modules", {"winrm": winrm_module, "winrm.protocol": protocol_module}):
            bundle = capture_winrm_bundle(host="192.168.1.10", port=5986, user_env="FIXTURE_USER", password_env="FIXTURE_PASS", cases_dir=Path(temporary) / "cases", project_alias="p", asset_alias="a", target=target, collection=collection)
            self.assertTrue((bundle / "manifest.json").is_file())
            self.assertFalse(any("never-log-this" in path.read_text(encoding="utf-8", errors="ignore") for path in bundle.rglob("*.txt")))
        url, options = calls[0]
        self.assertTrue(url.startswith("https://"))
        self.assertEqual(options["server_cert_validation"], "validate")
        self.assertEqual(options["transport"], "ssl")
        self.assertEqual(len([x for x in calls if isinstance(x, tuple) and len(x) == 2 and x[0] not in {"open", "cleanup", "close", "new_session"} and not str(x[0]).startswith("https://")]), len(WINRM_COMMANDS) + 1)
        self.assertEqual(len([x for x in calls if x[0] == "cleanup"]), len(WINRM_COMMANDS) + 1)
        sessions = [x[1] for x in calls if x[0] == "new_session"]
        self.assertEqual(len(sessions), len(WINRM_COMMANDS) + 1)
        self.assertTrue(all(session.trust_env is False and session.proxies == {} and session.verify is True and session._pc_inspection_hardened for session in sessions))
        first_open = next(x for x in calls if x[0] == "open")
        self.assertNotIn("working_directory", first_open[1])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "utf16.txt"
            _write_capture_file(Path(temporary), output.name, "Name=中文CPU\r\n".encode("utf-16"), 0)
            content = output.read_bytes()
            self.assertTrue(content.startswith(b"\xef\xbb\xbf"))
            self.assertEqual(content.decode("utf-8-sig"), "Name=中文CPU\n")

    def test_ollama_uses_findings_limited_schema_and_rejects_invalid_suggestions(self) -> None:
        finding = {"finding_id": "R1", "title": "Wildcard bind", "severity": "Warning", "category": "redis", "evidence": {"raw": "should never leave"}}
        findings = [finding] + [{"finding_id": f"R{i}", "title": f"Fixture {i}", "severity": "Info", "category": "test"} for i in range(2, 18)]
        observed = []
        response_content = json.dumps({"suggestions": [{"text": "Review finding", "evidence_refs": ["R1"]}]})
        original_findings = copy.deepcopy(findings)
        def responder(_host, _port, method, path, payload, _timeout):
            observed.append((method, path, payload))
            if path == "/api/version": return {"version": "0.1.0"}
            if path == "/api/tags": return {"models": [{"name": "local-test", "model": "local-test", "digest": "a" * 64, "size": 1024, "details": {"format": "gguf"}}]}
            if path == "/api/show": return {"details": {"format": "gguf"}}
            return {"message": {"content": response_content}}
        with patch("analyzers.local_ai._request", side_effect=responder):
            result = local_ai.request_suggestions(provider="ollama", endpoint="http://127.0.0.1:11434", model="local-test", findings=findings, cloud_disabled_acknowledged=True)
        schema = observed[-1][2]["format"]
        self.assertEqual(schema["properties"]["suggestions"]["minItems"], 1)
        item_schema = schema["properties"]["suggestions"]["items"]["properties"]
        self.assertEqual(item_schema["evidence_refs"]["items"]["enum"], [f"R{i}" for i in range(1, 17)])
        self.assertEqual(item_schema["evidence_refs"]["minItems"], 1)
        self.assertEqual(item_schema["text"]["minLength"], 1)
        self.assertNotIn("R17", json.dumps(schema))
        self.assertIn("格式示例", observed[-1][2]["messages"][0]["content"])
        self.assertNotIn("should never leave", json.dumps(observed))
        self.assertEqual(result["suggestions"], [{"text": "Review finding", "evidence_refs": ["R1"]}])
        self.assertEqual(findings, original_findings)

        for invalid in (
            {},
            {"suggestions": []},
            {"suggestions": [{"text": "", "evidence_refs": ["R1"]}]},
            {"suggestions": [{"text": "   ", "evidence_refs": ["R1"]}]},
            {"suggestions": [{"text": "Review", "evidence_refs": []}]},
            {"suggestions": [{"text": "Review", "evidence_refs": ["R17"]}]},
        ):
            response_content = json.dumps(invalid)
            with patch("analyzers.local_ai._request", side_effect=responder), self.assertRaises(local_ai.LocalAIError):
                local_ai.request_suggestions(provider="ollama", endpoint="http://127.0.0.1:11434", model="local-test", findings=findings, cloud_disabled_acknowledged=True)

        response_content = "[" * 1200 + "0" + "]" * 1200
        with patch("analyzers.local_ai._request", side_effect=responder), self.assertRaises(local_ai.LocalAIError):
            local_ai.request_suggestions(provider="ollama", endpoint="http://127.0.0.1:11434", model="local-test", findings=findings, cloud_disabled_acknowledged=True)

        response_content = json.dumps({"suggestions": []})
        with patch("analyzers.local_ai._request", side_effect=responder):
            empty = local_ai.request_suggestions(provider="ollama", endpoint="http://127.0.0.1:11434", model="local-test", findings=[], cloud_disabled_acknowledged=True)
        self.assertEqual(empty["suggestions"], [])
        self.assertEqual(observed[-1][2]["format"]["properties"]["suggestions"]["minItems"], 0)

        def remote(*args, **kwargs):
            if args[3] == "/api/version": return {"version": "fixture"}
            return {"models": [{"name": "local-test", "model": "local-test", "digest": "a" * 64, "size": 1024, "details": {"format": "gguf"}, "remote_model": "remote"}]}
        with patch("analyzers.local_ai._request", side_effect=remote), self.assertRaises(local_ai.LocalAIError):
            local_ai.request_suggestions(provider="ollama", endpoint="http://127.0.0.1:11434", model="local-test", findings=[finding], cloud_disabled_acknowledged=True)


if __name__ == "__main__":
    unittest.main()
