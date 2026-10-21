from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import inspection_cli
import run_inspection
from analyzers import local_ai
from models.analysis import AnalysisResult


class BilingualCLITests(unittest.TestCase):
    def _run_cli(self, script: str, *arguments: str,
                 extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "utf-8"
        environment.update(extra_env or {})
        return subprocess.run(
            [sys.executable, "-X", "utf8", "-B", str(ROOT / script), *arguments],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

    def test_inspection_cli_help_uses_requested_language_and_accepts_alias(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit_context:
            inspection_cli.main(["--language", "en", "--help"])
        self.assertEqual(exit_context.exception.code, 0)
        self.assertIn("Offline evidence inspection and reporting tool", output.getvalue())
        self.assertIn("Create a manifest", output.getvalue())
        self.assertIn("zh-CN|en-US|zh|en", output.getvalue())

    def test_legacy_help_uses_explicit_chinese_even_when_preference_is_english(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit_context:
            run_inspection.main(["--lang", "zh", "--help"])
        self.assertEqual(exit_context.exception.code, 0)
        self.assertIn("Windows 本地巡检工具", output.getvalue())
        self.assertIn("报告输出目录", output.getvalue())

    def test_cli_default_is_chinese_even_if_gui_preference_is_english(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            roaming = Path(temporary) / "roaming"
            preference = roaming / "PC Inspection Toolkit" / "preferences.json"
            preference.parent.mkdir(parents=True)
            preference.write_text(json.dumps({"schema_version": 1, "language": "en-US"}), encoding="utf-8")
            for script in ("inspection_cli.py", "run_inspection.py"):
                with self.subTest(script=script):
                    result = self._run_cli(script, "--help", extra_env={"APPDATA": str(roaming)})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("用法：", result.stdout)
                    self.assertIn("选项：", result.stdout)
                    self.assertNotIn("usage:", result.stdout)

    def test_real_cli_processes_localize_argparse_framework_text(self) -> None:
        root_help = self._run_cli("inspection_cli.py", "--lang", "zh", "--help")
        self.assertEqual(root_help.returncode, 0)
        for text in ("用法：", "位置参数：", "选项：", "显示此帮助信息并退出", "显示程序版本并退出"):
            self.assertIn(text, root_help.stdout)
        for text in ("usage:", "positional arguments:", "options:", "show this help message and exit", "show program's version number and exit"):
            self.assertNotIn(text, root_help.stdout)

        sub_help = self._run_cli("inspection_cli.py", "analyze", "--lang", "zh", "--help")
        self.assertEqual(sub_help.returncode, 0)
        self.assertIn("用法：", sub_help.stdout)
        self.assertIn("选项：", sub_help.stdout)
        self.assertIn("--report-lang", sub_help.stdout)
        self.assertIn("--report-language", sub_help.stdout)
        self.assertIn("选择报告语言；默认沿用 --lang", sub_help.stdout)
        self.assertNotIn("options:", sub_help.stdout)

        invalid = self._run_cli("inspection_cli.py", "--lang", "zh", "not-a-command")
        self.assertEqual(invalid.returncode, 2)
        self.assertIn("用法：", invalid.stderr)
        self.assertIn("参数错误：无效选项值", invalid.stderr)
        self.assertIn("not-a-command", invalid.stderr)
        self.assertNotIn("invalid choice:", invalid.stderr)

        missing_value = self._run_cli("inspection_cli.py", "--lang", "zh", "analyze", "case", "--output")
        self.assertEqual(missing_value.returncode, 2)
        self.assertIn("--output", missing_value.stderr)
        self.assertIn("缺少参数值", missing_value.stderr)
        self.assertNotIn("expected one argument", missing_value.stderr)

        invalid_float = self._run_cli("inspection_cli.py", "--lang", "zh", "analyze", "case", "--ai-timeout", "abc")
        self.assertEqual(invalid_float.returncode, 2)
        self.assertIn("--ai-timeout", invalid_float.stderr)
        self.assertIn("abc", invalid_float.stderr)
        self.assertIn("参数值类型无效", invalid_float.stderr)
        self.assertNotIn("invalid float value", invalid_float.stderr)

        legacy_help = self._run_cli("run_inspection.py", "--lang", "zh", "--help")
        self.assertEqual(legacy_help.returncode, 0)
        self.assertIn("用法：", legacy_help.stdout)
        self.assertIn("选项：", legacy_help.stdout)
        self.assertNotIn("options:", legacy_help.stdout)

        legacy_invalid = self._run_cli("run_inspection.py", "--lang", "zh", "--bogus")
        self.assertEqual(legacy_invalid.returncode, 2)
        self.assertIn("参数错误：", legacy_invalid.stderr)
        self.assertIn("无法识别的参数", legacy_invalid.stderr)
        self.assertIn("--bogus", legacy_invalid.stderr)
        self.assertNotIn("error:", legacy_invalid.stderr)

    def test_inspection_cli_passes_language_to_reports_and_keeps_protocol_values(self) -> None:
        manifest = {
            "project_alias": "p", "asset_alias": "a", "bundle_id": "B-1",
            "target": {"os_family": "linux"}, "items": [],
        }
        captured = {}
        def write_reports(_base, result, metadata, language):
            captured.setdefault("calls", []).append((language, result.status, metadata.copy()))
            return {"md": Path("report.md"), "html": Path("report.html"),
                    "csv": Path("findings.csv"), "json": Path("analysis.json")}

        output = io.StringIO()
        with patch("inspection_cli.validate_bundle", return_value=manifest), \
                patch("inspection_cli.analyze_evidence", return_value=AnalysisResult("PARTIAL")), \
                patch("inspection_cli._evidence_summary", return_value={}), \
                patch("inspection_cli.write_reports", side_effect=write_reports), \
                patch("inspection_cli.request_suggestions") as request_ai, \
                contextlib.redirect_stdout(output):
            status = inspection_cli.main(["analyze", "case", "--lang", "zh", "--report-lang", "en"])
            follow_status = inspection_cli.main(["analyze", "case", "--lang", "en"])

        self.assertEqual(status, 4)
        self.assertEqual(follow_status, 4)
        self.assertEqual([call[0] for call in captured["calls"]], ["en-US", "en-US"])
        self.assertEqual(captured["calls"][0][2]["ai_advisory"]["status"], "AI_NOT_RUN")
        request_ai.assert_not_called()
        lines = output.getvalue().splitlines()
        self.assertIn("ANALYSIS_STATUS=PARTIAL", lines)
        self.assertIn("AI_STATUS=AI_NOT_RUN", lines)
        self.assertTrue(any(line.startswith("INFO:") and "报告文件已生成" in line for line in lines))

    def test_report_language_override_changes_human_reports_but_not_analysis_json(self) -> None:
        sample_bundle = ROOT / "docs" / "examples" / "bilingual" / "source_bundle"
        self.assertTrue((sample_bundle / "manifest.json").is_file())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roaming = root / "roaming"
            preference = roaming / "PC Inspection Toolkit" / "preferences.json"
            preference.parent.mkdir(parents=True)
            preference.write_text(json.dumps({"schema_version": 1, "language": "en-US"}), encoding="utf-8")
            environment = {"APPDATA": str(roaming)}
            imported = self._run_cli("inspection_cli.py", "import", str(sample_bundle),
                                     "--cases", str(root / "cases"), extra_env=environment)
            self.assertEqual(imported.returncode, 0, imported.stderr)
            case_line = next((line for line in imported.stdout.splitlines() if line.startswith("CASE=")), None)
            self.assertIsNotNone(case_line, imported.stdout)
            case = case_line.split("=", 1)[1]

            zh_human_en_report = self._run_cli(
                "inspection_cli.py", "--report-lang", "en", "analyze", case,
                "--output", str(root / "rendered-zh-en"), extra_env=environment,
            )
            en_human_zh_report = self._run_cli(
                "inspection_cli.py", "analyze", case, "--output", str(root / "rendered-en-zh"),
                "--language", "en", "--report-language", "zh", extra_env=environment,
            )
            self.assertEqual(zh_human_en_report.returncode, 4, zh_human_en_report.stderr)
            self.assertEqual(en_human_zh_report.returncode, 4, en_human_zh_report.stderr)
            self.assertIn("INFO: 报告文件已生成。", zh_human_en_report.stdout)
            self.assertIn("INFO: Report files were created.", en_human_zh_report.stdout)
            self.assertIn("ANALYSIS_STATUS=PARTIAL", zh_human_en_report.stdout)
            self.assertIn("ANALYSIS_STATUS=PARTIAL", en_human_zh_report.stdout)

            def report_file(output: str, key: str) -> Path:
                line = next(line for line in output.splitlines() if line.startswith(f"{key}="))
                return Path(line.split("=", 1)[1])

            english_md = report_file(zh_human_en_report.stdout, "MD").read_text(encoding="utf-8")
            chinese_md = report_file(en_human_zh_report.stdout, "MD").read_text(encoding="utf-8")
            self.assertIn("# PC Inspection Evidence Analysis Report", english_md)
            self.assertIn("# PC 巡检证据分析报告", chinese_md)
            self.assertEqual(report_file(zh_human_en_report.stdout, "JSON").read_bytes(),
                             report_file(en_human_zh_report.stdout, "JSON").read_bytes())

    def test_local_ai_prompt_uses_selected_language_without_changing_schema(self) -> None:
        observed = []
        response = json.dumps({"suggestions": [{"text": "Review the applicable version.", "evidence_refs": ["R1"]}]})

        def responder(_host, _port, _method, path, payload, _timeout):
            observed.append((path, payload))
            if path == "/api/version": return {"version": "fixture"}
            if path == "/api/tags":
                return {"models": [{"name": "test-model", "model": "test-model", "digest": "a" * 64,
                                    "size": 10, "details": {"format": "gguf"}}]}
            if path == "/api/show": return {"details": {"format": "gguf"}}
            return {"message": {"content": response}}

        with patch("analyzers.local_ai._request", side_effect=responder):
            english_result = local_ai.request_suggestions(
                provider="ollama", endpoint="http://127.0.0.1:11434", model="test-model",
                findings=[{"finding_id": "R1", "title": "Review", "severity": "Warning"}],
                cloud_disabled_acknowledged=True, language="en",
            )
            chinese_result = local_ai.request_suggestions(
                provider="ollama", endpoint="http://127.0.0.1:11434", model="test-model",
                findings=[{"finding_id": "R1", "title": "Review", "severity": "Warning"}],
                cloud_disabled_acknowledged=True, language="zh",
            )

        prompts = [payload for _path, payload in observed if isinstance(payload, dict) and "messages" in payload]
        english_prompt = prompts[0]["messages"][0]["content"]
        chinese_prompt = prompts[-1]["messages"][0]["content"]
        self.assertIn("Respond in English", english_prompt)
        self.assertIn("请用简体中文", chinese_prompt)
        self.assertIn('"suggestions"', chinese_prompt)
        self.assertEqual(prompts[-1]["format"]["required"], ["suggestions"])
        self.assertEqual(english_result["suggestions"][0]["evidence_refs"], ["R1"])
        self.assertEqual(chinese_result["suggestions"][0]["evidence_refs"], ["R1"])
        self.assertEqual(english_result["label"], chinese_result["label"])
        self.assertEqual(english_result["status"], chinese_result["status"])

    def test_legacy_runner_uses_selected_language_for_report_and_preserves_raw_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = AnalysisResult("PARTIAL", warnings=["原始证据缺口"])
            rendered = {}
            with patch("run_inspection.application_root", return_value=root), \
                    patch("run_inspection.resolve_rule_configuration", return_value=object()), \
                    patch("run_inspection.logging.basicConfig"), \
                    patch("run_inspection.run_collection_pipeline", return_value=({"fixture": {"status": "partial", "data": {"fact": "原始中文事实"}, "warnings": [], "errors": []}}, result)), \
                    patch("run_inspection.render_report", side_effect=lambda *_args, **kwargs: rendered.update(kwargs)), \
                    contextlib.redirect_stdout(io.StringIO()):
                status = run_inspection.main(["--language", "zh", "--report-lang", "en"])

            self.assertEqual(status, 4)
            self.assertEqual(rendered["language"], "en-US")
            raw_path = next((root / "data" / "raw").glob("inspection-data-*.json"))
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            self.assertEqual(raw["collectors"]["fixture"]["data"]["fact"], "原始中文事实")
            self.assertEqual(raw["analysis"]["status"], "PARTIAL")

    def test_legacy_report_language_defaults_to_human_language(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = AnalysisResult("PARTIAL")
            rendered = {}
            with patch("run_inspection.application_root", return_value=root), \
                    patch("run_inspection.resolve_rule_configuration", return_value=object()), \
                    patch("run_inspection.logging.basicConfig"), \
                    patch("run_inspection.run_collection_pipeline", return_value=({}, result)), \
                    patch("run_inspection.render_report", side_effect=lambda *_args, **kwargs: rendered.update(kwargs)), \
                    contextlib.redirect_stdout(io.StringIO()):
                status = run_inspection.main(["--lang", "en"])
            self.assertEqual(status, 4)
            self.assertEqual(rendered["language"], "en-US")

    def test_local_ai_remains_opt_in_and_invalid_language_stops_before_request(self) -> None:
        with patch("analyzers.local_ai._request") as request:
            with self.assertRaises(local_ai.LocalAIError):
                local_ai.request_suggestions(
                    provider="ollama", endpoint="http://127.0.0.1:11434", model="test-model",
                    findings=[], cloud_disabled_acknowledged=False,
                )
            request.assert_not_called()

        with patch("analyzers.local_ai._request") as request:
            with self.assertRaises(ValueError):
                local_ai.request_suggestions(
                    provider="ollama", endpoint="http://127.0.0.1:11434", model="test-model",
                    findings=[], cloud_disabled_acknowledged=True, language="fr",
                )
            request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
