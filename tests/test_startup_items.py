from __future__ import annotations

import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.risk_analyzer import analyze
from collectors import startup_items
from reports.markdown_report import render_report
from rules.loader import load_rules


def test_collector_returns_facts_without_risk_policy_fields() -> None:
    original_system = startup_items.platform.system
    original_runner = startup_items.powershell_json

    def fake_runner(script: str, *, timeout: int):
        assert timeout == 30
        assert "CurrentVersion\\Run" in script
        assert "GetFolderPath('Startup')" in script
        assert "Protect-PciUserProfilePath" in script
        assert "Protect-UserProfilePath" not in script
        for forbidden in (
            "HighAttentionPaths",
            "ScriptInterpreters",
            "ScriptExtensions",
            "IsHighAttention",
            "Startup item review",
        ):
            assert forbidden not in script
        return {
            "Items": [{
                "Name": "MockStartup",
                "Command": r"C:\Mock\app.exe --start",
                "Location": "HKCU:MockRun",
                "Scope": "CurrentUser",
                "SourceType": "RegistryRun",
            }],
            "Findings": [],
            "Errors": [],
        }

    try:
        startup_items.platform.system = lambda: "Windows"
        startup_items.powershell_json = fake_runner
        result = startup_items.collect()
    finally:
        startup_items.platform.system = original_system
        startup_items.powershell_json = original_runner

    assert result["status"] == "ok"
    assert result["data"]["Findings"] == []
    item = result["data"]["Items"][0]
    assert item == {
        "Name": "MockStartup",
        "Command": r"C:\Mock\app.exe --start",
        "Location": "HKCU:MockRun",
        "Scope": "CurrentUser",
        "SourceType": "RegistryRun",
    }
    assert not set(item).intersection({
        "Risk", "Status", "Notes", "HighAttentionPaths", "ScriptInterpreters", "ScriptExtensions"
    })


def test_collector_failure_status_remains_compatible() -> None:
    original_system = startup_items.platform.system
    original_runner = startup_items.powershell_json

    def denied(_script: str, *, timeout: int):
        assert timeout == 30
        raise RuntimeError("Access is denied")

    try:
        startup_items.platform.system = lambda: "Windows"
        startup_items.powershell_json = denied
        result = startup_items.collect()
    finally:
        startup_items.platform.system = original_system
        startup_items.powershell_json = original_runner

    assert result["status"] == "need_admin"
    assert result["data"] == []
    assert result["errors"] == ["Access is denied"]


def test_report_ignores_legacy_collector_risk_fields_and_does_not_duplicate_finding() -> None:
    registry = load_rules(ROOT / "rules" / "windows_risk_rules.example.json")
    startup_result = {
        "collector": "startup_items",
        "status": "ok",
        "data": {
            "Items": [{
                "Name": "MockStartup",
                "Command": r"powershell.exe -File C:\Users\Mock\AppData\start.ps1",
                "Location": "HKCU:MockRun",
                "Scope": "CurrentUser",
                "SourceType": "RegistryRun",
                "Risk": "legacy-private-risk",
                "Status": "Warning",
                "HighAttentionPaths": ["legacy-private-path"],
            }],
            "Findings": [{"Risk": "legacy-private-risk", "Status": "Warning"}],
            "Errors": [],
        },
        "errors": [],
    }
    analysis = analyze({"startup_items": startup_result}, registry)
    target = [item for item in analysis if item.get("finding_id") == "WIN_STARTUP_SUSPICIOUS_PATH"]
    assert len(target) == 1

    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "report.md"
        render_report(
            {"startup_items": startup_result, "started_at": "mock"},
            analysis,
            output,
            Path(temp),
        )
        text = output.read_text(encoding="utf-8")

    assert text.count("启动项存在高关注路径或脚本解释器线索") == 1
    assert "legacy-private-risk" not in text
    assert "legacy-private-path" not in text
    assert "风险判断：统一由 AnalysisResult Findings 提供" in text


def main() -> int:
    test_collector_returns_facts_without_risk_policy_fields()
    test_collector_failure_status_remains_compatible()
    test_report_ignores_legacy_collector_risk_fields_and_does_not_duplicate_finding()
    print("Startup item boundary tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
