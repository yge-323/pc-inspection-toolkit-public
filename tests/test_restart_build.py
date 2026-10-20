from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path
from subprocess import CompletedProcess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import build_restart


class RestartBuildContractTests(unittest.TestCase):
    def test_allowlist_covers_cli_dynamic_local_chain_and_declared_resources(self) -> None:
        self.assertIn("inspection_cli.py", build_restart.SOURCE_FILES)
        self.assertIn("analyzers/listener_risk.py", build_restart.SOURCE_FILES)
        self.assertIn("desktop_launcher.py", build_restart.SOURCE_FILES)
        self.assertIn("desktop_app.py", build_restart.SOURCE_FILES)
        self.assertIn("desktop_ui.py", build_restart.SOURCE_FILES)
        self.assertIn("docs/PRODUCT.md", build_restart.SOURCE_FILES)
        self.assertIn("AGENTS.md", build_restart.SOURCE_FILES)
        self.assertIn("LICENSE", build_restart.SOURCE_FILES)
        self.assertIn("run_inspection.py", build_restart.SOURCE_FILES)
        for module in ("collectors/system_info.py", "collectors/security_vendors.py", "analyzers/risk_analyzer.py",
                       "evidence/bundle.py", "evidence/transports.py", "reports/unified.py", "rules/loader.py",
                       "platforms/__init__.py", "platforms/posix_capture.sh", "platforms/bounded_exec.pl"):
            self.assertIn(module, build_restart.SOURCE_FILES)
        self.assertEqual(set(build_restart.RESOURCE_FILES), {
            "rules/windows_risk_rules.example.json", "rules/platform_risk_rules.example.json",
            "rules/listener_knowledge.example.json", "rules/os_lifecycle.example.json",
        })
        self.assertFalse(any("local-profile.json" == item or item.startswith(("build/", "release/", "tools/", "work/"))
                             for item in build_restart.SOURCE_FILES))

    def test_output_root_must_be_new_and_under_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = root / "outputs"
            outputs.mkdir()
            destination = outputs / "new"
            self.assertEqual(build_restart._inside_outputs(destination, outputs), destination.resolve())
            with self.assertRaisesRegex(ValueError, "OUTPUT_ROOT_MUST_BE_UNDER_PROJECT_OUTPUTS"):
                build_restart._inside_outputs(root / "elsewhere", outputs)
            destination.mkdir()
            with self.assertRaises(FileExistsError):
                build_restart._refuse_existing_output(destination)

    def test_allowlisted_source_package_imports_cli_help_and_version_without_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            portable = Path(temporary) / "portable"
            build_restart._copy_allowlist(build_restart.PROJECT_ROOT, portable)
            entry = portable / "source" / "inspection_cli.py"
            for option, expected in (("--help", "usage:"), ("--version", "0.3.0-landable")):
                result = subprocess.run([sys.executable, "-B", str(entry), option], cwd=temporary,
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout.lower() if option == "--help" else result.stdout)

    def test_fake_build_binds_allowlisted_bytes_and_marks_platform_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (*build_restart.SOURCE_FILES, *build_restart.PORTABLE_FILES):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                content = 'VERSION = "0.2.0-test"\n' if relative == "inspection_cli.py" else f"fixture:{relative}\n"
                path.write_text(content, encoding="utf-8")
            (root / "outputs").mkdir()
            (root / "config" / "local-profile.json").write_text("private", encoding="utf-8")
            (root / "evidence" / "real-machine.txt").parent.mkdir(parents=True, exist_ok=True)
            (root / "evidence" / "real-machine.txt").write_text("private", encoding="utf-8")
            python = root / "python.exe"
            python.touch()
            output = root / "outputs" / "restart-build" / "candidate"
            calls: list[list[str]] = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if "PyInstaller" in command and "--version" in command:
                    return CompletedProcess(command, 0, "6.21.0\n")
                if "--version" in command and "PyInstaller" not in command:
                    return CompletedProcess(command, 0, "Python 3.12.10\n")
                if "PyInstaller" in command:
                    dist = Path(command[command.index("--distpath") + 1])
                    name = command[command.index("--name") + 1]
                    if "--onefile" in command:
                        dist.mkdir(parents=True, exist_ok=True)
                        (dist / f"{name}.exe").write_bytes(b"synthetic desktop executable")
                    else:
                        target = dist / name
                        target.mkdir(parents=True)
                        (target / f"{name}.exe").write_bytes(b"synthetic executable")
                    return CompletedProcess(command, 0, "simulated PyInstaller build\n")
                if command[:2] == ["git", "rev-parse"]:
                    return CompletedProcess(command, 0, "abc123\n")
                if command[:2] == ["git", "status"]:
                    return CompletedProcess(command, 0, "?? inspection_cli.py\n")
                raise AssertionError(f"unexpected command: {command}")

            with mock.patch.object(build_restart, "_is_windows_build_host", return_value=True):
                package, archive = build_restart.build_package(root, python, output, runner=fake_run)
            self.assertTrue((package / "windows" / "onedir" / "pc-inspection-toolkit.exe").is_file())
            self.assertTrue((package / "windows" / "onedir" / "pc-inspection-toolkit-desktop.exe").is_file())
            self.assertTrue((package / "windows" / "onedir" / "rules" / "os_lifecycle.example.json").is_file())
            self.assertTrue((package / "windows" / "onedir" / "rules" / "listener_knowledge.example.json").is_file())
            self.assertTrue((package / "portable" / "source" / "rules" / "listener_knowledge.example.json").is_file())
            self.assertTrue((package / "windows" / "onedir" / "config" / "local-profile.example.json").is_file())
            self.assertTrue((package / "windows" / "onedir" / "config" / "windows-risk-rules.override.example.json").is_file())
            self.assertTrue((package / "portable" / "source" / "inspection_cli.py").is_file())
            self.assertTrue((package / "portable" / "source" / "docs" / "PRODUCT.md").is_file())
            self.assertTrue((package / "portable" / "source" / "LICENSE").is_file())
            self.assertTrue((package / "portable" / "source" / "evidence" / "transports.py").is_file())
            self.assertTrue((package / "portable" / "source" / "platforms" / "posix_capture.sh").is_file())
            self.assertTrue((package / "portable" / "platforms" / "bounded_exec.pl").is_file())
            self.assertFalse((package / "portable" / "source" / "config" / "local-profile.json").exists())
            self.assertFalse((package / "portable" / "source" / "evidence" / "real-machine.txt").exists())
            manifest = json.loads((package / "build_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["source"]["head"], "abc123")
            self.assertTrue(manifest["source"]["dirty"])
            self.assertIn("working-tree file SHA-256", manifest["source"]["binding"])
            self.assertEqual(manifest["platform"]["linux"], "SOURCE_ONLY_NOT_LINUX_BUILT")
            self.assertEqual(manifest["acceptance"]["clean_windows"], "PENDING")
            self.assertIn("portable/source/inspection_cli.py",
                          [row["path"] for row in manifest["source"]["included_source_files"]])
            self.assertIn("portable/source/desktop_app.py",
                          [row["path"] for row in manifest["source"]["included_source_files"]])
            self.assertIn("portable/source/desktop_ui.py",
                          [row["path"] for row in manifest["source"]["included_source_files"]])
            self.assertIn("portable/source/docs/PRODUCT.md",
                          [row["path"] for row in manifest["source"]["included_source_files"]])
            self.assertIn("portable/source/LICENSE",
                          [row["path"] for row in manifest["source"]["included_source_files"]])
            self.assertEqual(manifest["acceptance"]["desktop_entry"], "BUILT; GUI_INTERACTION_AND_CLEAN_WINDOWS_PENDING")
            executable_paths = {row["path"] for row in manifest["package_executables"]}
            self.assertEqual(executable_paths, {"windows/onedir/pc-inspection-toolkit.exe",
                                                "windows/onedir/pc-inspection-toolkit-desktop.exe"})
            self.assertTrue(archive.is_file())
            with zipfile.ZipFile(archive) as zipped:
                names = zipped.namelist()
                self.assertTrue(any(name.endswith("/README_PORTABLE.txt") for name in names))
                self.assertFalse(any("real-machine.txt" in name or name.endswith("/local-profile.json") for name in names))
            build_calls = [call for call in calls if "PyInstaller" in call and "--version" not in call]
            self.assertEqual(len(build_calls), 2)
            command = next(call for call in build_calls if "--onedir" in call)
            self.assertIn("--onedir", command)
            self.assertNotIn("--clean", command)
            self.assertNotIn("--noconfirm", command)
            platform_resources = [item for item in command if isinstance(item, str) and ";platforms" in item]
            self.assertEqual(
                {Path(item.split(";", 1)[0]).name for item in platform_resources},
                {
                    "windows_capture.cmd",
                    "inspect.ps1",
                    "windows_capture_helpers.ps1",
                    "posix_capture.sh",
                    "posix_paste_export.sh",
                    "bounded_exec.pl",
                },
            )
            self.assertTrue(any(item.endswith("posix_capture.sh;platforms") for item in platform_resources))
            rule_resources = [item for item in command if isinstance(item, str) and ";rules" in item]
            self.assertEqual(len(rule_resources), 4)
            self.assertEqual(command[command.index("--distpath") + 1].startswith(str(root / "outputs" / "work")), True)
            gui_command = next(call for call in build_calls if "--onefile" in call)
            self.assertIn("--windowed", gui_command)
            self.assertTrue(gui_command[-1].endswith("desktop_launcher.py"))


if __name__ == "__main__":
    unittest.main()
