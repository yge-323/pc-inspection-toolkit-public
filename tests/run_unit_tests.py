from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


TEST_FILES = (
    "test_markdown_report.py",
    "test_markdown_report_security_vendors.py",
    "test_risk_analyzer.py",
    "test_listener_risk.py",
    "test_listener_cli_integration.py",
    "test_linux_baseline.py",
    "test_paste_import.py",
    "test_rule_resolution.py",
    "test_rules_loader.py",
    "test_runtime_status.py",
    "test_run_inspection_security_vendors.py",
    "test_security_vendors.py",
    "test_startup_items.py",
    "test_restart_pipeline.py",
    "test_lifecycle.py",
    "test_transport_contracts.py",
    "test_desktop_app.py",
    "test_windows_security.py",
    "test_windows_disk_cli.py",
    "test_windows_capture_contract.py",
    "test_posix_capture_runner.py",
    "test_windows_capture_runner.py",
)


def main() -> int:
    if sys.flags.optimize:
        print("ERROR: unit tests must not run with python -O.", file=sys.stderr)
        return 2

    tests_dir = Path(__file__).resolve().parent
    project_root = tests_dir.parent
    child_env = os.environ.copy()
    child_env["PYTHONDONTWRITEBYTECODE"] = "1"
    existing_pythonpath = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = str(project_root) + (os.pathsep + existing_pythonpath if existing_pythonpath else "")

    for test_file in TEST_FILES:
        test_path = tests_dir / test_file
        if not test_path.is_file():
            print(f"ERROR: required unit test file is missing: {test_file}", file=sys.stderr)
            return 2

        print(f"[PYTHON MVP CORE OFFLINE] {test_file}", flush=True)
        try:
            result = subprocess.run(
                [sys.executable, str(test_path)],
                cwd=project_root,
                env=child_env,
                check=False,
            )
        except OSError as exc:
            print(f"ERROR: could not start {test_file}: {exc}", file=sys.stderr)
            return 2

        if result.returncode != 0:
            print(
                f"FAILED: {test_file} exited with code {result.returncode}.",
                file=sys.stderr,
            )
            return result.returncode

    print(f"All {len(TEST_FILES)} Python MVP core offline test files passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
