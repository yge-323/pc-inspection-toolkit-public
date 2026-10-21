from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence


PROJECT_ROOT = Path(__file__).resolve().parent
PRODUCT_NAME = "pc-inspection-toolkit"
SOURCE_FILES = (
    "inspection_cli.py", "run_inspection.py", "README.md", "desktop_app.py", "desktop_ui.py", "desktop_launcher.py",
    "i18n.py", "locales/__init__.py", "locales/findings.py", "locales/cli.py", "locales/desktop_errors.py",
    "locales/listener_translations.py", "locales/rule_translations.py",
    "docs/PRODUCT.md",
    "LICENSE",
    "analyzers/__init__.py", "analyzers/evidence_analyzer.py", "analyzers/lifecycle.py",
    "analyzers/listener_risk.py", "analyzers/linux_baseline.py", "analyzers/local_ai.py", "analyzers/risk_analyzer.py",
    "analyzers/windows_security_rules.py",
    "analyzers/windows_disk_rules.py",
    "collectors/__init__.py", "collectors/common.py", "collectors/disks.py",
    "collectors/event_logs.py", "collectors/firewall.py", "collectors/network_ports.py",
    "collectors/remote_desktop.py", "collectors/scheduled_tasks.py", "collectors/security_vendors.py",
    "collectors/services.py", "collectors/shares.py", "collectors/startup_items.py",
    "collectors/system_info.py", "collectors/users.py", "collectors/processes.py",
    "collectors/windows_security.py",
    "evidence/__init__.py", "evidence/bundle.py", "evidence/config_sanitizer.py", "evidence/paste.py", "evidence/transports.py",
    "models/__init__.py", "models/analysis.py", "models/finding.py",
    "reports/__init__.py", "reports/markdown_report.py", "reports/unified.py",
    "rules/loader.py",
    "rules/windows_risk_rules.example.json", "rules/platform_risk_rules.example.json",
    "rules/listener_knowledge.example.json",
    "rules/os_lifecycle.example.json",
    "platforms/__init__.py", "platforms/windows_capture.cmd", "platforms/inspect.ps1",
    "platforms/windows_capture_helpers.ps1", "platforms/bounded_windows_capture.vbs",
    "platforms/posix_capture.sh", "platforms/posix_paste_export.sh", "platforms/bounded_exec.pl",
    "config/local-profile.example.json", "config/windows-risk-rules.override.example.json",
)
PORTABLE_FILES = (
    "platforms/windows_capture.cmd", "platforms/inspect.ps1", "platforms/windows_capture_helpers.ps1",
    "platforms/posix_capture.sh", "platforms/posix_paste_export.sh", "platforms/bounded_exec.pl",
)
RESOURCE_FILES = (
    "rules/windows_risk_rules.example.json",
    "rules/platform_risk_rules.example.json",
    "rules/listener_knowledge.example.json",
    "rules/os_lifecycle.example.json",
)
EXTERNAL_CONFIG_EXAMPLES = (
    "config/local-profile.example.json",
    "config/windows-risk-rules.override.example.json",
)
RUNNER = Callable[..., subprocess.CompletedProcess[str]]


def _is_windows_build_host() -> bool:
    """Narrow platform seam so build-host behavior can be tested without patching os.name."""
    return sys.platform == "win32"


def _tool_version(cli_path: Path) -> str:
    try:
        match = re.search(r'^VERSION\s*=\s*["\']([^"\']+)', cli_path.read_text(encoding="utf-8"), re.MULTILINE)
        return match.group(1) if match else "unknown"
    except OSError:
        return "unknown"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Build a reproducible Windows onedir package and portable source bundle.")
    result.add_argument("--version", action="version", version=_tool_version(PROJECT_ROOT / "inspection_cli.py"))
    result.add_argument("--python", type=Path, default=PROJECT_ROOT / ".venv-build" / "Scripts" / "python.exe",
                        help="Build runtime (default: project .venv-build Windows Python).")
    result.add_argument("--output-root", type=Path, default=None,
                        help="New output directory under project outputs/; existing paths are rejected.")
    return result


def _default_output_root(outputs: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return outputs / "restart-build" / f"{stamp}-{uuid.uuid4().hex[:8]}"


def _refuse_existing_output(path: Path) -> None:
    if path.exists():
        raise FileExistsError("OUTPUT_ROOT_ALREADY_EXISTS")


def _inside_outputs(path: Path, outputs: Path) -> Path:
    candidate = path if path.is_absolute() else PROJECT_ROOT / path
    resolved = candidate.resolve()
    base = outputs.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError("OUTPUT_ROOT_MUST_BE_UNDER_PROJECT_OUTPUTS") from exc
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: Sequence[str], *, cwd: Path, runner: RUNNER) -> str:
    completed = runner(list(command), cwd=str(cwd), check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    return completed.stdout.strip()


def _validate_sources(root: Path) -> None:
    missing = [name for name in (*SOURCE_FILES, *PORTABLE_FILES) if not (root / name).is_file()]
    if missing:
        raise FileNotFoundError("ALLOWLIST_SOURCE_MISSING:" + ",".join(missing))


def _copy_allowlist(root: Path, destination: Path) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=False)
    copied: list[Path] = []
    for relative in SOURCE_FILES:
        source = root / relative
        target = destination / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append(target)
    for relative in PORTABLE_FILES:
        source = root / relative
        target = destination / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append(target)
    for relative in PORTABLE_FILES:
        source = root / relative
        target = destination / "platforms" / Path(relative).name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append(target)
    return copied


def _resource_args(root: Path) -> list[str]:
    result: list[str] = []
    for relative in (*RESOURCE_FILES, *PORTABLE_FILES):
        # PyInstaller's Windows add-data separator is a semicolon.
        result.extend(["--add-data", f"{root / relative};{Path(relative).parent.as_posix()}"])
    return result


def _write_package_readme(path: Path, manifest_name: str) -> None:
    text = f"""PC Inspection Toolkit portable package

Windows package: {PRODUCT_NAME}.exe is a PyInstaller onedir build. Keep the complete
windows/onedir folder together. Start the Chinese guided interface with
{PRODUCT_NAME}-desktop.exe in that same folder; the CLI executable remains available.
Clean-Windows and ordinary-user/administrator
permission acceptance remains pending. Synthetic embedded-resource analysis is
covered by source/build contract tests; check build_manifest.json for the exact scope.
This package build does not authorize or start collection.

Safe first commands (they only print help/version):
  {PRODUCT_NAME}.exe --help
  {PRODUCT_NAME}.exe --version

Do not run analyze-local until the operator has authority for local system inspection.
Other commands operate on explicitly supplied evidence paths. Review the command help.

portable/source/README.md contains the recommended GUI USB import/analyze flow
and the advanced CLI seal/import workflow with required target/collection metadata. portable/ contains allow-listed
Python source and bounded capture scripts. Its Linux
status is SOURCE_ONLY_NOT_LINUX_BUILT; no Linux binary or Linux execution claim is
included. Review source and dependencies on the target platform before use.

Build provenance and per-file hashes: {manifest_name}. Hashes bind this package to
the included working-tree bytes; they do not claim a clean/committed source snapshot.
"""
    path.write_text(text, encoding="utf-8", newline="\n")


def build_package(
    root: Path,
    python_executable: Path,
    output_root: Path,
    *,
    runner: RUNNER = subprocess.run,
) -> tuple[Path, Path]:
    if not _is_windows_build_host():
        raise RuntimeError("WINDOWS_BUILD_HOST_REQUIRED")
    _validate_sources(root)
    outputs = root / "outputs"
    output_root = _inside_outputs(output_root, outputs)
    _refuse_existing_output(output_root)
    if not python_executable.is_file():
        raise FileNotFoundError("BUILD_PYTHON_NOT_FOUND")

    run_id = uuid.uuid4().hex
    work_root = outputs / "work" / f"restart-build-{run_id}"
    work_root.parent.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(exist_ok=False)
    staging = work_root / "staging"
    dist = work_root / "dist"
    pyinstaller_work = work_root / "work"
    staging.mkdir()
    dist.mkdir()
    pyinstaller_work.mkdir()
    assembled = staging / "package"
    assembled.mkdir()
    (assembled / "windows").mkdir()

    try:
        runtime_version = _run([str(python_executable), "-B", "--version"], cwd=root, runner=runner)
        pyinstaller_version = _run([str(python_executable), "-B", "-m", "PyInstaller", "--version"], cwd=root, runner=runner)
        command = [str(python_executable), "-B", "-m", "PyInstaller", "--onedir",
                   "--name", PRODUCT_NAME, "--paths", str(root), "--distpath", str(dist),
                   "--workpath", str(pyinstaller_work), "--specpath", str(staging),
                   *_resource_args(root), str(root / "inspection_cli.py")]
        _run(command, cwd=root, runner=runner)
        built_dir = dist / PRODUCT_NAME
        executable = built_dir / f"{PRODUCT_NAME}.exe"
        if not executable.is_file():
            raise FileNotFoundError("PYINSTALLER_OUTPUT_MISSING")
        gui_work = pyinstaller_work / "desktop"
        gui_spec = staging / "desktop-spec"
        gui_work.mkdir()
        gui_spec.mkdir()
        gui_command = [str(python_executable), "-B", "-m", "PyInstaller", "--onefile", "--windowed",
                       "--name", PRODUCT_NAME + "-desktop", "--paths", str(root), "--distpath", str(dist),
                       "--workpath", str(gui_work), "--specpath", str(gui_spec), str(root / "desktop_launcher.py")]
        _run(gui_command, cwd=root, runner=runner)
        gui_executable = dist / (PRODUCT_NAME + "-desktop.exe")
        if not gui_executable.is_file():
            raise FileNotFoundError("PYINSTALLER_DESKTOP_OUTPUT_MISSING")
        shutil.copyfile(gui_executable, built_dir / gui_executable.name)
        shutil.copytree(built_dir, assembled / "windows" / "onedir")

        for relative in RESOURCE_FILES:
            target = assembled / "windows" / "onedir" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, target)
        for relative in EXTERNAL_CONFIG_EXAMPLES:
            target = assembled / "windows" / "onedir" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, target)
        _copy_allowlist(root, assembled / "portable")
        _write_package_readme(assembled / "README_PORTABLE.txt", "build_manifest.json")

        distributed_sources = list(dict.fromkeys([
            *(assembled / "portable" / "source" / name for name in SOURCE_FILES),
            *(assembled / "portable" / "source" / name for name in PORTABLE_FILES),
            *(assembled / "portable" / "platforms" / Path(name).name for name in PORTABLE_FILES),
            *(assembled / "windows" / "onedir" / name for name in (*RESOURCE_FILES, *EXTERNAL_CONFIG_EXAMPLES)),
            assembled / "windows" / "onedir" / f"{PRODUCT_NAME}.exe",
            assembled / "windows" / "onedir" / f"{PRODUCT_NAME}-desktop.exe",
        ]))
        included = sorted(distributed_sources, key=lambda p: p.relative_to(assembled).as_posix())
        hashes = [{"path": p.relative_to(assembled).as_posix(), "sha256": _sha256(p)} for p in included]
        source_hashes = [row for row in hashes if not row["path"].casefold().endswith(".exe")]
        executable_hashes = [row for row in hashes if row["path"].casefold().endswith(".exe")]
        source_relatives = list(dict.fromkeys((*SOURCE_FILES, *PORTABLE_FILES)))
        git_head = _run(["git", "rev-parse", "HEAD"], cwd=root, runner=runner)
        git_status = _run(["git", "status", "--porcelain", "--", *source_relatives], cwd=root, runner=runner)
        manifest = {
            "schema_version": 1,
            "tool_version": _tool_version(root / "inspection_cli.py"),
            "platform": {"windows": "onedir build created; clean-Windows and permission validation pending",
                          "linux": "SOURCE_ONLY_NOT_LINUX_BUILT"},
            "build_runtime": {"python": runtime_version, "pyinstaller": pyinstaller_version},
            "source": {"head": git_head, "dirty": bool(git_status),
                       "binding": "included working-tree file SHA-256; source_dirty is informational; not a committed-tree claim",
                       "included_source_files": source_hashes},
            "package_executables": executable_hashes,
            "acceptance": {"desktop_entry": "BUILT; GUI_INTERACTION_AND_CLEAN_WINDOWS_PENDING",
                           "clean_windows": "PENDING", "ordinary_user_vs_admin": "PENDING",
                           "synthetic_embedded_rule_analysis": "SOURCE_AND_BUILD_CONTRACT_TESTED; PACKAGED_EXE_RUNTIME_PENDING", "tag": "NONE"},
        }
        (assembled / "build_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        outputs.mkdir(parents=True, exist_ok=True)
        archive_path = outputs / f"{output_root.name}.zip"
        if archive_path.exists():
            raise FileExistsError("OUTPUT_ARCHIVE_ALREADY_EXISTS")
        work_archive = work_root / f"{output_root.name}.zip"
        with zipfile.ZipFile(work_archive, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in assembled.rglob("*"):
                if path.is_file():
                    archive.write(path, Path(output_root.name) / path.relative_to(assembled))
        output_root.parent.mkdir(parents=True, exist_ok=True)
        if output_root.exists():
            raise FileExistsError("OUTPUT_ROOT_ALREADY_EXISTS")
        os.rename(assembled, output_root)
        if archive_path.exists():
            raise FileExistsError("OUTPUT_ARCHIVE_ALREADY_EXISTS")
        os.rename(work_archive, archive_path)
        return output_root, archive_path
    except Exception:
        # Retain this unique work directory after failure for diagnosis.
        raise


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = PROJECT_ROOT
    outputs = root / "outputs"
    target = args.output_root if args.output_root else _default_output_root(outputs)
    try:
        target = _inside_outputs(target, outputs)
        _refuse_existing_output(target)
        output, archive = build_package(root, args.python.resolve(), target)
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError, subprocess.CalledProcessError, OSError) as exc:
        message = str(exc) if str(exc).isupper() and "\\" not in str(exc) else type(exc).__name__
        print(f"BUILD_FAILED={message}", file=sys.stderr)
        return 2
    print(f"PACKAGE={output}")
    print(f"ZIP={archive}")
    print("WINDOWS_CLEAN_HOST_VALIDATION=PENDING")
    print("LINUX=SOURCE_ONLY_NOT_LINUX_BUILT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
