from __future__ import annotations

import json
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from evidence.bundle import BundleError, _decode_text, _is_reparse, import_bundle, parse_iso8601_timestamp, stage_native_evidence, validate_bundle, write_manifest

MAX_CHILD_SECONDS = 1860
MAX_CHILD_OUTPUT = 128 * 1024
USE_CASES = {
    "家用电脑": "home_pc",
    "办公电脑": "office_pc",
    "办公服务器": "office_server",
    "未知/其他": "unknown",
}
WINDOWS_NATIVE_FILES = frozenset({
    "collection_metadata.txt", "collection_start.txt", "collection_finish.txt", "os.txt", "os_detail.txt",
    "os_architecture.txt", "cpu.txt", "memory.txt", "graphics.txt", "disks.txt", "processes.txt", "services.txt",
    "listeners.txt", "firewall.txt", "privilege.txt", "accounts.txt", "startup_items.txt", "security_status.txt",
})
POSIX_NATIVE_FILES = frozenset({
    "collection_metadata.txt", "os.txt", "os_release.txt", "architecture.txt", "uptime.txt", "cpu_count.txt",
    "memory_summary.txt", "graphics_summary.txt", "disks.txt", "listeners.txt", "firewall.txt", "startup_items.txt",
    "services.txt", "privilege.txt", "accounts.txt", "security_status.txt", "packages_security.txt",
})
NATIVE_RAW_ALLOWED_NAMES = frozenset(
    set(WINDOWS_NATIVE_FILES | POSIX_NATIVE_FILES)
    | {Path(name).stem + ".exit-code.txt" for name in WINDOWS_NATIVE_FILES | POSIX_NATIVE_FILES}
)


def application_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def cli_command(arguments: list[str]) -> list[str]:
    root = application_root()
    if getattr(sys, "frozen", False):
        executable = root / "pc-inspection-toolkit.exe"
        if not executable.is_file():
            raise FileNotFoundError("便携目录缺少命令行程序 pc-inspection-toolkit.exe")
        return [str(executable), *arguments]
    return [sys.executable, "-B", str(root / "inspection_cli.py"), *arguments]


def _normalize_wmic_time(value: str) -> datetime:
    match = re.fullmatch(r"(\d{14})(?:\.(\d{1,6}))?([+-]\d{3,4})", value.strip())
    if not match:
        raise ValueError("WMI 本地时间证据缺少有效 UTC 偏移")
    offset_text = match.group(3)
    offset_minutes = int(offset_text)
    instant = datetime.strptime(match.group(1), "%Y%m%d%H%M%S")
    fraction = (match.group(2) or "").ljust(6, "0")
    instant = instant.replace(microsecond=int(fraction or "0"))
    return instant.replace(tzinfo=timezone(timedelta(minutes=offset_minutes)))


def _normalize_collection_time(text: str) -> datetime:
    """Accept only the fixed bounded runner's WMI or ISO-8601 UTC clock output."""
    lines = [line.strip() for line in text.replace("\r", "\n").splitlines() if line.strip()]
    if len(lines) == 1 and lines[0].startswith("LocalDateTime="):
        return _normalize_wmic_time(lines[0].split("=", 1)[1])
    if len(lines) == 1:
        return parse_iso8601_timestamp(lines[0])
    raise ValueError("采集时间输出格式不受支持")


def _read_evidence_text(root: Path, name: str) -> str:
    path = root / name
    if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        return ""
    return _decode_text(path.read_bytes())


def derive_native_metadata(root: Path, use_case: str) -> tuple[dict[str, str], dict[str, str]]:
    """Derive bundle facts only from fixed collector evidence and its metadata file."""
    if use_case not in set(USE_CASES.values()):
        raise ValueError("请选择列表中的实际用途。")
    metadata_text = _read_evidence_text(root, "collection_metadata.txt")
    values: dict[str, str] = {}
    for line in metadata_text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"started_at", "finished_at", "started_wmic", "finished_wmic", "timezone", "privilege", "collector_version", "command_catalog"}:
            if key in values:
                raise ValueError(f"采集元数据字段重复：{key}")
            values[key] = value.strip()
    try:
        if "started_wmic" in values or "finished_wmic" in values:
            started = _normalize_wmic_time(values["started_wmic"])
            finished = _normalize_wmic_time(values["finished_wmic"])
            timezone_name = "Windows WMI local UTC offset"
        elif "started_at" in values or "finished_at" in values:
            started = parse_iso8601_timestamp(values["started_at"])
            finished = parse_iso8601_timestamp(values["finished_at"])
            timezone_name = values.get("timezone", "unknown")
        else:
            started = _normalize_collection_time(_read_evidence_text(root, "collection_start.txt"))
            finished = _normalize_collection_time(_read_evidence_text(root, "collection_finish.txt"))
            timezone_name = "采集器记录的时区偏移"
    except (KeyError, ValueError) as exc:
        raise ValueError("证据未含可信格式的真实采集起止时间；不会使用文件时间代替，请用新版固定采集器重新采集。") from exc
    if started.tzinfo is None or started.utcoffset() is None or finished.tzinfo is None or finished.utcoffset() is None:
        raise ValueError("采集时间缺少明确时区，证据不能被封装为可比较时间。")
    if finished < started:
        raise ValueError("采集结束时间早于开始时间，证据元数据冲突，不能封装。")
    privilege = values.get("privilege", "unknown").casefold()
    if privilege not in {"unknown", "ordinary", "administrator", "root", "not_checked"}:
        privilege = "unknown"
    collector_version = values.get("collector_version", "unknown")
    catalog = values.get("command_catalog", "")
    if not collector_version or not catalog or not re.fullmatch(r"[a-z0-9_,.-]{1,500}", catalog):
        raise ValueError("采集器版本或固定命令目录元数据缺失/无效，不能封装。")
    collection = {
        "started_at": started.isoformat(), "finished_at": finished.isoformat(),
        "timezone": timezone_name, "privilege": privilege,
        "collector_version": collector_version[:100], "command_catalog": catalog,
    }

    target: dict[str, str] = {"os_family": "unknown", "product": "unknown", "version": "unknown", "architecture": "unknown",
                              "use_case": use_case, "scope": "basic"}
    windows_detail = _read_evidence_text(root, "os_detail.txt")
    if windows_detail:
        facts = _key_value_lines(windows_detail)
        arch_facts = _key_value_lines(_read_evidence_text(root, "os_architecture.txt"))
        arch = arch_facts.get("PROCESSOR_ARCHITEW6432") or arch_facts.get("PROCESSOR_ARCHITECTURE", "")
        target.update({"os_family": "windows", "product": facts.get("Caption", "unknown"),
                       "version": facts.get("Version", "unknown"),
                       "architecture": _normalize_arch(arch)})
    else:
        release = _read_evidence_text(root, "os_release.txt")
        os_text = _read_evidence_text(root, "os.txt")
        arch_text = _read_evidence_text(root, "architecture.txt")
        if release and ("ProductName:" in release or "ProductVersion:" in release or "Darwin" in os_text):
            facts = _key_value_lines(release)
            target.update({"os_family": "macos", "product": facts.get("ProductName", "macOS"),
                           "version": facts.get("ProductVersion", "unknown"), "architecture": _normalize_arch(arch_text.strip())})
        elif release or "linux" in os_text.casefold():
            facts = _key_value_lines(release)
            name = facts.get("NAME")
            version = facts.get("VERSION_ID")
            if not name and release.strip():
                first = release.splitlines()[0].strip()
                name = first
                version_match = re.search(r"(?i)(?:release|version)\s+([0-9][A-Za-z0-9._-]*)", first)
                version = version_match.group(1) if version_match else "unknown"
            target.update({"os_family": "linux", "product": name or "unknown", "version": version or "unknown",
                           "architecture": _normalize_arch(arch_text.strip())})
    if target["os_family"] == "unknown":
        raise ValueError("不能从固定证据识别 Windows/Linux/macOS；不会猜测目标平台。")
    expected_catalogs = {
        "windows": "collection_time,os,os_detail,os_architecture,cpu,memory,graphics,disks,processes,services,listeners,firewall,privilege,accounts,startup_items,security_status",
        "linux": "os,os_release,architecture,uptime,cpu_count,memory_summary,graphics_summary,disks,listeners,firewall,startup_items,services,privilege,accounts,security_status,packages_security",
        "macos": "os,os_release,architecture,uptime,cpu_count,memory_summary,graphics_summary,disks,listeners,firewall,startup_items,services,privilege,accounts,security_status,packages_security",
    }
    if catalog != expected_catalogs[target["os_family"]]:
        raise ValueError("采集命令目录与已识别的平台采集器不匹配或未受支持。")
    expected_files = set(POSIX_NATIVE_FILES)
    if target["os_family"] == "windows":
        expected_files = set(WINDOWS_NATIVE_FILES)
    missing_files = sorted(name for name in expected_files if not (root / name).is_file())
    if missing_files:
        raise ValueError("固定采集命令目录与输出文件不一致：" + ", ".join(missing_files))
    if any(path.is_dir() for path in root.iterdir()):
        raise ValueError("固定原生采集目录不得包含子目录。")
    expected_names = expected_files | {Path(name).stem + ".exit-code.txt" for name in expected_files}
    actual_names = {path.name for path in root.iterdir() if path.is_file()}
    extras = sorted(actual_names - expected_names)
    if extras:
        raise ValueError("原生采集目录含固定目录之外的文件，不会封装：" + ", ".join(extras[:20]))
    return target, collection


def _key_value_lines(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            # sw_vers output and similar native key/value facts use a colon.
            if ":" in line:
                key, value = line.split(":", 1)
                key, value = key.strip(), value.strip()
            else:
                continue
        else:
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
        if key and value:
            previous = values.get(key)
            if previous is not None and previous != value:
                raise ValueError(f"固定证据包含互相冲突的重复事实：{key}")
            values.setdefault(key, value)
    return values


def _normalize_arch(value: str) -> str:
    key = value.strip().casefold()
    return {"amd64": "x86_64", "x64": "x86_64", "x86_64": "x86_64", "x86": "x86",
            "i386": "x86", "i686": "x86", "arm64": "aarch64", "aarch64": "aarch64"}.get(key, "unknown")


def _read_process_output(command: list[str], *, timeout: int, cancelled: threading.Event,
                         on_output: Callable[[str], None]) -> int:
    flags = (subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "CREATE_NO_WINDOW", 0)) if os.name == "nt" else 0
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, shell=False, creationflags=flags,
                               start_new_session=(os.name != "nt"))
    output = bytearray()

    def drain() -> None:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(4096)
            if not chunk:
                break
            room = MAX_CHILD_OUTPUT - len(output)
            if room > 0:
                output.extend(chunk[:room])

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    started = time.monotonic()
    termination_reason: str | None = None
    while process.poll() is None:
        if cancelled.wait(0.1):
            termination_reason = "用户取消"
            cleanup_ok = _terminate_child_tree(process)
            break
        if time.monotonic() - started >= timeout:
            termination_reason = "操作超过时间上限"
            cleanup_ok = _terminate_child_tree(process)
            break
    else:
        cleanup_ok = True
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    reader.join(timeout=3)
    if reader.is_alive():
        raise RuntimeError("子进程输出管道未能在期限内关闭；请检查本次操作是否已停止。")
    if process.stdout is not None:
        process.stdout.close()
    on_output(bytes(output).decode("utf-8-sig", errors="replace"))
    if termination_reason:
        if not cleanup_ok:
            raise RuntimeError("请求停止后，无法确认所有本程序启动的子进程均已退出。")
        raise TimeoutError(termination_reason)
    return int(process.returncode or 0)


def _terminate_child_tree(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is not None:
        return True
    if os.name == "nt":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        taskkill = Path(root) / "System32" / "taskkill.exe"
        tree_stopped = False
        if taskkill.is_file():
            try:
                result = subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=6, check=False, shell=False)
                tree_stopped = result.returncode == 0
            except subprocess.TimeoutExpired:
                pass
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            return False
        return tree_stopped
    else:
        try:
            os.killpg(process.pid, 15)
        except OSError:
            process.kill()
            return True
        deadline = time.monotonic() + 1.0
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        try:
            os.killpg(process.pid, 9)
        except OSError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            return False
        try:
            os.killpg(process.pid, 0)
        except OSError:
            return True
        return False


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    startup_check = args == ["--startup-check"]
    if args and not startup_check:
        if sys.stderr is not None:
            print("Only the internal --startup-check option is accepted.", file=sys.stderr)
        return 2
    try:
        import tkinter as tk
    except ImportError:
        if sys.stderr is not None:
            print("Tkinter is unavailable; use inspection_cli.py.", file=sys.stderr)
        return 2
    from desktop_ui import InspectionDesktop
    root = tk.Tk()
    if startup_check:
        root.withdraw()
    InspectionDesktop(root)
    if startup_check:
        root.update_idletasks()
        root.destroy()
        return 0
    root.mainloop()
    return 0
