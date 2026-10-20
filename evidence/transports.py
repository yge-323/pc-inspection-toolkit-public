from __future__ import annotations

import os
import gzip
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

from evidence.bundle import BundleError, MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES, _decode_text, _validate_relative_path, write_manifest


SSH_MAX_ARCHIVE = MAX_TOTAL_BYTES + 1024 * 1024
SSH_MAX_DECOMPRESSED_BYTES = MAX_TOTAL_BYTES + MAX_FILES * 2048 + 64 * 1024
SSH_COMMAND_TIMEOUT = 600
WINRM_READ_TIMEOUT = 8
WINRM_COMMAND_TIMEOUT = 30
WINRM_CLEANUP_TIMEOUT = 10
WINRM_MAX_SOAP_BYTES = 1024 * 1024
WINRM_COMMANDS: dict[str, tuple[str, list[str], str]] = {
    "os": ("cmd.exe", ["/d", "/c", "ver"], "os.txt"),
    "os_detail": ("wmic.exe", ["os", "get", "Caption,Version,OSArchitecture", "/value"], "os_detail.txt"),
    "cpu": ("wmic.exe", ["cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors", "/value"], "cpu.txt"),
    "memory": ("wmic.exe", ["computersystem", "get", "TotalPhysicalMemory", "/value"], "memory.txt"),
    "graphics": ("wmic.exe", ["path", "Win32_VideoController", "get", "Name,AdapterRAM", "/value"], "graphics.txt"),
    "disks": ("wmic.exe", ["logicaldisk", "get", "DeviceID,FreeSpace,Size,FileSystem", "/value"], "disks.txt"),
    "services": ("sc.exe", ["query", "type=", "service", "state=", "all"], "services.txt"),
    "listeners": ("netstat.exe", ["-ano"], "listeners.txt"),
    "firewall": ("netsh.exe", ["advfirewall", "show", "allprofiles"], "firewall.txt"),
}
NOT_CHECKED_FILES = {
    "privilege.txt": "COLLECTOR_STATUS=NOT_CHECKED_PRIVILEGE",
    "accounts.txt": "COLLECTOR_STATUS=NOT_CHECKED_ACCOUNT_MEMBERSHIP_PRIVACY",
    "startup_items.txt": "COLLECTOR_STATUS=NOT_CHECKED_STARTUP_COMMAND_PRIVACY",
    "security_status.txt": "COLLECTOR_STATUS=NOT_CHECKED_PATCH_SECURITY_PRODUCT",
}


class TransportError(ValueError):
    pass


def capability_status() -> dict[str, str]:
    try:
        import importlib.util
        winrm_available = importlib.util.find_spec("winrm") is not None
    except (ImportError, ValueError):
        winrm_available = False
    return {"ssh": "available" if shutil.which("ssh") else "tool_unavailable",
            "winrm": "available" if winrm_available else "dependency_unavailable"}


def _validate_common(target: dict[str, Any], collection: dict[str, Any], project_alias: str, asset_alias: str) -> None:
    from evidence.bundle import _safe_alias, _validate_collection_metadata, _validate_object, COLLECTION_KEYS, TARGET_KEYS
    _safe_alias(project_alias); _safe_alias(asset_alias)
    _validate_object(target, TARGET_KEYS, "target")
    _validate_object(collection, COLLECTION_KEYS, "collection")
    _validate_collection_metadata(collection)


def _new_bundle(cases_dir: Path, *, project_alias: str, asset_alias: str, target: dict[str, Any], collection: dict[str, Any]) -> Path:
    _validate_common(target, collection, project_alias, asset_alias)
    if str(target.get("os_family", "")).casefold() not in {"windows", "linux", "macos"}:
        raise TransportError("Unsupported target operating system family.")
    cases_dir.mkdir(parents=True, exist_ok=True)
    stage = cases_dir / ("capture-" + str(uuid.uuid4()))
    stage.mkdir(mode=0o700)
    return stage


def _write_capture_file(root: Path, name: str, data: bytes, status_code: int, *, encoding_known: bool = True) -> None:
    output = root / name
    if len(data) > MAX_FILE_BYTES:
        data = b"COLLECTOR_STATUS=OUTPUT_LIMIT_EXCEEDED\n"
        status_code = 125
    normalized = None
    if encoding_known:
        try:
            if data.startswith((b"\xff\xfe", b"\xfe\xff")):
                normalized = data.decode("utf-16", errors="strict")
            elif data.startswith(b"\xef\xbb\xbf"):
                normalized = data.decode("utf-8-sig", errors="strict")
            else:
                normalized = data.decode("utf-8", errors="strict")
        except UnicodeError:
            encoding_known = False
    if not encoding_known and status_code == 0:
        data = b"COLLECTOR_STATUS=PARSE_FAILED_ENCODING_UNKNOWN\n"
    elif encoding_known and normalized is not None:
        data = b"\xef\xbb\xbf" + normalized.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            data = b"COLLECTOR_STATUS=OUTPUT_LIMIT_EXCEEDED\n"
            status_code = 125
    output.write_bytes(data)
    code = status_code if encoding_known else (status_code or 65)
    output.with_name(output.stem + ".exit-code.txt").write_text(f"{code}\n", encoding="ascii")


def _finish_bundle(root: Path, *, project_alias: str, asset_alias: str, target: dict[str, Any], collection: dict[str, Any]) -> Path:
    for name, marker in NOT_CHECKED_FILES.items():
        output = root / name
        if not output.exists():
            output.write_text(marker + "\n", encoding="ascii")
            output.with_name(output.stem + ".exit-code.txt").write_text("0\n", encoding="ascii")
    write_manifest(root, project_alias=project_alias, asset_alias=asset_alias, target=target, collection=collection)
    return root


def _ssh_arguments(host: str, user: str, port: int, known_hosts: Path, *, agent_auth: bool = False) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", host) or host.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user):
        raise TransportError("SSH host or user has unsafe syntax.")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise TransportError("SSH port must be between 1 and 65535.")
    if known_hosts.is_symlink() or not known_hosts.is_file() or known_hosts.stat().st_size > 4 * 1024 * 1024:
        raise TransportError("An existing bounded known_hosts file is required; automatic host-key acceptance is disabled.")
    if not agent_auth or not os.environ.get("SSH_AUTH_SOCK"):
        raise TransportError("SSH requires explicit --agent-auth and an existing SSH_AUTH_SOCK; private-key files are not read.")
    known_value = known_hosts.resolve().as_posix()
    if any(ord(ch) < 32 for ch in known_value) or any(ch in known_value for ch in ('"', "'", "%")):
        raise TransportError("known_hosts path contains characters unsupported by strict OpenSSH configuration parsing.")
    client = shutil.which("ssh")
    if not client:
        raise TransportError("OpenSSH client is unavailable.")
    return [client, "-F", os.devnull, "-T", "-p", str(port), "-l", user, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f'UserKnownHostsFile="{known_value}"', "-o", "GlobalKnownHostsFile=none",
            "-o", "IdentityAgent=SSH_AUTH_SOCK", "-o", "IdentityFile=none", "-o", "CertificateFile=none",
            "-o", "ClearAllForwardings=yes", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", host, "sh", "-s"]


def _ssh_wrapper(capture_script: bytes, bounded_runner: bytes, remote_id: str) -> bytes:
    if not re.fullmatch(r"[a-z0-9-]{8,48}", remote_id):
        raise TransportError("Invalid temporary remote path token.")
    script = capture_script.decode("utf-8", errors="strict")
    final_notice = "printf '%s\\n' 'Capture finished. Review individual statuses before sealing or transfer.'"
    if final_notice not in script:
        raise TransportError("Native capture script version is not recognized.")
    script = script.replace(final_notice, ":")
    delimiter = "PC_INSPECTION_" + remote_id.upper().replace("-", "_")
    if any(line.strip() == delimiter for line in script.splitlines()) or any(line.strip() == delimiter for line in bounded_runner.decode("utf-8").splitlines()):
        raise TransportError("Temporary script delimiter collision.")
    prefix = (f"set -eu\nd=/tmp/pc-inspection-{remote_id}\n(umask 077; mkdir \"$d\") || exit 2\n"
              "trap 'rm -rf \"$d\"' 0 1 2 15\n"
              f"cat >\"$d/bounded_exec.pl\" <<'{delimiter}_PERL'\n").encode("ascii")
    mid = (f"\n{delimiter}_PERL\ncat >\"$d/posix_capture.sh\" <<'{delimiter}_SH'\n").encode("ascii")
    suffix = (f"\n{delimiter}_SH\nsh \"$d/posix_capture.sh\" \"$d/evidence\" || :\ntar -czf - -C \"$d\" evidence\n").encode("ascii")
    return prefix + bounded_runner + mid + script.encode("utf-8") + suffix


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
        try:
            subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
    else:
        import signal
        try:
            os.killpg(process.pid, signal.SIGTERM)
            time.sleep(0.5)
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _extract_tar(root: Path, archive_data: bytes | Path) -> None:
    if (archive_data.stat().st_size if isinstance(archive_data, Path) else len(archive_data)) > SSH_MAX_ARCHIVE:
        raise TransportError("SSH capture archive exceeds the size limit.")
    count = total = 0
    seen: set[str] = set()
    fileobj = archive_data.open("rb") if isinstance(archive_data, Path) else BytesIO(archive_data)
    try:
        with fileobj, gzip.GzipFile(fileobj=fileobj, mode="rb") as decompressed:
            budgeted = _BudgetReader(decompressed, SSH_MAX_DECOMPRESSED_BYTES)
            with tarfile.open(fileobj=budgeted, mode="r|") as archive:
                for member in archive:
                    count += 1
                    if count > MAX_FILES * 2 + 32 or not (member.isdir() or member.isfile()) or member.issym() or member.islnk():
                        raise TransportError("SSH capture archive contains unsupported entry types or too many entries.")
                    rel = PurePosixPath(member.name)
                    if rel.is_absolute() or not rel.parts or rel.parts[0] != "evidence" or any(x in {"", ".", ".."} for x in rel.parts):
                        raise TransportError("SSH capture archive path is unsafe.")
                    inner = PurePosixPath(*rel.parts[1:]).as_posix()
                    if inner:
                        _validate_relative_path(inner)
                    if member.isdir():
                        continue
                    if inner.casefold() in seen:
                        raise TransportError("SSH capture archive contains duplicate paths.")
                    seen.add(inner)
                    if member.size > MAX_FILE_BYTES:
                        raise TransportError("SSH capture file exceeds the size limit.")
                    total += member.size
                    if total > MAX_TOTAL_BYTES:
                        raise TransportError("SSH capture archive exceeds the total evidence size limit.")
                    destination = root.joinpath(*PurePosixPath(*rel.parts[1:]).parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise TransportError("SSH capture archive file could not be read.")
                    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        remaining = member.size
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise TransportError("SSH capture archive is truncated.")
                            stream.write(chunk)
                            remaining -= len(chunk)
    except TransportError:
        raise
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise TransportError("SSH capture returned an invalid archive.") from exc


class _BudgetReader:
    def __init__(self, stream: Any, limit: int) -> None:
        self.stream = stream
        self.limit = limit
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.total
        request = remaining + 1 if size is None or size < 0 else min(size, remaining + 1)
        chunk = self.stream.read(request)
        self.total += len(chunk)
        if self.total > self.limit:
            raise TransportError("SSH archive decompressed metadata/data exceeds the size budget.")
        return chunk


def capture_ssh_bundle(*, host: str, user: str, port: int, known_hosts: Path, cases_dir: Path,
                       project_alias: str, asset_alias: str, target: dict[str, Any], collection: dict[str, Any],
                       timeout: int = SSH_COMMAND_TIMEOUT, agent_auth: bool = False) -> Path:
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= 900:
        raise TransportError("SSH capture timeout must be 10 to 900 seconds.")
    args = _ssh_arguments(host, user, port, known_hosts, agent_auth=agent_auth)
    base = Path(__file__).resolve().parents[1]
    wrapper = _ssh_wrapper((base / "platforms" / "posix_capture.sh").read_bytes(),
                           (base / "platforms" / "bounded_exec.pl").read_bytes(), uuid.uuid4().hex)
    stage = _new_bundle(cases_dir, project_alias=project_alias, asset_alias=asset_alias, target=target, collection=collection)
    archive_path = stage / ".capture.tar.gz"
    start = time.monotonic()
    try:
        with archive_path.open("xb") as output:
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                                       creationflags=creation_flags, start_new_session=(os.name != "nt"))
            assert process.stdin is not None
            write_errors: list[BaseException] = []
            def write_request() -> None:
                try:
                    process.stdin.write(wrapper)
                    process.stdin.close()
                except (BrokenPipeError, OSError) as exc:
                    write_errors.append(exc)
            writer = threading.Thread(target=write_request, daemon=True)
            writer.start()
            while process.poll() is None or writer.is_alive():
                if time.monotonic() - start > timeout or os.fstat(output.fileno()).st_size > SSH_MAX_ARCHIVE:
                    _terminate_process_tree(process)
                    raise TransportError("SSH capture timed out or exceeded the archive size limit.")
                time.sleep(0.1)
            if process.returncode != 0:
                raise TransportError("SSH capture failed; check host authorization, pinned key, permissions, and remote command availability.")
            if write_errors:
                raise TransportError("SSH request stream was interrupted.")
        if archive_path.stat().st_size > SSH_MAX_ARCHIVE:
            raise TransportError("SSH capture archive exceeds the size limit.")
        _extract_tar(stage, archive_path)
        archive_path.unlink()
        return _finish_bundle(stage, project_alias=project_alias, asset_alias=asset_alias, target=target, collection=collection)
    except Exception:
        archive_path.unlink(missing_ok=True)
        shutil.rmtree(stage, ignore_errors=True)
        raise


def capture_winrm_bundle(*, host: str, port: int, user_env: str, password_env: str, cases_dir: Path,
                         project_alias: str, asset_alias: str, target: dict[str, Any], collection: dict[str, Any]) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", host) or host.startswith("-") or not 1 <= port <= 65535:
        raise TransportError("WinRM requires an explicit host and valid HTTPS port; HTTP and redirects are unsupported.")
    username, password = os.environ.get(user_env), os.environ.get(password_env)
    if not user_env or not password_env or not username or not password:
        raise TransportError("WinRM credentials must be supplied via explicitly named environment variables.")
    try:
        from winrm.protocol import Protocol  # type: ignore[import-not-found]
    except ImportError as exc:
        raise TransportError("Optional pywinrm dependency is unavailable; no install was attempted.") from exc
    protocol = Protocol(f"https://{host}:{port}/wsman", username=username, password=password, transport="ssl",
                         server_cert_validation="validate", ca_trust_path=None, operation_timeout_sec=5,
                         read_timeout_sec=WINRM_READ_TIMEOUT, proxy=None)
    _harden_winrm_protocol(protocol)
    stage = _new_bundle(cases_dir, project_alias=project_alias, asset_alias=asset_alias, target=target, collection=collection)
    try:
        root_bytes, root_code = _run_winrm_command(protocol, "cmd.exe", ["/d", "/c", "echo %SystemRoot%"], timeout=WINRM_COMMAND_TIMEOUT, max_bytes=4096)
        try:
            system_root = _decode_text(root_bytes).strip().splitlines()[-1]
        except (UnicodeError, IndexError) as exc:
            raise TransportError("WinRM could not safely identify the target SystemRoot.") from exc
        if root_code != 0 or not re.fullmatch(r"[A-Za-z]:\\(?:[A-Za-z0-9 _.-]+\\?)+", system_root) or ".." in system_root:
            raise TransportError("WinRM returned an invalid or unavailable SystemRoot.")
        for _command_id, (executable, arguments, filename) in WINRM_COMMANDS.items():
            try:
                if executable == "cmd.exe":
                    command = system_root + r"\System32\cmd.exe"
                elif executable == "wmic.exe":
                    command = system_root + r"\System32\wbem\wmic.exe"
                else:
                    command = system_root + "\\System32\\" + executable
                data, code = _run_winrm_command(protocol, command, arguments, timeout=WINRM_COMMAND_TIMEOUT,
                                                max_bytes=MAX_FILE_BYTES, working_directory=system_root + "\\System32")
                _write_capture_file(stage, filename, data, code)
            except TransportCleanupError:
                raise
            except Exception:
                _write_capture_file(stage, filename, b"COLLECTOR_STATUS=FAILED_WINRM_QUERY\n", 126)
        return _finish_bundle(stage, project_alias=project_alias, asset_alias=asset_alias, target=target, collection=collection)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


class TransportCleanupError(TransportError):
    pass


def _harden_winrm_protocol(protocol: Any) -> None:
    transport = getattr(protocol, "transport", None)
    original_build = getattr(transport, "build_session", None)
    if not callable(original_build):
        raise TransportError("Installed pywinrm lacks the session hooks required for bounded, proxy-free HTTPS.")

    def build_hardened_session() -> Any:
        session = original_build()
        if not all(hasattr(session, name) for name in ("send", "trust_env", "proxies", "verify")):
            raise TransportError("Installed pywinrm session does not expose required security controls.")
        if getattr(session, "_pc_inspection_hardened", False):
            return session
        session.trust_env = False
        session.proxies = {}
        session.verify = True
        original_send = session.send

        def bounded_send(request: Any, **kwargs: Any) -> Any:
            deadline = getattr(protocol, "_pc_inspection_deadline", None)
            remaining = deadline - time.monotonic() if isinstance(deadline, (int, float)) else WINRM_READ_TIMEOUT
            if remaining <= 0:
                raise TimeoutError("WinRM total command deadline exceeded.")
            configured_timeout = kwargs.get("timeout", WINRM_READ_TIMEOUT)
            if isinstance(configured_timeout, tuple):
                kwargs["timeout"] = tuple(min(float(x), remaining) for x in configured_timeout)
            else:
                kwargs["timeout"] = min(float(configured_timeout), remaining)
            kwargs["allow_redirects"] = False
            kwargs["stream"] = True
            response = original_send(request, **kwargs)
            if 300 <= response.status_code < 400:
                response.close()
                raise TransportError("WinRM redirects are rejected.")
            body = bytearray()
            try:
                for chunk in response.iter_content(chunk_size=16 * 1024):
                    if deadline is not None and time.monotonic() >= deadline:
                        raise TimeoutError("WinRM total command deadline exceeded while reading SOAP response.")
                    if len(body) + len(chunk) > WINRM_MAX_SOAP_BYTES:
                        raise TransportError("WinRM SOAP response exceeded the per-message size limit.")
                    body.extend(chunk)
                response._content = bytes(body)
                response._content_consumed = True
                return response
            except Exception:
                response.close()
                raise

        session.send = bounded_send
        session._pc_inspection_hardened = True
        return session

    transport.build_session = build_hardened_session
    # Force capability validation before the first target request. Subsequent
    # close_session() calls reset the transport, so every later session passes
    # through this same guarded builder.
    build_hardened_session()


def _run_winrm_command(protocol: Any, executable: str, arguments: list[str], *, timeout: int, max_bytes: int,
                       working_directory: str | None = None) -> tuple[bytes, int]:
    shell_id = None
    command_id = None
    stdout = bytearray()
    stderr_size = 0
    deadline = time.monotonic() + timeout
    protocol._pc_inspection_deadline = deadline
    try:
        options = {"codepage": 65001}
        if working_directory is not None:
            options["working_directory"] = working_directory
        shell_id = protocol.open_shell(**options)
        if time.monotonic() >= deadline:
            raise TimeoutError
        command_id = protocol.run_command(shell_id, executable, arguments)
        if time.monotonic() >= deadline:
            raise TimeoutError
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError
            try:
                out, err, status, done = protocol.get_command_output_raw(shell_id, command_id)
            except Exception as exc:
                if type(exc).__name__ == "WinRMOperationTimeoutError":
                    if time.monotonic() < deadline:
                        continue
                    raise TimeoutError from exc
                raise
            if out:
                if len(stdout) + stderr_size + len(out) > max_bytes:
                    raise TransportError("WinRM query exceeded its bounded output size.")
                stdout.extend(out)
            if err:
                stderr_size += len(err)
                if len(stdout) + stderr_size > max_bytes:
                    raise TransportError("WinRM query exceeded its bounded output size.")
            if done:
                return bytes(stdout), int(status)
    except TimeoutError as exc:
        raise TransportError("WinRM fixed query exceeded its wall-clock deadline.") from exc
    finally:
        cleanup_error = None
        protocol._pc_inspection_deadline = time.monotonic() + WINRM_CLEANUP_TIMEOUT
        if shell_id is not None and command_id is not None:
            try:
                protocol.cleanup_command(shell_id, command_id)
            except Exception as exc:
                cleanup_error = exc
        if shell_id is not None:
            try:
                protocol.close_shell(shell_id)
            except Exception as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise TransportCleanupError("WinRM command/shell cleanup could not be confirmed; further target queries were stopped.") from cleanup_error
        protocol._pc_inspection_deadline = None
