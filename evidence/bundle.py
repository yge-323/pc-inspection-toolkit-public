from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1.0"
MAX_FILES = 512
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
ALLOWED_SUFFIXES = {".txt", ".json", ".csv", ".xml", ".log"}
REQUIRED_MANIFEST = {
    "schema_version", "bundle_id", "project_alias", "asset_alias", "target", "collection", "items"
}
TARGET_KEYS = {"os_family", "product", "version", "architecture", "use_case", "scope"}
COLLECTION_KEYS = {"started_at", "finished_at", "timezone", "privilege", "collector_version", "command_catalog"}
ITEM_KEYS = {"path", "status", "reason", "size_bytes", "sha256", "source", "exit_code"}
ITEM_STATUSES = {"collected", "permission_denied", "tool_unavailable", "not_applicable", "failed", "not_checked", "parse_failed"}
ISO_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,7}))?(?P<zone>Z|[+-]\d{2}:?\d{2})$"
)


def parse_iso8601_timestamp(value: str) -> datetime:
    """Parse a strict timezone-aware timestamp on Python 3.10+, truncating 100ns precision."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be text")
    match = ISO_TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("timestamp must be ISO-8601 with an explicit timezone")
    fraction = match.group("fraction")
    zone = match.group("zone")
    if zone == "Z":
        zone = "+00:00"
    else:
        unsigned_offset = zone[1:].replace(":", "")
        offset_hours = int(unsigned_offset[:2])
        offset_minutes = int(unsigned_offset[2:])
        if offset_hours >= 24 or offset_minutes >= 60:
            raise ValueError("timestamp timezone offset is out of range")
        if len(zone) == 5:
            zone = f"{zone[:3]}:{zone[3:]}"
    timestamp = match.group("date")
    if fraction:
        # datetime stores microseconds; collector clocks can emit a seventh 100ns digit.
        timestamp += "." + fraction[:6].ljust(6, "0")
    parsed = datetime.fromisoformat(timestamp + zone)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include an explicit timezone")
    return parsed


class BundleError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_usable_partial_facts(lines: list[str]) -> bool:
    for line in lines:
        value = line.strip()
        if not value or value.startswith(("COLLECTOR_STATUS=", "COLLECTOR_NOTE=", "COLLECTOR_ERROR=")):
            continue
        if value in {"COLLECTION_TIMEOUT", "OUTPUT_LIMIT_EXCEEDED"}:
            continue
        return True
    return False


def write_manifest(root: Path, *, project_alias: str, asset_alias: str, target: dict[str, Any], collection: dict[str, Any]) -> Path:
    """Seal a pre-created text evidence directory; this does not authenticate its source."""
    if _is_reparse(root):
        raise BundleError("Evidence root may not be a symbolic link.")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise BundleError("Evidence root must be a directory.")
    scanned_paths = sorted(_walk_regular_tree(root))
    data_paths = {path for path in scanned_paths if path.is_file() and path.name != "manifest.json" and not path.name.endswith(".exit-code.txt")}
    expected_sidecars = {path.with_name(path.stem + ".exit-code.txt") for path in data_paths}
    orphan_sidecars = {path for path in scanned_paths if path.is_file() and path.name.endswith(".exit-code.txt")} - expected_sidecars
    if orphan_sidecars:
        raise BundleError("Unassociated exit-code sidecar is not allowed.")
    items: list[dict[str, Any]] = []
    for path in scanned_paths:
        if path.is_dir():
            rel_dir = path.relative_to(root).as_posix()
            _validate_relative_path(rel_dir)
            continue
        if path.name == "manifest.json" or path.name.endswith(".exit-code.txt"):
            continue
        if _is_reparse(path) or not path.is_file():
            raise BundleError("Evidence bundles may contain regular files only.")
        rel = path.relative_to(root).as_posix()
        _validate_relative_path(rel)
        if path.suffix.casefold() not in ALLOWED_SUFFIXES:
            raise BundleError(f"Unsupported evidence file type: {path.suffix}")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise BundleError(f"Evidence file exceeds size limit: {rel}")
        exit_path = path.with_name(path.stem + ".exit-code.txt")
        exit_code, sidecar_status = _read_exit_sidecar(exit_path)
        if sidecar_status == "MALFORMED":
            status, reason = "failed", "Exit status sidecar is malformed."
        elif sidecar_status and sidecar_status not in {"COLLECTED", "OK", "SUCCESS"}:
            status, reason = "failed", {
                "TIMEOUT": "The bounded collector timed out.",
                "FAILED": "The collector failed while gathering evidence.",
                "OUTPUT_LIMIT_EXCEEDED": "The bounded collector exceeded its output limit.",
                "CLEANUP_FAILED": "The bounded collector could not confirm child-process cleanup.",
            }.get(sidecar_status, "Bounded capture runner reported a non-success status.")
        else:
            raw = path.read_bytes()
            try:
                decoded = _decode_text(raw)
                first_line = decoded.splitlines()[0].strip() if decoded.splitlines() else ""
                parse_error = False
            except UnicodeError:
                first_line = raw[:128].decode("ascii", errors="ignore").splitlines()[0].strip() if raw else ""
                parse_error = True
            if not parse_error and not decoded.strip():
                status, reason = "failed", "Evidence text is empty or whitespace-only."
            elif first_line.startswith("COLLECTOR_STATUS=TOOL_UNAVAILABLE"):
                status, reason = "tool_unavailable", "The required native command was unavailable."
            elif first_line.startswith("COLLECTOR_STATUS=NEED_ADMIN"):
                status, reason = "permission_denied", "The current account could not read this evidence; retry only with authorized administrator access."
            elif first_line == "COLLECTOR_STATUS=PARTIAL":
                has_partial_facts = _has_usable_partial_facts(decoded.splitlines()[1:])
                if has_partial_facts:
                    status, reason = "collected", "The collector returned partial facts; see its notes and do not treat missing fields as passing."
                else:
                    status, reason = "failed", "The collector reported partial status without usable facts."
            elif first_line.startswith("COLLECTOR_STATUS=NOT_CHECKED"):
                status, reason = "not_checked", "Collector explicitly marked this evidence unavailable or excluded."
            elif first_line.startswith("COLLECTOR_STATUS=PARSE_FAILED"):
                status, reason = "parse_failed", "Collector could not safely identify the native output encoding."
            elif first_line.startswith("COLLECTOR_STATUS="):
                # Unknown markers must not be sealed as collected; validate_bundle rejects them.
                status, reason = "failed", "Unsupported collector status marker."
            elif parse_error:
                status, reason = "parse_failed", "Evidence text encoding is unknown or invalid; content was not decoded."
            elif first_line in {"COLLECTION_TIMEOUT", "OUTPUT_LIMIT_EXCEEDED"} or exit_code not in {0}:
                status, reason = "failed", "The bounded native command failed, timed out, exceeded output limit, or did not record an exit code."
            else:
                status, reason = "collected", ""
        if status == "collected" and path.suffix.casefold() not in ALLOWED_SUFFIXES:
            status, reason = "failed", "Unsupported evidence type."
        items.append({"path": rel, "status": status, "reason": reason, "size_bytes": size,
                      "sha256": sha256_file(path), "source": "configuration_sanitizer" if path.name.endswith("-config.json") else "native_collector", "exit_code": exit_code})
    if len(items) > MAX_FILES or sum(x["size_bytes"] for x in items) > MAX_TOTAL_BYTES:
        raise BundleError("Evidence bundle exceeds file-count or total-size limits.")
    manifest = {"schema_version": SCHEMA_VERSION, "bundle_id": str(uuid.uuid4()),
                "project_alias": _safe_alias(project_alias), "asset_alias": _safe_alias(asset_alias), "target": _validate_object(target, TARGET_KEYS, "target"),
                "collection": _validate_object(collection, COLLECTION_KEYS, "collection"), "items": items}
    if manifest["target"]["os_family"].casefold() not in {"windows", "linux", "macos"}:
        raise BundleError("Unsupported os_family.")
    _validate_collection_metadata(manifest["collection"])
    output = root / "manifest.json"
    if output.exists() or output.is_symlink():
        raise BundleError("Existing manifest will not be overwritten.")
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def stage_native_evidence(source: Path, destination: Path, *, allowed_names: set[str] | frozenset[str] | None = None) -> Path:
    """Copy a native evidence directory into a new local staging folder safely.

    The selected source is never modified. Links/reparse points and unexpected
    file types fail closed before copying; size and path limits match bundles.
    """
    if _is_reparse(source):
        raise BundleError("Evidence source may not be a symbolic link or reparse point.")
    source_root = source.resolve(strict=True)
    if not source_root.is_dir():
        raise BundleError("Evidence source must be a directory.")
    destination = destination.resolve(strict=False)
    try:
        destination.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise BundleError("Local staging destination must be outside the selected source.")
    try:
        source_root.relative_to(destination)
    except ValueError:
        pass
    else:
        raise BundleError("Staging destination may not contain the selected source.")
    paths = sorted(_walk_regular_tree(source_root), key=lambda item: item.as_posix())
    if allowed_names is not None:
        for path in paths:
            relative = path.relative_to(source_root)
            if len(relative.parts) != 1 or path.name not in allowed_names:
                raise BundleError("Evidence source contains a path outside the fixed native collector file allowlist.")
    files: list[Path] = []
    for path in paths:
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise BundleError("Evidence source may contain regular files and directories only.")
        files.append(path)
    if not files or len(files) > MAX_FILES * 2:
        raise BundleError("Evidence source is empty or exceeds the bounded entry count.")
    total = 0
    for path in files:
        rel = path.relative_to(source_root).as_posix()
        _validate_relative_path(rel)
        if path.name != "manifest.json" and not path.name.endswith(".exit-code.txt") and path.suffix.casefold() not in ALLOWED_SUFFIXES:
            raise BundleError("Evidence source contains an unsupported file type.")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise BundleError("Evidence source contains an oversized file.")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise BundleError("Evidence source exceeds the total-size limit.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or _is_reparse(destination):
        raise BundleError("Local staging path already exists or is unsafe.")
    destination.mkdir(exist_ok=False)
    try:
        for path in paths:
            relative = path.relative_to(source_root)
            target = destination.joinpath(*relative.parts)
            info = path.lstat()
            if _is_reparse(path):
                raise BundleError("Evidence source changed to a link during staging.")
            if stat.S_ISDIR(info.st_mode):
                target.mkdir(exist_ok=True)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise BundleError("Evidence source changed to a special file during staging.")
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            with path.open("rb") as source_stream, target.open("xb") as target_stream:
                while True:
                    chunk = source_stream.read(1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > MAX_FILE_BYTES:
                        raise BundleError("Evidence source grew beyond the file-size limit during staging.")
                    target_stream.write(chunk)
            if copied != info.st_size:
                raise BundleError("Evidence source changed while it was being staged.")
        return destination
    except Exception:
        if destination.exists() and not _is_reparse(destination):
            shutil.rmtree(destination)
        raise


def validate_bundle(root: Path) -> dict[str, Any]:
    if _is_reparse(root):
        raise BundleError("Bundle root may not be a symbolic link.")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise BundleError("Bundle must be a regular directory.")
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 1024 * 1024:
        raise BundleError("Missing or oversized manifest.json.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError("Manifest is not valid UTF-8 JSON.") from exc
    if not isinstance(manifest, dict) or set(manifest) != REQUIRED_MANIFEST:
        raise BundleError("Manifest has unsupported fields or missing required fields.")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise BundleError("Unsupported evidence schema version.")
    try:
        uuid.UUID(str(manifest["bundle_id"]))
    except (ValueError, TypeError) as exc:
        raise BundleError("bundle_id must be a UUID.") from exc
    _safe_alias(manifest.get("project_alias")); _safe_alias(manifest.get("asset_alias"))
    _validate_object(manifest.get("target"), TARGET_KEYS, "target")
    _validate_object(manifest.get("collection"), COLLECTION_KEYS, "collection")
    if manifest["target"]["os_family"].casefold() not in {"windows", "linux", "macos"}:
        raise BundleError("Unsupported os_family.")
    _validate_collection_metadata(manifest["collection"])
    items = manifest.get("items")
    if not isinstance(items, list) or len(items) > MAX_FILES:
        raise BundleError("items must be a bounded array.")
    seen: set[str] = set()
    total = 0
    listed: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != ITEM_KEYS:
            raise BundleError("Evidence item fields do not match schema.")
        rel = item.get("path")
        _validate_relative_path(rel)
        key = rel.casefold()
        if key in seen:
            raise BundleError("Duplicate evidence path.")
        seen.add(key); listed.add(rel)
        if Path(rel).suffix.casefold() not in ALLOWED_SUFFIXES:
            raise BundleError("Unsupported evidence file type.")
        if item.get("status") not in ITEM_STATUSES:
            raise BundleError("Unknown evidence status.")
        if not isinstance(item.get("reason"), str) or not isinstance(item.get("source"), str) or (item.get("exit_code") is not None and (not isinstance(item.get("exit_code"), int) or isinstance(item.get("exit_code"), bool))):
            raise BundleError("Invalid evidence source, reason, or exit code.")
        size = item.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > MAX_FILE_BYTES:
            raise BundleError("Invalid evidence size.")
        if not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", item["sha256"]):
            raise BundleError("Every evidence item requires a SHA-256 integrity record.")
        if item.get("status") == "collected" and (item.get("exit_code") != 0 or item.get("source") not in {"native_collector", "configuration_sanitizer"}):
            raise BundleError("Collected evidence requires an explicit successful exit status and recognized source.")
        file_path = root.joinpath(*PurePosixPath(rel).parts)
        _assert_contained_regular_file(root, file_path)
        sidecar = file_path.with_name(file_path.stem + ".exit-code.txt")
        sidecar_code, sidecar_status = _read_exit_sidecar(sidecar)
        if sidecar_status == "MALFORMED" or sidecar_code != item["exit_code"]:
            raise BundleError("Capture sidecar and manifest exit code disagree.")
        if sidecar_status and item["status"] == "collected" and sidecar_status not in {"OK", "SUCCESS", "COLLECTED"}:
            raise BundleError("Capture sidecar status disagrees with collected evidence.")
        if item["status"] == "collected" and sidecar_status is None and not sidecar.is_file():
            raise BundleError("Collected evidence is missing its explicit success sidecar.")
        actual_size = file_path.stat().st_size
        if actual_size != size or sha256_file(file_path) != item["sha256"].lower():
            raise BundleError(f"Evidence integrity mismatch: {rel}")
        if item["status"] == "collected":
            try:
                decoded = _decode_text(file_path.read_bytes())
                lines = decoded.splitlines()
                first_line = lines[0].strip() if lines else ""
                partial_has_facts = first_line == "COLLECTOR_STATUS=PARTIAL" and _has_usable_partial_facts(lines[1:])
                invalid_status_marker = first_line.startswith("COLLECTOR_STATUS=") and not partial_has_facts
                if not decoded.strip() or invalid_status_marker or first_line in {"COLLECTION_TIMEOUT", "OUTPUT_LIMIT_EXCEEDED"}:
                    raise BundleError("Collected evidence must contain usable text, not an empty result or status marker.")
            except UnicodeError as exc:
                raise BundleError("Collected evidence encoding is invalid.") from exc
        total += size
    if total > MAX_TOTAL_BYTES:
        raise BundleError("Bundle exceeds total-size limit.")
    for path in _walk_regular_tree(root):
        if path.is_file() and path.name != "manifest.json":
            rel = path.relative_to(root).as_posix()
            _validate_relative_path(rel)
            if path.name.endswith(".exit-code.txt"):
                _, state = _read_exit_sidecar(path)
                if state == "MALFORMED":
                    raise BundleError("Malformed capture status sidecar.")
                expected = {PurePosixPath(name).with_name(PurePosixPath(name).stem + ".exit-code.txt").as_posix() for name in listed}
                if rel not in expected:
                    raise BundleError("Unassociated exit-code sidecar is not allowed.")
            elif rel not in listed:
                raise BundleError("Unlisted files are not allowed in bundles.")
    return manifest


def import_bundle(root: Path, cases_dir: Path) -> Path:
    manifest = validate_bundle(root)
    source_root = root.resolve(strict=True)
    destination_root = cases_dir.resolve(strict=False)
    try:
        destination_root.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise BundleError("Case output directory must be outside the source bundle.")
    cases_dir.mkdir(parents=True, exist_ok=True)
    case_path = cases_dir / str(manifest["bundle_id"])
    if case_path.exists():
        raise BundleError("Duplicate bundle_id; existing case was preserved.")
    temp = cases_dir / ("." + str(uuid.uuid4()) + ".importing")
    try:
        shutil.copytree(root, temp, symlinks=False)
        validate_bundle(temp)
        os.replace(temp, case_path)
    except Exception:
        if temp.exists():
            shutil.rmtree(temp)
        raise
    return case_path


def _validate_relative_path(value: Any) -> None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BundleError("Evidence path must be a relative POSIX path.")
    path = PurePosixPath(value)
    if path.as_posix() != value:
        raise BundleError("Evidence path is not canonical.")
    for part in path.parts:
        stem = part.split(".", 1)[0].casefold()
        if (part in {"", ".", ".."} or ":" in part or part.endswith((".", " "))
                or stem in {"con", "prn", "aux", "nul"} or re.fullmatch(r"(?:com|lpt)[1-9]", stem)):
            raise BundleError("Unsafe Windows-compatible evidence path.")
    if path.is_absolute():
        raise BundleError("Unsafe evidence path.")


def _assert_contained_regular_file(root: Path, path: Path) -> None:
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise BundleError("Evidence path escapes the bundle root.") from exc
    if _is_reparse(path) or not path.is_file():
        raise BundleError("Evidence item is not a regular file.")


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag) or bool(getattr(path, "is_junction", lambda: False)())


def _walk_regular_tree(root: Path) -> list[Path]:
    """Enumerate without following symlinks, Windows junctions, or reparse points."""
    found: list[Path] = []
    stack = [root]
    while stack:
        parent = stack.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                if _is_reparse(path):
                    raise BundleError("Links and reparse points are forbidden in evidence bundles.")
                found.append(path)
                if len(found) > MAX_FILES * 5:
                    raise BundleError("Evidence directory tree has too many entries.")
                if len(path.relative_to(root).parts) > 32:
                    raise BundleError("Evidence directory tree is nested too deeply.")
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
    return found


def _read_exit_sidecar(path: Path) -> tuple[int | None, str | None]:
    if not path.exists():
        return None, None
    if _is_reparse(path) or not path.is_file():
        return None, "MALFORMED"
    try:
        lines = path.read_text(encoding="ascii").splitlines()
        if len(lines) == 1 and re.fullmatch(r"-?[0-9]{1,4}", lines[0]):
            return int(lines[0]), None
        if len(lines) == 2 and re.fullmatch(r"EXIT_CODE=-?[0-9]{1,4}", lines[0]) and re.fullmatch(r"STATUS=[A-Z_]{1,40}", lines[1]):
            return int(lines[0].split("=", 1)[1]), lines[1].split("=", 1)[1]
    except (OSError, UnicodeError, ValueError):
        pass
    return None, "MALFORMED"


def _validate_object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys or any(not isinstance(v, str) for v in value.values()):
        raise BundleError(f"{name} must contain exactly the documented string fields.")
    return value


def _safe_alias(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value.strip()):
        raise BundleError("Project and asset aliases must be short opaque ASCII labels (for example, asset-01).")
    return value.strip()


def _validate_collection_metadata(value: dict[str, Any]) -> None:
    parsed: dict[str, datetime] = {}
    for key in ("started_at", "finished_at"):
        try:
            parsed[key] = parse_iso8601_timestamp(value[key])
        except ValueError as exc:
            raise BundleError(f"{key} must be an ISO-8601 timestamp.") from exc
    if parsed["finished_at"] < parsed["started_at"]:
        raise BundleError("finished_at must not precede started_at.")
    if value["privilege"].casefold() not in {"unknown", "ordinary", "administrator", "root", "not_checked"}:
        raise BundleError("privilege must use a documented level.")


def _decode_text(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        value = data.decode("utf-8-sig", errors="strict")
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        value = data.decode("utf-16", errors="strict")
    else:
        value = data.decode("utf-8", errors="strict")
    return value.replace("\r\n", "\n").replace("\r", "\n")
