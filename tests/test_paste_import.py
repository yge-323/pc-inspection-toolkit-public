from __future__ import annotations

import base64
import gzip
import hashlib
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidence.paste import PasteError, decode_paste_text, import_paste_text, materialize_paste_payload


def _build_paste(files: dict[str, bytes]) -> str:
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    raw = gzip.compress(tar_buf.getvalue())
    digest = hashlib.sha256(raw).hexdigest()
    b64 = base64.b64encode(raw).decode("ascii")
    chunk = b64
    return "\n".join([
        "-----BEGIN PC-INSPECTION-PASTE-----",
        "format=1",
        "encoding=gzip-tar-base64",
        f"payload_sha256={digest}",
        f"payload_bytes={len(raw)}",
        "chunks=1",
        "-----CHUNK 1/1-----",
        chunk,
        "-----END PC-INSPECTION-PASTE-----",
        "",
    ])


class PasteImportTests(unittest.TestCase):
    def test_round_trip_materialize(self) -> None:
        paste = _build_paste({
            "os.txt": b"Linux\n",
            "listeners.txt": b"tcp LISTEN 0 128 0.0.0.0:2375 0.0.0.0:*\n",
            "os.exit-code.txt": b"0\n",
            "listeners.exit-code.txt": b"0\n",
        })
        raw = decode_paste_text(paste)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            materialize_paste_payload(raw, dest)
            self.assertEqual((dest / "os.txt").read_text(encoding="utf-8"), "Linux\n")
            self.assertIn("2375", (dest / "listeners.txt").read_text(encoding="utf-8"))

    def test_rejects_path_traversal(self) -> None:
        paste = _build_paste({"../evil.txt": b"nope\n"})
        raw = decode_paste_text(paste)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            with self.assertRaises(PasteError):
                materialize_paste_payload(raw, dest)

    def test_hash_mismatch_fails(self) -> None:
        paste = _build_paste({"os.txt": b"x\n"})
        lines = []
        for line in paste.splitlines():
            if line.startswith("payload_sha256="):
                lines.append("payload_sha256=" + ("0" * 64))
            else:
                lines.append(line)
        with self.assertRaises(PasteError):
            decode_paste_text("\n".join(lines) + "\n")

    def test_import_paste_text_creates_dir(self) -> None:
        paste = _build_paste({"os.txt": b"ok\n", "os.exit-code.txt": b"0\n"})
        with tempfile.TemporaryDirectory() as tmp:
            path = import_paste_text(paste, Path(tmp))
            self.assertTrue((path / "os.txt").is_file())

    def test_posix_paste_export_script_round_trip(self) -> None:
        import os
        import subprocess
        script = ROOT / "platforms" / "posix_paste_export.sh"
        if not script.is_file() or os.name == "nt":
            self.skipTest("POSIX paste export script unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "evidence"
            src.mkdir()
            (src / "os.txt").write_text("Linux fixture\n", encoding="utf-8")
            (src / "os.exit-code.txt").write_text("0\n", encoding="utf-8")
            (src / "listeners.txt").write_text("tcp LISTEN 0.0.0.0:22\n", encoding="utf-8")
            (src / "listeners.exit-code.txt").write_text("0\n", encoding="utf-8")
            completed = subprocess.run(
                ["sh", str(script), str(src)],
                cwd=str(ROOT),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("-----CHUNK 1/", completed.stdout)
            self.assertNotIn("Illegal option", completed.stderr)
            dest_parent = Path(tmp) / "staging"
            path = import_paste_text(completed.stdout, dest_parent)
            self.assertEqual((path / "os.txt").read_text(encoding="utf-8"), "Linux fixture\n")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
