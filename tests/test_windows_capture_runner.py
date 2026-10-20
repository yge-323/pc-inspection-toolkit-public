"""Windows-only fixture tests for the bounded WSH runner.

These tests patch a temporary copy of the runner's fixed command map. They do
not invoke any real inspection command and add no test mode to the shipped VBS.
"""
from __future__ import annotations

import shutil
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evidence.bundle import parse_iso8601_timestamp  # noqa: E402

RUNNER = ROOT / "platforms" / "bounded_windows_capture.vbs"


@unittest.skipUnless(__import__("os").name == "nt", "requires Windows Script Host")
class BoundedWindowsCaptureRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cscript = shutil.which("cscript.exe")
        if not cls.cscript:
            raise unittest.SkipTest("cscript.exe is unavailable")
        cls.temp = tempfile.TemporaryDirectory(
            prefix="capture-fixture-", dir=ROOT / "work"
        )
        cls.base = Path(cls.temp.name)
        cls.runner = cls.base / "fixture_runner.vbs"
        source = RUNNER.read_text(encoding="utf-8")
        replacements = {
            "os": "echo FIXTURE_OK",
            "cpu": "cmd.exe /d /c exit 7",
            "memory": "ping.exe -n 30 127.0.0.1",
            "graphics": 'call "' + str(cls.base / "large fixture.cmd") + '"',
            "disks": 'call "' + str(cls.base / "tree fixture.cmd") + '"',
        }
        for command_id, command in replacements.items():
            pattern = rf'(?m)^    Case "{command_id}": CommandFor = .*?$'
            source, count = re.subn(
                pattern,
                lambda _match, c=command: (
                    f'    Case "{command_id}": CommandFor = "{c.replace(chr(34), chr(34) * 2)}"'
                ),
                source,
                count=1,
            )
            if count != 1:
                raise AssertionError(f"runner command map entry missing: {command_id}")
        cls.runner.write_text(source, encoding="utf-16")
        cls.output_marker = cls.base / "output-ready.marker"
        (cls.base / "large fixture.cmd").write_text(
            "@echo off\r\nfor /L %%i in (1,1,100000) do echo FIXTURE_OUTPUT\r\n"
            f'echo READY>"{cls.output_marker}"\r\n'
            "rem Keep stdout open and the leader active until the runner observes the byte bound.\r\n"
            "ping.exe -n 30 127.0.0.1 > nul\r\n",
            encoding="ascii",
        )
        cls.marker = cls.base / "child survived.txt"
        child_cmd = cls.base / "tree fixture.cmd"
        child_cmd.write_text(
            '@echo off\r\n'
            'start "" /b cmd.exe /d /c "ping.exe -n 12 127.0.0.1 > nul & echo SURVIVED > "'
            + str(cls.marker)
            + '""\r\n'
            'ping.exe -n 30 127.0.0.1 > nul\r\n',
            encoding="ascii",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def run_capture(self, name: str, command_id: str, timeout: int = 10,
                    byte_limit: int = 8192) -> subprocess.CompletedProcess[str]:
        output = self.base / "capture fixture 中文" / name
        output.parent.mkdir(exist_ok=True)
        return subprocess.run(
            [self.cscript, "//nologo", str(self.runner), str(output), command_id,
             str(timeout), str(byte_limit)],
            capture_output=True, text=True, timeout=20, check=False,
        )

    def run_with_runner(
        self,
        runner: Path,
        name: str,
        command_id: str,
        timeout: int = 10,
        byte_limit: int = 8192,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        output = self.base / "capture fixture 中文" / name
        output.parent.mkdir(exist_ok=True)
        result = subprocess.run(
            [self.cscript, "//nologo", str(runner), str(output), command_id,
             str(timeout), str(byte_limit)],
            capture_output=True, text=True, timeout=20, check=False,
        )
        return result, output

    def sidecar(self, name: str) -> str:
        return (self.base / "capture fixture 中文" /
                (Path(name).stem + ".exit-code.txt")).read_text(encoding="ascii")

    def test_size_getter_refreshes_read_only_without_reading_output(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        getter = source.split("Function TryGetFileSize(path, sizeValue, errorCode)", 1)[1]
        getter = getter.split("End Function", 1)[0]
        self.assertIn("fso.OpenTextFile(path, 1, False, 0)", getter)
        self.assertIn("fileStream.Close", getter)
        self.assertNotRegex(getter, r"\.\s*(?:Read|ReadAll|Write|WriteLine)\b")

    def size_failure_runner(
        self,
        name: str,
        condition: str,
        *,
        before_normalize: bool = False,
        after_normalize_write: bool = False,
    ) -> Path:
        source = self.runner.read_text(encoding="utf-16")
        source = source.replace(
            "Dim cleanupOK, resultCode, statusText, sizeError, sizeUnavailable",
            "Dim cleanupOK, resultCode, statusText, sizeError, sizeUnavailable, "
            "sizeInjectPath, sizeInjected, injectMarker",
            1,
        )
        source = source.replace(
            "outputPath = args(0)",
            "outputPath = args(0)\r\n"
            f'sizeInjectPath = "{self.base / (name + ".inject")}"\r\n'
            "sizeInjected = False",
            1,
        )
        injection = r'''  If fso.FileExists(sizeInjectPath) And Not sizeInjected And CONDITION Then
    sizeInjected = True
    TryGetFileSize = False
    sizeValue = -1
    errorCode = 70
    Exit Function
  End If
'''.replace("CONDITION", condition)
        function_signature = "Function TryGetFileSize(path, sizeValue, errorCode)"
        source = source.replace(function_signature, function_signature + "\r\n" + injection, 1)
        if function_signature + "\r\n" + injection not in source:
            raise AssertionError("TryGetFileSize injection point missing")
        if before_normalize:
            marker = "  encodingResult = NormalizeOutput("
            create_marker = (
                '  Set injectMarker = fso.CreateTextFile(sizeInjectPath, False, False)\r\n'
                "  injectMarker.Close\r\n"
            )
            source, count = source.replace(marker, create_marker + marker, 1), source.count(marker)
            if count != 1:
                raise AssertionError("NormalizeOutput injection point missing")
        if after_normalize_write:
            marker = "  If Not TryGetFileSize(path, normalizedSize, sizeError) Then"
            create_marker = (
                '  Set injectMarker = fso.CreateTextFile(sizeInjectPath, False, False)\r\n'
                "  injectMarker.Close\r\n"
            )
            source, count = source.replace(marker, create_marker + marker, 1), source.count(marker)
            if count != 1:
                raise AssertionError("post-normalization size injection point missing")
        runner = self.base / (name + ".vbs")
        runner.write_text(source, encoding="utf-16")
        return runner

    def test_quotes_unicode_path_and_success_exit_code(self) -> None:
        result = self.run_capture("success output.txt", "os")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "", "runner emitted a VBScript error")
        contents = (self.base / "capture fixture 中文" /
                    "success output.txt").read_text(encoding="utf-8-sig")
        self.assertIn("FIXTURE_OK", contents)
        sidecar = self.sidecar("success output.txt")
        self.assertEqual(sidecar.splitlines(), ["EXIT_CODE=0", "STATUS=OK"],
                         f"sidecar={sidecar!r}; output={(self.base / 'capture fixture 中文' / 'success output.txt').read_bytes()!r}")

    def test_empty_output_is_a_valid_zero_byte_input(self) -> None:
        source = self.runner.read_text(encoding="utf-16")
        pattern = r'(?m)^    Case "os": CommandFor = .*?$'
        source, count = re.subn(
            pattern,
            '    Case "os": CommandFor = "cmd.exe /d /c exit 0"',
            source,
            count=1,
        )
        self.assertEqual(count, 1)
        runner = self.base / "empty-output-runner.vbs"
        runner.write_text(source, encoding="utf-16")
        result, output = self.run_with_runner(runner, "empty output.txt", "os")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.sidecar("empty output.txt").splitlines(), ["EXIT_CODE=0", "STATUS=OK"])
        self.assertEqual(output.read_bytes(), b"\xef\xbb\xbf")

    def test_collection_time_uses_bounded_native_clock_command(self) -> None:
        result = self.run_capture("collection time.txt", "collection_time", timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "", "runner emitted a VBScript error")
        output = (self.base / "capture fixture 中文" / "collection time.txt").read_text(encoding="utf-8-sig").strip()
        if output.startswith("LocalDateTime="):
            stamp = output.split("=", 1)[1]
            self.assertRegex(stamp, r"^\d{14}(?:\.\d{1,6})?[+-]\d{3,4}$")
        else:
            parsed = parse_iso8601_timestamp(output)
            self.assertIsNotNone(parsed.tzinfo)
            self.assertEqual(parsed.utcoffset().total_seconds(), 0)
        self.assertEqual(self.sidecar("collection time.txt").splitlines(),
                         ["EXIT_CODE=0", "STATUS=OK"])

    def test_utf16_bom_fixture_is_normalized_to_utf8_bom(self) -> None:
        fixture = self.base / "synthetic unicode fixture.bin"
        fixture.write_bytes("Fixture 中文\r\n".encode("utf-16"))
        source = RUNNER.read_text(encoding="utf-8-sig")
        # Patch only this disposable copy: replace its post-process output with
        # the fixed UTF-16 fixture immediately before the real normalization path.
        marker = '  consoleCodePage = QueryConsoleCodePage()'
        injected = '  fso.CopyFile "' + str(fixture) + '", outputPath, True' + "\r\n" + marker
        source, count = source.replace(marker, injected, 1), source.count(marker)
        self.assertEqual(count, 1)
        runner = self.base / "fixture_utf16_runner.vbs"
        runner.write_text(source, encoding="utf-16")
        output = self.base / "capture fixture 中文" / "utf16 output.txt"
        result = subprocess.run(
            [self.cscript, "//nologo", str(runner), str(output), "os", "10", "8192"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "", "runner emitted a VBScript error")
        raw = output.read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), raw[:8])
        self.assertEqual(raw.decode("utf-8-sig"), "Fixture 中文\r\n")
        sidecar = output.with_name("utf16 output.exit-code.txt").read_text(encoding="ascii")
        self.assertEqual(sidecar.splitlines(), ["EXIT_CODE=0", "STATUS=OK"])

    def test_nonzero_exit_is_preserved(self) -> None:
        result = self.run_capture("failure.txt", "cpu")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("EXIT_CODE=7", self.sidecar("failure.txt"))
        self.assertIn("STATUS=COMMAND_FAILED", self.sidecar("failure.txt"))

    def test_active_capture_size_failure_cleans_tree_and_reports_74(self) -> None:
        runner = self.size_failure_runner("active-size-unavailable", "proc.Status = 0")
        (self.base / "active-size-unavailable.inject").write_text("inject", encoding="ascii")
        self.marker.unlink(missing_ok=True)
        result, _ = self.run_with_runner(runner, "active size unavailable.txt", "disks")
        sidecar = self.sidecar("active size unavailable.txt")
        details = f"stdout={result.stdout!r}; stderr={result.stderr!r}; sidecar={sidecar!r}"
        self.assertEqual(result.returncode, 74, details)
        self.assertEqual(sidecar.splitlines(), ["EXIT_CODE=74", "STATUS=OUTPUT_SIZE_UNAVAILABLE"])
        time.sleep(14)
        self.assertFalse(self.marker.exists(), "descendant survived size-unavailable cleanup")

    def test_size_failure_before_normalization_preserves_raw_output(self) -> None:
        runner = self.size_failure_runner(
            "normalize-size-unavailable", "True", before_normalize=True
        )
        result, output = self.run_with_runner(
            runner, "normalize size unavailable.txt", "os"
        )
        sidecar = self.sidecar("normalize size unavailable.txt")
        details = f"stdout={result.stdout!r}; stderr={result.stderr!r}; sidecar={sidecar!r}"
        self.assertEqual(result.returncode, 74, details)
        self.assertEqual(sidecar.splitlines(), ["EXIT_CODE=74", "STATUS=OUTPUT_SIZE_UNAVAILABLE"])
        self.assertEqual(output.read_bytes(), b"FIXTURE_OK \r\n")

    def test_size_failure_after_normalization_does_not_report_success(self) -> None:
        runner = self.size_failure_runner(
            "normalized-size-unavailable", "True", after_normalize_write=True
        )
        result, output = self.run_with_runner(
            runner, "normalized size unavailable.txt", "os"
        )
        sidecar = self.sidecar("normalized size unavailable.txt")
        details = f"stdout={result.stdout!r}; stderr={result.stderr!r}; sidecar={sidecar!r}"
        self.assertEqual(result.returncode, 74, details)
        self.assertEqual(sidecar.splitlines(), ["EXIT_CODE=74", "STATUS=OUTPUT_SIZE_UNAVAILABLE"])
        self.assertEqual(output.read_bytes(), b"\xef\xbb\xbfFIXTURE_OK \r\n")

    def test_size_failure_after_leader_exit_fails_closed_126(self) -> None:
        child_marker = self.base / "child after leader exit.marker"
        child_fixture = self.base / "leader exits with child.cmd"
        child_fixture.write_text(
            '@echo off\r\n'
            'start "" /b cmd.exe /d /c "ping.exe -n 4 127.0.0.1 > nul & echo SURVIVED > "'
            + str(child_marker)
            + '""\r\n'
            'exit /b 0\r\n',
            encoding="ascii",
        )
        runner = self.size_failure_runner("exited-size-unavailable", "proc.Status <> 0")
        (self.base / "exited-size-unavailable.inject").write_text("inject", encoding="ascii")
        source = runner.read_text(encoding="utf-16")
        pattern = r'(?m)^    Case "graphics": CommandFor = .*?$'
        source, count = re.subn(
            pattern,
            lambda _match: f'    Case "graphics": CommandFor = "call ""{child_fixture}"""',
            source,
            count=1,
        )
        self.assertEqual(count, 1)
        runner.write_text(source, encoding="utf-16")
        result, _ = self.run_with_runner(runner, "exited size unavailable.txt", "graphics")
        sidecar = self.sidecar("exited size unavailable.txt")
        details = f"stdout={result.stdout!r}; stderr={result.stderr!r}; sidecar={sidecar!r}"
        self.assertEqual(result.returncode, 126, details)
        self.assertEqual(sidecar.splitlines(), ["EXIT_CODE=126", "STATUS=CLEANUP_FAILED"])
        time.sleep(5)
        self.assertTrue(child_marker.exists(), "fixture did not retain child after leader exit")

    def test_timeout_kills_process_tree_and_reports_124(self) -> None:
        result = self.run_capture("timeout.txt", "disks", timeout=1)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("STATUS=TIMEOUT", self.sidecar("timeout.txt"))
        time.sleep(14)
        self.assertFalse(self.marker.exists(), "descendant process survived taskkill /T")

    def test_output_limit_reports_125(self) -> None:
        production_name = "large-production.txt"
        self.output_marker.unlink(missing_ok=True)
        production_result, production_output = self.run_with_runner(
            self.runner, production_name, "graphics", timeout=10, byte_limit=1024
        )
        production_sidecar_path = production_output.with_name("large-production.exit-code.txt")
        production_sidecar = (
            production_sidecar_path.read_text(encoding="ascii")
            if production_sidecar_path.exists() else "<missing>"
        )
        production_size = production_output.stat().st_size if production_output.exists() else -1
        production_details = (
            f"production_exit={production_result.returncode}; "
            f"production_stderr={production_result.stderr!r}; "
            f"production_size={production_size}; "
            f"production_sidecar={production_sidecar!r}"
        )
        self.output_marker.unlink(missing_ok=True)
        source = self.runner.read_text(encoding="utf-16")
        source = source.replace(
            "Dim cleanupOK, resultCode, statusText, sizeError, sizeUnavailable",
            "Dim cleanupOK, resultCode, statusText, sizeError, sizeUnavailable, diagPath, readyPath, diagCount, diagErrorCount, diagLineCount, diagTrace",
            1,
        )
        source = source.replace(
            "outputPath = args(0)",
            "outputPath = args(0)\r\n"
            'diagPath = outputPath & ".probe.txt"\r\n'
            f'readyPath = "{self.output_marker}"\r\n'
            "diagCount = 0: diagErrorCount = 0: diagLineCount = 0",
            1,
        )
        source = source.replace("  Dim fileObject", "  Dim fileObject, trace", 1)
        diagnostic_observation = r'''  diagCount = diagCount + 1
  If errorCode <> 0 Then diagErrorCount = diagErrorCount + 1
  If (errorCode <> 0 Or diagCount <= 3 Or (diagCount Mod 32) = 0 Or sizeValue > maxBytes) _
      And diagLineCount < 19 Then
    On Error Resume Next
    Err.Clear
    Set trace = fso.OpenTextFile(diagPath, 8, True, 0)
    If Err.Number = 0 Then
      trace.WriteLine CStr(Timer) & " n=" & CStr(diagCount) & _
        " size=" & CStr(sizeValue) & " err=" & CStr(errorCode) & _
        " ready=" & CStr(fso.FileExists(readyPath)) & _
        " leader=" & CStr(proc.Status)
      trace.Close
      diagLineCount = diagLineCount + 1
    End If
    Err.Clear
    On Error GoTo 0
  End If
'''
        success_line = "  If errorCode = 0 Then TryGetFileSize = True"
        source, observation_count = source.replace(
            success_line,
            success_line + "\r\n" + diagnostic_observation,
            1,
        ), source.count(success_line)
        self.assertEqual(observation_count, 1)
        summary = r'''On Error Resume Next
Err.Clear
Set diagTrace = fso.OpenTextFile(diagPath, 8, True, 0)
If Err.Number = 0 And diagLineCount < 20 Then
  diagTrace.WriteLine "SUMMARY samples=" & CStr(diagCount) & " errors=" & CStr(diagErrorCount) & _
    " marker=" & CStr(fso.FileExists(readyPath)) & " leader=" & CStr(proc.Status)
  diagTrace.Close
End If
Err.Clear
On Error GoTo 0
'''
        marker = "' Catch a command that exits between polls after crossing the byte bound."
        source, marker_count = source.replace(marker, summary + marker, 1), source.count(marker)
        self.assertEqual(marker_count, 1)
        diagnostic_runner = self.base / "output-limit-diagnostic.vbs"
        diagnostic_runner.write_text(source, encoding="utf-16")
        output = self.base / "capture fixture 中文" / "large.txt"
        output.parent.mkdir(exist_ok=True)
        result = subprocess.run(
            [self.cscript, "//nologo", str(diagnostic_runner), str(output),
             "graphics", "10", "1024"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        output_path = self.base / "capture fixture 中文" / "large.txt"
        size = output_path.stat().st_size if output_path.exists() else -1
        sidecar_path = output_path.with_name("large.exit-code.txt")
        sidecar = sidecar_path.read_text(encoding="ascii") if sidecar_path.exists() else "<missing>"
        diagnostic_path = Path(str(output_path) + ".probe.txt")
        diagnostic = diagnostic_path.read_text(encoding="ascii") if diagnostic_path.exists() else "<missing>"
        details = (
            f"stdout={result.stdout!r}; stderr={result.stderr!r}; output_size={size}; "
            f"marker_reached={self.output_marker.exists()}; sidecar={sidecar!r}; "
            f"{production_details}; "
            f"size_probe={diagnostic!r}"
        )
        self.assertEqual(production_result.returncode, 125, details)
        self.assertIn("STATUS=OUTPUT_LIMIT_EXCEEDED", production_sidecar, details)
        self.assertEqual(result.returncode, 125, details)
        self.assertIn("STATUS=OUTPUT_LIMIT_EXCEEDED", sidecar, details)
        self.assertNotEqual(diagnostic, "<missing>", details)
        self.assertLessEqual(len(diagnostic.splitlines()), 20, details)

    def test_output_limit_with_exited_leader_fails_closed_126(self) -> None:
        fast_output = self.base / "fast output.cmd"
        fast_output.write_text(
            "@echo off\r\nfor /L %%i in (1,1,1000) do echo FIXTURE_OUTPUT\r\n",
            encoding="ascii",
        )
        source = self.runner.read_text(encoding="utf-16")
        pattern = r'(?m)^    Case "graphics": CommandFor = .*?$'
        source, command_count = re.subn(
            pattern,
            lambda _match: f'    Case "graphics": CommandFor = "call ""{fast_output}"""',
            source,
            count=1,
        )
        self.assertEqual(command_count, 1)
        marker = "' Catch a command that exits between polls after crossing the byte bound."
        exit_guard = (
            "' Test-only guard: require and bound observation of the exited leader.\r\n"
            "Dim fixtureWaitStarted, fixtureWaitElapsed\r\n"
            "fixtureWaitStarted = Timer\r\n"
            "Do While proc.Status = 0\r\n"
            "  WScript.Sleep 10\r\n"
            "  fixtureWaitElapsed = Timer - fixtureWaitStarted\r\n"
            "  If fixtureWaitElapsed < 0 Then fixtureWaitElapsed = fixtureWaitElapsed + 86400\r\n"
            "  If fixtureWaitElapsed >= 5 Then Exit Do\r\n"
            "Loop\r\n"
            "If proc.Status = 0 Then\r\n"
            "  Call StopProcessTree(proc.ProcessID)\r\n"
            "  WScript.Quit 98\r\n"
            "End If\r\n"
        )
        source, marker_count = source.replace(marker, exit_guard + marker, 1), source.count(marker)
        self.assertEqual(marker_count, 1)
        runner = self.base / "exited-leader-runner.vbs"
        runner.write_text(source, encoding="utf-16")
        output = self.base / "capture fixture 中文" / "exited-large.txt"
        output.parent.mkdir(exist_ok=True)
        result = subprocess.run(
            [self.cscript, "//nologo", str(runner), str(output), "graphics", "10", "1024"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertIn("STATUS=CLEANUP_FAILED", output.with_name("exited-large.exit-code.txt").read_text(encoding="ascii"))


if __name__ == "__main__":
    unittest.main()
