"""Synthetic subprocess tests for bounded_exec.pl; never invokes collectors."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "platforms" / "bounded_exec.pl"


def _perl_candidates() -> list[str]:
    override = os.environ.get("PC_INSPECTION_TEST_PERL")
    if override:
        return [override]
    candidates: list[str] = []
    native = shutil.which("perl")
    if native:
        candidates.append(native)
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            for parent in Path(git).resolve().parents:
                candidate = parent / "usr" / "bin" / "perl.exe"
                if candidate.is_file():
                    candidates.append(str(candidate))
                    break
    return list(dict.fromkeys(candidates))


def _posix_perl_probe(perl: str) -> tuple[bool, str]:
    probe = (
        "use POSIX qw(setpgid SIGXFSZ); "
        "my $signal = SIGXFSZ(); die 'SIGXFSZ unavailable' unless $signal; "
        "my $result = setpgid(0, 0); die 'setpgid unavailable' unless defined($result) && $result == 0;"
    )
    try:
        result = subprocess.run([perl, "-e", probe], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Perl capability probe failed ({type(exc).__name__})"
    if result.returncode != 0:
        return False, "Perl lacks working POSIX::setpgid/SIGXFSZ support"
    return True, ""


def select_posix_perl() -> tuple[str | None, str]:
    candidates = _perl_candidates()
    if not candidates:
        return None, "Perl runtime unavailable"
    reasons: list[str] = []
    for candidate in candidates:
        supported, reason = _posix_perl_probe(candidate)
        if supported:
            return candidate, ""
        reasons.append(f"{Path(candidate).name}: {reason}")
    return None, "; ".join(reasons)


SELECTED_PERL, PERL_SKIP_REASON = select_posix_perl()
@unittest.skipUnless(SELECTED_PERL, PERL_SKIP_REASON)
class BoundedPosixCaptureRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.perl = SELECTED_PERL
        cls.temp = tempfile.TemporaryDirectory(prefix="bounded-posix-fixture-", dir=ROOT / "work")
        cls.base = Path(cls.temp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def run_helper(self, name: str, timeout: int, max_bytes: int,
                   code: str, *args: str, output: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
        output = output or self.base / name
        return subprocess.run(
            [self.perl, str(HELPER), str(timeout), str(max_bytes), str(output),
             "--", self.perl, "-e", code, *args],
            capture_output=True, text=True, timeout=10, check=False,
        )

    def output(self, name: str) -> str:
        return (self.base / name).read_text(encoding="utf-8", errors="replace")

    def test_fast_leader_cannot_skip_final_output_limit_check(self) -> None:
        result = self.run_helper("fast-large.txt", 5, 1024,
                                 'print "X" x 1000000;')
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(self.output("fast-large.txt"), "OUTPUT_LIMIT_EXCEEDED\n")

    def test_timeout_terminates_group_and_reports_timeout(self) -> None:
        result = self.run_helper("timeout.txt", 1, 1024,
                                 '$| = 1; print "FIXTURE_STARTED\\n"; sleep 30;')
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual(self.output("timeout.txt"), "COLLECTION_TIMEOUT\n")

    def test_nonzero_exit_is_preserved(self) -> None:
        result = self.run_helper("nonzero.txt", 5, 1024, 'print "FIXTURE_OK\\n"; exit 7;')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(self.output("nonzero.txt"), "FIXTURE_OK\n")

    def test_natural_leader_exit_cleans_descendant_and_fails_closed(self) -> None:
        marker = str(self.base / "descendant-survived.txt")
        code = (
            'my $child = fork(); die "fork failed" unless defined $child; '
            'if (!$child) { sleep 2; open my $fh, ">", $ARGV[0] or die $!; '
            'print {$fh} "SURVIVED"; close $fh; exit 0; } exit 0;'
        )
        result = self.run_helper("descendant.txt", 5, 1024, code, marker)
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertEqual(self.output("descendant.txt"), "UNEXPECTED_RESIDUAL_PROCESS_TREE\n")
        time.sleep(2.2)
        self.assertFalse(Path(marker).exists(), "descendant continued after helper returned")

    def test_existing_output_file_is_refused_without_modification(self) -> None:
        output = self.base / "existing.txt"
        output.write_text("KEEP_EXISTING_DATA", encoding="ascii")
        result = self.run_helper("existing.txt", 5, 1024, 'print "REPLACEMENT";', output=output)
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertEqual(output.read_text(encoding="ascii"), "KEEP_EXISTING_DATA")

    def test_existing_symlink_is_refused(self) -> None:
        target = self.base / "link-target.txt"
        target.write_text("KEEP_TARGET_DATA", encoding="ascii")
        link = self.base / "existing-link.txt"
        try:
            link.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        result = self.run_helper("existing-link.txt", 5, 1024,
                                 'print "REPLACEMENT";', output=link)
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(encoding="ascii"), "KEEP_TARGET_DATA")

    def test_invalid_output_limits_are_rejected_before_file_creation(self) -> None:
        for value in ("-1", "1023", "8388609", "999999999999"):
            with self.subTest(max_bytes=value):
                output = self.base / ("invalid-limit-" + value.replace("-", "minus") + ".txt")
                result = subprocess.run(
                    [self.perl, str(HELPER), "5", value, str(output), "--",
                     self.perl, "-e", 'print "SHOULD_NOT_RUN";'],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())

    def test_marker_refuses_path_replaced_by_child(self) -> None:
        output = self.base / "replaced-path.txt"
        code = (
            'unlink $ARGV[0] or die $!; open my $fh, ">", $ARGV[0] or die $!; '
            'print {$fh} "REPLACEMENT_DATA"; close $fh; $| = 1; sleep 30;'
        )
        result = self.run_helper("replaced-path.txt", 1, 1024, code, str(output), output=output)
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertEqual(output.read_text(encoding="ascii"), "REPLACEMENT_DATA")


if __name__ == "__main__":
    unittest.main()
