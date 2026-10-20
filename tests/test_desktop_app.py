from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.evidence_analyzer import analyze_evidence
from desktop_app import NATIVE_RAW_ALLOWED_NAMES, _normalize_collection_time, _normalize_wmic_time, _read_process_output, derive_native_metadata
from evidence.bundle import parse_iso8601_timestamp
from evidence.bundle import BundleError, import_bundle, stage_native_evidence, validate_bundle, write_manifest


class DesktopAppContracts(unittest.TestCase):
    def _windows_raw(self, root: Path) -> Path:
        root.mkdir()
        (root / "collection_metadata.txt").write_text(
            "metadata_schema=1\nprivilege=unknown\ncollector_version=0.3.0\n"
            "command_catalog=collection_time,os,os_detail,os_architecture,cpu,memory,graphics,disks,processes,services,listeners,firewall,privilege,accounts,startup_items,security_status\n",
            encoding="ascii")
        (root / "collection_start.txt").write_text("LocalDateTime=20261005100500.000000+480\n", encoding="ascii")
        (root / "collection_finish.txt").write_text("LocalDateTime=20261005100600.000000+480\n", encoding="ascii")
        (root / "os_detail.txt").write_text("Caption=Microsoft Windows 11 Pro\nVersion=10.0.26100\nOSArchitecture=64-bit\n", encoding="utf-8")
        (root / "os_architecture.txt").write_text("PROCESSOR_ARCHITECTURE=x86\nPROCESSOR_ARCHITEW6432=AMD64\n", encoding="ascii")
        required = ("os.txt", "cpu.txt", "memory.txt", "graphics.txt", "disks.txt", "processes.txt", "services.txt", "listeners.txt", "firewall.txt",
                    "privilege.txt", "accounts.txt", "startup_items.txt", "security_status.txt")
        for name in required:
            (root / name).write_text("COLLECTOR_STATUS=NOT_CHECKED_FIXTURE\n", encoding="ascii")
        for path in root.iterdir():
            if path.name.endswith(".txt") and not path.name.endswith(".exit-code.txt"):
                path.with_name(path.stem + ".exit-code.txt").write_text("EXIT_CODE=0\nSTATUS=COLLECTED\n", encoding="ascii")
        return root

    def test_wmi_timestamp_and_win64_under_32bit_shell_are_derived_from_capture_facts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._windows_raw(Path(temporary) / "raw")
            target, collection = derive_native_metadata(root, "office_pc")
            self.assertEqual(target["os_family"], "windows")
            self.assertEqual(target["product"], "Microsoft Windows 11 Pro")
            self.assertEqual(target["architecture"], "x86_64")
            self.assertEqual(target["use_case"], "office_pc")
            self.assertEqual(collection["privilege"], "unknown")
            self.assertEqual(collection["started_at"], "2026-10-05T10:05:00+08:00")
            self.assertEqual(_normalize_wmic_time("20261005100500.000000+480").utcoffset().total_seconds(), 28800)

    def test_bounded_runner_iso_utc_clock_fallback_is_timezone_aware(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._windows_raw(Path(temporary) / "raw")
            (root / "collection_start.txt").write_text("2026-10-05T02:05:00.1234567+00:00\r\n", encoding="ascii")
            (root / "collection_finish.txt").write_text("2026-10-05T02:06:00.1234567+00:00\r\n", encoding="ascii")
            target, collection = derive_native_metadata(root, "office_pc")
            self.assertEqual(target["os_family"], "windows")
            self.assertEqual(collection["started_at"], "2026-10-05T02:05:00.123456+00:00")
            self.assertEqual(_normalize_collection_time("2026-10-05T02:05:00Z").utcoffset().total_seconds(), 0)

    def test_strict_iso_parser_accepts_fraction_lengths_and_rejects_bad_zone_or_naive(self) -> None:
        expected = {1: 100000, 2: 120000, 3: 123000, 4: 123400, 5: 123450, 6: 123456, 7: 123456}
        for length, microseconds in expected.items():
            value = "2026-10-05T02:05:00." + "1234567"[:length] + "+05:30"
            with self.subTest(length=length):
                parsed = parse_iso8601_timestamp(value)
                self.assertEqual(parsed.microsecond, microseconds)
                self.assertEqual(parsed.utcoffset().total_seconds(), 19800)
        self.assertEqual(parse_iso8601_timestamp("2026-10-05T02:05:00Z").utcoffset().total_seconds(), 0)
        for value in (
            "2026-10-05T02:05:00", "2026-02-30T02:05:00Z", "2026-10-05 02:05:00Z",
            "2026-10-05T02:05:00.12345678Z", "2026-10-05T02:05:00+00:60", "2026-10-05T02:05:00+24:00",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_iso8601_timestamp(value)

    def test_naive_or_conflicting_capture_times_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._windows_raw(Path(temporary) / "raw")
            (root / "collection_start.txt").write_text("LocalDateTime=20261005100700.000000+480\n", encoding="ascii")
            with self.assertRaises(ValueError):
                derive_native_metadata(root, "office_pc")
            (root / "collection_metadata.txt").write_text(
                "started_at=2026-10-05T10:06:00+00:00\nfinished_at=2026-10-05T10:05:00+00:00\n"
                "timezone=UTC\nprivilege=unknown\ncollector_version=0.2\ncommand_catalog=fixture\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "早于开始时间"):
                derive_native_metadata(root, "office_pc")
            (root / "collection_metadata.txt").write_text(
                "started_at=2026-10-05T10:05:00\nfinished_at=2026-10-05T10:06:00\n"
                "timezone=unknown\nprivilege=unknown\ncollector_version=0.2\ncommand_catalog=fixture\n", encoding="ascii")
            with self.assertRaises(ValueError):
                derive_native_metadata(root, "office_pc")

    def test_conflicting_duplicate_os_facts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._windows_raw(Path(temporary) / "raw")
            (root / "os_detail.txt").write_text(
                "Caption=Microsoft Windows 11 Pro\nCaption=Windows Server 2008 R2\n"
                "Version=10.0.26100\nOSArchitecture=64-bit\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "互相冲突的重复事实"):
                derive_native_metadata(root, "office_pc")

    def test_native_bundle_staging_does_not_modify_source_and_runs_analysis_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = self._windows_raw(base / "usb-evidence")
            before = {p.relative_to(source).as_posix(): p.read_bytes() for p in source.iterdir()}
            cases = base / "cases"
            cases.mkdir()
            staging = stage_native_evidence(source, cases / ".stage-test", allowed_names=NATIVE_RAW_ALLOWED_NAMES)
            target, collection = derive_native_metadata(staging, "office_pc")
            write_manifest(staging, project_alias="corp-test", asset_alias="pc-01", target=target, collection=collection)
            case = import_bundle(staging, cases)
            manifest = validate_bundle(case)
            analysis = analyze_evidence(case, manifest)
            self.assertEqual(analysis.status, "PARTIAL")
            self.assertTrue(any(w.startswith("EVIDENCE_NOT_CHECKED:") for w in analysis.warnings))
            self.assertEqual({p.relative_to(source).as_posix(): p.read_bytes() for p in source.iterdir()}, before)
            self.assertTrue((case / "manifest.json").is_file())

    def test_staging_rejects_unexpected_executable_without_touching_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "usb"
            source.mkdir()
            (source / "collector.exe").write_bytes(b"never execute")
            with self.assertRaises(BundleError):
                stage_native_evidence(source, Path(temporary) / "local-stage")
            self.assertTrue((source / "collector.exe").is_file())
            self.assertFalse((Path(temporary) / "local-stage").exists())

    def test_native_directory_rejects_extra_configuration_even_when_text_like(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = self._windows_raw(Path(temporary) / "usb-evidence")
            secret_config = source / "passwords.txt"
            secret_config.write_text("must not be packaged", encoding="utf-8")
            staging = Path(temporary) / "staged"
            with mock.patch.object(Path, "open", side_effect=AssertionError("unexpected file read")):
                with self.assertRaisesRegex(BundleError, "fixed native collector file allowlist"):
                    stage_native_evidence(source, staging, allowed_names=NATIVE_RAW_ALLOWED_NAMES)
            self.assertEqual(secret_config.read_text(encoding="utf-8"), "must not be packaged")
            self.assertFalse(staging.exists())

    def test_native_allowlist_rejects_nested_paths_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "usb"
            source.mkdir()
            subdir = source / "configs"
            subdir.mkdir()
            (subdir / "nginx.conf.txt").write_text("not a collector output", encoding="utf-8")
            staging = Path(temporary) / "staging"
            with self.assertRaisesRegex(BundleError, "fixed native collector file allowlist"):
                stage_native_evidence(source, staging, allowed_names=NATIVE_RAW_ALLOWED_NAMES)
            self.assertFalse(staging.exists())

    @unittest.skipUnless(os.name != "nt" and hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_staging_rejects_special_files_without_opening_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "usb"
            source.mkdir()
            os.mkfifo(source / "blocked.txt")
            with self.assertRaisesRegex(BundleError, "regular files and directories"):
                stage_native_evidence(source, Path(temporary) / "stage")
            self.assertTrue((source / "blocked.txt").exists())

    def test_cli_child_process_is_bounded_and_cancel_stops_own_group(self) -> None:
        output: list[str] = []
        code = _read_process_output([sys.executable, "-c", "print('GUI_FIXTURE_OK')"], timeout=3,
                                    cancelled=threading.Event(), on_output=output.append)
        self.assertEqual(code, 0)
        self.assertIn("GUI_FIXTURE_OK", "".join(output))
        cancelled = threading.Event(); cancelled.set()
        with self.assertRaises(TimeoutError):
            _read_process_output([sys.executable, "-c", "import time; time.sleep(5)"], timeout=3,
                                 cancelled=cancelled, on_output=lambda _text: None)


    @unittest.skipUnless(os.name == "nt" or os.environ.get("DISPLAY"), "requires a Tk display")
    def test_v3_gui_pages_theme_report_state_and_authorization_gate(self) -> None:
        import tkinter as tk
        from tkinter.font import Font
        from desktop_ui import InspectionDesktop

        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tk display unavailable: {exc}")
        screen_width, screen_height = root.winfo_screenwidth(), root.winfo_screenheight()
        window_max_width = max(1240, screen_width)
        window_max_height = max(840, screen_height)
        initial_width, initial_height = 1240, 840
        initial_geometry = f"{initial_width}x{initial_height}"
        try:
            app = InspectionDesktop(root)
            root.update()
            root.maxsize(window_max_width, window_max_height)
            root.geometry(initial_geometry)
            root.update()
            self.assertEqual((root.winfo_width(), root.winfo_height()), (initial_width, initial_height),
                             f"Tk did not apply requested initial geometry {initial_geometry}; "
                             f"screen={screen_width}x{screen_height}, maxsize={root.maxsize()}")
            self.assertEqual(set(app.pages), {"overview", "local", "import", "report", "review"})
            self.assertEqual(len(app.nav_buttons), 5)
            wheel_tags = {page["wheel_tag"] for page in app.pages.values()}
            self.assertEqual(len(wheel_tags), 5)
            self.assertEqual(root.bind_all("<MouseWheel>"), "")
            for page in app.pages.values():
                self.assertIn(page["wheel_tag"], page["header"].bindtags())
                for header_child in page["header"].winfo_children():
                    self.assertIn(page["wheel_tag"], header_child.bindtags())
                canvas = page["canvas"]
                bounds = canvas.bbox(page["window"])
                self.assertIsNotNone(bounds)
                overflows = bounds[3] - bounds[1] > canvas.winfo_height()
                self.assertEqual(page["scrollbar"].winfo_manager(), "grid" if overflows else "")
                if not overflows:
                    region = [float(value) for value in canvas.cget("scrollregion").split()]
                    self.assertAlmostEqual(region[3] - region[1], canvas.winfo_height())
            overview = app.pages["overview"]
            review = app.pages["review"]

            def send_wheel(widget, delta: int) -> None:
                widget.event_generate("<MouseWheel>", delta=delta)
                root.update()

            initial_overflow = []
            for page in (overview, review):
                bounds = page["canvas"].bbox(page["window"])
                self.assertIsNotNone(bounds)
                initial_overflow.append(max(0, bounds[3] - bounds[1] - page["canvas"].winfo_height()))
            fit_height = root.winfo_height() + max(initial_overflow) + 16
            fit_geometry = f"{root.winfo_width()}x{fit_height}"
            root.maxsize(window_max_width, max(window_max_height, fit_height))
            root.geometry(fit_geometry)
            root.update()
            self.assertEqual((root.winfo_width(), root.winfo_height()),
                             (initial_width, fit_height),
                             f"Tk did not apply requested fit geometry {fit_geometry}; "
                             f"screen={screen_width}x{screen_height}, maxsize={root.maxsize()}")
            for page in (overview, review):
                fit_bounds = page["canvas"].bbox(page["window"])
                self.assertIsNotNone(fit_bounds)
                self.assertGreater(len(page["content"].winfo_children()), 0)
                self.assertGreaterEqual(page["canvas"].winfo_height() - (fit_bounds[3] - fit_bounds[1]), 8)
                self.assertEqual(page["scrollbar"].winfo_manager(), "")
                fit_region = [float(value) for value in page["canvas"].cget("scrollregion").split()]
                self.assertAlmostEqual(fit_region[3] - fit_region[1], page["canvas"].winfo_height())
                for delta in (-120, 120, -240, 240):
                    send_wheel(page["header"].winfo_children()[0], delta)
                    send_wheel(page["content"], delta)
                    self.assertAlmostEqual(page["canvas"].yview()[0], 0.0)

            root.minsize(980, 660)
            small_width, small_height = 980, 660
            small_geometry = f"{small_width}x{small_height}"
            root.geometry(small_geometry)
            root.update()
            self.assertEqual((root.winfo_width(), root.winfo_height()), (small_width, small_height),
                             f"Tk did not apply requested overflow geometry {small_geometry}; "
                             f"screen={screen_width}x{screen_height}, maxsize={root.maxsize()}")
            app._navigate("overview")
            root.update()
            overview_bounds = overview["canvas"].bbox(overview["window"])
            self.assertGreater(overview_bounds[3] - overview_bounds[1], overview["canvas"].winfo_height())
            self.assertEqual(overview["scrollbar"].winfo_manager(), "grid")
            send_wheel(overview["content"], -120)
            self.assertGreater(overview["canvas"].yview()[0], 0.0)

            app._navigate("review")
            root.update()
            review_bounds = review["canvas"].bbox(review["window"])
            self.assertGreater(review_bounds[3] - review_bounds[1], review["canvas"].winfo_height())
            self.assertEqual(review["scrollbar"].winfo_manager(), "grid")
            send_wheel(review["content"], -120)
            self.assertGreater(review["canvas"].yview()[0], 0.0)

            root.geometry(fit_geometry)
            root.update()
            self.assertEqual((root.winfo_width(), root.winfo_height()), (initial_width, fit_height),
                             f"Tk did not restore requested fit geometry {fit_geometry}; "
                             f"screen={screen_width}x{screen_height}, maxsize={root.maxsize()}")
            app._navigate("overview")
            root.update()
            for page in (overview, review):
                bounds = page["canvas"].bbox(page["window"])
                self.assertIsNotNone(bounds)
                self.assertLessEqual(bounds[3] - bounds[1], page["canvas"].winfo_height())
                self.assertEqual(page["scrollbar"].winfo_manager(), "")
                self.assertAlmostEqual(page["canvas"].yview()[0], 0.0)
                region = [float(value) for value in page["canvas"].cget("scrollregion").split()]
                self.assertAlmostEqual(region[3] - region[1], page["canvas"].winfo_height())
                for delta in (-120, 120, -240, 240):
                    send_wheel(page["header"].winfo_children()[0], delta)
                    send_wheel(page["content"], delta)
                    self.assertAlmostEqual(page["canvas"].yview()[0], 0.0)

            review = app.pages["review"]
            self.assertEqual(review["scrollbar"].winfo_manager(), "")
            app._navigate("report")
            report_canvas = app.pages["report"]["canvas"]
            report_canvas.yview_moveto(1)
            root.update()
            self.assertGreater(report_canvas.yview()[0], 0.0)
            self.assertGreater(review["canvas"].winfo_width(), report_canvas.winfo_width())
            app._navigate("review")
            root.update()
            self.assertAlmostEqual(review["canvas"].yview()[0], 0.0)
            first_content_row = min(
                widget.winfo_y() for widget in review["content"].winfo_children()
                if widget.winfo_manager() == "grid"
            )
            self.assertLessEqual(first_content_row, 8)
            style = app.ttk.Style(root)
            self.assertTrue(style.lookup("Primary.TButton", "padding"))
            self.assertEqual(style.lookup("Primary.TButton", "padding"),
                             style.lookup("Secondary.TButton", "padding"))
            self.assertEqual(str(style.lookup("CardInner.TFrame", "borderwidth")), "0")
            self.assertEqual(app.footer_progress.winfo_manager(), "")
            self.assertTrue(all(progress.winfo_manager() == "" for progress in app.progress_bars))
            self.assertEqual(app.finding_empty_label.winfo_manager(), "grid")
            self.assertEqual(app.pages["overview"]["canvas"].grid_info()["row"], 1)
            self.assertEqual(app.footer_progress.master.grid_info()["row"], 2)
            self.assertEqual(app.finding_detail.cget("height"), 3)
            self.assertFalse(app.ai_enabled_var.get())
            self.assertEqual(app._ai_options(), [])
            app.ai_enabled_var.set(True)
            with mock.patch.object(app, "_message") as ai_message:
                self.assertIsNone(app._ai_options())
            ai_message.assert_called_once()
            app.ai_ack_var.set(True)
            app.ai_endpoint_var.set("http://ollama.example.invalid")
            app.ai_model_var.set("synthetic-test-model")
            self.assertEqual(app._ai_options(), [
                "--ai-provider", "ollama", "--ai-endpoint", "http://ollama.example.invalid",
                "--ai-model", "synthetic-test-model", "--ai-cloud-disabled-ack", "--ai-timeout", "180",
            ])
            with mock.patch.object(app, "_message") as message:
                app._start_local()
            message.assert_called_once()
            self.assertFalse(app.busy)

            with tempfile.TemporaryDirectory() as temporary:
                analysis_path = Path(temporary) / "analysis.json"
                fixture = {
                    "status": "PARTIAL",
                    "findings": [{
                        "finding_id": "TEST_FIXTURE_001",
                        "title": "Synthetic GUI fixture",
                        "severity": "Warning",
                        "evidence": {"source": "test fixture"},
                        "needs_human_review": True,
                    }],
                    "warnings": ["SYNTHETIC_EVIDENCE_GAP"],
                    "errors": [],
                }
                app._show_analysis({
                    "analysis": fixture,
                    "metadata": {"ai_advisory": {"status": "AI_NOT_RUN", "reason": "test fixture"}},
                    "analysis_path": str(analysis_path),
                    "report_dir": temporary,
                })
                self.assertEqual(app.analysis_status_var.get(), "PARTIAL")
                self.assertEqual(app.finding_count_var.get(), "1")
                self.assertEqual(app.gap_count_var.get(), "1")
                self.assertEqual(len(app.finding_tree.get_children()), 1)
                self.assertEqual(app.finding_detail.cget("height"), 5)
                self.assertEqual(app.finding_tree.winfo_manager(), "grid")
                self.assertEqual(app.finding_empty_label.winfo_manager(), "")
                self.assertIn("AI 状态：AI_NOT_RUN", app.ai_text.get("1.0", "end"))
                self.assertEqual(app.workflow_vars[2][2].get(), "PARTIAL · 1 条")
                app._set_filter("gaps")
                self.assertEqual(app.finding_tree.winfo_manager(), "")
                self.assertEqual(app.finding_detail.cget("height"), 3)
                self.assertIn("显示在下方", app.finding_empty_var.get())
                app._set_filter("all")
                self.assertEqual(app.finding_tree.winfo_manager(), "grid")
                app._navigate("report")
                root.update()
                report_canvas = app.pages["report"]["canvas"]
                app.analysis_status_badge.event_generate("<MouseWheel>", delta=-120)
                root.update()
                self.assertGreater(report_canvas.yview()[0], 0.0)
                app.analysis_status_badge.event_generate("<MouseWheel>", delta=120)
                root.update()
                self.assertAlmostEqual(report_canvas.yview()[0], 0.0)

                canvas_top = report_canvas.yview()[0]
                app._set_text(app.gaps_text, "\n".join(f"synthetic gap {i}" for i in range(24)))
                root.update()
                text_top = app.gaps_text.yview()[0]
                app.gaps_text.event_generate("<MouseWheel>", delta=-120)
                root.update()
                self.assertGreater(app.gaps_text.yview()[0], text_top)
                self.assertAlmostEqual(report_canvas.yview()[0], canvas_top)

                root.geometry("980x660")
                root.update()
                app._navigate("report")
                root.update()
                self.assertEqual(app.pages["report"]["scrollbar"].winfo_manager(), "grid")
                report_page = app.pages["report"]
                report_title = report_page["header"].winfo_children()[0]

                def assert_wheel_sequence(deltas: list[int], expected_units: int | list[int]) -> None:
                    report_page["wheel_delta"] = 0
                    report_canvas.yview_moveto(0.5)
                    root.update()
                    for delta in deltas:
                        report_title.event_generate("<MouseWheel>", delta=delta)
                        root.update()
                    actual_position = report_canvas.yview()[0]
                    report_page["wheel_delta"] = 0
                    report_canvas.yview_moveto(0.5)
                    if isinstance(expected_units, int):
                        expected_units = [expected_units]
                    for units in expected_units:
                        report_canvas.yview_scroll(units, "units")
                        root.update()
                    expected_position = report_canvas.yview()[0]
                    self.assertAlmostEqual(actual_position, expected_position, places=6)

                assert_wheel_sequence([-30] * 4, 1)
                assert_wheel_sequence([-60] * 2, 1)
                assert_wheel_sequence([-120], 1)
                assert_wheel_sequence([120], -1)
                assert_wheel_sequence([-240], 2)
                assert_wheel_sequence([240], -2)
                assert_wheel_sequence([120, -120], [-1, 1])
                assert_wheel_sequence([-120, 120], [1, -1])

                report_page["wheel_delta"] = 0
                report_canvas.yview_moveto(0.5)
                root.update()
                reversal_start = report_canvas.yview()[0]
                for delta in (-60, 30, 30, 90, -60, -30):
                    report_title.event_generate("<MouseWheel>", delta=delta)
                    root.update()
                    self.assertAlmostEqual(report_canvas.yview()[0], reversal_start)
                self.assertEqual(report_page["wheel_delta"], 0)

                app._navigate("review")
                root.update()
                review_page = app.pages["review"]
                self.assertEqual(review_page["scrollbar"].winfo_manager(), "grid")
                review_page["wheel_delta"] = 0
                review_page["content"].event_generate("<MouseWheel>", delta=-60)
                root.update()
                self.assertAlmostEqual(review_page["canvas"].yview()[0], 0.0)
                app._navigate("report")
                report_title.event_generate("<MouseWheel>", delta=-60)
                root.update()
                self.assertAlmostEqual(review_page["canvas"].yview()[0], 0.0)
                self.assertAlmostEqual(report_canvas.yview()[0], 0.0)
                app._navigate("review")
                review_page["content"].event_generate("<MouseWheel>", delta=-60)
                root.update()
                self.assertGreater(review_page["canvas"].yview()[0], 0.0)
                self.assertAlmostEqual(report_canvas.yview()[0], 0.0)
                review_position = review_page["canvas"].yview()[0]
                app._navigate("report")
                report_title.event_generate("<MouseWheel>", delta=-60)
                root.update()
                self.assertGreater(report_canvas.yview()[0], 0.0)
                self.assertAlmostEqual(review_page["canvas"].yview()[0], review_position)

                root.geometry("1240x840")
                app._navigate("import")
                root.update()
                import_page = app.pages["import"]
                import_content = import_page["content"]
                import_pair = next(child for child in import_content.winfo_children()
                                   if child.grid_info().get("row") == 0)
                source_card, options_card = import_pair.winfo_children()
                rules_frame = options_card.winfo_children()[1]
                rule_widgets = rules_frame.winfo_children()
                self.assertEqual(len(rule_widgets), 8)
                for row in range(4):
                    bullet, label = rule_widgets[row * 2:row * 2 + 2]
                    bullet_grid, label_grid = bullet.grid_info(), label.grid_info()
                    self.assertEqual(int(bullet_grid["row"]), row)
                    self.assertEqual(int(label_grid["row"]), row)
                    self.assertLess(label.winfo_x() - bullet.winfo_x(), 40)
                    self.assertEqual(str(label.cget("anchor")), "w")
                    self.assertEqual(str(label.cget("justify")), "left")
                    self.assertEqual(bullet_grid["pady"], label_grid["pady"])
                self.assertEqual(
                    int(rule_widgets[1].cget("wraplength")),
                    max(160, rules_frame.winfo_width() - 32),
                )
                long_rule = rule_widgets[-1]
                original_rule = long_rule.cget("text")
                long_rule.configure(text=original_rule * 3)
                root.update()
                self.assertGreater(long_rule.winfo_height(), rule_widgets[1].winfo_height())
                long_rule.configure(text=original_rule)
                root.update()

                cases_frame = source_card.grid_slaves(row=10)[0]
                reports_frame = source_card.grid_slaves(row=12)[0]
                cases_entry = cases_frame.grid_slaves(row=0, column=0)[0]
                reports_entry = reports_frame.grid_slaves(row=0, column=0)[0]
                synthetic_prefix = "C:\\synthetic-test-root\\" + "nested-folder-" * 12
                cases_path = synthetic_prefix + "cases"
                reports_path = synthetic_prefix + "reports"
                app.cases_var.set(cases_path)
                app.reports_var.set(reports_path)
                root.update()
                self.assertEqual(cases_entry.get(), app.cases_var.get())
                self.assertEqual(reports_entry.get(), app.reports_var.get())
                cases_font = Font(root=root, font=cases_entry.cget("font"))
                reports_font = Font(root=root, font=reports_entry.cget("font"))
                self.assertGreater(cases_font.measure(cases_entry.get()), cases_entry.winfo_width())
                self.assertGreater(reports_font.measure(reports_entry.get()), reports_entry.winfo_width())
                self.assertGreater(cases_entry.xview()[0], 0.0)
                self.assertGreater(reports_entry.xview()[0], 0.0)

                root.geometry("980x660")
                root.update()
                self.assertEqual(import_page["scrollbar"].winfo_manager(), "grid")
                import_page["canvas"].yview_moveto(1.0)
                root.update()
                progress_card = next(child for child in import_content.winfo_children()
                                     if child.grid_info().get("row") == 1)
                controls = progress_card.grid_slaves(row=3, column=0)[0]
                import_button = controls.winfo_children()[0]
                canvas_top = import_page["canvas"].winfo_rooty()
                canvas_bottom = canvas_top + import_page["canvas"].winfo_height()
                self.assertGreaterEqual(import_button.winfo_rooty(), canvas_top)
                self.assertLessEqual(import_button.winfo_rooty() + import_button.winfo_height(), canvas_bottom)
            root.update_idletasks()
        finally:
            root.destroy()
if __name__ == "__main__":
    unittest.main()
