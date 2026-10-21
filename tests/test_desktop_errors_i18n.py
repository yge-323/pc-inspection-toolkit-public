from __future__ import annotations

import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from locales.desktop_errors import display_desktop_error


class DesktopErrorDisplayTests(unittest.TestCase):
    def test_known_static_diagnostics_are_localized(self) -> None:
        cases = {
            "WMI 本地时间证据缺少有效 UTC 偏移": "The WMI local-time evidence does not contain a valid UTC offset.",
            "采集时间输出格式不受支持": "The collection-time output format is unsupported.",
            "证据未含可信格式的真实采集起止时间；不会使用文件时间代替，请用新版固定采集器重新采集。":
                "The evidence does not contain trusted, well-formed collection start and end times. File timestamps will not be substituted; recollect with the current fixed collector.",
            "采集时间缺少明确时区，证据不能被封装为可比较时间。":
                "The collection time has no explicit timezone, so the evidence cannot be sealed with a comparable timestamp.",
            "采集结束时间早于开始时间，证据元数据冲突，不能封装。":
                "The collection end time precedes the start time. The evidence metadata conflicts and cannot be sealed.",
            "采集器版本或固定命令目录元数据缺失/无效，不能封装。":
                "Collector version or fixed command-catalog metadata is missing or invalid; the evidence cannot be sealed.",
            "不能从固定证据识别 Windows/Linux/macOS；不会猜测目标平台。":
                "The target platform cannot be identified as Windows, Linux, or macOS from the fixed evidence. The platform will not be guessed.",
            "采集命令目录与已识别的平台采集器不匹配或未受支持。":
                "The collector command catalog does not match the identified platform or is unsupported.",
            "固定原生采集目录不得包含子目录。":
                "The fixed native collector folder must not contain subdirectories.",
            "analysis.json 不存在。": "analysis.json does not exist.",
            "analysis.json 超出 20 MiB 安全读取上限。":
                "analysis.json exceeds the 20 MiB safe-read limit.",
            "分析结果结构不正确。": "The analysis result has an invalid structure.",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(display_desktop_error(source, "en-US"), expected)
                self.assertEqual(display_desktop_error(source, "zh-CN"), source)

    def test_known_dynamic_suffixes_are_preserved(self) -> None:
        cases = {
            "采集元数据字段重复：started_at":
                "Duplicate collection metadata field: started_at",
            "固定采集命令目录与输出文件不一致：cpu.txt, memory.txt":
                "The fixed collector command catalog does not match the output files: cpu.txt, memory.txt",
            "原生采集目录含固定目录之外的文件，不会封装：private-note.txt":
                "The native collector folder contains files outside the fixed allow-list and will not be sealed: private-note.txt",
            "固定证据包含互相冲突的重复事实：Version":
                "The fixed evidence contains conflicting duplicate facts: Version",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(display_desktop_error(source, "en"), expected)
                self.assertEqual(display_desktop_error(source, "zh"), source)

    def test_ui_file_errors_and_exception_prefix_are_handled(self) -> None:
        self.assertEqual(
            display_desktop_error("FileNotFoundError: 所选证据目录不存在。", "en-US"),
            "FileNotFoundError: The selected evidence folder does not exist.",
        )
        self.assertEqual(
            display_desktop_error("FileNotFoundError: 所选证据目录不存在。", "zh-CN"),
            "FileNotFoundError: 所选证据目录不存在。",
        )
        self.assertEqual(
            display_desktop_error("所选粘贴导出文件不存在。", "en-US"),
            "The selected paste-export file does not exist.",
        )
        self.assertEqual(
            display_desktop_error("现有 paste-import 命令未返回已导入案例路径。", "en-US"),
            "The existing paste-import command did not return the imported case path.",
        )

    def test_unknown_diagnostics_remain_intact_and_are_marked_in_english(self) -> None:
        diagnostic = "TclError: can't open display at C:/private/session"
        self.assertEqual(display_desktop_error(diagnostic, "zh-CN"), diagnostic)
        self.assertEqual(display_desktop_error(diagnostic, "en-US"), f"Original diagnostic: {diagnostic}")
        self.assertEqual(
            display_desktop_error("third-party 中文诊断: token-42", "en"),
            "Original diagnostic: third-party 中文诊断: token-42",
        )

    def test_invalid_language_uses_the_shared_normalizer(self) -> None:
        with self.assertRaises(ValueError):
            display_desktop_error("diagnostic", "fr-FR")


if __name__ == "__main__":
    unittest.main()
