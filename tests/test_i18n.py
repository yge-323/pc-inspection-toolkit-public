from __future__ import annotations

import json
import ast
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import i18n
from i18n import (
    DEFAULT_LANGUAGE,
    LanguagePreferenceError,
    LocaleResourceError,
    load_language_preference,
    normalize_language,
    save_language_preference,
    tr,
    validate_ui_resources,
)


class LanguageHelpersTests(unittest.TestCase):
    def test_desktop_literal_translations_are_registered_and_resources_are_valid(self) -> None:
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / "desktop_ui.py").read_text(encoding="utf-8"))
        phrases = {
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "tr"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        }
        missing = sorted(phrase for phrase in phrases
                         if phrase not in i18n._ZH_EN and phrase not in i18n._EN_ZH)
        self.assertEqual(missing, [])
        validate_ui_resources("zh-CN")
        validate_ui_resources("en-US")

    def test_invalid_owned_translation_fails_closed(self) -> None:
        with mock.patch.dict(i18n._ZH_EN, {"无法加载分析文件：{error}": "Could not load {other}"}):
            with self.assertRaises(LocaleResourceError):
                validate_ui_resources("en-US")
        with mock.patch.dict(i18n._ZH_EN, {"概览": "  "}):
            with self.assertRaises(LocaleResourceError):
                validate_ui_resources("en-US")

    def test_missing_required_ui_key_fails_closed(self) -> None:
        removed = i18n._ZH_EN.pop("概览")
        try:
            with self.assertRaises(LocaleResourceError):
                validate_ui_resources("en-US")
        finally:
            i18n._ZH_EN["概览"] = removed

    def test_aliases_and_default_resolve_to_two_canonical_locales(self) -> None:
        self.assertEqual(normalize_language(None), "zh-CN")
        self.assertEqual(normalize_language("zh"), "zh-CN")
        self.assertEqual(normalize_language("zh-Hans"), "zh-CN")
        self.assertEqual(normalize_language("en"), "en-US")
        self.assertEqual(normalize_language("English"), "en-US")
        with self.assertRaises(ValueError):
            normalize_language("fr-CA")

    def test_translation_matches_complete_application_phrase_only(self) -> None:
        phrase = "本机巡检"
        self.assertEqual(tr(phrase, "en-US"), "Local inspection")
        self.assertEqual(tr("Local inspection", "zh-CN"), phrase)
        external = "Check this Windows device and send the user's original text."
        self.assertEqual(tr(external, "zh-CN"), external)

    def test_preference_defaults_and_round_trips_in_isolated_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings" / "preferences.json"
            self.assertEqual(load_language_preference(path), (DEFAULT_LANGUAGE, None))
            save_language_preference("en", path)
            self.assertEqual(load_language_preference(path), ("en-US", None))
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")),
                             {"schema_version": 1, "language": "en-US"})
            save_language_preference("zh-CN", path)
            self.assertEqual(load_language_preference(path), ("zh-CN", None))

    def test_invalid_preference_is_ignored_without_being_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "preferences.json"
            original = b'{"schema_version":1,"language":"fr-FR"}'
            path.write_bytes(original)
            language, warning = load_language_preference(path)
            self.assertEqual(language, DEFAULT_LANGUAGE)
            self.assertTrue(warning)
            self.assertEqual(path.read_bytes(), original)
            with self.assertRaises(LanguagePreferenceError):
                save_language_preference("fr-FR", path)
            self.assertEqual(path.read_bytes(), original)

    def test_link_preferences_are_ignored_and_link_targets_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text('{"schema_version":1,"language":"en-US"}', encoding="utf-8")
            link = root / "preferences.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable in this environment")
            language, warning = load_language_preference(link)
            self.assertEqual(language, DEFAULT_LANGUAGE)
            self.assertTrue(warning)
            with self.assertRaises(LanguagePreferenceError):
                save_language_preference("zh-CN", link)
            self.assertEqual(target.read_text(encoding="utf-8"),
                             '{"schema_version":1,"language":"en-US"}')


if __name__ == "__main__":
    unittest.main()
