"""
Tests for core/utils.py — focusing on extract_json_from_text with
the json-repair fallback for LLM-generated malformed JSON.
"""

import unittest

from core.utils import extract_json_from_text, fix_json_formatting


class TestExtractJsonFromText(unittest.TestCase):

    def test_valid_json_parsed_directly(self):
        result = extract_json_from_text('{"key": "value"}')
        self.assertEqual(result, {"key": "value"})

    def test_json_wrapped_in_markdown_code_block(self):
        text = '```json\n{"rules": []}\n```'
        result = extract_json_from_text(text)
        self.assertEqual(result, {"rules": []})

    def test_json_wrapped_in_unmarked_code_block(self):
        text = '```\n{"rules": []}\n```'
        result = extract_json_from_text(text)
        self.assertEqual(result, {"rules": []})

    def test_json_embedded_in_surrounding_text(self):
        text = 'Here is the output:\n{"rules": [{"name": "Test"}]}\nDone.'
        result = extract_json_from_text(text)
        self.assertEqual(result["rules"][0]["name"], "Test")

    def test_trailing_comma_fixed(self):
        text = '{"rules": ["a", "b",]}'
        result = extract_json_from_text(text)
        self.assertEqual(result["rules"], ["a", "b"])

    def test_unescaped_quotes_repaired(self):
        """LLM output with unescaped double quotes inside string values."""
        bad = '{"rules": [{"name": "Test", "rule_content": "field="value" | stats count"}]}'
        result = extract_json_from_text(bad)
        self.assertIn("rules", result)
        self.assertEqual(len(result["rules"]), 1)
        self.assertEqual(result["rules"][0]["name"], "Test")

    def test_raises_on_completely_invalid_input(self):
        with self.assertRaises(ValueError):
            extract_json_from_text("this is not json at all, no braces")

    def test_nested_json_parsed(self):
        text = '{"a": {"b": {"c": 42}}}'
        result = extract_json_from_text(text)
        self.assertEqual(result["a"]["b"]["c"], 42)


class TestFixJsonFormatting(unittest.TestCase):

    def test_trailing_comma_removed(self):
        result = fix_json_formatting('{"a": 1,}')
        self.assertNotIn(",}", result)

    def test_escaped_quotes_preserved(self):
        """Escaped quotes in SPL strings must not be destroyed."""
        original = '{"rule_content": "sourcetype=\\"syslog\\""}'
        result = fix_json_formatting(original)
        self.assertIn('\\"syslog\\"', result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
