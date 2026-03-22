"""
tests/test_stage0.py — Stage 0: Pre-Load Unicode Scan
Session 0 test suite. Written before implementation.
"""

import json
import sys
import unittest.mock as mock
from pathlib import Path

import pytest

from sidecar.stage0_unicode_scan import (
    GLASSWORM_RANGES,
    scan_for_invisible_unicode,
    scan_file,
    _emit_span,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestScanForInvisibleUnicode:
    def test_clean_content_returns_pass(self):
        content = "const server = new MCPServer({ name: 'lint-checker' });\nserver.start();"
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "PASS"
        assert result["detection_type"] is None
        assert result["evidence"]["codepoints_found"] == 0
        assert result["evidence"]["positions"] == []

    def test_variation_selector_fe00_returns_block(self):
        content = "const hidden = '\ufe00';"
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "invisible_unicode_detected"
        assert result["evidence"]["codepoints_found"] == 1
        assert result["evidence"]["positions"][0]["codepoint"] == hex(0xFE00)

    def test_variation_selector_fe0f_boundary_returns_block(self):
        # U+FE0F is the last codepoint in the first Glassworm range
        content = "x\ufe0fy"
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "BLOCK"
        assert result["evidence"]["codepoints_found"] == 1
        assert result["evidence"]["positions"][0]["codepoint"] == hex(0xFE0F)

    def test_variation_selector_supplement_e0100_returns_block(self):
        # U+E0100 is in the Supplementary Multilingual Plane — requires chr() not literal
        content = "prefix" + chr(0xE0100) + "suffix"
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "invisible_unicode_detected"
        assert result["evidence"]["codepoints_found"] == 1
        assert result["evidence"]["positions"][0]["codepoint"] == hex(0xE0100)

    def test_variation_selector_supplement_e01ef_boundary_returns_block(self):
        content = chr(0xE01EF)
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "BLOCK"
        assert result["evidence"]["codepoints_found"] == 1

    def test_eight_fe00_codepoints_counted_correctly(self):
        # Matches exactly what the Glassworm fixture contains
        content = "".join(chr(0xFE00 + i) for i in range(8))
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "BLOCK"
        assert result["evidence"]["codepoints_found"] == 8
        assert len(result["evidence"]["positions"]) == 8

    def test_position_indices_are_correct(self):
        content = "ab\ufe00cd\ufe01ef"
        result = scan_for_invisible_unicode(content)
        positions = result["evidence"]["positions"]
        assert len(positions) == 2
        assert positions[0]["position"] == 2
        assert positions[1]["position"] == 5

    def test_normal_multibyte_unicode_not_flagged(self):
        content = "const greeting = '日本語テスト';"
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "PASS"

    def test_codepoint_just_below_fe00_not_flagged(self):
        # U+FDFF is one below the first range
        content = chr(0xFDFF)
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "PASS"

    def test_codepoint_just_above_fe0f_not_flagged(self):
        # U+FE10 is one above the first range
        content = chr(0xFE10)
        result = scan_for_invisible_unicode(content)
        assert result["verdict"] == "PASS"

    def test_empty_string_returns_pass(self):
        result = scan_for_invisible_unicode("")
        assert result["verdict"] == "PASS"


class TestScanFile:
    def test_clean_fixture_returns_pass(self):
        result = scan_file(str(FIXTURES / "clean_mcp_server.js"))
        assert result["verdict"] == "PASS"
        assert result["evidence"]["codepoints_found"] == 0
        assert result["evidence"]["file"].endswith("clean_mcp_server.js")

    def test_glassworm_fixture_returns_block(self):
        result = scan_file(str(FIXTURES / "glassworm_mcp_server.js"))
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "invisible_unicode_detected"

    def test_glassworm_fixture_codepoint_count(self):
        # Fixture contains 8 codepoints: U+FE00–U+FE07 (see fixture comment)
        result = scan_file(str(FIXTURES / "glassworm_mcp_server.js"))
        assert result["evidence"]["codepoints_found"] == 8

    def test_glassworm_fixture_all_positions_in_fe00_range(self):
        result = scan_file(str(FIXTURES / "glassworm_mcp_server.js"))
        for pos in result["evidence"]["positions"]:
            cp = int(pos["codepoint"], 16)
            assert 0xFE00 <= cp <= 0xFE0F, f"Unexpected codepoint: {pos['codepoint']}"

    def test_scan_file_adds_file_field_to_evidence(self):
        result = scan_file(str(FIXTURES / "clean_mcp_server.js"))
        assert "file" in result["evidence"]


class TestGlasswormRanges:
    def test_ranges_constant_has_two_entries(self):
        assert len(GLASSWORM_RANGES) == 2

    def test_fe00_range(self):
        lo, hi = GLASSWORM_RANGES[0]
        assert lo == 0xFE00
        assert hi == 0xFE0F

    def test_e0100_range(self):
        lo, hi = GLASSWORM_RANGES[1]
        assert lo == 0xE0100
        assert hi == 0xE01EF


class TestOtelSpanEmission:
    def _make_mock_span(self):
        mock_span = mock.MagicMock()
        cm = mock.MagicMock()
        cm.__enter__ = mock.MagicMock(return_value=mock_span)
        cm.__exit__ = mock.MagicMock(return_value=False)
        mock_tracer = mock.MagicMock()
        mock_tracer.start_as_current_span.return_value = cm
        mock_trace = mock.MagicMock()
        mock_trace.get_tracer.return_value = mock_tracer
        return mock_span, mock_trace

    def test_block_span_has_correct_security_fields(self):
        mock_span, mock_trace = self._make_mock_span()
        result = {
            "verdict": "BLOCK",
            "detection_type": "invisible_unicode_detected",
            "evidence": {"codepoints_found": 8, "positions": [], "file": "glassworm.js"},
        }
        with mock.patch("sidecar.stage0_unicode_scan.trace", mock_trace):
            _emit_span(result, file_path="glassworm.js")

        attrs = {c[0][0]: c[0][1] for c in mock_span.set_attribute.call_args_list}
        assert attrs["security.stage"] == 0
        assert attrs["security.layer"] == "Stage0"
        assert attrs["security.verdict"] == "BLOCK"
        assert attrs["security.detection_type"] == "invisible_unicode_detected"
        evidence = json.loads(attrs["security.evidence"])
        assert evidence["codepoints_found"] == 8

    def test_pass_span_has_correct_verdict(self):
        mock_span, mock_trace = self._make_mock_span()
        result = {
            "verdict": "PASS",
            "detection_type": None,
            "evidence": {"codepoints_found": 0, "positions": [], "file": "clean.js"},
        }
        with mock.patch("sidecar.stage0_unicode_scan.trace", mock_trace):
            _emit_span(result, file_path="clean.js")

        attrs = {c[0][0]: c[0][1] for c in mock_span.set_attribute.call_args_list}
        assert attrs["security.verdict"] == "PASS"
        # detection_type not set when verdict is PASS
        assert "security.detection_type" not in attrs

    def test_span_emission_graceful_when_trace_is_none(self):
        """No crash when opentelemetry not available (trace module-level var is None)."""
        with mock.patch("sidecar.stage0_unicode_scan.trace", None):
            # Should not raise
            _emit_span(
                {"verdict": "PASS", "detection_type": None, "evidence": {}},
                file_path=None,
            )
