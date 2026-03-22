"""
tests/test_span_emitter.py — Session 1: span_emitter.py
Unified OTel span emission used by all stages.
Written before implementation.
"""

import json
import unittest.mock as mock

import pytest

from sidecar.span_emitter import SECURITY_FIELDS, emit_detection_span


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_otel():
    """Return (mock_span, mock_trace) with a working context-manager tracer."""
    mock_span = mock.MagicMock()
    cm = mock.MagicMock()
    cm.__enter__ = mock.MagicMock(return_value=mock_span)
    cm.__exit__ = mock.MagicMock(return_value=False)
    mock_tracer = mock.MagicMock()
    mock_tracer.start_as_current_span.return_value = cm
    mock_trace = mock.MagicMock()
    mock_trace.get_tracer.return_value = mock_tracer
    return mock_span, mock_trace


def _attrs(mock_span):
    """Return {attribute_name: value} from all set_attribute calls."""
    return {c[0][0]: c[0][1] for c in mock_span.set_attribute.call_args_list}


# ---------------------------------------------------------------------------
# SECURITY_FIELDS constant
# ---------------------------------------------------------------------------

class TestSecurityFieldsConstant:
    REQUIRED = [
        "security.tool_description_hash",
        "security.declared_scope",
        "security.observed_scope",
        "security.declared_destinations",
        "security.observed_egress",
        "security.layer",
        "security.stage",
        "security.detection_type",
        "security.verdict",
        "security.evidence",
        "gen_ai.task.requester",
    ]

    def test_all_required_fields_present(self):
        for field in self.REQUIRED:
            assert field in SECURITY_FIELDS, f"Missing required field: {field}"

    def test_is_list(self):
        assert isinstance(SECURITY_FIELDS, list)


# ---------------------------------------------------------------------------
# Core field emission
# ---------------------------------------------------------------------------

class TestCoreFields:
    def test_security_stage_set(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="BLOCK",
                detection_type="invisible_unicode_detected",
                evidence={"codepoints_found": 8},
            )
        assert _attrs(mock_span)["security.stage"] == 0

    def test_security_layer_set(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="BLOCK",
                detection_type="invisible_unicode_detected",
                evidence={"codepoints_found": 8},
            )
        assert _attrs(mock_span)["security.layer"] == "Stage0"

    def test_security_verdict_block(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=2, layer="L0.5", verdict="BLOCK",
                detection_type="unregistered_server",
                evidence={"server": "~/.dev-utils/mcp.js"},
            )
        assert _attrs(mock_span)["security.verdict"] == "BLOCK"

    def test_security_verdict_warn(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=1, layer="Stage1", verdict="WARN",
                detection_type="typosquat_detected",
                evidence={"package": "suport-color"},
            )
        assert _attrs(mock_span)["security.verdict"] == "WARN"

    def test_security_verdict_pass(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="PASS",
                detection_type=None,
                evidence={"codepoints_found": 0},
            )
        assert _attrs(mock_span)["security.verdict"] == "PASS"

    def test_security_evidence_json_serialized(self):
        mock_span, mock_trace = _make_mock_otel()
        evidence = {"codepoints_found": 8, "positions": [{"position": 5, "codepoint": "0xfe00"}]}
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="BLOCK",
                detection_type="invisible_unicode_detected",
                evidence=evidence,
            )
        raw = _attrs(mock_span)["security.evidence"]
        parsed = json.loads(raw)
        assert parsed["codepoints_found"] == 8
        assert parsed["positions"][0]["codepoint"] == "0xfe00"


# ---------------------------------------------------------------------------
# detection_type field
# ---------------------------------------------------------------------------

class TestDetectionTypeField:
    def test_detection_type_set_when_provided(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=3, layer="L2", verdict="BLOCK",
                detection_type="orphaned_action_expired_task",
                evidence={},
            )
        assert _attrs(mock_span)["security.detection_type"] == "orphaned_action_expired_task"

    def test_detection_type_not_set_when_none(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="PASS",
                detection_type=None,
                evidence={},
            )
        assert "security.detection_type" not in _attrs(mock_span)


# ---------------------------------------------------------------------------
# Optional gen_ai fields
# ---------------------------------------------------------------------------

class TestOptionalGenAiFields:
    def test_tool_name_sets_gen_ai_tool_name(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=4, layer="L2b", verdict="BLOCK",
                detection_type="filesystem_scope_violation",
                evidence={},
                tool_name="lint_check",
            )
        assert _attrs(mock_span)["gen_ai.tool.name"] == "lint_check"

    def test_task_id_sets_gen_ai_task_id(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=3, layer="L2", verdict="PASS",
                detection_type=None,
                evidence={},
                task_id="task_abc123",
            )
        assert _attrs(mock_span)["gen_ai.task.id"] == "task_abc123"

    def test_tool_name_absent_when_not_provided(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="BLOCK",
                detection_type="invisible_unicode_detected",
                evidence={},
            )
        assert "gen_ai.tool.name" not in _attrs(mock_span)

    def test_task_id_absent_when_not_provided(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="BLOCK",
                detection_type="invisible_unicode_detected",
                evidence={},
            )
        assert "gen_ai.task.id" not in _attrs(mock_span)


# ---------------------------------------------------------------------------
# security_fields dict (Stage 4 scope fields)
# ---------------------------------------------------------------------------

class TestSecurityFieldsDict:
    def test_string_security_field_propagated(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=4, layer="L2b", verdict="BLOCK",
                detection_type="description_hash_mismatch",
                evidence={},
                security_fields={
                    "security.tool_description_hash": "sha256:abc123",
                },
            )
        assert _attrs(mock_span)["security.tool_description_hash"] == "sha256:abc123"

    def test_list_security_field_json_serialized(self):
        mock_span, mock_trace = _make_mock_otel()
        declared = ["./staged_files/"]
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=4, layer="L2b", verdict="BLOCK",
                detection_type="filesystem_scope_violation",
                evidence={},
                security_fields={
                    "security.declared_scope": declared,
                    "security.observed_scope": ["~/.ssh/id_rsa", "~/.aws/credentials"],
                },
            )
        attrs = _attrs(mock_span)
        assert json.loads(attrs["security.declared_scope"]) == ["./staged_files/"]
        assert "~/.ssh/id_rsa" in json.loads(attrs["security.observed_scope"])

    def test_network_scope_fields_propagated(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=4, layer="L2b", verdict="BLOCK",
                detection_type="network_egress_violation",
                evidence={},
                security_fields={
                    "security.declared_destinations": [],
                    "security.observed_egress": ["45.139.104.115:443"],
                },
            )
        attrs = _attrs(mock_span)
        assert json.loads(attrs["security.declared_destinations"]) == []
        assert json.loads(attrs["security.observed_egress"]) == ["45.139.104.115:443"]

    def test_unknown_key_in_security_fields_not_set(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=4, layer="L2b", verdict="PASS",
                detection_type=None,
                evidence={},
                security_fields={
                    "security.unknown_field": "should_be_ignored",
                },
            )
        assert "security.unknown_field" not in _attrs(mock_span)

    def test_gen_ai_task_requester_via_security_fields(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=3, layer="L2", verdict="BLOCK",
                detection_type="trigger_source_mismatch",
                evidence={},
                security_fields={"gen_ai.task.requester": "ci"},
            )
        assert _attrs(mock_span)["gen_ai.task.requester"] == "ci"

    def test_none_security_fields_is_fine(self):
        mock_span, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="PASS",
                detection_type=None,
                evidence={},
                security_fields=None,
            )
        # Should not raise; core fields still set
        assert _attrs(mock_span)["security.stage"] == 0


# ---------------------------------------------------------------------------
# Span naming
# ---------------------------------------------------------------------------

class TestSpanNaming:
    def test_span_name_includes_stage_number(self):
        _, mock_trace = _make_mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=2, layer="L0.5", verdict="BLOCK",
                detection_type="unregistered_server",
                evidence={},
            )
        tracer = mock_trace.get_tracer.return_value
        call_args = tracer.start_as_current_span.call_args
        span_name = call_args[0][0]
        assert "2" in span_name

    def test_different_stages_produce_different_span_names(self):
        _, mock_trace_a = _make_mock_otel()
        _, mock_trace_b = _make_mock_otel()

        with mock.patch("sidecar.span_emitter.trace", mock_trace_a):
            emit_detection_span(stage=0, layer="Stage0", verdict="PASS",
                                detection_type=None, evidence={})
        with mock.patch("sidecar.span_emitter.trace", mock_trace_b):
            emit_detection_span(stage=4, layer="L2b", verdict="BLOCK",
                                detection_type="filesystem_scope_violation", evidence={})

        name_a = mock_trace_a.get_tracer.return_value.start_as_current_span.call_args[0][0]
        name_b = mock_trace_b.get_tracer.return_value.start_as_current_span.call_args[0][0]
        assert name_a != name_b


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------

class TestGracefulDegradation:
    def test_no_crash_when_trace_is_none(self):
        with mock.patch("sidecar.span_emitter.trace", None):
            emit_detection_span(
                stage=0, layer="Stage0", verdict="BLOCK",
                detection_type="invisible_unicode_detected",
                evidence={"codepoints_found": 8},
            )

    def test_no_crash_with_all_optional_fields_when_trace_is_none(self):
        with mock.patch("sidecar.span_emitter.trace", None):
            emit_detection_span(
                stage=4, layer="L2b", verdict="BLOCK",
                detection_type="filesystem_scope_violation",
                evidence={"violations": ["~/.ssh/id_rsa"]},
                tool_name="lint_check",
                task_id="task_abc123",
                security_fields={
                    "security.declared_scope": ["./staged_files/"],
                    "security.observed_scope": ["~/.ssh/id_rsa"],
                },
            )


# ---------------------------------------------------------------------------
# Integration smoke: stage0 result flows through emit_detection_span
# ---------------------------------------------------------------------------

class TestIntegrationWithStage0:
    def test_stage0_import_chain_clean(self):
        """Both modules importable in same process with no conflicts."""
        from sidecar.stage0_unicode_scan import scan_for_invisible_unicode
        from sidecar.span_emitter import emit_detection_span
        assert callable(scan_for_invisible_unicode)
        assert callable(emit_detection_span)

    def test_stage0_block_result_accepted_by_emit_detection_span(self):
        from sidecar.stage0_unicode_scan import scan_for_invisible_unicode
        mock_span, mock_trace = _make_mock_otel()

        content = "".join(chr(0xFE00 + i) for i in range(8))
        result = scan_for_invisible_unicode(content)

        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0,
                layer="Stage0",
                verdict=result["verdict"],
                detection_type=result["detection_type"],
                evidence=result["evidence"],
            )

        attrs = _attrs(mock_span)
        assert attrs["security.verdict"] == "BLOCK"
        assert attrs["security.detection_type"] == "invisible_unicode_detected"
        assert json.loads(attrs["security.evidence"])["codepoints_found"] == 8

    def test_stage0_pass_result_accepted_by_emit_detection_span(self):
        from sidecar.stage0_unicode_scan import scan_for_invisible_unicode
        mock_span, mock_trace = _make_mock_otel()

        result = scan_for_invisible_unicode("const x = 'clean content';")

        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            emit_detection_span(
                stage=0,
                layer="Stage0",
                verdict=result["verdict"],
                detection_type=result["detection_type"],
                evidence=result["evidence"],
            )

        attrs = _attrs(mock_span)
        assert attrs["security.verdict"] == "PASS"
        assert "security.detection_type" not in attrs
