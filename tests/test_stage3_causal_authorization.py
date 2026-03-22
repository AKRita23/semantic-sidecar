"""
tests/test_stage3_causal_authorization.py — Stage 3: Causal Authorization

Tests for stage3_causal_authorization.py.

Critical test: SANDWORM_MODE 48h delay — task_id expired 47 hours ago → BLOCK.
All datetime comparisons use datetime.now(UTC) ± timedelta to avoid
hardcoded timestamps and prevent time-dependent test failures.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from sidecar.stage3_causal_authorization import (
    AgentBadgeResult,
    AgentBadgeVerifier,
    AgntcyAgentBadgeVerifier,
    StubAgentBadgeVerifier,
    TaskContext,
    TaskRegistry,
    check_causal_authorization,
    register_task_from_badge,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_context(
    task_id: str = "task-001",
    permitted_tools: list = None,
    hours_ago: float = 0.0,
    duration_hours: float = 2.0,
) -> TaskContext:
    """Create a TaskContext issued `hours_ago` hours in the past, valid for `duration_hours`."""
    issued_at = _now() - timedelta(hours=hours_ago)
    expires_at = issued_at + timedelta(hours=duration_hours)
    return TaskContext(
        task_id=task_id,
        agent_badge_metadata_id="did:agntcy:agent:openclaw-v1",
        authorized_by="user@example.com",
        issued_at=issued_at,
        expires_at=expires_at,
        permitted_tools=permitted_tools if permitted_tools is not None else ["weather_query", "slack_post"],
    )


def _make_registry(*contexts: TaskContext) -> TaskRegistry:
    reg = TaskRegistry()
    for ctx in contexts:
        reg.register(ctx)
    return reg


# ---------------------------------------------------------------------------
# 1. No task_id → BLOCK orphaned_action_no_task_id
# ---------------------------------------------------------------------------

def test_no_task_id_blocks():
    reg = _make_registry(_make_context())
    result = check_causal_authorization("weather_query", None, reg)
    assert result["verdict"] == "BLOCK"
    assert result["detection_type"] == "orphaned_action_no_task_id"


# ---------------------------------------------------------------------------
# 2. Unknown task_id → BLOCK orphaned_action_unknown_task_id
# ---------------------------------------------------------------------------

def test_unknown_task_id_blocks():
    reg = _make_registry()  # empty registry
    result = check_causal_authorization("weather_query", "nonexistent-task", reg)
    assert result["verdict"] == "BLOCK"
    assert result["detection_type"] == "orphaned_action_unknown_task_id"


# ---------------------------------------------------------------------------
# 3. Valid task, not expired, tool permitted → PASS
# ---------------------------------------------------------------------------

def test_valid_task_not_expired_permitted_tool_passes():
    ctx = _make_context(hours_ago=0.1, duration_hours=2.0)
    reg = _make_registry(ctx)
    result = check_causal_authorization("weather_query", ctx.task_id, reg)
    assert result["verdict"] == "PASS"
    assert result["detection_type"] is None


# ---------------------------------------------------------------------------
# 4. task_id expired 47h ago → BLOCK  ← CRITICAL: SANDWORM_MODE 48h delay
# ---------------------------------------------------------------------------

def test_task_expired_47h_ago_blocks():
    """
    SANDWORM_MODE detection: task issued 47 hours ago, valid for 1 hour.
    Task expired 46 hours ago. Tool invocation is orphaned.
    """
    ctx = _make_context(hours_ago=47.0, duration_hours=1.0)
    assert ctx.expires_at < _now(), "Precondition: task must already be expired"
    reg = _make_registry(ctx)
    result = check_causal_authorization("weather_query", ctx.task_id, reg)
    assert result["verdict"] == "BLOCK"
    assert result["detection_type"] == "orphaned_action_expired_task"


# ---------------------------------------------------------------------------
# 5. task_id expires in future → PASS
# ---------------------------------------------------------------------------

def test_task_expires_in_future_passes():
    ctx = _make_context(hours_ago=0.0, duration_hours=1.0)
    reg = _make_registry(ctx)
    result = check_causal_authorization("weather_query", ctx.task_id, reg)
    assert result["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# 6. task_id expired 1 second ago → BLOCK
# ---------------------------------------------------------------------------

def test_task_expired_1s_ago_blocks():
    issued_at = _now() - timedelta(hours=1)
    expires_at = _now() - timedelta(seconds=1)
    ctx = TaskContext(
        task_id="task-expired-1s",
        agent_badge_metadata_id="did:agntcy:agent:openclaw-v1",
        authorized_by="user@example.com",
        issued_at=issued_at,
        expires_at=expires_at,
        permitted_tools=["weather_query"],
    )
    reg = _make_registry(ctx)
    result = check_causal_authorization("weather_query", ctx.task_id, reg)
    assert result["verdict"] == "BLOCK"
    assert result["detection_type"] == "orphaned_action_expired_task"


# ---------------------------------------------------------------------------
# 7. tool_name not in permitted_tools → BLOCK
# ---------------------------------------------------------------------------

def test_tool_not_in_permitted_tools_blocks():
    ctx = _make_context(permitted_tools=["weather_query"])
    reg = _make_registry(ctx)
    result = check_causal_authorization("read_file", ctx.task_id, reg)
    assert result["verdict"] == "BLOCK"
    assert result["detection_type"] == "orphaned_action_unauthorized_tool"


# ---------------------------------------------------------------------------
# 8. Glassworm scenario: no task_id at init time → BLOCK
# ---------------------------------------------------------------------------

def test_glassworm_no_task_id_at_init():
    """
    Glassworm fires at MCP server init — no task context exists yet.
    tool_name is 'init' or similar; task_id is None.
    """
    reg = TaskRegistry()  # no tasks registered
    result = check_causal_authorization("init", None, reg)
    assert result["verdict"] == "BLOCK"
    assert result["detection_type"] == "orphaned_action_no_task_id"


# ---------------------------------------------------------------------------
# 9. TaskRegistry.is_valid() correctly checks expiry
# ---------------------------------------------------------------------------

def test_task_registry_is_valid_checks_expiry_false_for_expired():
    ctx = _make_context(task_id="expired-task", hours_ago=2.0, duration_hours=1.0)
    reg = _make_registry(ctx)
    assert reg.is_valid("expired-task") is False


def test_task_registry_is_valid_checks_expiry_true_for_active():
    ctx = _make_context(task_id="active-task", hours_ago=0.1, duration_hours=1.0)
    reg = _make_registry(ctx)
    assert reg.is_valid("active-task") is True


def test_task_registry_is_valid_false_for_unknown():
    reg = TaskRegistry()
    assert reg.is_valid("ghost-task") is False


# ---------------------------------------------------------------------------
# 10. Evidence contains required fields
# ---------------------------------------------------------------------------

def test_evidence_contains_task_id_on_block():
    ctx = _make_context()
    reg = _make_registry(ctx)
    result = check_causal_authorization("bad_tool", ctx.task_id, reg)
    assert result["verdict"] == "BLOCK"
    assert result["evidence"]["task_id"] == ctx.task_id


def test_evidence_contains_expires_at_on_expired_block():
    ctx = _make_context(hours_ago=47.0, duration_hours=1.0)
    reg = _make_registry(ctx)
    result = check_causal_authorization("weather_query", ctx.task_id, reg)
    assert "expires_at" in result["evidence"]


def test_evidence_contains_authorized_by_on_pass():
    ctx = _make_context()
    reg = _make_registry(ctx)
    result = check_causal_authorization("weather_query", ctx.task_id, reg)
    assert result["evidence"]["authorized_by"] == "user@example.com"


# ---------------------------------------------------------------------------
# 11-14. OTel span emission
# ---------------------------------------------------------------------------

def test_otel_span_emitted_on_block_no_task_id():
    with patch("sidecar.stage3_causal_authorization.emit_detection_span") as mock_emit:
        reg = TaskRegistry()
        check_causal_authorization("weather_query", None, reg)
        mock_emit.assert_called_once()
        call_kwargs = mock_emit.call_args[1] if mock_emit.call_args[1] else {}
        call_args = mock_emit.call_args[0] if mock_emit.call_args[0] else ()
        # Works with both positional and keyword calls
        assert mock_emit.called


def test_otel_span_verdict_block_on_orphaned():
    with patch("sidecar.stage3_causal_authorization.emit_detection_span") as mock_emit:
        reg = TaskRegistry()
        check_causal_authorization("weather_query", None, reg)
        _, kwargs = mock_emit.call_args
        assert kwargs.get("verdict") == "BLOCK"


def test_otel_span_detection_type_correct_on_orphaned():
    with patch("sidecar.stage3_causal_authorization.emit_detection_span") as mock_emit:
        reg = TaskRegistry()
        check_causal_authorization("weather_query", None, reg)
        _, kwargs = mock_emit.call_args
        assert kwargs.get("detection_type") == "orphaned_action_no_task_id"


def test_otel_span_gen_ai_task_requester_model_autonomous_on_orphaned():
    """Orphaned actions get gen_ai.task.requester = 'model_autonomous' in security_fields."""
    with patch("sidecar.stage3_causal_authorization.emit_detection_span") as mock_emit:
        reg = TaskRegistry()
        check_causal_authorization("weather_query", None, reg)
        _, kwargs = mock_emit.call_args
        sf = kwargs.get("security_fields", {})
        assert sf.get("gen_ai.task.requester") == "model_autonomous"


def test_otel_span_task_id_passed_when_present():
    """When task_id is known (unknown in registry), task_id still passed to span."""
    with patch("sidecar.stage3_causal_authorization.emit_detection_span") as mock_emit:
        reg = TaskRegistry()
        check_causal_authorization("weather_query", "some-task-id", reg)
        _, kwargs = mock_emit.call_args
        assert kwargs.get("task_id") == "some-task-id"


def test_otel_span_emitted_on_pass():
    with patch("sidecar.stage3_causal_authorization.emit_detection_span") as mock_emit:
        ctx = _make_context()
        reg = _make_registry(ctx)
        check_causal_authorization("weather_query", ctx.task_id, reg)
        mock_emit.assert_called_once()
        _, kwargs = mock_emit.call_args
        assert kwargs.get("verdict") == "PASS"


def test_otel_span_stage_is_3():
    with patch("sidecar.stage3_causal_authorization.emit_detection_span") as mock_emit:
        reg = TaskRegistry()
        check_causal_authorization("weather_query", None, reg)
        _, kwargs = mock_emit.call_args
        assert kwargs.get("stage") == 3


def test_otel_span_layer_is_L2():
    with patch("sidecar.stage3_causal_authorization.emit_detection_span") as mock_emit:
        reg = TaskRegistry()
        check_causal_authorization("weather_query", None, reg)
        _, kwargs = mock_emit.call_args
        assert kwargs.get("layer") == "L2"


# ---------------------------------------------------------------------------
# 15. register_task_from_badge — badge verifier integration
# ---------------------------------------------------------------------------

def test_register_task_from_badge_valid_badge():
    stub = StubAgentBadgeVerifier({
        "did:agntcy:agent:openclaw-v1": AgentBadgeResult(
            valid=True,
            authorized_by="alice@example.com",
            permitted_tools=["weather_query"],
            issued_at=_now(),
            expires_at=_now() + timedelta(hours=1),
            issuer="okta.example.com",
            evidence={},
        )
    })
    reg = TaskRegistry()
    result = register_task_from_badge(
        task_id="task-badge-001",
        agent_badge_metadata_id="did:agntcy:agent:openclaw-v1",
        registry=reg,
        verifier=stub,
    )
    assert result["verdict"] == "PASS"
    assert reg.get("task-badge-001") is not None


def test_register_task_from_badge_invalid_badge():
    stub = StubAgentBadgeVerifier({
        "did:agntcy:agent:openclaw-v1": AgentBadgeResult(
            valid=False,
            authorized_by="",
            permitted_tools=[],
            issued_at=_now(),
            expires_at=_now() + timedelta(hours=1),
            issuer="",
            evidence={"error": "signature_invalid"},
        )
    })
    reg = TaskRegistry()
    result = register_task_from_badge(
        task_id="task-bad-badge",
        agent_badge_metadata_id="did:agntcy:agent:openclaw-v1",
        registry=reg,
        verifier=stub,
    )
    assert result["verdict"] == "BLOCK"
    assert result["detection_type"] == "badge_verification_failed"
    assert reg.get("task-bad-badge") is None


def test_stub_to_agntcy_verifier_one_line_swap():
    """Verifies the swap interface exists and is an AgentBadgeVerifier subclass."""
    assert issubclass(AgntcyAgentBadgeVerifier, AgentBadgeVerifier)
    assert issubclass(StubAgentBadgeVerifier, AgentBadgeVerifier)
    # One-line swap: verifier=AgntcyAgentBadgeVerifier()
    prod = AgntcyAgentBadgeVerifier()
    assert hasattr(prod, "verify")


# ---------------------------------------------------------------------------
# 16. AgentBadgeResult fields correctly populated
# ---------------------------------------------------------------------------

def test_agent_badge_result_fields():
    now = _now()
    expires = now + timedelta(hours=1)
    result = AgentBadgeResult(
        valid=True,
        authorized_by="user@example.com",
        permitted_tools=["tool_a", "tool_b"],
        issued_at=now,
        expires_at=expires,
        issuer="okta.example.com",
        evidence={"source": "stub"},
    )
    assert result.valid is True
    assert result.authorized_by == "user@example.com"
    assert "tool_a" in result.permitted_tools
    assert result.issuer == "okta.example.com"


# ---------------------------------------------------------------------------
# 17. TaskRegistry.get() returns None for missing task
# ---------------------------------------------------------------------------

def test_task_registry_get_returns_none_for_missing():
    reg = TaskRegistry()
    assert reg.get("not-there") is None


def test_task_registry_get_returns_context_when_registered():
    ctx = _make_context(task_id="t-42")
    reg = _make_registry(ctx)
    fetched = reg.get("t-42")
    assert fetched is not None
    assert fetched.task_id == "t-42"
