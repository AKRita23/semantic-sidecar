"""
tests/test_stage5_cedar_policy.py — Stage 5: Cedar Policy (L3)

Tests for stage5_cedar_policy.py.

Cedar is the deterministic floor: runs unconditionally regardless of what prior
stages decided. If L2b had a race condition and missed a credential read, Cedar
denies it at access time with no timing dependency.

PolicyWatcher: threading.Event for clean stop — no hanging threads in tests.
"""

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from sidecar.stage5_cedar_policy import (
    CedarEvaluator,
    CedarRequest,
    CedarResult,
    PolicyWatcher,
    RealCedarEvaluator,
    StubCedarEvaluator,
    check_cedar_policy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STUB = StubCedarEvaluator()


def _check(action: str, resource: str, context: dict = None) -> dict:
    return check_cedar_policy(
        action=action,
        resource=resource,
        principal="MCPServer",
        context=context or {},
        evaluator=_STUB,
    )


# ---------------------------------------------------------------------------
# 1. file_read on ~/.ssh/* → BLOCK
# ---------------------------------------------------------------------------

def test_file_read_ssh_id_rsa_blocks():
    result = _check('Action::"file_read"', "/home/user/.ssh/id_rsa")
    assert result["verdict"] == "BLOCK"
    assert result["detection_type"] == "cedar_policy_deny"
    assert any("ssh" in r for r in result["reasons"])


def test_file_read_ssh_authorized_keys_blocks():
    result = _check('Action::"file_read"', "/home/ubuntu/.ssh/authorized_keys")
    assert result["verdict"] == "BLOCK"


# ---------------------------------------------------------------------------
# 2. file_read on ~/.aws/* → BLOCK
# ---------------------------------------------------------------------------

def test_file_read_aws_credentials_blocks():
    result = _check('Action::"file_read"', "/home/user/.aws/credentials")
    assert result["verdict"] == "BLOCK"
    assert any("aws" in r for r in result["reasons"])


def test_file_read_aws_config_blocks():
    result = _check('Action::"file_read"', "/home/user/.aws/config")
    assert result["verdict"] == "BLOCK"


# ---------------------------------------------------------------------------
# 3. file_read on ~/.config/gh/* → BLOCK
# ---------------------------------------------------------------------------

def test_file_read_gh_config_blocks():
    result = _check('Action::"file_read"', "/home/user/.config/gh/hosts.yml")
    assert result["verdict"] == "BLOCK"
    assert any("gh" in r for r in result["reasons"])


# ---------------------------------------------------------------------------
# 4. file_read on legitimate path → PASS
# ---------------------------------------------------------------------------

def test_file_read_staged_files_passes():
    result = _check('Action::"file_read"', "./staged_files/main.py")
    assert result["verdict"] == "PASS"
    assert result["detection_type"] is None
    assert result["reasons"] == []


def test_file_read_tmp_passes():
    result = _check('Action::"file_read"', "/tmp/lint_output.txt")
    assert result["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# 5. network_egress to declared destination → PASS
# ---------------------------------------------------------------------------

def test_network_egress_declared_destination_passes():
    result = _check(
        'Action::"network_egress"',
        "api.example.com:443",
        context={"declared_destinations": ["api.example.com:443"]},
    )
    assert result["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# 6. network_egress to undeclared destination → BLOCK
# ---------------------------------------------------------------------------

def test_network_egress_undeclared_blocks():
    result = _check(
        'Action::"network_egress"',
        "45.139.104.115:443",
        context={"declared_destinations": []},
    )
    assert result["verdict"] == "BLOCK"
    assert any("egress" in r for r in result["reasons"])


def test_network_egress_no_declared_destinations_blocks():
    """Empty declared_destinations means no egress allowed."""
    result = _check(
        'Action::"network_egress"',
        "1.2.3.4:80",
        context={},
    )
    assert result["verdict"] == "BLOCK"


# ---------------------------------------------------------------------------
# 7. tool_response with injection phrase → BLOCK
# ---------------------------------------------------------------------------

def test_tool_response_injection_phrase_blocks():
    result = _check(
        'Action::"tool_response"',
        "tool_output",
        context={"contains_injection_phrase": True},
    )
    assert result["verdict"] == "BLOCK"
    assert any("injection" in r for r in result["reasons"])


# ---------------------------------------------------------------------------
# 8. tool_response with tool call directive → BLOCK
# ---------------------------------------------------------------------------

def test_tool_response_tool_call_directive_blocks():
    result = _check(
        'Action::"tool_response"',
        "tool_output",
        context={"contains_tool_call_directive": True},
    )
    assert result["verdict"] == "BLOCK"
    assert any("tool_call" in r for r in result["reasons"])


# ---------------------------------------------------------------------------
# 9. tool_response clean → PASS
# ---------------------------------------------------------------------------

def test_tool_response_clean_passes():
    result = _check(
        'Action::"tool_response"',
        "tool_output",
        context={"contains_injection_phrase": False, "contains_tool_call_directive": False},
    )
    assert result["verdict"] == "PASS"


def test_tool_response_no_context_flags_passes():
    result = _check('Action::"tool_response"', "tool_output", context={})
    assert result["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# 10. StubCedarEvaluator returns decision + reasons
# ---------------------------------------------------------------------------

def test_stub_evaluator_returns_deny_with_reasons():
    req = CedarRequest(
        principal="MCPServer",
        action='Action::"file_read"',
        resource="/home/user/.ssh/id_rsa",
        context={},
    )
    result = _STUB.evaluate(req)
    assert result.decision == "Deny"
    assert len(result.reasons) > 0
    assert result.errors == []


def test_stub_evaluator_returns_allow_with_empty_reasons():
    req = CedarRequest(
        principal="MCPServer",
        action='Action::"file_read"',
        resource="./staged_files/clean.py",
        context={},
    )
    result = _STUB.evaluate(req)
    assert result.decision == "Allow"
    assert result.reasons == []


# ---------------------------------------------------------------------------
# 11. PolicyWatcher detects new file in policies/dynamic/
# ---------------------------------------------------------------------------

def test_policy_watcher_detects_new_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        watcher = PolicyWatcher(dynamic_dir=tmpdir, evaluator=_STUB, poll_interval=0.05)
        # Trigger initial baseline
        watcher._check_for_updates()
        initial_mtime = watcher._last_mtime

        # Drop a new file — wait briefly to ensure mtime changes
        time.sleep(0.05)
        (Path(tmpdir) / "new_policy.cedar").write_text("// new policy")

        watcher._check_for_updates()
        assert watcher._last_mtime > initial_mtime
        assert watcher.update_count >= 1


# ---------------------------------------------------------------------------
# 12. PolicyWatcher stops cleanly — no hanging threads
# ---------------------------------------------------------------------------

def test_policy_watcher_stops_cleanly():
    with tempfile.TemporaryDirectory() as tmpdir:
        watcher = PolicyWatcher(dynamic_dir=tmpdir, evaluator=_STUB, poll_interval=0.05)
        watcher.start()
        assert watcher._thread is not None
        assert watcher._thread.is_alive()
        watcher.stop()
        assert not watcher._thread.is_alive()


# ---------------------------------------------------------------------------
# 13-16. OTel span emission
# ---------------------------------------------------------------------------

def test_otel_span_emitted_on_block():
    with patch("sidecar.stage5_cedar_policy.emit_detection_span") as mock_emit:
        check_cedar_policy(
            action='Action::"file_read"',
            resource="/home/user/.ssh/id_rsa",
            principal="MCPServer",
            context={},
            evaluator=_STUB,
        )
        mock_emit.assert_called_once()
        _, kwargs = mock_emit.call_args
        assert kwargs["verdict"] == "BLOCK"
        assert kwargs["stage"] == 5
        assert kwargs["layer"] == "L3"
        assert kwargs["detection_type"] == "cedar_policy_deny"


def test_otel_span_emitted_on_pass():
    with patch("sidecar.stage5_cedar_policy.emit_detection_span") as mock_emit:
        check_cedar_policy(
            action='Action::"file_read"',
            resource="./staged_files/main.py",
            principal="MCPServer",
            context={},
            evaluator=_STUB,
        )
        mock_emit.assert_called_once()
        _, kwargs = mock_emit.call_args
        assert kwargs["verdict"] == "PASS"


def test_otel_span_evidence_contains_reasons():
    with patch("sidecar.stage5_cedar_policy.emit_detection_span") as mock_emit:
        check_cedar_policy(
            action='Action::"file_read"',
            resource="/home/user/.ssh/id_rsa",
            principal="MCPServer",
            context={},
            evaluator=_STUB,
        )
        _, kwargs = mock_emit.call_args
        assert "reasons" in kwargs["evidence"]
        assert isinstance(kwargs["evidence"]["reasons"], list)


def test_otel_span_detection_type_none_on_pass():
    with patch("sidecar.stage5_cedar_policy.emit_detection_span") as mock_emit:
        check_cedar_policy(
            action='Action::"file_read"',
            resource="./staged_files/main.py",
            principal="MCPServer",
            context={},
            evaluator=_STUB,
        )
        _, kwargs = mock_emit.call_args
        assert kwargs["detection_type"] is None


# ---------------------------------------------------------------------------
# 17. Cedar always runs — test with all prior stages hypothetically PASS
# ---------------------------------------------------------------------------

def test_cedar_always_runs_regardless_of_prior_stages():
    """
    Cedar is the floor. Even if every prior stage returned PASS, Cedar still
    evaluates. Simulate: prior stages PASSed, tool reads ~/.ssh/id_rsa.
    Cedar must BLOCK unconditionally.
    """
    # Prior stages all "PASSed" — we call Cedar directly
    result = check_cedar_policy(
        action='Action::"file_read"',
        resource="/home/user/.ssh/id_rsa",
        principal="MCPServer",
        context={"prior_stage_verdicts": ["PASS", "PASS", "PASS", "PASS", "PASS"]},
        evaluator=_STUB,
    )
    assert result["verdict"] == "BLOCK"


# ---------------------------------------------------------------------------
# 18. One-line swap: StubCedarEvaluator → RealCedarEvaluator
# ---------------------------------------------------------------------------

def test_swap_stub_to_real_one_line():
    """Swap interface: evaluator=RealCedarEvaluator() is a one-line change."""
    assert issubclass(RealCedarEvaluator, CedarEvaluator)
    assert issubclass(StubCedarEvaluator, CedarEvaluator)
    real = RealCedarEvaluator()
    assert hasattr(real, "evaluate")


# ---------------------------------------------------------------------------
# 19-20. Dataclass field completeness
# ---------------------------------------------------------------------------

def test_cedar_request_dataclass_fields():
    req = CedarRequest(
        principal="MCPServer::lint_check",
        action='Action::"file_read"',
        resource="/tmp/test.py",
        context={"declared_destinations": []},
    )
    assert req.principal == "MCPServer::lint_check"
    assert req.action == 'Action::"file_read"'
    assert req.resource == "/tmp/test.py"
    assert req.context == {"declared_destinations": []}


def test_cedar_result_dataclass_fields():
    res = CedarResult(decision="Deny", reasons=["sandworm_mode:deny_ssh"], errors=[])
    assert res.decision == "Deny"
    assert "sandworm_mode:deny_ssh" in res.reasons
    assert res.errors == []


# ---------------------------------------------------------------------------
# 21. Reasons list contains policy name — SIEM knows which policy fired
# ---------------------------------------------------------------------------

def test_reasons_list_contains_policy_name_ssh():
    result = _check('Action::"file_read"', "/home/user/.ssh/id_rsa")
    assert any("sandworm_mode" in r for r in result["reasons"])


def test_reasons_list_contains_policy_name_egress():
    result = _check(
        'Action::"network_egress"', "45.139.104.115:443",
        context={"declared_destinations": []},
    )
    assert any("sandworm_mode" in r for r in result["reasons"])


def test_reasons_list_contains_policy_name_injection():
    result = _check(
        'Action::"tool_response"', "output",
        context={"contains_injection_phrase": True},
    )
    assert any("output_validation" in r for r in result["reasons"])


# ---------------------------------------------------------------------------
# 22. Multiple deny reasons collected
# ---------------------------------------------------------------------------

def test_multiple_deny_reasons_when_both_flags_set():
    """Both injection phrase AND tool call directive set → two reasons."""
    result = _check(
        'Action::"tool_response"', "output",
        context={"contains_injection_phrase": True, "contains_tool_call_directive": True},
    )
    assert result["verdict"] == "BLOCK"
    assert len(result["reasons"]) >= 2
