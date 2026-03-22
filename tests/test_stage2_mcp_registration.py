"""
tests/test_stage2_mcp_registration.py — Session 3: stage2_mcp_registration.py (Stage 2 / L0.5)
Hard BLOCK gate — AGNTCY MCP Server Badge verification.
Written before implementation.
"""

import json
import unittest.mock as mock
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sidecar.stage2_mcp_registration import (
    BadgeResult,
    BadgeVerifier,
    AgntcyBadgeVerifier,
    StubBadgeVerifier,
    verify_mcp_registration,
)

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

GOOD_HASH = "a" * 64   # 64-char hex string simulating a sha256
BAD_HASH  = "b" * 64
BADGE_ID  = "did:agntcy:mcp:lint-checker-v1.2"

ALLOWLIST = {
    "servers": [
        {
            "name": "lint-checker",
            "path_pattern": "~/.local/share/mcp/lint-checker*",
            "sha256": GOOD_HASH,
            "badge_metadata_id": BADGE_ID,
            "declared_capabilities": ["lint_check", "read_staged_files"],
            "declared_scope": ["./staged_files/"],
            "declared_destinations": [],
        }
    ],
    "suspicious_path_patterns": [
        "~/.dev-utils/",
        "/tmp/",
        "~/.cache/",
        "/var/tmp/",
    ],
}

VALID_PATH = "~/.local/share/mcp/lint-checker-v1.js"


def _make_stub() -> StubBadgeVerifier:
    return StubBadgeVerifier(ALLOWLIST)


def _mock_otel():
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
    return {c[0][0]: c[0][1] for c in mock_span.set_attribute.call_args_list}


# ---------------------------------------------------------------------------
# BadgeResult dataclass
# ---------------------------------------------------------------------------

class TestBadgeResult:
    def test_valid_badge_result(self):
        br = BadgeResult(
            valid=True,
            capabilities=["lint_check"],
            declared_scope=["./staged/"],
            declared_destinations=[],
            issuer="did:example:issuer",
            expires_at=None,
            evidence={},
        )
        assert br.valid is True
        assert br.capabilities == ["lint_check"]

    def test_invalid_badge_result_defaults(self):
        br = BadgeResult(valid=False)
        assert br.valid is False
        assert br.capabilities == []
        assert br.declared_scope == []
        assert br.declared_destinations == []
        assert br.issuer == ""
        assert br.expires_at is None
        assert br.evidence == {}

    def test_expires_at_accepts_datetime(self):
        dt = datetime(2027, 1, 1, tzinfo=timezone.utc)
        br = BadgeResult(valid=True, expires_at=dt)
        assert br.expires_at == dt


# ---------------------------------------------------------------------------
# StubBadgeVerifier
# ---------------------------------------------------------------------------

class TestStubBadgeVerifier:
    def test_known_badge_id_returns_valid_result(self):
        stub = _make_stub()
        result = stub.verify(BADGE_ID)
        assert result.valid is True
        assert "lint_check" in result.capabilities
        assert "read_staged_files" in result.capabilities

    def test_known_badge_id_populates_scope(self):
        stub = _make_stub()
        result = stub.verify(BADGE_ID)
        assert "./staged_files/" in result.declared_scope

    def test_known_badge_id_populates_destinations(self):
        stub = _make_stub()
        result = stub.verify(BADGE_ID)
        assert result.declared_destinations == []

    def test_unknown_badge_id_returns_invalid(self):
        stub = _make_stub()
        result = stub.verify("did:agntcy:mcp:unknown-server-xyz")
        assert result.valid is False

    def test_unknown_badge_evidence_contains_error(self):
        stub = _make_stub()
        result = stub.verify("did:agntcy:mcp:no-such-server")
        assert "error" in result.evidence

    def test_returns_badge_result_instances(self):
        stub = _make_stub()
        result = stub.verify(BADGE_ID)
        assert isinstance(result, BadgeResult)

    def test_loads_real_allowlist_json_by_default(self):
        """StubBadgeVerifier with no args reads badges/allowlist.json."""
        stub = StubBadgeVerifier()  # no allowlist arg — reads from file
        result = stub.verify("did:agntcy:mcp:lint-checker-v1.2")
        # The real allowlist.json has this badge_metadata_id
        assert isinstance(result, BadgeResult)


# ---------------------------------------------------------------------------
# BadgeVerifier interface (swap test)
# ---------------------------------------------------------------------------

class TestBadgeVerifierInterface:
    def test_stub_is_subclass_of_badge_verifier(self):
        assert issubclass(StubBadgeVerifier, BadgeVerifier)

    def test_agntcy_is_subclass_of_badge_verifier(self):
        assert issubclass(AgntcyBadgeVerifier, BadgeVerifier)

    def test_both_implement_verify_method(self):
        assert hasattr(StubBadgeVerifier, "verify")
        assert hasattr(AgntcyBadgeVerifier, "verify")

    def test_swapping_requires_one_line(self):
        """
        Verify the one-line swap contract:
          verifier=StubBadgeVerifier(allowlist)   ← testing
          verifier=AgntcyBadgeVerifier()          ← production
        Both satisfy BadgeVerifier and return BadgeResult.
        """
        stub  = StubBadgeVerifier(ALLOWLIST)
        agntcy = AgntcyBadgeVerifier()

        assert isinstance(stub, BadgeVerifier)
        assert isinstance(agntcy, BadgeVerifier)

        stub_result  = stub.verify(BADGE_ID)
        agntcy_result = agntcy.verify(BADGE_ID)

        assert isinstance(stub_result, BadgeResult)
        assert isinstance(agntcy_result, BadgeResult)

    def test_agntcy_verifier_returns_invalid_when_sdk_unavailable(self):
        """AgntcyBadgeVerifier degrades gracefully when agntcy_identity not installed."""
        agntcy = AgntcyBadgeVerifier()
        result = agntcy.verify("did:agntcy:mcp:anything")
        # SDK not installed → valid=False, no crash
        assert isinstance(result, BadgeResult)
        assert result.valid is False


# ---------------------------------------------------------------------------
# verify_mcp_registration — suspicious path (check 1)
# ---------------------------------------------------------------------------

class TestSuspiciousPath:
    def test_dev_utils_path_is_blocked(self):
        result = verify_mcp_registration(
            "~/.dev-utils/mcp-server.js", GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "suspicious_path"
        assert result["badge_valid"] is False

    def test_tmp_path_is_blocked(self):
        result = verify_mcp_registration(
            "/tmp/mcp-server.js", GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "suspicious_path"

    def test_cache_path_is_blocked(self):
        # Glassworm installed at ~/.cache/
        result = verify_mcp_registration(
            "~/.cache/watercrawl-mcp/server.js", GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "suspicious_path"

    def test_var_tmp_path_is_blocked(self):
        result = verify_mcp_registration(
            "/var/tmp/evil-mcp.js", GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "suspicious_path"

    def test_suspicious_path_evidence_includes_matched_pattern(self):
        result = verify_mcp_registration(
            "~/.dev-utils/mcp-server.js", GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert "matched_pattern" in result["evidence"]
        assert "server_path" in result["evidence"]


# ---------------------------------------------------------------------------
# verify_mcp_registration — server not in allowlist (check 2)
# ---------------------------------------------------------------------------

class TestNotInAllowlist:
    def test_unknown_path_not_suspicious_is_blocked(self):
        # Non-suspicious path but not in allowlist
        result = verify_mcp_registration(
            "~/.local/share/mcp/unknown-server.js", GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "server_not_in_allowlist"

    def test_glassworm_package_not_in_allowlist_is_blocked(self):
        # @iflow-mcp/watercrawl path (not in allowlist, also not suspicious path)
        result = verify_mcp_registration(
            "~/.local/share/mcp/watercrawl-watercrawl-mcp.js", GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "server_not_in_allowlist"

    def test_evidence_includes_server_path(self):
        result = verify_mcp_registration(
            "~/.local/share/mcp/not-there.js", GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["evidence"]["server_path"].endswith("not-there.js")


# ---------------------------------------------------------------------------
# verify_mcp_registration — hash mismatch (check 3)
# ---------------------------------------------------------------------------

class TestHashMismatch:
    def test_hash_mismatch_is_blocked(self):
        result = verify_mcp_registration(
            VALID_PATH, BAD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "binary_hash_mismatch"
        assert result["badge_valid"] is False

    def test_hash_mismatch_evidence_includes_both_hashes(self):
        result = verify_mcp_registration(
            VALID_PATH, BAD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["evidence"]["expected_hash"] == GOOD_HASH
        assert result["evidence"]["actual_hash"] == BAD_HASH

    def test_correct_hash_passes_check(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        # Should not be blocked for hash mismatch (may pass or fail later checks)
        assert result["detection_type"] != "binary_hash_mismatch"

    def test_entry_without_sha256_skips_hash_check(self):
        """Allowlist entry with no sha256 field does not block."""
        allowlist = {
            "servers": [
                {
                    "name": "no-hash-server",
                    "path_pattern": "~/.local/share/mcp/no-hash*",
                    "badge_metadata_id": "did:agntcy:mcp:no-hash-v1",
                    "declared_capabilities": ["do_thing"],
                    "declared_scope": [],
                    "declared_destinations": [],
                }
            ],
            "suspicious_path_patterns": [],
        }
        stub = StubBadgeVerifier(allowlist)
        result = verify_mcp_registration(
            "~/.local/share/mcp/no-hash-server.js", "any-hash",
            verifier=stub, allowlist=allowlist,
        )
        assert result["detection_type"] != "binary_hash_mismatch"


# ---------------------------------------------------------------------------
# verify_mcp_registration — badge verification (check 4)
# ---------------------------------------------------------------------------

class TestBadgeVerification:
    def test_invalid_badge_is_blocked(self):
        bad_verifier = mock.MagicMock(spec=BadgeVerifier)
        bad_verifier.verify.return_value = BadgeResult(
            valid=False, evidence={"error": "signature_invalid"}
        )
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            verifier=bad_verifier, allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "badge_verification_failed"
        assert result["badge_valid"] is False

    def test_badge_evidence_in_block_result(self):
        bad_verifier = mock.MagicMock(spec=BadgeVerifier)
        bad_verifier.verify.return_value = BadgeResult(
            valid=False, evidence={"error": "expired"}
        )
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            verifier=bad_verifier, allowlist=ALLOWLIST,
        )
        assert "badge_metadata_id" in result["evidence"]

    def test_valid_badge_passes_check(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "PASS"
        assert result["badge_valid"] is True


# ---------------------------------------------------------------------------
# verify_mcp_registration — tool capability check (check 5)
# ---------------------------------------------------------------------------

class TestToolCapabilityCheck:
    def test_tool_not_in_capabilities_is_blocked(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            tool_names=["lint_check", "read_credentials"],  # read_credentials not declared
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "BLOCK"
        assert result["detection_type"] == "tool_not_in_declared_capabilities"

    def test_unauthorized_tools_listed_in_evidence(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            tool_names=["read_credentials", "exfil_data"],
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        ev = result["evidence"]
        assert "read_credentials" in ev["unauthorized_tools"]
        assert "exfil_data" in ev["unauthorized_tools"]

    def test_declared_capabilities_in_evidence(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            tool_names=["unauthorized_tool"],
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert "declared_capabilities" in result["evidence"]

    def test_tool_check_badge_valid_is_true_when_badge_ok(self):
        """badge_valid=True even if tool is unauthorized — badge itself was valid."""
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            tool_names=["unauthorized_tool"],
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["badge_valid"] is True

    def test_all_tools_in_capabilities_passes(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            tool_names=["lint_check", "read_staged_files"],
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "PASS"

    def test_no_tool_names_skips_capability_check(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            tool_names=None,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# verify_mcp_registration — PASS result
# ---------------------------------------------------------------------------

class TestPassResult:
    def test_pass_includes_capabilities(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert "lint_check" in result["capabilities"]
        assert "read_staged_files" in result["capabilities"]

    def test_pass_includes_declared_scope(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert "./staged_files/" in result["declared_scope"]

    def test_pass_includes_declared_destinations(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["declared_destinations"] == []

    def test_pass_badge_valid_is_true(self):
        result = verify_mcp_registration(
            VALID_PATH, GOOD_HASH,
            verifier=_make_stub(), allowlist=ALLOWLIST,
        )
        assert result["badge_valid"] is True


# ---------------------------------------------------------------------------
# OTel span emission
# ---------------------------------------------------------------------------

class TestSpanEmission:
    def test_block_suspicious_path_emits_span(self):
        mock_span, mock_trace = _mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            result = verify_mcp_registration(
                "~/.dev-utils/evil.js", GOOD_HASH,
                verifier=_make_stub(), allowlist=ALLOWLIST,
            )
        assert result["verdict"] == "BLOCK"
        attrs = _attrs(mock_span)
        assert attrs["security.verdict"] == "BLOCK"
        assert attrs["security.stage"] == 2
        assert attrs["security.layer"] == "L0.5"

    def test_block_badge_failed_emits_span_with_badge_valid_false(self):
        bad_verifier = mock.MagicMock(spec=BadgeVerifier)
        bad_verifier.verify.return_value = BadgeResult(valid=False, evidence={})
        mock_span, mock_trace = _mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            result = verify_mcp_registration(
                VALID_PATH, GOOD_HASH,
                verifier=bad_verifier, allowlist=ALLOWLIST,
            )
        assert result["verdict"] == "BLOCK"
        attrs = _attrs(mock_span)
        assert attrs["security.verdict"] == "BLOCK"
        ev = json.loads(attrs["security.evidence"])
        assert ev.get("badge_valid") is False

    def test_pass_emits_span_with_capabilities(self):
        mock_span, mock_trace = _mock_otel()
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            result = verify_mcp_registration(
                VALID_PATH, GOOD_HASH,
                tool_names=["lint_check"],
                verifier=_make_stub(), allowlist=ALLOWLIST,
            )
        assert result["verdict"] == "PASS"
        attrs = _attrs(mock_span)
        assert attrs["security.verdict"] == "PASS"
        ev = json.loads(attrs["security.evidence"])
        assert "lint_check" in ev.get("capabilities", [])


# ---------------------------------------------------------------------------
# allowlist.json structure
# ---------------------------------------------------------------------------

class TestAllowlistJson:
    ALLOWLIST_PATH = Path(__file__).parent.parent / "badges" / "allowlist.json"

    def test_allowlist_file_exists(self):
        assert self.ALLOWLIST_PATH.exists()

    def test_allowlist_has_servers_list(self):
        data = json.loads(self.ALLOWLIST_PATH.read_text())
        assert "servers" in data
        assert isinstance(data["servers"], list)

    def test_allowlist_has_suspicious_path_patterns(self):
        data = json.loads(self.ALLOWLIST_PATH.read_text())
        assert "suspicious_path_patterns" in data

    def test_allowlist_does_not_have_malicious_list(self):
        """v3: allowlist.json is trust registry only — no threat intel."""
        data = json.loads(self.ALLOWLIST_PATH.read_text())
        assert "known_malicious_packages" not in data

    def test_server_entry_has_required_fields(self):
        data = json.loads(self.ALLOWLIST_PATH.read_text())
        required = {"name", "path_pattern", "sha256", "badge_metadata_id",
                    "declared_capabilities", "declared_scope", "declared_destinations"}
        for server in data["servers"]:
            for field in required:
                assert field in server, f"Server entry missing field: {field}"

    def test_badge_metadata_id_looks_like_did(self):
        data = json.loads(self.ALLOWLIST_PATH.read_text())
        for server in data["servers"]:
            mid = server.get("badge_metadata_id", "")
            assert mid.startswith("did:"), f"badge_metadata_id should be a DID: {mid}"

    def test_suspicious_path_patterns_include_key_paths(self):
        data = json.loads(self.ALLOWLIST_PATH.read_text())
        patterns = data["suspicious_path_patterns"]
        assert any("dev-utils" in p for p in patterns)
        assert any("/tmp" in p for p in patterns)
        assert any("cache" in p for p in patterns)
