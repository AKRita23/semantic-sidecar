"""
sidecar/stage2_mcp_registration.py — Stage 2: MCP Registration Integrity (L0.5)

Hard BLOCK gate. No advisory here — if any check fails, the server does not load.

AGNTCY MCP Server Badge facts (do not change):
  - W3C Verifiable Credential with RS256 signature
  - Verification is PERMISSIONLESS — no IdP needed at verify time
  - `identity badge verify {metadata_id}` is a public operation
  - Badge carries: capabilities, declared_scope, declared_destinations, issuer, expiry
  - Okta/Auth0 are trusted issuers for badge ISSUANCE only — not needed for verification

Five checks in order:
  1. Server binary path matches a suspicious pattern   → BLOCK
  2. Server path matches an allowlist entry            → BLOCK if not found
  3. SHA-256 hash matches allowlist entry              → BLOCK if mismatch
  4. AGNTCY badge verification returns valid           → BLOCK if invalid
  5. Invoked tool names ⊆ badge declared_capabilities → BLOCK if any missing

BadgeVerifier interface enables one-line swap from StubBadgeVerifier (testing)
to AgntcyBadgeVerifier (production) with no other code changes.

OTel spans emitted on both BLOCK and PASS — hard gate decisions require
full audit trail, not just failure records.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import List, Optional

from sidecar.span_emitter import emit_detection_span

# ---------------------------------------------------------------------------
# BadgeResult — returned by all BadgeVerifier implementations
# ---------------------------------------------------------------------------

@dataclass
class BadgeResult:
    """Result of an AGNTCY badge verification call."""
    valid: bool
    capabilities: List[str] = field(default_factory=list)
    declared_scope: List[str] = field(default_factory=list)
    declared_destinations: List[str] = field(default_factory=list)
    issuer: str = ""
    expires_at: Optional[datetime] = None
    evidence: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# BadgeVerifier interface + implementations
# ---------------------------------------------------------------------------

class BadgeVerifier(ABC):
    """Abstract interface for AGNTCY badge verification. Swap implementations freely."""

    @abstractmethod
    def verify(self, metadata_id: str) -> BadgeResult:
        """Verify an AGNTCY badge and return its claims."""
        ...


class AgntcyBadgeVerifier(BadgeVerifier):
    """
    Production verifier using the AGNTCY identity SDK.
    Verification is permissionless — no IdP or credentials required.
    Degrades gracefully if agntcy_identity is not installed.
    """

    def verify(self, metadata_id: str) -> BadgeResult:
        try:
            from agntcy_identity import verify_badge  # type: ignore
            result = verify_badge(metadata_id=metadata_id)
            expires_at = None
            if result.get("expires_at"):
                try:
                    expires_at = datetime.fromisoformat(result["expires_at"])
                except (ValueError, TypeError):
                    pass
            return BadgeResult(
                valid=result.get("valid", False),
                capabilities=result.get("capabilities", []),
                declared_scope=result.get("declared_scope", []),
                declared_destinations=result.get("declared_destinations", []),
                issuer=result.get("issuer", ""),
                expires_at=expires_at,
                evidence=result,
            )
        except ImportError:
            return BadgeResult(
                valid=False,
                evidence={"error": "agntcy_identity SDK not installed"},
            )
        except Exception as exc:
            return BadgeResult(
                valid=False,
                evidence={"error": str(exc)},
            )


class StubBadgeVerifier(BadgeVerifier):
    """
    Stub verifier for testing and SDK-unavailable scenarios.
    Reads badge claims from badges/allowlist.json (or an injected dict).
    Returns real BadgeResult objects — not mocks.

    To swap to production:  verifier=AgntcyBadgeVerifier()  ← one line
    """

    def __init__(self, allowlist: Optional[dict] = None):
        if allowlist is None:
            allowlist_path = Path(__file__).parent.parent / "badges" / "allowlist.json"
            allowlist = json.loads(allowlist_path.read_text(encoding="utf-8"))
        self._allowlist = allowlist

    def verify(self, metadata_id: str) -> BadgeResult:
        for server in self._allowlist.get("servers", []):
            if server.get("badge_metadata_id") == metadata_id:
                return BadgeResult(
                    valid=True,
                    capabilities=server.get("declared_capabilities", []),
                    declared_scope=server.get("declared_scope", []),
                    declared_destinations=server.get("declared_destinations", []),
                    issuer="stub-issuer",
                    expires_at=None,
                    evidence={"source": "allowlist", "server_name": server.get("name")},
                )
        return BadgeResult(
            valid=False,
            evidence={"error": f"badge_metadata_id not found in allowlist: {metadata_id}"},
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_mcp_registration(
    server_path: str,
    server_binary_hash: str,
    tool_names: Optional[List[str]] = None,
    verifier: Optional[BadgeVerifier] = None,
    allowlist: Optional[dict] = None,
) -> dict:
    """
    Hard BLOCK gate for MCP server registration integrity.

    Args:
        server_path:        Path to the MCP server binary or script.
        server_binary_hash: SHA-256 hex digest of the binary at load time.
        tool_names:         Tool names being invoked; checked against declared_capabilities.
                            Pass None to skip capability check.
        verifier:           BadgeVerifier implementation. Defaults to StubBadgeVerifier.
                            Swap to AgntcyBadgeVerifier() for production — one line change.
        allowlist:          Allowlist dict. Defaults to reading badges/allowlist.json.

    Returns:
        {
            "verdict": "BLOCK" | "PASS",
            "detection_type": str | None,
            "badge_valid": bool,
            "evidence": dict,
            # On PASS only:
            "capabilities": List[str],
            "declared_scope": List[str],
            "declared_destinations": List[str],
        }
    """
    if allowlist is None:
        allowlist = _load_allowlist()
    if verifier is None:
        verifier = StubBadgeVerifier(allowlist)

    expanded = _expand(server_path)

    # --- Check 1: suspicious path patterns -------------------------------------
    for pattern in allowlist.get("suspicious_path_patterns", []):
        if expanded.startswith(_expand(pattern)):
            evidence = {"server_path": server_path, "matched_pattern": pattern}
            return _block("suspicious_path", evidence, badge_valid=False)

    # --- Check 2: path must match an allowlist entry ---------------------------
    entry = _find_entry(expanded, allowlist)
    if entry is None:
        evidence = {"server_path": server_path}
        return _block("server_not_in_allowlist", evidence, badge_valid=False)

    # --- Check 3: SHA-256 hash must match allowlist entry ----------------------
    expected_hash = entry.get("sha256", "")
    if expected_hash and expected_hash != server_binary_hash:
        evidence = {
            "server_path": server_path,
            "expected_hash": expected_hash,
            "actual_hash": server_binary_hash,
        }
        return _block("binary_hash_mismatch", evidence, badge_valid=False)

    # --- Check 4: AGNTCY badge must be valid -----------------------------------
    badge_metadata_id = entry.get("badge_metadata_id", "")
    badge = verifier.verify(badge_metadata_id)
    if not badge.valid:
        evidence = {
            "server_path": server_path,
            "badge_metadata_id": badge_metadata_id,
            "badge_valid": False,
            **badge.evidence,
        }
        return _block("badge_verification_failed", evidence, badge_valid=False)

    # --- Check 5: invoked tools must be within declared_capabilities -----------
    if tool_names:
        unauthorized = [t for t in tool_names if t not in badge.capabilities]
        if unauthorized:
            evidence = {
                "server_path": server_path,
                "unauthorized_tools": unauthorized,
                "declared_capabilities": badge.capabilities,
            }
            return _block("tool_not_in_declared_capabilities", evidence, badge_valid=True)

    # --- PASS ------------------------------------------------------------------
    evidence = {
        "server_path": server_path,
        "badge_metadata_id": badge_metadata_id,
        "capabilities": badge.capabilities,
        "declared_scope": badge.declared_scope,
        "declared_destinations": badge.declared_destinations,
    }
    emit_detection_span(
        stage=2, layer="L0.5", verdict="PASS",
        detection_type=None, evidence=evidence,
    )
    return {
        "verdict": "PASS",
        "detection_type": None,
        "badge_valid": True,
        "capabilities": badge.capabilities,
        "declared_scope": badge.declared_scope,
        "declared_destinations": badge.declared_destinations,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _expand(path: str) -> str:
    """Expand ~ to the home directory."""
    return str(Path(path).expanduser())


def _find_entry(expanded_path: str, allowlist: dict) -> Optional[dict]:
    """Find the first allowlist server entry whose path_pattern matches."""
    for server in allowlist.get("servers", []):
        pattern = _expand(server.get("path_pattern", ""))
        if fnmatch(expanded_path, pattern):
            return server
    return None


def _block(detection_type: str, evidence: dict, badge_valid: bool) -> dict:
    """Emit BLOCK span and return a BLOCK result dict."""
    emit_detection_span(
        stage=2, layer="L0.5", verdict="BLOCK",
        detection_type=detection_type, evidence=evidence,
    )
    return {
        "verdict": "BLOCK",
        "detection_type": detection_type,
        "badge_valid": badge_valid,
        "evidence": evidence,
    }


def _load_allowlist() -> dict:
    path = Path(__file__).parent.parent / "badges" / "allowlist.json"
    return json.loads(path.read_text(encoding="utf-8"))
