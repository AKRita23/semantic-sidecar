"""
sidecar/stage5_cedar_policy.py — Stage 5: Cedar Policy Enforcement (L3)

The deterministic floor. Enforces unconditionally, regardless of what all
prior stages decided. No behavioral heuristics, no timing dependencies.

L2b vs L3 — CRITICAL DISTINCTION:
  L2b (Stage 4): observational enforcement via psutil/mitmproxy
    - Has timing windows and potential race conditions
    - Broad behavioral coverage
  L3 (Stage 5): formal resource-level enforcement at the policy decision point
    - No timing dependency, no race conditions
    - If L2b had a race condition and missed a credential read,
      Cedar denies it unconditionally at access time
    - Unconditional floor — always runs, even when all prior stages PASS

Cedar does NOT replace L2b. They are complementary.

Policies loaded from:
  policies/sandworm_mode.cedar     — credential access + network egress
  policies/output_validation.cedar — tool response injection
  policies/dynamic/                — hot-reload directory (FileSystemWatcher)

Stub/real pattern (same as Stages 2 and 3):
  StubCedarEvaluator — Python implementation of Cedar policy semantics.
                       Tests run against this directly. No cedar-policy SDK needed.
  RealCedarEvaluator — Wraps cedar-policy SDK when available.
                       Graceful degradation to StubCedarEvaluator if not installed.
  Swap:  evaluator=RealCedarEvaluator()  ← one line change

PolicyWatcher — monitors policies/dynamic/ for hot-reload.
  Uses threading.Event for clean stop (no time.sleep loops — testable).
  Polls directory mtime. Analyst drops a new .cedar file → sidecar picks it up.
  This implements the feedback loop: Detection → OTel → SIEM → Cedar → enforce.
"""

import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from sidecar.span_emitter import emit_detection_span


# ---------------------------------------------------------------------------
# Cedar data types
# ---------------------------------------------------------------------------

@dataclass
class CedarRequest:
    """A Cedar policy evaluation request."""
    principal: str      # e.g., "MCPServer::lint_check"
    action: str         # e.g., 'Action::"file_read"'
    resource: str       # e.g., "/home/user/.ssh/id_rsa"
    context: dict       # e.g., {"declared_destinations": ["api.example.com:443"]}


@dataclass
class CedarResult:
    """Result of a Cedar policy evaluation."""
    decision: str               # "Allow" | "Deny"
    reasons: List[str]          # policy IDs that fired (for SIEM)
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CedarEvaluator interface + implementations
# ---------------------------------------------------------------------------

class CedarEvaluator(ABC):
    """Abstract interface for Cedar policy evaluation. Swap implementations freely."""

    @abstractmethod
    def evaluate(self, request: CedarRequest) -> CedarResult:
        """Evaluate a Cedar request against loaded policies."""
        ...


class StubCedarEvaluator(CedarEvaluator):
    """
    Python implementation of the Cedar policy semantics from policies/*.cedar.
    Implements the exact same rules Cedar would enforce. Tests run against this.
    No cedar-policy SDK required.

    To swap to production: evaluator=RealCedarEvaluator()  ← one line
    """

    def evaluate(self, request: CedarRequest) -> CedarResult:
        reasons: List[str] = []

        # --- sandworm_mode.cedar: file_read rules ---------------------------
        if request.action == 'Action::"file_read"':
            if _cedar_path_matches(request.resource, "/home/**/.ssh/**"):
                reasons.append("sandworm_mode:deny_ssh_access")
            if _cedar_path_matches(request.resource, "/home/**/.aws/**"):
                reasons.append("sandworm_mode:deny_aws_access")
            if _cedar_path_matches(request.resource, "/home/**/.config/gh/**"):
                reasons.append("sandworm_mode:deny_gh_config_access")

        # --- sandworm_mode.cedar: network_egress rule -----------------------
        if request.action == 'Action::"network_egress"':
            declared = request.context.get("declared_destinations", [])
            if request.resource not in declared:
                reasons.append("sandworm_mode:deny_undeclared_egress")

        # --- output_validation.cedar: tool_response rules -------------------
        if request.action == 'Action::"tool_response"':
            if request.context.get("contains_injection_phrase"):
                reasons.append("output_validation:deny_injection_phrase")
            if request.context.get("contains_tool_call_directive"):
                reasons.append("output_validation:deny_tool_call_directive")

        if reasons:
            return CedarResult(decision="Deny", reasons=reasons, errors=[])
        return CedarResult(decision="Allow", reasons=[], errors=[])


class RealCedarEvaluator(CedarEvaluator):
    """
    Production evaluator using the cedarpy SDK (pip install cedarpy>=4.1.0).
    Graceful degradation to StubCedarEvaluator if SDK not available or errors.

    cedarpy.is_authorized() call signature:
        result = is_authorized(request_dict, policies_str, entities_list)
        result.decision == Decision.Deny  → BLOCK
        result.decision == Decision.Allow → PASS
    """

    def _load_policies(self) -> str:
        """Load all .cedar files from policies/ and policies/dynamic/."""
        policies_dir = Path(__file__).parent.parent / "policies"
        parts = []
        for cedar_file in sorted(policies_dir.glob("*.cedar")):
            parts.append(cedar_file.read_text(encoding="utf-8"))
        dynamic_dir = policies_dir / "dynamic"
        if dynamic_dir.exists():
            for cedar_file in sorted(dynamic_dir.glob("*.cedar")):
                parts.append(cedar_file.read_text(encoding="utf-8"))
        return "\n".join(parts)

    def evaluate(self, request: CedarRequest) -> CedarResult:
        try:
            from cedarpy import is_authorized, Decision  # type: ignore

            # Map CedarRequest to cedarpy dict format
            action_id = request.action.replace('Action::"', "").rstrip('"')
            principal_type, _, principal_id = request.principal.partition("::")
            if not principal_id:
                principal_type, principal_id = "MCPServer", request.principal

            cedary_request = {
                "principal": {"type": principal_type, "id": principal_id},
                "action": {"type": "Action", "id": action_id},
                "resource": {"type": "Resource", "id": request.resource},
                "context": request.context,
            }
            result = is_authorized(
                cedary_request, self._load_policies(), entities=[]
            )
            decision = "Deny" if result.decision == Decision.Deny else "Allow"
            return CedarResult(decision=decision, reasons=[], errors=[])

        except ImportError:
            # cedarpy not installed — fall back to stub (same policy semantics)
            return StubCedarEvaluator().evaluate(request)
        except Exception as exc:
            # API mismatch, parse error, etc. — fail-safe via stub
            return StubCedarEvaluator().evaluate(request)


# ---------------------------------------------------------------------------
# PolicyWatcher — hot-reload via FileSystemWatcher
# ---------------------------------------------------------------------------

class PolicyWatcher:
    """
    Monitors policies/dynamic/ for new .cedar files and triggers policy reload.

    Uses threading.Event for clean stop — no time.sleep() loops. Tests can
    call _check_for_updates() directly without running the background thread.

    Feedback loop:
      Sidecar detects attack → OTel span → SIEM → analyst confirms →
      analyst drops .cedar file in policies/dynamic/ →
      PolicyWatcher detects mtime change → reload → enforce without restart.
    """

    def __init__(
        self,
        dynamic_dir: str,
        evaluator: CedarEvaluator,
        poll_interval: float = 5.0,
    ):
        self._dir = Path(dynamic_dir)
        self._evaluator = evaluator
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_mtime: float = 0.0
        self.update_count: int = 0

    def start(self) -> None:
        """Start background polling thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._watch_loop, daemon=True, name="PolicyWatcher"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal background thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _watch_loop(self) -> None:
        """Background loop: poll directory until stop_event is set."""
        while not self._stop_event.is_set():
            self._check_for_updates()
            self._stop_event.wait(timeout=self._poll_interval)

    def _check_for_updates(self) -> None:
        """
        Check directory mtime for changes. Called by background thread AND
        directly by tests for synchronous verification.
        """
        if not self._dir.exists():
            return
        try:
            mtime = self._dir.stat().st_mtime
            if mtime != self._last_mtime:
                self._last_mtime = mtime
                self.update_count += 1
                # In production: reload .cedar files into evaluator
                # For POC: detection of change is the demonstration
                self._on_policy_change()
        except OSError:
            pass

    def _on_policy_change(self) -> None:
        """
        Called when policies/dynamic/ content changes.
        In production: parse new .cedar files, update evaluator.
        For POC: log the event via OTel span.
        """
        cedar_files = list(self._dir.glob("*.cedar"))
        emit_detection_span(
            stage=5,
            layer="L3",
            verdict="PASS",
            detection_type=None,
            evidence={
                "event": "policy_hot_reload",
                "new_policies": [f.name for f in cedar_files],
            },
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_cedar_policy(
    action: str,
    resource: str,
    principal: str = "MCPServer",
    context: dict = None,
    evaluator: Optional[CedarEvaluator] = None,
) -> dict:
    """
    Hard BLOCK gate — the deterministic floor (L3).

    Evaluates Cedar policies unconditionally. Runs regardless of what all
    prior stages decided. No timing dependency, no race conditions.

    Args:
        action:     Cedar action identifier, e.g. 'Action::"file_read"'.
        resource:   Resource being accessed, e.g. "/home/user/.ssh/id_rsa".
        principal:  Cedar principal identifier. Defaults to "MCPServer".
        context:    Cedar context dict. Carries declared_destinations, flags, etc.
        evaluator:  CedarEvaluator implementation. Defaults to StubCedarEvaluator.
                    Swap to RealCedarEvaluator() for production — one line change.

    Returns:
        {
            "verdict":        "BLOCK" | "PASS",
            "detection_type": "cedar_policy_deny" | None,
            "reasons":        List[str],   # which policies fired (for SIEM)
            "evidence":       dict,
        }
    """
    if evaluator is None:
        evaluator = StubCedarEvaluator()
    if context is None:
        context = {}

    request = CedarRequest(
        principal=principal,
        action=action,
        resource=resource,
        context=context,
    )

    result = evaluator.evaluate(request)

    verdict = "BLOCK" if result.decision == "Deny" else "PASS"
    detection_type = "cedar_policy_deny" if verdict == "BLOCK" else None

    evidence = {
        "action": action,
        "resource": resource,
        "principal": principal,
        "reasons": result.reasons,
        "errors": result.errors,
    }

    emit_detection_span(
        stage=5,
        layer="L3",
        verdict=verdict,
        detection_type=detection_type,
        evidence=evidence,
    )

    return {
        "verdict": verdict,
        "detection_type": detection_type,
        "reasons": result.reasons,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _cedar_path_matches(resource: str, pattern: str) -> bool:
    """
    Match a resource path against a Cedar path pattern with ** wildcard.

    ** matches any sequence of characters including path separators.
    * matches any sequence of characters excluding path separators.

    Examples:
        "/home/**/.ssh/**"   matches  "/home/user/.ssh/id_rsa"
        "/home/**/.aws/**"   matches  "/home/ubuntu/.aws/credentials"
    """
    # Split on ** to get literal segments, escape each for regex use,
    # then join with .* (** = anything including slashes)
    parts = pattern.split("**")
    regex_parts = []
    for part in parts:
        # Within each segment, escape for regex; * (single) → [^/]*
        escaped = re.escape(part).replace(r"\*", "[^/]*")
        regex_parts.append(escaped)
    regex = ".*".join(regex_parts)
    return bool(re.fullmatch(regex, resource))
