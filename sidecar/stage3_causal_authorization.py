"""
sidecar/stage3_causal_authorization.py — Stage 3: Causal Authorization (L2)

Hard BLOCK gate. Every tool invocation must trace back to a valid,
unexpired, human-authorized task. If it cannot — it is an orphaned action.

AGNTCY Agent Badge facts (do not change):
  - W3C Verifiable Credential with RS256 signature
  - Verification is PERMISSIONLESS — no IdP needed at verify time
  - Badge IS the Policy Root — no HMAC, no separate signing mechanism
  - Badge carries: authorized_by, permitted_tools, issued_at, expires_at, issuer

Four BLOCK conditions (checked in order):
  1. No task_id present           → "orphaned_action_no_task_id"
     (Glassworm fires at init — no task context exists)
  2. task_id not in registry      → "orphaned_action_unknown_task_id"
  3. TaskContext is expired        → "orphaned_action_expired_task"
     (SANDWORM_MODE 48h delay outlasts task validity — CRITICAL TEST)
  4. tool_name not in permitted_tools → "orphaned_action_unauthorized_tool"

Workload identity = WHO. L2 causal authorization = WHY. These are orthogonal.
GhostAction had valid workload identity (legitimate runner) but failed L2:
no authorized task for "read PYPI_API_TOKEN + POST externally."

BadgeVerifier interface enables one-line swap:
  register_task_from_badge(..., verifier=AgntcyAgentBadgeVerifier())  ← production
  register_task_from_badge(..., verifier=StubAgentBadgeVerifier(...)) ← test/offline

OTel spans emitted on every decision — full audit trail for both BLOCK and PASS.
Orphaned BLOCK spans include gen_ai.task.requester = "model_autonomous".
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sidecar.span_emitter import emit_detection_span


# ---------------------------------------------------------------------------
# AgentBadgeResult — returned by all AgentBadgeVerifier implementations
# ---------------------------------------------------------------------------

@dataclass
class AgentBadgeResult:
    """Claims extracted from an AGNTCY Agent Badge (W3C VC, RS256)."""
    valid: bool
    authorized_by: str                  # human identity from IdP
    permitted_tools: List[str]
    issued_at: datetime
    expires_at: datetime
    issuer: str
    evidence: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# AgentBadgeVerifier interface + implementations
# ---------------------------------------------------------------------------

class AgentBadgeVerifier(ABC):
    """Abstract interface for AGNTCY Agent Badge verification. Swap implementations freely."""

    @abstractmethod
    def verify(self, metadata_id: str) -> AgentBadgeResult:
        """Verify an AGNTCY Agent Badge and return its claims."""
        ...


class AgntcyAgentBadgeVerifier(AgentBadgeVerifier):
    """
    Production verifier using the AGNTCY identity SDK (agntcy-identity-sdk).
    Verification is permissionless — no IdP or credentials required.
    Requires IDENTITY_NODE_GRPC_SERVER_URL env var pointing to an Identity Node.
    Degrades gracefully if the SDK is not installed or the node is unreachable.

    Usage:
        from agntcyidentity.sdk import IdentitySdk
        sdk = IdentitySdk()
        badge = sdk.get_badge(metadata_id)   # fetches EnvelopedCredential
        result = sdk.verify_badge(badge)     # returns VerificationResult
    """

    def verify(self, metadata_id: str) -> AgentBadgeResult:
        try:
            from agntcyidentity.sdk import IdentitySdk  # type: ignore
            from google.protobuf.json_format import MessageToDict  # type: ignore

            sdk = IdentitySdk()
            badge = sdk.get_badge(metadata_id)
            result = sdk.verify_badge(badge)

            # Extract credential subject content (google.protobuf.Struct → dict)
            content: dict = {}
            if result.document and result.document.HasField("content"):
                content = MessageToDict(result.document.content)

            # Agent badge carries application-specific claims in content Struct
            authorized_by = content.get("authorizedBy", content.get("authorized_by", ""))
            permitted_tools = content.get("permittedTools", content.get("permitted_tools", []))
            if not isinstance(permitted_tools, list):
                permitted_tools = []

            issuer = ""
            issued_at = _now()
            expires_at = _now()
            if result.document:
                issuer = result.document.issuer or ""
                if result.document.issuance_date:
                    issued_at = _parse_dt(result.document.issuance_date) or _now()
                if result.document.expiration_date:
                    expires_at = _parse_dt(result.document.expiration_date) or _now()

            return AgentBadgeResult(
                valid=bool(result.status),
                authorized_by=authorized_by,
                permitted_tools=permitted_tools,
                issued_at=issued_at,
                expires_at=expires_at,
                issuer=issuer,
                evidence={"metadata_id": metadata_id, "content": content},
            )
        except ImportError:
            return AgentBadgeResult(
                valid=False,
                authorized_by="",
                permitted_tools=[],
                issued_at=_now(),
                expires_at=_now(),
                issuer="",
                evidence={"error": "agntcy-identity-sdk not installed"},
            )
        except Exception as exc:
            return AgentBadgeResult(
                valid=False,
                authorized_by="",
                permitted_tools=[],
                issued_at=_now(),
                expires_at=_now(),
                issuer="",
                evidence={"error": str(exc)},
            )


class StubAgentBadgeVerifier(AgentBadgeVerifier):
    """
    Stub verifier for testing and SDK-unavailable scenarios.
    Reads badge claims from an injected dict keyed by metadata_id.
    Returns real AgentBadgeResult objects — not mocks.

    To swap to production:  verifier=AgntcyAgentBadgeVerifier()  ← one line
    """

    def __init__(self, badges: Optional[Dict[str, AgentBadgeResult]] = None):
        self._badges: Dict[str, AgentBadgeResult] = badges or {}

    def verify(self, metadata_id: str) -> AgentBadgeResult:
        if metadata_id in self._badges:
            return self._badges[metadata_id]
        return AgentBadgeResult(
            valid=False,
            authorized_by="",
            permitted_tools=[],
            issued_at=_now(),
            expires_at=_now(),
            issuer="",
            evidence={"error": f"metadata_id not found in stub: {metadata_id}"},
        )


# ---------------------------------------------------------------------------
# TaskContext — one active human-authorized task
# ---------------------------------------------------------------------------

@dataclass
class TaskContext:
    """Represents a human-authorized task session."""
    task_id: str
    agent_badge_metadata_id: str    # AGNTCY Agent Badge VC metadata ID
    authorized_by: str              # human identity (from badge authorized_by)
    issued_at: datetime
    expires_at: datetime
    permitted_tools: List[str]


# ---------------------------------------------------------------------------
# TaskRegistry — in-memory registry of active TaskContexts
# ---------------------------------------------------------------------------

class TaskRegistry:
    """In-memory registry of active human-authorized tasks."""

    def __init__(self):
        self._tasks: Dict[str, TaskContext] = {}

    def register(self, ctx: TaskContext) -> None:
        """Register a TaskContext. Overwrites any existing entry with the same task_id."""
        self._tasks[ctx.task_id] = ctx

    def get(self, task_id: str) -> Optional[TaskContext]:
        """Return the TaskContext for task_id, or None if not registered."""
        return self._tasks.get(task_id)

    def is_valid(self, task_id: str) -> bool:
        """
        Return True if task_id is registered AND not yet expired.
        False for unknown task_id or expired task.
        """
        ctx = self._tasks.get(task_id)
        if ctx is None:
            return False
        return ctx.expires_at > _now()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_task_from_badge(
    task_id: str,
    agent_badge_metadata_id: str,
    registry: TaskRegistry,
    verifier: Optional[AgentBadgeVerifier] = None,
) -> dict:
    """
    Verify an AGNTCY Agent Badge and register the resulting TaskContext.

    Called at task creation time. Badge verification happens here, not at
    every tool invocation. check_causal_authorization() trusts the registry.

    Args:
        task_id:                  Unique ID for this task session.
        agent_badge_metadata_id:  AGNTCY Agent Badge VC metadata ID.
        registry:                 TaskRegistry to register into on success.
        verifier:                 AgentBadgeVerifier. Defaults to StubAgentBadgeVerifier.

    Returns:
        {"verdict": "PASS", ...} or {"verdict": "BLOCK", "detection_type": ..., "evidence": ...}
    """
    if verifier is None:
        verifier = StubAgentBadgeVerifier()

    badge = verifier.verify(agent_badge_metadata_id)
    if not badge.valid:
        evidence = {
            "agent_badge_metadata_id": agent_badge_metadata_id,
            **badge.evidence,
        }
        emit_detection_span(
            stage=3, layer="L2", verdict="BLOCK",
            detection_type="badge_verification_failed",
            evidence=evidence,
            task_id=task_id,
        )
        return {
            "verdict": "BLOCK",
            "detection_type": "badge_verification_failed",
            "evidence": evidence,
        }

    ctx = TaskContext(
        task_id=task_id,
        agent_badge_metadata_id=agent_badge_metadata_id,
        authorized_by=badge.authorized_by,
        issued_at=badge.issued_at,
        expires_at=badge.expires_at,
        permitted_tools=badge.permitted_tools,
    )
    registry.register(ctx)
    evidence = {
        "task_id": task_id,
        "agent_badge_metadata_id": agent_badge_metadata_id,
        "authorized_by": badge.authorized_by,
        "expires_at": badge.expires_at.isoformat(),
        "permitted_tools": badge.permitted_tools,
    }
    emit_detection_span(
        stage=3, layer="L2", verdict="PASS",
        detection_type=None,
        evidence=evidence,
        task_id=task_id,
        security_fields={"gen_ai.task.requester": badge.authorized_by},
    )
    return {"verdict": "PASS", "detection_type": None, "evidence": evidence}


def check_causal_authorization(
    tool_name: str,
    task_id: Optional[str],
    registry: TaskRegistry,
) -> dict:
    """
    Hard BLOCK gate for causal authorization.

    Every tool invocation must trace back to a valid, unexpired,
    human-authorized task in the registry. If it cannot — BLOCK.

    Args:
        tool_name:  MCP tool being invoked.
        task_id:    Active task ID, or None if not present.
        registry:   TaskRegistry holding authorized task contexts.

    Returns:
        {"verdict": "BLOCK" | "PASS", "detection_type": str | None, "evidence": dict}
    """
    # --- Check 1: task_id must be present -----------------------------------
    if task_id is None:
        evidence = {"tool_name": tool_name, "task_id": None}
        return _block(
            "orphaned_action_no_task_id", evidence, task_id=None, tool_name=tool_name
        )

    # --- Check 2: task_id must exist in registry ----------------------------
    ctx = registry.get(task_id)
    if ctx is None:
        evidence = {"tool_name": tool_name, "task_id": task_id}
        return _block(
            "orphaned_action_unknown_task_id", evidence, task_id=task_id, tool_name=tool_name
        )

    # --- Check 3: task must not be expired ----------------------------------
    if ctx.expires_at <= _now():
        age_seconds = (_now() - ctx.expires_at).total_seconds()
        evidence = {
            "tool_name": tool_name,
            "task_id": task_id,
            "authorized_by": ctx.authorized_by,
            "expires_at": ctx.expires_at.isoformat(),
            "expired_seconds_ago": round(age_seconds),
        }
        return _block(
            "orphaned_action_expired_task", evidence, task_id=task_id, tool_name=tool_name
        )

    # --- Check 4: tool must be in permitted_tools ---------------------------
    if tool_name not in ctx.permitted_tools:
        evidence = {
            "tool_name": tool_name,
            "task_id": task_id,
            "authorized_by": ctx.authorized_by,
            "permitted_tools": ctx.permitted_tools,
        }
        return _block(
            "orphaned_action_unauthorized_tool", evidence, task_id=task_id, tool_name=tool_name
        )

    # --- PASS ---------------------------------------------------------------
    evidence = {
        "tool_name": tool_name,
        "task_id": task_id,
        "authorized_by": ctx.authorized_by,
        "expires_at": ctx.expires_at.isoformat(),
    }
    emit_detection_span(
        stage=3, layer="L2", verdict="PASS",
        detection_type=None,
        evidence=evidence,
        tool_name=tool_name,
        task_id=task_id,
        security_fields={"gen_ai.task.requester": ctx.authorized_by},
    )
    return {"verdict": "PASS", "detection_type": None, "evidence": evidence}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _block(
    detection_type: str,
    evidence: dict,
    task_id: Optional[str],
    tool_name: str,
) -> dict:
    """Emit BLOCK span and return a BLOCK result dict."""
    emit_detection_span(
        stage=3, layer="L2", verdict="BLOCK",
        detection_type=detection_type,
        evidence=evidence,
        tool_name=tool_name,
        task_id=task_id,
        security_fields={"gen_ai.task.requester": "model_autonomous"},
    )
    return {
        "verdict": "BLOCK",
        "detection_type": detection_type,
        "evidence": evidence,
    }


def _parse_dt(value) -> Optional[datetime]:
    """Parse an ISO 8601 string to a UTC-aware datetime, or return None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None
