"""
sidecar/span_emitter.py — Unified OTel span emission for all stages.

Wraps ioa_observe_sdk (AGNTCY observe SDK) with security.* field support.
Every detection event across all pipeline stages calls emit_detection_span().

Graceful degradation order:
  1. ioa_observe.sdk available → Observe.init() configures the global tracer
                                 provider; OTLP_HTTP_ENDPOINT sets the collector.
  2. opentelemetry available  → use standard OTel tracer directly (no exporter).
  3. Neither available        → no-op (stages still function, no spans emitted).

Observe.init() is called lazily on the first emit — once per process.
Set OTLP_HTTP_ENDPOINT before running to ship spans to a collector:
  export OTLP_HTTP_ENDPOINT=http://localhost:4318

Security field names are final. Do not rename without updating CLAUDE.md.
"""

import json
import os

try:
    from opentelemetry import trace
except ImportError:
    trace = None

try:
    from ioa_observe.sdk import Observe as _Observe
    _IOA_OBSERVE_AVAILABLE = True
except ImportError:
    _IOA_OBSERVE_AVAILABLE = False

# Lazy initialization flag — Observe.init() called at most once per process.
_observe_initialized = False


def _ensure_observe_init() -> None:
    """
    Initialize the AGNTCY Observe SDK on first use — only when
    OTLP_HTTP_ENDPOINT is explicitly set in the environment.

    Requiring the env var prevents the SDK from spawning background exporter
    threads during tests (where no collector is running). When the env var IS
    set, Observe.init() configures the global OTel tracer provider so that
    subsequent trace.get_tracer() calls export spans to that collector.

    No-ops if:
      - already initialized
      - ioa_observe is not installed
      - OTLP_HTTP_ENDPOINT is not set (falls back to raw OTel / no-op)
    """
    global _observe_initialized
    if _observe_initialized or not _IOA_OBSERVE_AVAILABLE:
        return
    endpoint = os.getenv("OTLP_HTTP_ENDPOINT")
    if not endpoint:
        _observe_initialized = True   # skip SDK; raw OTel or no-op takes over
        return
    try:
        _Observe.init(app_name="semantic-sidecar", api_endpoint=endpoint)
    except Exception:
        pass  # collector unreachable or init error — degrade gracefully
    _observe_initialized = True

# ---------------------------------------------------------------------------
# Security field registry — exact names, do not change
# ---------------------------------------------------------------------------

SECURITY_FIELDS = [
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

_SECURITY_FIELDS_SET = set(SECURITY_FIELDS)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def emit_detection_span(
    stage: int,
    layer: str,
    verdict: str,
    detection_type: str,
    evidence: dict,
    tool_name: str = None,
    task_id: str = None,
    security_fields: dict = None,
) -> None:
    """
    Emit an OTel span for a sidecar detection event.

    Args:
        stage:           Pipeline stage number (0-5).
        layer:           Layer name: "Stage0" | "Stage1a" | "Stage1b" | "L0.5" | "L2" | "L2b" | "L3".
        verdict:         "BLOCK" | "ALLOW" | "WARN" | "PASS".
        detection_type:  Detection enum string (see SPEC.md), or None for PASS/ALLOW.
        evidence:        Arbitrary dict; JSON-serialized into security.evidence.
        tool_name:       MCP tool name → gen_ai.tool.name. Optional.
        task_id:         Active task ID → gen_ai.task.id. Optional.
        security_fields: Extra security.* attributes (Stage 4 scope fields etc.).
                         Keys must be in SECURITY_FIELDS. List values JSON-serialized.
    """
    _ensure_observe_init()

    if trace is None:
        return

    tracer = trace.get_tracer("semantic-sidecar")
    with tracer.start_as_current_span(f"sidecar.stage{stage}.detection") as span:
        # --- Core fields (always set) ---
        span.set_attribute("security.stage", stage)
        span.set_attribute("security.layer", layer)
        span.set_attribute("security.verdict", verdict)
        span.set_attribute("security.evidence", json.dumps(evidence))

        # --- detection_type: only set when present (absent on PASS) ---
        if detection_type is not None:
            span.set_attribute("security.detection_type", detection_type)

        # --- Optional gen_ai identification fields ---
        if tool_name is not None:
            span.set_attribute("gen_ai.tool.name", tool_name)
        if task_id is not None:
            span.set_attribute("gen_ai.task.id", task_id)

        # --- Additional security_fields (Stage 4 scope, requester, hash, etc.) ---
        if security_fields:
            for key, value in security_fields.items():
                if key not in _SECURITY_FIELDS_SET:
                    continue  # reject unknown keys — schema is closed
                if isinstance(value, list):
                    span.set_attribute(key, json.dumps(value))
                else:
                    span.set_attribute(key, value)
