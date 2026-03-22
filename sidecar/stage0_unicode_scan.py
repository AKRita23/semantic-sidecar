"""
sidecar/stage0_unicode_scan.py — Stage 0: Pre-Load Unicode Scan

Catches: Glassworm MCP — invisible Unicode eval() payload in MCP source,
         fires at server initialization before any task context exists.

Verdict: BLOCK or PASS

Why load-bearing: Glassworm fires at MCP server initialization — before Stage 3
has a task_id to check, before Stage 4 has scope to assert. This is the only
layer positioned before eval() executes.

Detection targets:
  U+FE00–FE0F    Variation Selectors (16 codepoints)
  U+E0100–E01EF  Variation Selectors Supplement (240 codepoints)
"""

import json
from pathlib import Path

try:
    from opentelemetry import trace
except ImportError:
    trace = None  # OTel not installed — span emission degrades gracefully

# ---------------------------------------------------------------------------
# Detection constants
# ---------------------------------------------------------------------------

GLASSWORM_RANGES = [
    (0xFE00, 0xFE0F),    # Variation Selectors
    (0xE0100, 0xE01EF),  # Variation Selectors Supplement
]


# ---------------------------------------------------------------------------
# Core detection logic
# ---------------------------------------------------------------------------

def scan_for_invisible_unicode(content: str) -> dict:
    """
    Scan a string for invisible Unicode codepoints used in Glassworm attacks.

    Returns:
        {
            "verdict": "BLOCK" | "PASS",
            "detection_type": "invisible_unicode_detected" | None,
            "evidence": {
                "codepoints_found": int,
                "positions": [{"position": int, "codepoint": str}, ...]
            }
        }
    """
    positions = []
    for i, ch in enumerate(content):
        cp = ord(ch)
        for lo, hi in GLASSWORM_RANGES:
            if lo <= cp <= hi:
                positions.append({"position": i, "codepoint": hex(cp)})
                break

    if positions:
        return {
            "verdict": "BLOCK",
            "detection_type": "invisible_unicode_detected",
            "evidence": {
                "codepoints_found": len(positions),
                "positions": positions,
            },
        }

    return {
        "verdict": "PASS",
        "detection_type": None,
        "evidence": {
            "codepoints_found": 0,
            "positions": [],
        },
    }


def scan_file(file_path: str) -> dict:
    """
    Read a file and scan it for invisible Unicode. Emits OTel span on detection.

    Returns scan result dict with result["evidence"]["file"] set to the file path.
    """
    path = Path(file_path)
    content = path.read_text(encoding="utf-8", errors="replace")
    result = scan_for_invisible_unicode(content)
    result["evidence"]["file"] = str(path)
    _emit_span(result, file_path=str(path))
    return result


# ---------------------------------------------------------------------------
# OTel span emission
# ---------------------------------------------------------------------------

def _emit_span(result: dict, file_path: str = None) -> None:
    """
    Emit an OTel span for a Stage 0 detection event.
    No-ops silently if opentelemetry is not installed or trace is None.
    """
    if trace is None:
        return

    tracer = trace.get_tracer("semantic-sidecar.stage0")
    with tracer.start_as_current_span("stage0.unicode_scan") as span:
        span.set_attribute("security.stage", 0)
        span.set_attribute("security.layer", "Stage0")
        span.set_attribute("security.verdict", result["verdict"])
        if result.get("detection_type"):
            span.set_attribute("security.detection_type", result["detection_type"])
        span.set_attribute("security.evidence", json.dumps(result["evidence"]))
        if file_path:
            span.set_attribute("security.scanned_file", file_path)
