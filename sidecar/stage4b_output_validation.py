"""
sidecar/stage4b_output_validation.py — Stage 4b: Output Validation (L2b_output)

NOVEL CONTRIBUTION — no existing framework does this.

Runs AFTER the tool executes, BEFORE the result enters the model context.
Every other framework uses OTel spans post-hoc for observability.
This stage enforces inline on tool response content.

Why this closes a gap Stage 4 cannot:
  Stage 4 (L2b) catches behavioral violations — does the tool read the right files,
  connect to declared destinations? A server that does ONLY that can still inject
  into the model via its response content. Stage 4b catches that.

  Stage 4 = did the tool honor its declared scope?
  Stage 4b = is the tool's response safe to pass to the model?

Five checks (all findings collected before verdict, same pattern as Stage 4):

  1. Injection phrases in output content → BLOCK
     Scans all string values recursively. Case-insensitive.
     Patterns: "ignore previous instructions", "disregard", "you are now",
               "new system prompt", "system:", "[INST]", "<|system|>", "<|im_start|>system"
     detection_type: "output_injection_phrase"

  2. Tool call directives in output → BLOCK
     Tool trying to inject new tool calls into model context.
     Checks: <tool_call> XML tags, {"tool_call": ...} / {"function_call": ...} dict keys,
             "tool_use" key in any nested dict, JSON string patterns.
     detection_type: "output_tool_call_directive"

  3. Invisible Unicode in output → BLOCK (Glassworm variant in tool response)
     Reuses stage0_unicode_scan.scan_for_invisible_unicode() on all string values.
     detection_type: "output_invisible_unicode"

  4. Base64 blobs > 100 chars → WARN
     Potential exfil or injection payload delivery. Legitimate tools also return
     base64 (images, files) so this is advisory, not a hard gate.
     detection_type: "output_base64_blob"

  5. Output size anomaly → WARN
     Serialized output > max_response_bytes (default 100KB).
     Suggests bulk data exfil via oversized response.
     detection_type: "output_size_anomaly"

Verdict:
  BLOCK  — any of checks 1, 2, or 3 fired
  WARN   — checks 4 or 5 fired (and no BLOCK condition)
  PASS   — nothing fired

OTel span uses:
  stage=4, layer="L2b_output"  (same stage as 4, sub-check of L2b)
  evidence includes: findings, tool_name, output_size_bytes
"""

import json
import re
from typing import Any, List, Optional

from sidecar.span_emitter import emit_detection_span
from sidecar.stage0_unicode_scan import scan_for_invisible_unicode

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Injection phrase patterns — case-insensitive
_INJECTION_PATTERNS = [
    r"ignore\b.{0,40}\bprevious\b.{0,40}\binstructions?\b",
    r"\bdisregard\b",
    r"\byou are now\b",
    r"\bnew system prompt\b",
    r"system:\s",
    r"\[INST\]",
    r"<\|system\|>",
    r"<\|im_start\|>system",
]

# Tool call directive patterns — string-level detection
_TOOL_CALL_STR_PATTERNS = [
    r"<tool_call\b",
    r"</tool_call>",
    r'"tool_call"\s*:',
    r'"function_call"\s*:',
    r'"tool_use"\s*:',
]

# Dict keys that signal an injected tool call directive
_TOOL_CALL_KEYS = frozenset({"tool_call", "function_call", "tool_use"})

# Base64: match runs of >= 100 base64-alphabet chars (the run itself must be long)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_tool_output(
    tool_name: str,
    output: Any,
    declared_capabilities: List[str],
    max_response_bytes: int = 102400,
) -> dict:
    """
    Validate a tool's response before it enters the model context.

    Args:
        tool_name:            MCP tool that produced this output.
        output:               Tool response — any JSON-serializable structure.
        declared_capabilities: Tool capabilities from AGNTCY MCP Server Badge.
        max_response_bytes:   Size threshold for output_size_anomaly (default 100KB).

    Returns:
        {
            "verdict":          "BLOCK" | "WARN" | "PASS",
            "findings":         List[dict],   # one entry per detection type found
            "output_size_bytes": int,
        }
    """
    findings: List[dict] = []

    # --- Serialize output for size check ------------------------------------
    try:
        serialized = json.dumps(output, ensure_ascii=False)
    except (TypeError, ValueError):
        serialized = str(output)
    output_size_bytes = len(serialized.encode("utf-8"))

    # --- Extract all string values recursively ------------------------------
    strings = _extract_strings(output)

    # --- Check 1: injection phrases -----------------------------------------
    injections = _scan_injection_phrases(strings)
    if injections:
        findings.append({
            "detection_type": "output_injection_phrase",
            "matches": injections[:5],   # cap excerpt list
            "check": "injection_phrase",
        })

    # --- Check 2: tool call directives --------------------------------------
    tool_call_hits = _scan_tool_call_directives(output, strings)
    if tool_call_hits:
        findings.append({
            "detection_type": "output_tool_call_directive",
            "matches": tool_call_hits[:5],
            "check": "tool_call_directive",
        })

    # --- Check 3: invisible Unicode -----------------------------------------
    unicode_hits = _scan_invisible_unicode(strings)
    if unicode_hits:
        findings.append({
            "detection_type": "output_invisible_unicode",
            "codepoints_found": sum(h["codepoints_found"] for h in unicode_hits),
            "check": "invisible_unicode",
        })

    # --- Check 4: base64 blobs (WARN) ---------------------------------------
    b64_hits = _scan_base64_blobs(strings)
    if b64_hits:
        findings.append({
            "detection_type": "output_base64_blob",
            "blobs_found": len(b64_hits),
            "check": "base64_blob",
        })

    # --- Check 5: output size anomaly (WARN) --------------------------------
    if output_size_bytes > max_response_bytes:
        findings.append({
            "detection_type": "output_size_anomaly",
            "evidence": {
                "size_bytes": output_size_bytes,
                "limit_bytes": max_response_bytes,
            },
            "check": "size_anomaly",
        })

    # --- Verdict: BLOCK > WARN > PASS ---------------------------------------
    _block_types = {"output_injection_phrase", "output_tool_call_directive", "output_invisible_unicode"}
    _warn_types = {"output_base64_blob", "output_size_anomaly"}

    has_block = any(f["detection_type"] in _block_types for f in findings)
    has_warn = any(f["detection_type"] in _warn_types for f in findings)

    if has_block:
        verdict = "BLOCK"
    elif has_warn:
        verdict = "WARN"
    else:
        verdict = "PASS"

    first_detection = findings[0]["detection_type"] if findings else None

    # --- OTel span ----------------------------------------------------------
    emit_detection_span(
        stage=4,
        layer="L2b_output",
        verdict=verdict,
        detection_type=first_detection,
        evidence={
            "tool_name": tool_name,
            "findings": findings,
            "output_size_bytes": output_size_bytes,
        },
        tool_name=tool_name,
    )

    return {
        "verdict": verdict,
        "findings": findings,
        "output_size_bytes": output_size_bytes,
    }


# ---------------------------------------------------------------------------
# Recursive string extraction
# ---------------------------------------------------------------------------

def _extract_strings(output: Any) -> List[str]:
    """
    Recursively extract all string values from output.
    Handles: str, dict (values only), list (elements), nested combinations.
    Non-string leaf values (int, bool, None) are silently skipped.
    """
    if isinstance(output, str):
        return [output]
    if isinstance(output, dict):
        result = []
        for v in output.values():
            result.extend(_extract_strings(v))
        return result
    if isinstance(output, list):
        result = []
        for item in output:
            result.extend(_extract_strings(item))
        return result
    return []


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def _scan_injection_phrases(strings: List[str]) -> List[str]:
    """Return list of matched injection phrase excerpts (50-char max each)."""
    hits = []
    for s in strings:
        for pattern in _INJECTION_PATTERNS:
            m = re.search(pattern, s, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 10)
                excerpt = s[start: m.end() + 10][:50]
                hits.append(excerpt)
                break  # one hit per string, avoid duplicate excerpts
    return hits


def _scan_tool_call_directives(output: Any, strings: List[str]) -> List[str]:
    """
    Detect tool call injection attempts via two mechanisms:
    1. String patterns: <tool_call> tags, JSON tool_call keys in string values.
    2. Dict key inspection: "tool_call", "function_call", "tool_use" as dict keys.
    """
    hits = []
    # String pattern scan
    for s in strings:
        for pattern in _TOOL_CALL_STR_PATTERNS:
            m = re.search(pattern, s, re.IGNORECASE)
            if m:
                hits.append(s[:60])
                break
    # Dict key scan
    key_hits = _find_tool_call_keys(output)
    hits.extend(key_hits)
    return hits


def _find_tool_call_keys(obj: Any) -> List[str]:
    """Recursively find tool call directive keys in nested dicts."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _TOOL_CALL_KEYS:
                hits.append(f"key:{k}")
            hits.extend(_find_tool_call_keys(v))
    elif isinstance(obj, list):
        for item in obj:
            hits.extend(_find_tool_call_keys(item))
    return hits


def _scan_invisible_unicode(strings: List[str]) -> List[dict]:
    """Return list of stage0 evidence dicts for strings containing invisible Unicode."""
    hits = []
    for s in strings:
        result = scan_for_invisible_unicode(s)
        if result["verdict"] == "BLOCK":
            hits.append(result["evidence"])
    return hits


def _scan_base64_blobs(strings: List[str]) -> List[str]:
    """Return base64 matches that are >= 100 chars long."""
    hits = []
    for s in strings:
        for m in _B64_RE.finditer(s):
            hits.append(m.group()[:20] + "…")  # truncated excerpt
    return hits
