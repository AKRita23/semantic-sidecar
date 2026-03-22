"""
sidecar/stage1_mcp_skill_scanner.py — Stage 1b: MCP/Skill Scanner

Two distinct questions:
  scan_mcp_package — Is this package safe for installation? (supply-chain analysis)
  scan_skill       — Is this tool description safe for agentic use? (input validation)

scan_mcp_package checks:
  1. Post-install config writes to MCP client paths → WARN  (SANDWORM_MODE exact behavior)
  2. Invisible Unicode in source files   → BLOCK (defense-in-depth; Stage 0 is primary)
  3. No AGNTCY MCP Server Badge present → WARN  (Stage 2 does hard enforcement)
  4. Levenshtein distance ≤ 2 vs known MCP/AI packages → WARN

scan_skill checks:
  1. Prompt injection phrases in description → WARN
  2. URLs in description → WARN
  3. Base64 blobs in description → WARN
  Always records tool_description_hash for Stage 4 comparison.

Verdict: WARN or BLOCK (scan_mcp_package) | WARN or PASS (scan_skill)
OTel span emitted on WARN and BLOCK only.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import List, Optional

from sidecar.span_emitter import emit_detection_span
from sidecar.stage0_unicode_scan import scan_for_invisible_unicode

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MCP_CONFIG_PATHS = [
    "~/.config/Claude/",
    "~/.cursor/",
    "~/.codeium/",
    "~/.continue/",
]

KNOWN_MCP_PACKAGES = [
    "anthropic",
    "openai",
    "@anthropic-ai/claude-code",
    "@anthropic-ai/sdk",
    "@anthropic-ai/mcp",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "mcp-server-filesystem",
    "mcp-server-git",
    "mcp-server-github",
    "supports-color",
]

# Prompt injection detection patterns for scan_skill
_INJECTION_PATTERNS = [
    r"ignore\b.{0,40}\bprevious\b.{0,40}\binstructions?\b",
    r"\bdisregard\b.{0,30}\b(instructions?|guidelines?|rules?|prior)\b",
    r"\byou are now\b",
    r"\bnew system prompt\b",
    r"\bsystem:\s",
    r"\[INST\]",
    r"<\|system\|>",
    r"\bjailbreak\b",
    r"\bact as\b.{0,10}\b(a|an)\b.{0,20}\b(ai|model|assistant|bot)\b",
    r"\bforget\b.{0,30}\b(your|all|previous)\b.{0,30}\binstructions?\b",
    r"\bpretend\b.{0,20}\b(you are|to be)\b",
    r"\bDAN\b",
]

_URL_RE = re.compile(r"https?://\S{4,}", re.IGNORECASE)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_mcp_package(package_name: str, source_path: str) -> dict:
    """
    Static analysis of an npm package for MCP supply-chain attack indicators.

    Args:
        package_name: Package name as declared (e.g. "@scope/name" or "plain-name").
        source_path:  Path to the extracted package directory.

    Returns:
        {
            "verdict": "BLOCK" | "WARN" | "PASS",
            "detection_type": str | None,
            "evidence": dict,
        }
    """
    path = Path(source_path).expanduser()
    pkg_json = _read_package_json(path)
    warnings: List[str] = []
    evidence: dict = {}

    # --- Check 1: post-install config writes (SANDWORM_MODE behavior) -----------
    postinstall = pkg_json.get("scripts", {}).get("postinstall", "")
    if postinstall:
        config_writes = _find_config_refs(path)
        if config_writes:
            warnings.append("postinstall_config_write_detected")
            evidence["config_writes"] = config_writes
            evidence["postinstall_script"] = postinstall

    # --- Check 2: invisible Unicode (defense in depth — Stage 0 is primary) ----
    for js_file in sorted(path.rglob("*.js")):
        try:
            content = js_file.read_text(encoding="utf-8", errors="replace")
        except IOError:
            continue
        scan = scan_for_invisible_unicode(content)
        if scan["verdict"] == "BLOCK":
            ev = {**scan["evidence"], "file": str(js_file)}
            emit_detection_span(
                stage=1, layer="Stage1b", verdict="BLOCK",
                detection_type="invisible_unicode_detected", evidence=ev,
            )
            return {"verdict": "BLOCK", "detection_type": "invisible_unicode_detected", "evidence": ev}

    # --- Check 3: AGNTCY MCP Server Badge (advisory; Stage 2 hard-gates) --------
    has_badge = bool(
        pkg_json.get("mcp_badge_id")
        or pkg_json.get("agntcy_badge")
        or pkg_json.get("badge_metadata_id")
    )
    evidence["has_badge"] = has_badge
    if not has_badge:
        warnings.append("no_agntcy_badge")

    # --- Check 4: Levenshtein typosquat -----------------------------------------
    typosquat = _check_typosquat(package_name)
    if typosquat:
        warnings.append("typosquat_suspected")
        evidence["typosquat"] = typosquat

    # --- Verdict -----------------------------------------------------------------
    if warnings:
        evidence["warnings"] = warnings
        result = {
            "verdict": "WARN",
            "detection_type": warnings[0],
            "evidence": evidence,
        }
        emit_detection_span(
            stage=1, layer="Stage1b", verdict="WARN",
            detection_type=warnings[0], evidence=evidence,
        )
        return result

    return {"verdict": "PASS", "detection_type": None, "evidence": evidence}


def scan_skill(skill_name: str, description: str) -> dict:
    """
    Scan an MCP tool description for prompt injection patterns and record its hash.

    The returned tool_description_hash is stored by the pipeline and compared at
    invocation time by Stage 4 (semantic scope assertion) to detect mutation.

    Args:
        skill_name:  MCP tool/skill name.
        description: Tool description string as registered.

    Returns:
        {
            "verdict": "WARN" | "PASS",
            "detection_type": str | None,
            "tool_description_hash": "sha256:<hex>",
            "evidence": dict,
        }
    """
    desc_hash = f"sha256:{hashlib.sha256(description.encode()).hexdigest()}"
    evidence = {"skill_name": skill_name, "tool_description_hash": desc_hash}

    # --- Injection phrase patterns -----------------------------------------------
    matched = [p for p in _INJECTION_PATTERNS if re.search(p, description, re.IGNORECASE)]
    if matched:
        evidence["patterns_matched"] = matched
        result = {
            "verdict": "WARN",
            "detection_type": "injection_pattern_detected",
            "tool_description_hash": desc_hash,
            "evidence": evidence,
        }
        emit_detection_span(
            stage=1, layer="Stage1b", verdict="WARN",
            detection_type="injection_pattern_detected", evidence=evidence,
            security_fields={"security.tool_description_hash": desc_hash},
        )
        return result

    # --- URLs in description -----------------------------------------------------
    urls = _URL_RE.findall(description)
    if urls:
        evidence["urls_found"] = urls
        result = {
            "verdict": "WARN",
            "detection_type": "url_in_description",
            "tool_description_hash": desc_hash,
            "evidence": evidence,
        }
        emit_detection_span(
            stage=1, layer="Stage1b", verdict="WARN",
            detection_type="url_in_description", evidence=evidence,
            security_fields={"security.tool_description_hash": desc_hash},
        )
        return result

    # --- Base64 blobs ------------------------------------------------------------
    b64_matches = [m for m in _B64_RE.findall(description) if len(m) >= 40]
    if b64_matches:
        evidence["base64_found"] = b64_matches[:3]
        result = {
            "verdict": "WARN",
            "detection_type": "base64_blob_in_description",
            "tool_description_hash": desc_hash,
            "evidence": evidence,
        }
        emit_detection_span(
            stage=1, layer="Stage1b", verdict="WARN",
            detection_type="base64_blob_in_description", evidence=evidence,
            security_fields={"security.tool_description_hash": desc_hash},
        )
        return result

    return {
        "verdict": "PASS",
        "detection_type": None,
        "tool_description_hash": desc_hash,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_package_json(package_path: Path) -> dict:
    pkg_json_path = package_path / "package.json"
    if not pkg_json_path.exists():
        return {}
    try:
        return json.loads(pkg_json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, IOError):
        return {}


def _find_config_refs(package_path: Path) -> List[dict]:
    """Scan .js files for references to MCP client config paths."""
    found = []
    for js_file in sorted(package_path.rglob("*.js")):
        try:
            content = js_file.read_text(encoding="utf-8", errors="replace")
        except IOError:
            continue
        for config_path in MCP_CONFIG_PATHS:
            bare = config_path.replace("~/", "")
            if config_path in content or bare in content:
                found.append({"file": str(js_file), "config_path": config_path})
                break
    return found


def _edit_distance(a: str, b: str) -> int:
    """Wagner-Fischer edit distance. No external dependencies."""
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i - 1] == b[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


def _extract_basename(name: str) -> str:
    """Strip npm scope: '@scope/pkg' → 'pkg', 'pkg' → 'pkg'."""
    return name.split("/")[-1] if "/" in name else name


def _check_typosquat(package_name: str) -> Optional[dict]:
    """
    Return typosquat evidence if package_name is within edit distance 2 of any
    known legitimate package. Returns None if it IS a known package (distance 0
    on full name) or if distance > 2.
    """
    basename = _extract_basename(package_name)
    min_dist = len(package_name) + 1  # sentinel
    closest = None

    for legit in KNOWN_MCP_PACKAGES:
        legit_base = _extract_basename(legit)
        d = min(
            _edit_distance(package_name, legit),
            _edit_distance(basename, legit_base),
        )
        if d < min_dist:
            min_dist = d
            closest = legit

    # Exact full-name match → it IS the legitimate package, not a typosquat
    if min_dist == 0 and package_name == closest:
        return None

    if min_dist <= 2:
        return {"package": package_name, "closest": closest, "distance": min_dist}

    return None
