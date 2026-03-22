"""
sidecar/stage4_semantic_scope.py — Stage 4: Semantic Scope Assertion (L2b)

Runtime behavioral enforcement. Three checks that verify the tool is doing
what it declared it would do. The AGNTCY MCP Server Badge is the contract.
This stage audits whether the contract is honored at invocation time.

Relationship to Stage 2 (L0.5):
  Stage 2: checks the STATIC badge contract at registration time
  Stage 4: checks whether RUNTIME BEHAVIOR matches that contract
  These are NOT redundant. A server with a valid badge can still violate
  its declared scope at runtime.

Three checks in order:
  1. tool_description_hash  — SHA-256 of current description vs allowlist baseline
     Mismatch → BLOCK (description_hash_mismatch)
     Detects: post-install description mutation, prompt-injection rug-pull

  2. Filesystem scope (psutil)
     psutil.Process(mcp_pid).open_files() vs declared_scope from badge
     Any path outside declared_scope → BLOCK (filesystem_scope_violation)
     Detects: SANDWORM_MODE credential exfil (reading ~/.ssh, ~/.aws)

  3. Network scope (mitmproxy intercept layer)
     observed_connections (passed in from pipeline) vs declared_destinations
     Any undeclared egress → BLOCK (network_egress_violation)
     Detects: SANDWORM_MODE C2 exfil POST

OTel contribution — five fields always populated, even on PASS:
  security.tool_description_hash   — current hash at invocation
  security.declared_scope          — from badge (list)
  security.observed_scope          — from psutil (list)
  security.declared_destinations   — from badge (list)
  security.observed_egress         — from observed_connections (list)

These five fields are the AGNTCY upstream OTel contribution.
They are set on every span regardless of verdict — observability, not just enforcement.

Injectable get_open_files avoids psutil dependency in unit tests.
observed_connections passed in from pipeline — no mitmproxy import here.

Field names imported from span_emitter.SECURITY_FIELDS — no string literals.
"""

import hashlib
from pathlib import Path
from typing import Callable, List, Optional

from sidecar.span_emitter import SECURITY_FIELDS, emit_detection_span

# ---------------------------------------------------------------------------
# Stage 4 OTel field names — bound from span_emitter registry
# No hardcoded strings: if SECURITY_FIELDS changes, these update automatically.
# ---------------------------------------------------------------------------

(
    _F_HASH,        # "security.tool_description_hash"
    _F_DECL_SCOPE,  # "security.declared_scope"
    _F_OBS_SCOPE,   # "security.observed_scope"
    _F_DECL_DEST,   # "security.declared_destinations"
    _F_OBS_EGRESS,  # "security.observed_egress"
) = SECURITY_FIELDS[:5]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_semantic_scope(
    tool_name: str,
    current_description: str,
    mcp_pid: int,
    observed_connections: List[str],
    declared_scope: List[str],
    declared_destinations: List[str],
    allowlist: dict,
    get_open_files: Optional[Callable] = None,
) -> dict:
    """
    Runtime behavioral enforcement gate (L2b).

    Verifies that a tool invocation matches its declared behavioral contract
    across three dimensions: description integrity, filesystem scope, network scope.

    All five OTel security fields are populated in the return value and span
    regardless of verdict — this stage contributes observability even on PASS.

    Args:
        tool_name:            MCP tool being invoked.
        current_description:  Tool description string at invocation time.
        mcp_pid:              PID of the MCP server process (for psutil).
        observed_connections: Network connections observed by mitmproxy intercept.
        declared_scope:       Filesystem paths declared in AGNTCY MCP Server Badge.
        declared_destinations: Network destinations declared in badge.
        allowlist:            Trust registry dict (badges/allowlist.json or inline).
        get_open_files:       Callable(pid) -> List[str]. Defaults to psutil.
                              Inject a stub in tests — no psutil required.

    Returns:
        {
            "verdict":         "BLOCK" | "PASS",
            "findings":        List[dict],  # one entry per violation type found
            "security_fields": dict,        # all five OTel fields, always populated
        }
    """
    _open_files_fn = get_open_files or _default_get_open_files

    # --- Current description hash -------------------------------------------
    current_hash = f"sha256:{hashlib.sha256(current_description.encode()).hexdigest()}"

    # --- Collect open files (injectable — no psutil in tests) ----------------
    open_files: List[str] = _open_files_fn(mcp_pid)

    # --- Security fields — populated regardless of verdict -------------------
    security_fields = {
        _F_HASH:       current_hash,
        _F_DECL_SCOPE: declared_scope,
        _F_OBS_SCOPE:  open_files,
        _F_DECL_DEST:  declared_destinations,
        _F_OBS_EGRESS: observed_connections,
    }

    findings: List[dict] = []

    # --- Check 1: description hash ------------------------------------------
    declared_hash = _find_declared_hash(tool_name, allowlist)
    if declared_hash:  # empty string means "not yet recorded" → skip
        if declared_hash != current_hash:
            findings.append({
                "check": "description_hash",
                "detection_type": "description_hash_mismatch",
                "declared_hash": declared_hash,
                "current_hash": current_hash,
                "tool_name": tool_name,
            })

    # --- Check 2: filesystem scope ------------------------------------------
    fs_violations = _check_filesystem_scope(open_files, declared_scope)
    if fs_violations:
        findings.append({
            "check": "filesystem_scope",
            "detection_type": "filesystem_scope_violation",
            "violations": fs_violations,
            "declared_scope": declared_scope,
        })

    # --- Check 3: network scope ---------------------------------------------
    net_violations = _check_network_scope(observed_connections, declared_destinations)
    if net_violations:
        findings.append({
            "check": "network_scope",
            "detection_type": "network_egress_violation",
            "violations": net_violations,
            "declared_destinations": declared_destinations,
        })

    # --- Verdict + OTel span ------------------------------------------------
    verdict = "BLOCK" if findings else "PASS"
    first_detection = findings[0]["detection_type"] if findings else None

    emit_detection_span(
        stage=4,
        layer="L2b",
        verdict=verdict,
        detection_type=first_detection,
        evidence={"tool_name": tool_name, "findings": findings},
        tool_name=tool_name,
        security_fields=security_fields,
    )

    return {
        "verdict": verdict,
        "findings": findings,
        "security_fields": security_fields,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_declared_hash(tool_name: str, allowlist: dict) -> Optional[str]:
    """
    Look up the declared tool_description_hash for tool_name in the allowlist.
    Returns the hash string, empty string (skip check), or None (not found → skip).
    """
    for server in allowlist.get("servers", []):
        hashes = server.get("tool_description_hashes", {})
        if tool_name in hashes:
            return hashes[tool_name]
    return None


def _expand_path(path_str: str) -> str:
    """Expand ~ and resolve to absolute path without touching the filesystem."""
    p = Path(path_str).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    return str(p)


def _check_filesystem_scope(
    open_files: List[str],
    declared_scope: List[str],
) -> List[str]:
    """
    Return the subset of open_files that fall outside declared_scope.

    Empty declared_scope means the server declared no filesystem access —
    any open file is a violation.
    """
    if not declared_scope:
        return list(open_files)

    expanded_scopes = [_expand_path(s) for s in declared_scope]
    violations = []
    for f_path in open_files:
        expanded_file = _expand_path(f_path)
        in_scope = any(expanded_file.startswith(scope) for scope in expanded_scopes)
        if not in_scope:
            violations.append(f_path)
    return violations


def _check_network_scope(
    observed: List[str],
    declared: List[str],
) -> List[str]:
    """
    Return connections in observed that are not in declared_destinations.

    Empty declared means the server declared no outbound connections —
    any connection is a violation.
    """
    if not declared:
        return list(observed)
    declared_set = set(declared)
    return [c for c in observed if c not in declared_set]


def _default_get_open_files(pid: int) -> List[str]:
    """
    Default get_open_files using psutil. Only imported here — never at module level.
    Inject a stub in tests to avoid psutil dependency.
    Degrades gracefully if psutil is not installed or PID is unavailable.
    """
    try:
        import psutil  # type: ignore
        return [f.path for f in psutil.Process(pid).open_files()]
    except Exception:
        return []
