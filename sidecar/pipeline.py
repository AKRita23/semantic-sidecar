"""
sidecar/pipeline.py — Stage 8: Full Detection Pipeline

Orchestrates all five detection stages in order. Stage 5 (Cedar) always runs
unconditionally — it is the deterministic floor regardless of prior verdicts.

Stage data flow:
  Stage 2 (MCP registration) PASS → badge carries capabilities, declared_scope,
  declared_destinations → forwarded to Stage 4 (semantic scope) and Stage 4b
  (output validation). If Stage 2 BLOCKs, downstream stages use empty lists
  (most conservative: every file and connection is a violation).

SANDWORM_MODE end-to-end path:
  [STAGE 0]  Unicode scan      → BLOCK | glassworm_mcp.js: 8 invisible codepoints
  [STAGE 1a] npm provenance    → WARN  | suport-color: no sigstore attestation
  [STAGE 1a] OSV advisory      → WARN  | claude-code: found in OSV database
  [STAGE 1b] MCP scanner       → WARN  | claude-code: typosquat distance 1
  [STAGE 2]  MCP registration  → BLOCK | ~/.dev-utils/mcp-server.js: suspicious path
  [STAGE 3]  Causal auth       → BLOCK | task_id expired 47h ago (orphaned action)
  [STAGE 4]  Semantic scope    → BLOCK | ~/.ssh/id_rsa outside declared scope
  [STAGE 4b] Output validation → BLOCK | response contains injection phrase
  [STAGE 5]  Cedar policy      → BLOCK | credential_access_denied
"""

from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from sidecar.stage0_unicode_scan import scan_file
from sidecar.stage1_mcp_skill_scanner import scan_mcp_package
from sidecar.stage1_provenance import check_npm_provenance, check_osv
from sidecar.stage2_mcp_registration import BadgeVerifier, verify_mcp_registration
from sidecar.stage3_causal_authorization import TaskRegistry, check_causal_authorization
from sidecar.stage4_semantic_scope import check_semantic_scope
from sidecar.stage4b_output_validation import validate_tool_output
from sidecar.stage5_cedar_policy import CedarEvaluator, check_cedar_policy


# ---------------------------------------------------------------------------
# Pipeline input / result types
# ---------------------------------------------------------------------------

@dataclass
class PipelineInput:
    """All inputs required to run the full detection pipeline."""

    # Stage 0 — Unicode scan
    mcp_source_file: str            # path to MCP server source file to scan

    # Stage 1a — npm provenance (advisory)
    package_name: str               # npm package name for provenance + OSV checks
    package_version: Optional[str] = None

    # Stage 1b — MCP package + skill scanner
    package_source_path: str = ""   # path to extracted package directory

    # Stage 2 — MCP registration integrity
    server_path: str = ""           # MCP server binary/script path
    server_binary_hash: str = ""    # SHA-256 of server binary at load time
    tool_names: List[str] = field(default_factory=list)
    mcp_badge_verifier: Optional[BadgeVerifier] = None
    allowlist: Optional[dict] = None

    # Stage 3 — Causal authorization
    task_id: Optional[str] = None
    registry: Optional[TaskRegistry] = None

    # Stage 4 — Semantic scope assertion
    tool_name: str = ""             # MCP tool being invoked
    current_description: str = ""   # tool description at invocation time
    mcp_pid: int = 0
    observed_connections: List[str] = field(default_factory=list)
    get_open_files: Optional[Callable] = None   # injectable; defaults to psutil

    # Stage 4b — Output validation
    tool_output: Any = None         # tool response before it enters model context

    # Stage 5 — Cedar policy (unconditional floor)
    cedar_action: str = 'Action::"file_read"'
    cedar_resource: str = ""
    cedar_principal: str = "MCPServer"
    cedar_context: Optional[dict] = None
    cedar_evaluator: Optional[CedarEvaluator] = None

    # Injectable HTTP sessions for Stage 1a (tests only)
    _npm_session: Any = None
    _osv_session: Any = None


@dataclass
class PipelineResult:
    """Collected results from all pipeline stages."""

    stage0: dict
    stage1a_provenance: dict
    stage1a_osv: dict
    stage1b: dict
    stage2: dict
    stage3: dict
    stage4: dict
    stage4b: dict
    stage5: dict

    # Badge data forwarded from Stage 2 → Stage 4 / 4b
    badge_capabilities: List[str] = field(default_factory=list)
    badge_declared_scope: List[str] = field(default_factory=list)
    badge_declared_destinations: List[str] = field(default_factory=list)

    def blocks(self) -> List[str]:
        """Return stage labels whose verdict is BLOCK."""
        labels = ["stage0", "stage2", "stage3", "stage4", "stage4b", "stage5"]
        stages = [self.stage0, self.stage2, self.stage3,
                  self.stage4, self.stage4b, self.stage5]
        return [label for label, s in zip(labels, stages) if s.get("verdict") == "BLOCK"]

    def warns(self) -> List[str]:
        """Return stage labels whose verdict is WARN."""
        labels = ["stage1a_provenance", "stage1a_osv", "stage1b"]
        stages = [self.stage1a_provenance, self.stage1a_osv, self.stage1b]
        return [label for label, s in zip(labels, stages) if s.get("verdict") == "WARN"]

    def format_summary(self) -> str:
        """Format the Six+ Red Lights demo output."""
        lines = []

        def _v(r: dict) -> str:
            return r.get("verdict", "PASS")

        # Stage 0
        s0 = self.stage0
        ev0 = s0.get("evidence", {})
        if _v(s0) == "BLOCK":
            file0 = ev0.get("file", "")
            cp0 = ev0.get("codepoints_found", 0)
            detail0 = f"{file0}: {cp0} invisible codepoints"
        else:
            detail0 = "clean"
        lines.append(f"[STAGE 0]  Unicode scan      → {_v(s0):<5} | {detail0}")

        # Stage 1a provenance
        s1p = self.stage1a_provenance
        ev1p = s1p.get("evidence", {})
        pkg1p = ev1p.get("package", "")
        r1p = s1p.get("reason", "")
        detail1p = f"{pkg1p}: {r1p}" if _v(s1p) == "WARN" else f"{pkg1p}: provenance ok"
        lines.append(f"[STAGE 1a] npm provenance    → {_v(s1p):<5} | {detail1p}")

        # Stage 1a OSV
        s1o = self.stage1a_osv
        ev1o = s1o.get("evidence", {})
        pkg1o = ev1o.get("package", "")
        r1o = s1o.get("reason", "")
        detail1o = f"{pkg1o}: {r1o}" if _v(s1o) == "WARN" else f"{pkg1o}: no known CVEs"
        lines.append(f"[STAGE 1a] OSV advisory      → {_v(s1o):<5} | {detail1o}")

        # Stage 1b
        s1b = self.stage1b
        ev1b = s1b.get("evidence", {})
        tq = ev1b.get("typosquat", {})
        if tq:
            detail1b = (
                f"{tq.get('package')}: typosquat distance {tq.get('distance')} "
                f"from {tq.get('closest')}"
            )
        elif _v(s1b) == "WARN":
            detail1b = s1b.get("detection_type", "warn")
        else:
            detail1b = "clean"
        lines.append(f"[STAGE 1b] MCP scanner       → {_v(s1b):<5} | {detail1b}")

        # Stage 2
        s2 = self.stage2
        ev2 = s2.get("evidence", {})
        dt2 = s2.get("detection_type", "")
        sp2 = ev2.get("server_path", "")
        mp2 = ev2.get("matched_pattern", "")
        if _v(s2) == "BLOCK":
            detail2 = f"{sp2}: {dt2}" + (f" ({mp2})" if mp2 else "")
        else:
            detail2 = f"{sp2}: badge verified"
        lines.append(f"[STAGE 2]  MCP registration  → {_v(s2):<5} | {detail2}")

        # Stage 3
        s3 = self.stage3
        ev3 = s3.get("evidence", {})
        expired_sec = ev3.get("expired_seconds_ago")
        if expired_sec is not None:
            detail3 = f"task_id expired {int(expired_sec) // 3600}h ago (orphaned action)"
        elif _v(s3) == "BLOCK":
            detail3 = s3.get("detection_type", "block")
        else:
            detail3 = f"task authorized (by {ev3.get('authorized_by', 'unknown')})"
        lines.append(f"[STAGE 3]  Causal auth       → {_v(s3):<5} | {detail3}")

        # Stage 4
        s4 = self.stage4
        findings4 = s4.get("findings", [])
        if findings4:
            fs_f = next(
                (f for f in findings4 if f.get("check") == "filesystem_scope"), None
            )
            if fs_f:
                viol = fs_f.get("violations", ["?"])[0]
                detail4 = f"{viol} outside declared scope"
            else:
                detail4 = findings4[0].get("detection_type", "violation")
        elif _v(s4) == "PASS":
            detail4 = "scope honored"
        else:
            detail4 = "violation"
        lines.append(f"[STAGE 4]  Semantic scope    → {_v(s4):<5} | {detail4}")

        # Stage 4b
        s4b = self.stage4b
        findings4b = s4b.get("findings", [])
        if findings4b:
            detail4b = findings4b[0].get("detection_type", "violation")
        elif _v(s4b) == "PASS":
            detail4b = "output clean"
        else:
            detail4b = "violation"
        lines.append(f"[STAGE 4b] Output validation → {_v(s4b):<5} | {detail4b}")

        # Stage 5
        s5 = self.stage5
        reasons5 = s5.get("reasons", [])
        if reasons5:
            detail5 = reasons5[0]
        elif _v(s5) == "PASS":
            detail5 = "policy allow"
        else:
            detail5 = "cedar_policy_deny"
        lines.append(f"[STAGE 5]  Cedar policy      → {_v(s5):<5} | {detail5}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_pipeline(inp: PipelineInput) -> PipelineResult:
    """
    Run all detection stages in order.

    Stage 5 always runs — it is the unconditional floor. BLOCK verdicts from
    prior stages are recorded in PipelineResult but do not short-circuit the
    pipeline. The goal is complete visibility: every layer's decision is
    captured in the result and emitted as an OTel span.

    Badge data (capabilities, declared_scope, declared_destinations) from
    Stage 2 PASS flows forward to Stage 4 and Stage 4b. On Stage 2 BLOCK,
    downstream stages receive empty lists — the most conservative behavior
    (every open file and connection is a violation).

    Args:
        inp: PipelineInput bundling all stage inputs.

    Returns:
        PipelineResult with per-stage result dicts and forwarded badge data.
    """
    registry = inp.registry or TaskRegistry()
    tool_name = inp.tool_name or (inp.tool_names[0] if inp.tool_names else "")

    # --- Stage 0: Pre-load Unicode scan ----------------------------------------
    stage0 = scan_file(inp.mcp_source_file)

    # --- Stage 1a: npm provenance (advisory — WARN only) -----------------------
    stage1a_prov = check_npm_provenance(
        inp.package_name, _session=inp._npm_session
    )
    stage1a_osv = check_osv(
        inp.package_name, inp.package_version, _session=inp._osv_session
    )

    # --- Stage 1b: MCP package scanner -----------------------------------------
    stage1b = scan_mcp_package(inp.package_name, inp.package_source_path)

    # --- Stage 2: MCP registration integrity (hard BLOCK gate) -----------------
    stage2 = verify_mcp_registration(
        inp.server_path,
        inp.server_binary_hash,
        tool_names=inp.tool_names or None,
        verifier=inp.mcp_badge_verifier,
        allowlist=inp.allowlist,
    )

    # --- Badge data forwarding: Stage 2 → Stage 4 / 4b -------------------------
    if stage2.get("verdict") == "PASS":
        badge_capabilities = stage2.get("capabilities", [])
        badge_declared_scope = stage2.get("declared_scope", [])
        badge_declared_destinations = stage2.get("declared_destinations", [])
    else:
        badge_capabilities = []
        badge_declared_scope = []
        badge_declared_destinations = []

    # --- Stage 3: Causal authorization (hard BLOCK gate) -----------------------
    stage3 = check_causal_authorization(
        tool_name=tool_name,
        task_id=inp.task_id,
        registry=registry,
    )

    # --- Stage 4: Semantic scope assertion (hard BLOCK gate) -------------------
    stage4 = check_semantic_scope(
        tool_name=tool_name,
        current_description=inp.current_description,
        mcp_pid=inp.mcp_pid,
        observed_connections=inp.observed_connections,
        declared_scope=badge_declared_scope,
        declared_destinations=badge_declared_destinations,
        allowlist=inp.allowlist or {},
        get_open_files=inp.get_open_files,
    )

    # --- Stage 4b: Output validation (hard BLOCK gate) -------------------------
    stage4b = validate_tool_output(
        tool_name=tool_name,
        output=inp.tool_output,
        declared_capabilities=badge_capabilities,
    )

    # --- Stage 5: Cedar policy (unconditional floor — always runs) -------------
    stage5 = check_cedar_policy(
        action=inp.cedar_action,
        resource=inp.cedar_resource,
        principal=inp.cedar_principal,
        context=inp.cedar_context or {},
        evaluator=inp.cedar_evaluator,
    )

    return PipelineResult(
        stage0=stage0,
        stage1a_provenance=stage1a_prov,
        stage1a_osv=stage1a_osv,
        stage1b=stage1b,
        stage2=stage2,
        stage3=stage3,
        stage4=stage4,
        stage4b=stage4b,
        stage5=stage5,
        badge_capabilities=badge_capabilities,
        badge_declared_scope=badge_declared_scope,
        badge_declared_destinations=badge_declared_destinations,
    )
