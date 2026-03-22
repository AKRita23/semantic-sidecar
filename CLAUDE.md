# CLAUDE.md — Semantic Sidecar POC
## Claude Code Workflow Rules — Read This First Every Session

---

## What This Builds

A Python POC that detects and blocks two active MCP supply chain attacks:

- **SANDWORM_MODE** — typosquatted npm → silent post-install MCP injection → 48h delay → credential exfil
- **Glassworm MCP** — invisible Unicode eval() payload in MCP source → fires at server initialization

Both passed every existing auth check. This sidecar catches them via five detection layers.

---

## Architecture — Five Layers

```
Stage 0  Pre-load Unicode scan          BLOCK  ← Glassworm
Stage 1  npm provenance check           WARN   ← advisory only
Stage 2  MCP registration integrity     BLOCK  ← AGNTCY MCP Server Badge (W3C VC, RS256)
Stage 3  Causal authorization           BLOCK  ← AGNTCY Agent Badge (W3C VC, RS256) + Cedar
Stage 4  Semantic scope assertion       BLOCK  ← psutil + mitmproxy + tool_description_hash
Stage 5  Cedar hard boundary            BLOCK  ← unconditional credential/egress deny
```

## Key Architectural Facts — Do Not Change Without Explicit Instruction

1. **No HMAC anywhere.** Causal authorization uses AGNTCY Agent Badge — W3C VC with RS256
   signature, publicly verifiable via `identity badge verify`. No separate signing mechanism.

2. **Badge verification is permissionless.** Stage 2 calls `identity badge verify {metadata_id}`.
   No Okta required for verification — any published badge can be verified by anyone.
   Okta is one supported trusted issuer for badge *issuance*, not verification.

3. **Stage 0 is load-bearing for Glassworm.** Glassworm fires at initialization — before
   any task context, before any tool call. Stage 0 is the only layer positioned to catch it
   before eval() executes. It is not optional.

4. **Cedar evaluates badge claims, not raw identity.** Cedar policy receives the VC claims
   (capabilities, declared scope) from the AGNTCY badge and enforces boundaries against them.
   Cedar does not replace the badge — it enforces on top of it.

5. **BLOCK at any stage halts pipeline.** WARN at Stage 1 does not halt.
   Stage 5 Cedar always runs regardless — it is the unconditional floor.

6. **Novel contribution: enforcement not observability.** All other frameworks use OTel
   spans post-hoc. This sidecar uses SpanProcessor.on_start() to enforce inline before
   execution. This is what makes it distinct.

---

## Session Startup Checklist

1. Read this file fully
2. Read SPEC.md fully
3. Read tasks/todo.md — find the current incomplete session
4. Read tasks/lessons.md for prior session learnings
5. State what session you are starting and what it delivers
6. Write the test plan before writing any code

---

## Workflow Rules

### Plan First
Before writing code state:
- What this session builds
- Inputs and outputs
- Test cases (happy path + attack path + OTel span verification)
- Any open questions

### One Session = One Stage
Do not combine sessions. Each session builds exactly one module + its tests.

### Test-Driven
Write test file first. Every stage must have:
- Happy path test (legitimate server/action → ALLOW)
- Attack path test (SANDWORM_MODE or Glassworm → BLOCK)
- OTel span field verification (security.* fields populated correctly)
- Stage 3 must include: 48h expired task_id → orphaned action → BLOCK

### Session Complete When
- `pytest tests/test_stageN.py` passes with no warnings
- Module imports cleanly
- tasks/todo.md updated
- One entry added to tasks/lessons.md

---

## Security Field Naming — Exact, Do Not Change

These are proposed for AGNTCY upstream contribution:

```python
"security.tool_description_hash"    # SHA-256 of tool description at invocation
"security.declared_scope"           # filesystem paths tool declared
"security.observed_scope"           # filesystem paths actually observed (psutil)
"security.declared_destinations"    # network destinations tool declared
"security.observed_egress"          # network connections actually observed (mitmproxy)
"security.layer"                    # Stage0 | L0.5 | L2 | L2b | L3
"security.stage"                    # 0-5
"security.detection_type"           # see SPEC.md for enum values
"security.verdict"                  # BLOCK | ALLOW | WARN
"security.evidence"                 # JSON string with detection details
"gen_ai.task.requester"             # "human" | "ci" | "model_autonomous"
```

---

## AGNTCY SDK Usage

```python
# Badge verification (Stage 2 + Stage 3)
from agntcy_identity import verify_badge
result = verify_badge(metadata_id=server_metadata_id)
# Returns: {valid: bool, capabilities: [...], declared_scope: [...], issuer: ...}

# OTel span emission (all stages)
from ioa_observe.sdk import Observe
from ioa_observe.sdk.tracing import get_current_span
span = get_current_span()
span.set_attribute("security.verdict", "BLOCK")
span.set_attribute("security.detection_type", "invisible_unicode_detected")
```

---

## Starting Session 0

Build: `sidecar/stage0_unicode_scan.py` + `tests/test_stage0.py`

Scan MCP server source files for invisible Unicode before load.
Target codepoint ranges: U+FE00–FE0F and U+E0100–E01EF.
Return BLOCK + evidence dict if found, PASS if clean.
Emit OTel span with security.* fields.

Read SPEC.md Stage 0 section before writing a single line.
