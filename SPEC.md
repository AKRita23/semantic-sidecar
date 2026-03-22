# Semantic Sidecar — Build Spec v3.0
**Date:** March 21, 2026 | **Language:** Python 3.9 | **License:** Apache 2.0

---

## What This Builds

A Python sidecar catching two active attacks and server-side injection
attacks no existing framework addresses.

| Attack | Primary layers |
|---|---|
| SANDWORM_MODE | L2 + L2b |
| Glassworm MCP | Stage 0 + L0.5 |
| Server-side injection | Stage 4b (NEW) |

---

## v3 Key Design Changes

### 1. allowlist.json = trust registry only
Stores verified server identity: AGNTCY badge metadata IDs, SHA-256
hashes, behavioral contracts. NOT threat intelligence. Human-signed.
Static. Changes only when a new verified server is added.

### 2. Threat intelligence = live feeds
No hardcoded malicious lists. Query live:
- OSV database: POST https://api.osv.dev/v1/query (npm ecosystem)
- npm advisory API: registry.npmjs.org/-/npm/v1/security/advisories/bulk
Both already contain SANDWORM_MODE and Glassworm package entries.

### 3. Cedar policies are hot-reloadable
policies/dynamic/ watched by FileSystemWatcher. Analyst confirms
detection → pushes new Cedar policy → sidecar enforces without restart.

### 4. Feedback loop via OTel
Detection events emit OTel spans → SIEM ingests → analyst confirms →
Cedar policy pushed to policies/dynamic/ → hot-reload.
The observability layer IS the feedback mechanism.

### 5. Stage 4b — Output Validation (NEW, NOVEL)
Server-side prompt injection — malicious content in tool responses
injecting into model context — requires enforcement AFTER tool executes
but BEFORE result enters model context. No existing framework does this.

---

## Project Structure

```
semantic-sidecar/
├── CLAUDE.md
├── SPEC.md
├── requirements.txt
├── sidecar/
│   ├── __init__.py
│   ├── pipeline.py
│   ├── stage0_unicode_scan.py          ✅ DONE
│   ├── stage1_provenance.py            ← npm sigstore + OSV
│   ├── stage1_mcp_skill_scanner.py     ← MCP-specific static analysis
│   ├── stage2_mcp_registration.py      ← AGNTCY MCP Server Badge
│   ├── stage3_causal_authorization.py  ← AGNTCY Agent Badge + Cedar
│   ├── stage4_semantic_scope.py        ← psutil + mitmproxy + hash
│   ├── stage4b_output_validation.py    ← server-side injection (NEW)
│   ├── stage5_cedar_policy.py          ← hard boundary + hot-reload
│   └── span_emitter.py                 ✅ DONE
├── policies/
│   ├── sandworm_mode.cedar
│   ├── glassworm.cedar
│   ├── output_validation.cedar
│   └── dynamic/                        ← hot-reload from feedback loop
├── badges/
│   └── allowlist.json                  ← trust registry only
├── feeds/
│   └── osv_cache.json                  ← local cache of OSV queries
├── tests/
│   ├── test_stage0.py                  ✅ DONE (22 tests)
│   ├── test_span_emitter.py            ✅ DONE (27 tests)
│   └── fixtures/
│       ├── clean_mcp_server.js
│       ├── glassworm_mcp_server.js     ✅ FIXED
│       └── sandworm_mcp_server.js
├── simulate/
│   ├── sandworm_injection.py
│   └── glassworm_mcp.py
└── tasks/
    ├── todo.md
    └── lessons.md
```

---

## Stage Specifications

### Stage 0 — Pre-Load Unicode Scan ✅ DONE
Scans for U+FE00-FE0F and U+E0100-E01EF before MCP server loads.
22 tests pass. Glassworm fixture verified with real Unicode bytes.

---

### Stage 1a — npm Provenance Check
**File:** sidecar/stage1_provenance.py | **Verdict:** WARN only

```python
def check_npm_provenance(package_name: str) -> dict:
    # GET https://registry.npmjs.org/{package_name}
    # Check dist.signatures or dist.attestations in latest version
    # No attestation → WARN | Network failure → PASS

def check_osv(package_name: str, version: str) -> dict:
    # POST https://api.osv.dev/v1/query
    # {"package": {"name": package_name, "ecosystem": "npm"}}
    # Known vuln → WARN with OSV ID | Network failure → PASS
```

Why OSV replaces hardcoded lists: already contains SANDWORM_MODE and
Glassworm entries, community-maintained, near-real-time, no stale data.

Tests: valid provenance → PASS, no provenance → WARN, OSV hit (mock) →
WARN with ID, network failure → PASS, OTel span on WARN only.

---

### Stage 1b — MCP/Skill Scanner
**File:** sidecar/stage1_mcp_skill_scanner.py | **Verdict:** WARN or BLOCK

```python
def scan_mcp_package(package_name: str, source_path: str) -> dict:
    # 1. Post-install writes to AI tool configs → WARN
    #    (~/.config/Claude/, ~/.cursor/, ~/.codeium/, ~/.continue/)
    #    SANDWORM_MODE exact behavior
    # 2. Invisible Unicode in source → BLOCK (defense in depth)
    # 3. AGNTCY MCP Server Badge absent → WARN
    # 4. Levenshtein distance <= 2 vs known MCP/AI packages → WARN

def scan_skill(skill_name: str, description: str) -> dict:
    # Prompt injection patterns in description → WARN
    # "ignore previous", "disregard", "you are now",
    # "new system prompt", URLs in description, base64 blobs
    # Records tool_description_hash for Stage 4 comparison
```

Tests: post-install → ~/.config/Claude/ → WARN, invisible Unicode →
BLOCK, no badge → WARN, claude-code typosquat → WARN,
"ignore previous instructions" in description → WARN,
description_hash recorded correctly, clean package → PASS.

---

### Stage 2 — MCP Registration Integrity (L0.5)
**File:** sidecar/stage2_mcp_registration.py | **Verdict:** BLOCK or PASS

AGNTCY MCP Server Badge: W3C VC, RS256 signature, publicly verifiable.
Badge verification is permissionless — no IdP needed.
Checks: path in allowlist + SHA-256 hash + badge verify.

---

### Stage 3 — Causal Authorization (L2)
**File:** sidecar/stage3_causal_authorization.py | **Verdict:** BLOCK or PASS

AGNTCY Agent Badge is the Policy Root. W3C VC, RS256. No HMAC.

Action is ORPHANED if:
- No task_id (Glassworm fires at init)
- task_id expired (SANDWORM_MODE 48h delay) ← CRITICAL TEST
- tool_name not in permitted_tools

Workload identity = WHO. L2 = WHY. These are orthogonal.

---

### Stage 4 — Semantic Scope Assertion (L2b)
**File:** sidecar/stage4_semantic_scope.py | **Verdict:** BLOCK or PASS

Three checks:
1. tool_description_hash — invocation vs Stage 1b baseline
2. Filesystem scope via psutil vs declared_scope from badge
3. Network scope via mitmproxy vs declared_destinations from badge

OTel fields: security.tool_description_hash, security.declared_scope,
security.observed_scope, security.declared_destinations,
security.observed_egress

---

### Stage 4b — Output Validation (NEW — NOVEL CONTRIBUTION)
**File:** sidecar/stage4b_output_validation.py | **Verdict:** BLOCK or WARN

Runs AFTER tool executes, BEFORE result enters model context.
No existing framework does this. Closes server-side injection gap.

```python
def validate_tool_output(tool_name: str,
                          output: dict,
                          declared_capabilities: List[str]) -> dict:
    """
    Input validation (model → tool):
      Already covered by tool_description_hash in Stage 4.

    Output validation (tool → model) — this stage:
    1. Injection phrases → BLOCK
       "ignore previous instructions", "disregard", "you are now",
       "new system prompt", "system:", "[INST]", "<|system|>"
    2. Tool call directives in output → BLOCK
       Tool trying to inject new tool calls into model context
    3. Invisible Unicode in output → BLOCK (Glassworm variant)
    4. Base64 blobs in output → WARN (potential exfil/injection)
    5. Output size anomaly vs declared capability → WARN
    6. Paths outside declared_scope in output content → WARN
    """
```

Uses SpanProcessor.on_end() — the second OTel hook this sidecar uses.
on_start() for pre-execution enforcement (Stages 0-4).
on_end() for post-execution enforcement (Stage 4b).

Tests: injection phrase → BLOCK, tool_call directive → BLOCK,
invisible Unicode in output → BLOCK, base64 blob → WARN,
oversized response → WARN, clean output → PASS.

---

### Stage 5 — Cedar Policy (L3)
**File:** sidecar/stage5_cedar_policy.py | **Verdict:** BLOCK — unconditional

```cedar
// sandworm_mode.cedar
forbid(principal is MCPServer, action == Action::"file_read",
       resource matches "/home/**/.ssh/**");
forbid(principal is MCPServer, action == Action::"file_read",
       resource matches "/home/**/.aws/**");
forbid(principal is MCPServer, action == Action::"network_egress",
       resource != context.declared_destinations);

// output_validation.cedar
forbid(principal is MCPServer, action == Action::"tool_response",
       context.contains_injection_phrase == true);
forbid(principal is MCPServer, action == Action::"tool_response",
       context.contains_tool_call_directive == true);
```

policies/dynamic/ watched by FileSystemWatcher. Hot-reload on change.
Cedar always runs — even if all previous stages PASS. It is the floor.

---

## The Feedback Loop

```
Sidecar detects attack
        ↓
OTel span emitted (security.* fields)
        ↓
SIEM / ClickHouse ingests (AGNTCY observe backend)
        ↓
Analyst confirms true positive
        ↓
New Cedar policy → policies/dynamic/
        ↓
FileSystemWatcher hot-reloads
        ↓
Sidecar enforces — no restart required
```

The AGNTCY OTel observe backend IS the feedback mechanism.

---

## Expected Demo Output

```
[STAGE 0]  Unicode scan      → BLOCK | glassworm_mcp.js: 247 invisible codepoints
[STAGE 1a] npm provenance    → WARN  | suport-color: no sigstore attestation
[STAGE 1a] OSV advisory      → WARN  | suport-color: found in OSV database
[STAGE 1b] MCP scanner       → WARN  | post-install writes ~/.config/Claude/
[STAGE 2]  MCP registration  → BLOCK | no valid AGNTCY badge
[STAGE 3]  Causal auth       → BLOCK | task_id expired 47h ago
[STAGE 4]  Semantic scope    → BLOCK | ~/.ssh/id_rsa outside declared scope
[STAGE 4]  Semantic scope    → BLOCK | 45.139.104.115:443 undeclared egress
[STAGE 4b] Output validation → BLOCK | response contains injection phrase
[STAGE 5]  Cedar policy      → BLOCK | credential_access_denied
```

---

## Build Order (11 Sessions)

| Session | File | Status |
|---|---|---|
| 0 | stage0_unicode_scan.py | ✅ DONE |
| 1 | span_emitter.py | ✅ DONE |
| 2 | stage1_provenance.py + stage1_mcp_skill_scanner.py | 🔄 CURRENT |
| 3 | stage2_mcp_registration.py | ⬜ |
| 4 | stage3_causal_authorization.py | ⬜ |
| 5 | stage4_semantic_scope.py | ⬜ |
| 6 | stage4b_output_validation.py | ⬜ |
| 7 | policies/ + stage5_cedar_policy.py | ⬜ |
| 8 | pipeline.py + test_pipeline.py | ⬜ |
| 9 | simulate/ + README.md + CI | ⬜ |

---

## Architecture Decisions — Final

1. No HMAC — AGNTCY Agent Badge (W3C VC, RS256) is the Policy Root
2. Badge verification is permissionless — no IdP at verify time
3. Stage 0 is load-bearing for Glassworm — not optional
4. allowlist.json = trust registry only — not threat intel
5. OSV replaces hardcoded malicious lists — live feed, no stale data
6. Stage 4b is novel — no existing framework validates tool output
7. Feedback loop runs through OTel — detection → span → Cedar update
8. Cedar hot-reloads — policies/dynamic/ watched by FileSystemWatcher
9. Two OTel hooks — on_start() pre-execution, on_end() Stage 4b
