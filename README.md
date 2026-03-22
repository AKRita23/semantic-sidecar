# Semantic Sidecar

A Python security research POC that detects SANDWORM_MODE and Glassworm MCP
supply-chain attacks on developer workstations in real time.

---

## What This Is

MCP (Model Context Protocol) servers run as local processes with access to your
filesystem, network, and credentials. The sidecar intercepts every tool call and
validates it against a stack of detection layers before the result reaches the
model's context window.

This is a research prototype demonstrating that a multi-layer, observable
detection stack can catch both the SANDWORM_MODE attack chain (including the
48-hour delayed activation technique) and Glassworm steganographic payloads.

---

## The Two Attacks

### SANDWORM_MODE
A supply-chain attack via MCP typosquatting with delayed activation:

1. Attacker publishes `claude-code` (vs `@anthropic-ai/claude-code`) to npm
2. Package includes a post-install hook that drops a rogue binary on the developer's machine
3. MCP server is installed by a developer who misreads the package scope
4. Server registers from a suspicious path (`~/.dev-utils/mcp-server.js`)
5. Server waits 48 hours — outlasting any human-authorized task window
6. After expiry, server reads `~/.ssh/id_rsa` and exfiltrates it
7. Tool response contains an injection phrase to redirect the model

The sidecar fires at every step: **six red lights, all independent**.

First reported by Socket and analyzed in depth by Endor Labs (February 2026).

### Glassworm
`@iflow-mcp/watercrawl-watercrawl-mcp` delivered MCP servers containing
invisible Unicode variation selectors (U+FE00–FE0F, U+E0100–E01EF) in source
files. The codepoints encode a steganographic payload that an eval()-capable
runtime can decode and execute.

Stage 0 catches this at **server load time**, before any tool is ever called.

Documented by Aikido Security (March 2026).

---

## Detection Stack

| Stage  | Layer  | Check                           | Verdict    |
|--------|--------|---------------------------------|------------|
| 0      | Stage0 | Invisible Unicode scan          | BLOCK/PASS |
| 1a     | L1     | npm sigstore provenance         | WARN/PASS  |
| 1a     | L1     | OSV vulnerability database      | WARN/PASS  |
| 1b     | L1     | Typosquat + MCP skill scanner   | WARN/PASS  |
| 2      | L0.5   | MCP registration integrity      | BLOCK/PASS |
| 3      | L2     | Causal authorization (AGNTCY)   | BLOCK/PASS |
| 4      | L2b    | Semantic scope assertion        | BLOCK/PASS |
| 4b     | L2b    | Output validation               | BLOCK/PASS |
| 5      | L3     | Cedar policy (unconditional)    | BLOCK/PASS |

**Stages 1a/1b are advisory (WARN).** Stages 0, 2, 3, 4, 4b, 5 are hard gates
(BLOCK halts delivery of the tool result to the model).

**Stage 5 always runs.** It is the deterministic floor. Even if stages 0–4b all
PASS, Cedar evaluates the resource access independently with no timing dependency.

---

## Quick Start

```bash
git clone <repo>
cd semantic-sidecar
pip install -r requirements.txt

# Run the demo (three scenarios, fully offline)
python simulate/run_demo.py

# Run the test suite
pytest tests/ -v
```

Expected demo output:

```
SCENARIO 1: SANDWORM_MODE (supply-chain + 48h delayed activation)
──────────────────────────────────────────────────────────────────────
[STAGE 0]  Unicode scan      → BLOCK | glassworm_mcp_server.js: 8 invisible codepoints
[STAGE 1a] npm provenance    → WARN  | claude-code: no_provenance_attestation
[STAGE 1a] OSV advisory      → WARN  | claude-code: found in OSV database
[STAGE 1b] MCP scanner       → WARN  | claude-code: typosquat distance 0 from @anthropic-ai/claude-code
[STAGE 2]  MCP registration  → BLOCK | ~/.dev-utils/mcp-server.js: suspicious_path
[STAGE 3]  Causal auth       → BLOCK | task_id expired 47h ago (orphaned action)
[STAGE 4]  Semantic scope    → BLOCK | /home/user/.ssh/id_rsa outside declared scope
[STAGE 4b] Output validation → BLOCK | output_injection_phrase
[STAGE 5]  Cedar policy      → BLOCK | sandworm_mode:deny_ssh_access
```

---

## Live OTel Traces (Optional)

To see `security.*` spans flow into a real trace backend:

```bash
pip install ioa_observe_sdk
git clone https://github.com/agntcy/observe.git
cd observe/deploy && docker compose up -d
cd ../..
export OTLP_HTTP_ENDPOINT=http://localhost:4318
PYTHONPATH=. python simulate/run_demo.py
```

Query detections in ClickHouse:

```bash
docker exec -it clickhouse-server clickhouse-client --query \
"SELECT SpanAttributes['security.layer'] AS layer,
        SpanAttributes['security.verdict'] AS verdict,
        SpanAttributes['security.detection_type'] AS detection,
        SpanAttributes['security.observed_scope'] AS observed_scope,
        SpanAttributes['gen_ai.task.requester'] AS requester
 FROM otel_traces
 WHERE SpanAttributes['security.verdict'] = 'BLOCK'
 ORDER BY Timestamp ASC FORMAT Pretty"
```

---

## Running Tests

```bash
# Full suite
pytest tests/ -v --tb=short

# Single stage
pytest tests/test_stage0.py -v
pytest tests/test_pipeline.py -v

# Demo tests only
pytest tests/test_demo.py -v
```

The test suite is fully offline. All external dependencies (npm registry, OSV,
AGNTCY identity service, Cedar SDK) are replaced with injectable stubs. No
network access required.

---

## Architecture

```
simulate/run_demo.py          ← demo entry point (offline, stubs only)
sidecar/
  pipeline.py                 ← orchestrates all stages; PipelineInput/PipelineResult
  stage0_unicode_scan.py      ← U+FE00-FE0F + U+E0100-E01EF codepoint scan
  stage1_provenance.py        ← npm sigstore + OSV advisory (WARN only)
  stage1_mcp_skill_scanner.py ← typosquat, postinstall, badge, injection patterns
  stage2_mcp_registration.py  ← allowlist + AGNTCY MCP Server Badge (hard BLOCK)
  stage3_causal_authorization.py ← AGNTCY Agent Badge as Policy Root (hard BLOCK)
  stage4_semantic_scope.py    ← psutil filesystem + mitmproxy network scope
  stage4b_output_validation.py ← output scanning before model context injection
  stage5_cedar_policy.py      ← Cedar policy: deterministic floor
  span_emitter.py             ← OTel span emission (every stage)
policies/
  sandworm_mode.cedar         ← credential access + network egress deny rules
  output_validation.cedar     ← tool response injection deny rules
  dynamic/                    ← hot-reload directory (PolicyWatcher)
badges/
  allowlist.json              ← trust registry for verified MCP servers
tests/
  fixtures/
    glassworm_mcp_server.js   ← real U+FE00 codepoints for Stage 0 tests
    clean_mcp_server.js       ← clean baseline for PASS tests
```

### Key design choices

**Stub/Real pattern everywhere.** Every external dependency has an abstract
interface and a stub implementation. Tests use stubs; production swaps to
real implementations with a one-line change:

```python
# Test
verifier = StubBadgeVerifier(allowlist)

# Production
verifier = AgntcyBadgeVerifier()
```

**Injectable dependencies.** `get_open_files`, HTTP sessions, badge verifiers,
and Cedar evaluators are all injected at call sites. No module-level imports of
psutil, mitmproxy, or network clients.

**Badge data flows forward.** Stage 2 PASS extracts `capabilities`,
`declared_scope`, and `declared_destinations` from the AGNTCY MCP Server Badge.
These flow to Stage 4 (scope enforcement) and Stage 4b (output validation).
Stage 2 BLOCK → empty lists → maximum conservative enforcement downstream.

**All findings before verdict.** Stages 4 and 4b collect all violations before
deciding the verdict. A single tool call with a scope violation AND an injection
phrase records both findings. The SIEM gets complete evidence, not just the first
hit.

---

## Observability

Every detection decision emits an OTel-compatible span via `emit_detection_span()`.

Span fields emitted on every stage:

```
trace_id, span_id, stage, layer, verdict, detection_type, evidence
```

Stage 4 additionally emits five security fields on every span (including PASS):

```
security.tool_description_hash
security.declared_scope
security.observed_scope
security.declared_destinations
security.observed_egress
```

These fields are the **AGNTCY upstream OTel contribution**: the behavioral
snapshot of every MCP tool invocation, regardless of verdict. A SIEM baseline
is built from PASS spans; anomaly detection fires when observed behavior diverges
from declared behavior.

---

## AGNTCY Integration

This POC uses two AGNTCY identity constructs:

**AGNTCY MCP Server Badge** (Stage 2)
A W3C Verifiable Credential (RS256) that carries `declared_capabilities`,
`declared_scope`, and `declared_destinations`. Verification is permissionless —
no IdP required at verify time. The badge IS the trust anchor.

```bash
# Verify a badge offline
identity badge verify did:agntcy:mcp:lint-checker-v1.2
```

**AGNTCY Agent Badge** (Stage 3)
A W3C Verifiable Credential (RS256) that encodes a human-authorized task.
`authorized_by` carries the identity from the IdP; `permitted_tools` is the
capability grant; `expires_at` is the authorization window.

The 48-hour SANDWORM_MODE delay is caught because the task window (`expires_at`)
expires long before the attack fires. No HMAC, no separate signing. The badge
IS the Policy Root.

---

## Contributing / Upstream Proposals

This POC surfaces three concrete proposals for upstream standardization:

1. **OTel semantic conventions for MCP tool calls.** The five `security.*`
   fields emitted by Stage 4 should be standardized so SIEM tools can consume
   them without custom parsers.

2. **AGNTCY MCP Server Badge schema.** `declared_scope` and
   `declared_destinations` are currently implementation-specific. Standardizing
   these fields would allow cross-vendor scope enforcement.

3. **Cedar policy profiles for MCP.** The Cedar policies in `policies/` are
   minimal but correct. A Cedar policy profile for MCP resource types
   (`MCPServer`, `Action::"file_read"`, `Action::"network_egress"`) would let
   organizations compose policies across tools.

