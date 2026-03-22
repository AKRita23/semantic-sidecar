# tasks/lessons.md

## Architecture Corrections (Pre-Build)

These were resolved before coding started. Do not reopen them.

**HMAC removed:** Early drafts used HMAC-signed Policy Roots for causal authorization.
This was wrong. The AGNTCY Agent Badge (W3C VC, RS256) already carries capability
attestation and causal authorization. Badge verification is permissionless — no IdP
needed at verify time. Okta is a trusted issuer, not a verification dependency.

**L0 (hardware attestation) dropped:** Does not apply to developer workstations or
open source contributor machines. GhostAction used a legitimate GitHub runner —
hardware attestation would have passed. L2 catches it (no authorized task for the
malicious workflow).

**GhostAction remapped L0 → L2:** Not a rogue runner attack. Attacker pushed malicious
workflow via compromised dev account. Legitimate runner executed it. L2 (no Policy Root
for "read PYPI_API_TOKEN and POST externally") is the correct catch layer.

**Glassworm is co-equal, not adjacent:** @iflow-mcp/watercrawl-watercrawl-mcp was
deliberately MCP-targeted. Stage 0 is load-bearing, not optional.

---

## Session Learnings

*(populated after each session)*

## Session Learnings

**Session 0 — stage0_unicode_scan.py**
- Fixture files must embed real codepoint bytes, not language-level escape sequences.
  Python reads `\ufe00` in a JS file as literal backslash-u-f-e-0-0, not the codepoint.
  Fix: write actual U+FE00–FE07 bytes directly into the fixture file.
- 22 tests: happy path, both codepoint ranges, boundary values, glassworm fixture,
  position tracking, OTel span field verification, graceful degradation.
- Deliverables: stage0_unicode_scan.py, tests/test_stage0.py,
  tests/fixtures/glassworm_mcp_server.js (fixed with real bytes).

**Up next — Session 1: sidecar/span_emitter.py**

**Session 1 — sidecar/span_emitter.py**
- Closed field registry (_SECURITY_FIELDS_SET) prevents schema drift at call sites —
  unknown keys rejected at emit time, not silently dropped.
- Lazy tracer instantiation inside the function (not at module import time) keeps
  tests mockable without module reloads. Critical for isolated stage testing.
- emit_detection_span() is the single entry point for all stages — core fields +
  optional tool_name/task_id + Stage-4 scope fields via security_fields dict.
- List values for scope fields JSON-serialized (declared_scope, observed_scope etc.)
- Graceful degradation when OTel unavailable — stages work in isolation.
- 27 tests: constants, core fields, optional fields, security_fields dict,
  unknown key rejection, span naming, graceful degradation x2, stage0 smoke x3.
- Total: 49/49 across sessions 0+1.

### Session 3 — stage2_mcp_registration.py + badges/allowlist.json

**BadgeVerifier ABC enables one-line production swap without touching any other code.**
StubBadgeVerifier(allowlist) for testing, AgntcyBadgeVerifier() for production.
Both inherit BadgeVerifier and return BadgeResult. verify_mcp_registration() takes
`verifier=` parameter — swap target is a single argument at the call site.

**Five checks run in cost order, fastest first.**
Suspicious path (string prefix, O(n patterns)) → allowlist lookup (fnmatch) →
hash compare (string equality) → badge verify (network/SDK) → capability check (set
membership). Cheaper checks short-circuit before expensive ones.

**badge_valid in evidence differentiates two BLOCK reasons at check 5.**
When a tool is unauthorized but the badge itself was valid, badge_valid=True in the
BLOCK result. Upstream code (pipeline, SIEM) needs to distinguish "bad server" from
"valid server attempting unauthorized tool" for different response actions.

**SHA-256 entry with empty string skips hash check — intentional design.**
A newly added server may not have its hash computed yet. Empty sha256 field means
"hash not yet recorded" and skips the check rather than blocking everything. The
badge check provides the integrity guarantee in that window.

**allowlist.json = trust registry, not threat intel (v3 architecture).**
Removed known_malicious_packages from allowlist.json. v3 separates concerns:
allowlist is human-signed, static, changes only when a verified server is added.
OSV (stage1_provenance) is the live threat feed. Mixing them creates stale data risk.

**Up next — Session 4: sidecar/stage3_causal_authorization.py**

### Session 2 — stage1_provenance.py + stage1_mcp_skill_scanner.py

**Implementation files can silently disappear between sessions.**
Sessions 0 and 1 wrote stage0_unicode_scan.py and span_emitter.py; they
were confirmed written but were missing at session 2 start. Always verify
all prior implementation files exist before starting a new session. Use
`find . -name "*.py" | sort` at session start.

**Two distinct questions = two distinct modules.**
stage1_provenance.py answers "did this come from where it claims?" (registry
attestation + OSV). stage1_mcp_skill_scanner.py answers "is it safe for
agentic use?" (postinstall behavior + Unicode + badge + typosquat + injection
patterns). Mixing them would make both harder to test in isolation.

**PASS on network failure is non-negotiable for advisory checks.**
Both provenance checks wrap every network call in try/except and return PASS
on any exception. Advisory stages cannot block developer workflow due to
connectivity issues — Stage 2 is the hard gate.

**Postinstall + config path reference = WARN; config path alone = not flagged.**
A JS file referencing ~/.config/Claude/ is not suspicious by itself
(could be documentation). The attack pattern requires BOTH: a postinstall
script AND source files referencing those paths. The two conditions are
ANDed in _find_config_refs only executing when postinstall is present.

**Levenshtein distance 0 guard needs full-name comparison, not just distance.**
Scope squatting: @evil/claude-code has basename distance 0 from claude-code.
The guard `if min_dist == 0 and package_name == closest: return None` correctly
lets scope squats (same basename, different scope) through as WARN distance=0.

**Native Wagner-Fischer edit distance removes the python-levenshtein dependency.**
python-levenshtein was in requirements.txt but not installed. 12-line
native implementation is cleaner for a POC and removes an install-time risk.
