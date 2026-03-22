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

**Up next — Session 9: simulate/ + README.md + CI**

### Session 8 — sidecar/pipeline.py + tests/test_pipeline.py

**PipelineInput dataclass bundles all stage inputs; PipelineResult captures all outputs.**
run_pipeline() orchestrates all five stages. Stage 5 always runs — it is the unconditional
floor. BLOCK from prior stages does not short-circuit. Every layer's decision is captured.

**Badge data flows Stage 2 → Stage 4 / 4b.**
If Stage 2 PASS: badge.capabilities, badge.declared_scope, badge.declared_destinations
forwarded to Stage 4 (semantic scope) and Stage 4b (output validation).
If Stage 2 BLOCK: downstream stages receive empty lists — most conservative behavior
(every open file and every connection is a violation).

**"claude-code" (unscoped) removed from KNOWN_MCP_PACKAGES — it is a scope-squat.**
The real package is "@anthropic-ai/claude-code". Leaving "claude-code" in the list
made the guard (`if min_dist == 0 and package_name == closest`) fire, preventing
scope-squat detection. Removing it allows "claude-code" → typosquat distance 0 from
"@anthropic-ai/claude-code" via basename comparison — correctly flagged as WARN.
Three existing tests updated to reflect this: test_claude_code_in_list →
test_anthropic_claude_code_scoped_in_list; test_exact_legitimate_package renamed to
test exact match on "supports-color"; test_distance_1 updated (closest is now the scoped name).

**format_summary() produces the Nine-line demo output.**
One line per detection point: [STAGE 0] through [STAGE 5] (two 1a lines).
Callers can print result.format_summary() for the Six+ Red Lights demo.
PipelineResult.blocks() and .warns() return stage label lists for programmatic use.

**Injectable sessions, verifiers, evaluators, get_open_files throughout.**
All external dependencies injectable in tests. No mocking at module level required.
Same pattern established in Sessions 1-7 applies uniformly to the pipeline.

**28 tests: 17 SANDWORM_MODE scenario, 3 clean/PASS, 2 Cedar unconditional, 6 helpers.**
Total: 310/310 across all sessions.

### Session 7 — policies/ + stage5_cedar_policy.py

**Cedar Python package is `cedarpy`, not `cedar-policy`.**
`pip install cedarpy` (pre-built wheels available for older versions).
cedarpy 4.x requires Cargo edition2024 to build from source — use 0.4.1 wheel.
cedarpy 0.4.1 wheel for cp39-macosx_arm64 installs cleanly but has a Python/Rust
ABI mismatch (Python wrapper passes List[dict]; Rust backend expects something else).
Graceful degradation to StubCedarEvaluator on any exception — correct behavior.

**StubCedarEvaluator implements Cedar policy semantics in Python — no SDK in tests.**
Same stub/real pattern as Stages 2 and 3. Tests use StubCedarEvaluator directly.
RealCedarEvaluator wraps cedarpy.is_authorized() with try/except ImportError and
except Exception fallback to stub. Swap = one line: evaluator=RealCedarEvaluator().

**_cedar_path_matches: split on ** then re.escape each segment, join with .*.**
`pattern.split("**")` → escape each part → join with `.*` → re.fullmatch.
This correctly converts `/home/**/.ssh/**` to regex `/home/.*/.\\ssh/.*`.
Single `*` within a segment uses `[^/]*` (no path separators). Not needed for
the current patterns but correct if added.

**PolicyWatcher uses threading.Event.wait(timeout=N) — not time.sleep().**
`_stop_event.wait(timeout=poll_interval)` returns immediately when stop() signals.
`time.sleep(N)` would hang the thread for N seconds after stop() is called.
The Event pattern allows sub-second test teardown. Tests call _check_for_updates()
directly without starting the background thread — synchronous and deterministic.

**Reasons list tells the SIEM which policy fired, not just that something fired.**
`"sandworm_mode:deny_ssh_access"`, `"output_validation:deny_injection_phrase"` etc.
SIEM can route ssh-access violations differently than injection-phrase violations.
All reasons collected (no short-circuit) — tool_response with both flags gets 2 reasons.

**Cedar always runs — unconditional floor even when all prior stages PASS.**
Test: inject prior_stage_verdicts=["PASS"]*5 into context. Cedar still evaluates.
This is the key L3 property: no timing dependency, no race conditions from L2b.

**30 tests: 5 BLOCK paths, 2 PASS paths, 3 network egress, 3 tool_response, 2 stub unit,
2 PolicyWatcher (detect + stop), 4 OTel spans, cedar_always_runs, swap, 2 dataclasses,
3 reasons names, multiple_reasons. requirements.txt: cedar-policy → cedarpy>=4.1.0.
Total: 282/282 across all sessions.**

### Session 6 — stage4b_output_validation.py

**Two tool call directive detection mechanisms cover both cases.**
String pattern scan (regex on extracted strings — catches <tool_call> XML and
JSON-string tool_call keys) plus dict key inspection (_find_tool_call_keys walks
the output tree). String-only patterns miss {"tool_call": {...}} when the key
is a Python dict key, not a JSON string. Both must run.

**Verdict precedence: BLOCK > WARN > PASS, collected across all findings.**
BLOCK types: output_injection_phrase, output_tool_call_directive, output_invisible_unicode.
WARN types: output_base64_blob, output_size_anomaly.
Collect ALL findings first. Check for any BLOCK type. Fall through to WARN.
Never short-circuit — both findings should appear for mixed BLOCK+WARN output.

**_extract_strings exported for direct unit testing.**
Critical recursive helper: str/dict/list/nested. Testing it directly avoids
constructing complex payloads. Non-string leaves (int, bool, None) silently skipped.

**stage0 scan_for_invisible_unicode is the Glassworm-in-response integration point.**
Reusing stage0 avoids duplicating codepoint range logic. Novel: Glassworm codepoints
delivered via tool RESPONSE, not just server source. Stage 0 catches at load time;
Stage 4b catches in runtime output.

**Base64 threshold: match run ≥ 100 chars via regex `[A-Za-z0-9+/]{100,}={0,2}`.**
Not string length — the consecutive base64 run must be ≥ 100. SHA-256 hex digests
and short encoded values pass cleanly.

**34 tests: clean str/dict, 5 injection phrases, nested injection, tool_call key/XML/nested,
invisible unicode, base64 warn, size warn, multiple findings, BLOCK>WARN, SANDWORM output,
OTel fields, _extract_strings x5, output_size_bytes, custom threshold.
Total: 252/252 across all sessions.**

### Session 5 — stage4_semantic_scope.py

**Bind Stage 4 OTel field names from SECURITY_FIELDS[:5] — no string literals.**
`(_F_HASH, _F_DECL_SCOPE, _F_OBS_SCOPE, _F_DECL_DEST, _F_OBS_EGRESS) = SECURITY_FIELDS[:5]`
at module level. If span_emitter renames a field, stage4 picks it up automatically.
The field registry in span_emitter is the single source of truth.

**security_fields always populated regardless of verdict — observability, not just enforcement.**
All five Stage 4 fields (hash, declared_scope, observed_scope, declared_destinations,
observed_egress) are populated in every span. This is the AGNTCY upstream OTel
contribution: even a clean PASS carries the full behavioral snapshot.

**Injectable get_open_files breaks psutil dependency at test time.**
`_default_get_open_files` imports psutil INSIDE the function body, not at module level.
Tests pass a stub lambda. No psutil install required to run the test suite.
Same pattern applies to mitmproxy — never imported at module level.

**Package attribute must be restored alongside sys.modules after module-deletion tests.**
`patch("sidecar.stage4_semantic_scope.emit_detection_span")` resolves via
`getattr(sidecar_pkg, "stage4_semantic_scope")`, NOT via sys.modules lookup alone.
When a test reimports the module (creating M2) and restores sys.modules to the
original (M), it must ALSO set `sidecar.stage4_semantic_scope = M` on the package
object or subsequent patches will land on M2.__dict__ while check_semantic_scope
reads from M.__dict__ — mock called 0 times, test fails silently.

**Empty declared_scope / declared_destinations = "no access declared" — all observed = violation.**
An MCP server that declared no filesystem or network access has every open file and
every connection as a violation. This is the correct semantics, not a bug.

**23 tests: hash match/mismatch, file in/out scope, multiple violations, network scope,
all 5 OTel fields, SANDWORM_MODE scenario, injectable mock, no-psutil, no-mitmproxy,
module restore, empty scope, missing hash, empty-string hash, psutil not called.
Total: 218/218 across all sessions.**

### Session 4 — stage3_causal_authorization.py

**Separate badge verification (at registration) from authorization check (at invocation).**
register_task_from_badge() verifies the AGNTCY Agent Badge once and populates a
TaskContext into the registry. check_causal_authorization() trusts the registry —
no badge I/O on every tool call. This keeps the hot path cheap and testable.

**TaskRegistry.is_valid() is the single expiry check location.**
Both check_causal_authorization() and external callers use is_valid(). Avoids
duplicating the expires_at < now comparison. Tests call is_valid() directly
to verify boundary behavior without going through the full auth check.

**Four detection types map to four distinct BLOCK reasons.**
orphaned_action_no_task_id / orphaned_action_unknown_task_id /
orphaned_action_expired_task / orphaned_action_unauthorized_tool.
Each type tells the SIEM a different story — don't collapse them.

**Expired task test: use datetime.now(UTC) ± timedelta, never hardcoded timestamps.**
test_task_expired_47h_ago_blocks() creates a task issued 47h ago valid for 1h,
then asserts expires_at < now() as a precondition. Tests remain valid regardless
of when they run.

**gen_ai.task.requester = "model_autonomous" on all BLOCK spans.**
Orphaned actions have no known human requester by definition. "model_autonomous"
signals to the SIEM that the action was not traceable to a human authorization —
the right trigger for alert escalation.

**28 tests: all four BLOCK conditions, PASS, registry expiry, span fields,
register_task_from_badge valid/invalid, one-line swap assertion, evidence fields.**

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
