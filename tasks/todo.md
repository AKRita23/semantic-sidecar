# tasks/todo.md — Semantic Sidecar v3

## Current Session: 9
**Build:** simulate/ + README.md + CI
**Status:** 🔄 CURRENT

---

## Session Queue

| # | File | Status |
|---|---|---|
| 0 | stage0_unicode_scan.py | ✅ DONE (22 tests) |
| 1 | span_emitter.py | ✅ DONE (27 tests) |
| 2 | stage1_provenance.py + stage1_mcp_skill_scanner.py | ✅ DONE (68 tests) |
| 3 | stage2_mcp_registration.py + badges/allowlist.json | ✅ DONE (50 tests) |
| 4 | stage3_causal_authorization.py | ✅ DONE (28 tests) |
| 5 | stage4_semantic_scope.py | ✅ DONE (23 tests) |
| 6 | stage4b_output_validation.py | ✅ DONE (34 tests) |
| 7 | policies/ + stage5_cedar_policy.py | ✅ DONE (30 tests) |
| **8** | pipeline.py + test_pipeline.py | ✅ DONE (28 tests) |
| 9 | simulate/ + README.md + CI | 🔄 CURRENT |

**Total passing: 310/310**

---

## Session 8 Design Notes

### SANDWORM_MODE scenario package name
Session 8 SANDWORM_MODE pipeline test uses `package_name="claude-code"`.
Detection path: stage1_mcp_skill_scanner.scan_mcp_package("claude-code", ...)
→ Levenshtein distance 1 from "@anthropic-ai/claude-code" in KNOWN_MCP_PACKAGES
→ WARN "typosquat_suspected"
(allowlist.json remains trust registry only — no malicious list)

### Expected pipeline output (Six+ Red Lights)
```
[STAGE 0]  Unicode scan      → BLOCK | glassworm_mcp.js: 8 invisible codepoints
[STAGE 1a] npm provenance    → WARN  | suport-color: no sigstore attestation
[STAGE 1a] OSV advisory      → WARN  | claude-code: found in OSV database
[STAGE 1b] MCP scanner       → WARN  | claude-code: typosquat distance 1 from @anthropic-ai/claude-code
[STAGE 2]  MCP registration  → BLOCK | ~/.dev-utils/mcp-server.js: suspicious path
[STAGE 3]  Causal auth       → BLOCK | task_id expired 47h ago (orphaned action)
[STAGE 4]  Semantic scope    → BLOCK | ~/.ssh/id_rsa outside declared scope
[STAGE 4b] Output validation → BLOCK | response contains injection phrase
[STAGE 5]  Cedar policy      → BLOCK | credential_access_denied
```

---

## v3 Architecture Changes (from v2)

- allowlist.json = trust registry only (no malicious lists)
- OSV database replaces hardcoded malicious lists (live feed)
- Stage 4b added: output validation, novel contribution
- Cedar hot-reload via FileSystemWatcher on policies/dynamic/
- Feedback loop: OTel span → SIEM → Cedar policy update

---

## Open Questions

- [ ] Stage 9: README demo — record terminal output or script it?
- [ ] Stage 9: GitHub Actions CI — Python 3.9 + 3.11 matrix?
