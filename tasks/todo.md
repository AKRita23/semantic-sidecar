# tasks/todo.md — Semantic Sidecar v3

## Current Session: 2
**Build:** stage1_provenance.py + stage1_mcp_skill_scanner.py
**Status:** 🔄 CURRENT

---

## Session Queue

| # | File | Status |
|---|---|---|
| 0 | stage0_unicode_scan.py | ✅ DONE (22 tests) |
| 1 | span_emitter.py | ✅ DONE (27 tests) |
| **2** | stage1_provenance.py + stage1_mcp_skill_scanner.py | ✅ DONE (68 new tests; 117 total) |
| 3 | stage2_mcp_registration.py + badges/allowlist.json | ✅ DONE (50 new tests; 167 total) |
| 4 | stage3_causal_authorization.py | ⬜ |
| 5 | stage4_semantic_scope.py | ⬜ |
| 6 | stage4b_output_validation.py | ⬜ NEW |
| 7 | policies/ + stage5_cedar_policy.py | ⬜ |
| 8 | pipeline.py + test_pipeline.py | ⬜ |
| 9 | simulate/ + README.md + CI | ⬜ |

---

## v3 Architecture Changes (from v2)

- allowlist.json = trust registry only (no malicious lists)
- OSV database replaces hardcoded malicious lists (live feed)
- Stage 4b added: output validation, novel contribution
- Cedar hot-reload via FileSystemWatcher on policies/dynamic/
- Feedback loop: OTel span → SIEM → Cedar policy update

---

## Open Questions

- [ ] Stage 3: confirm agntcy-identity Python SDK install path
- [ ] Stage 3: identity-service TBAC — Docker needed or can stub?
- [ ] Stage 5: mitmproxy transparent proxy on macOS arm64
- [ ] Stage 5: psutil race condition mitigation strategy
- [ ] Stage 4b: how to intercept tool output before model receives it?
      Need to confirm MCP protocol hook point for on_end()
