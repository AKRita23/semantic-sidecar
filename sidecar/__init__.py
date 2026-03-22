# sidecar/__init__.py
"""
Semantic Sidecar — MCP supply chain attack detection and enforcement.

Five-layer pipeline:
  Stage 0: Pre-load Unicode scan (Glassworm)
  Stage 1: npm provenance check (advisory)
  Stage 2: MCP registration integrity via AGNTCY MCP Server Badge (W3C VC, RS256)
  Stage 3: Causal authorization via AGNTCY Agent Badge (W3C VC, RS256) + Cedar
  Stage 4: Semantic scope assertion (psutil + mitmproxy + tool_description_hash)
  Stage 5: Cedar policy hard boundary (unconditional)

AGNTCY identity repo: https://github.com/agntcy/identity
AGNTCY observe repo:  https://github.com/agntcy/observe
"""

__version__ = "0.1.0"
