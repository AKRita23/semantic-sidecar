"""
tests/test_demo.py — Smoke tests for simulate/run_demo.py

Verifies:
  - Module imports without error
  - SANDWORM_MODE scenario returns BLOCK on at least one stage
  - Glassworm scenario returns BLOCK on at least one stage
  - Clean pass scenario returns no BLOCKs
  - SANDWORM_MODE output contains "BLOCK"
  - Script exits 0 when invoked as __main__
"""

import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import smoke test
# ---------------------------------------------------------------------------

def test_run_demo_imports_without_error():
    """simulate/run_demo.py must import cleanly with no side effects."""
    import simulate.run_demo  # noqa: F401


# ---------------------------------------------------------------------------
# Scenario return value tests
# ---------------------------------------------------------------------------

def test_sandworm_scenario_returns_block():
    from simulate.run_demo import run_sandworm_scenario
    result = run_sandworm_scenario()
    assert len(result.blocks()) > 0, "SANDWORM_MODE should produce at least one BLOCK"


def test_glassworm_scenario_returns_block():
    from simulate.run_demo import run_glassworm_scenario
    result = run_glassworm_scenario()
    assert len(result.blocks()) > 0, "Glassworm scenario should produce at least one BLOCK"


def test_clean_scenario_returns_pass():
    from simulate.run_demo import run_clean_scenario
    result = run_clean_scenario()
    assert len(result.blocks()) == 0, "Clean pass should not produce any BLOCKs"


# ---------------------------------------------------------------------------
# Output content test
# ---------------------------------------------------------------------------

def test_sandworm_summary_contains_block():
    from simulate.run_demo import run_sandworm_scenario
    result = run_sandworm_scenario()
    summary = result.format_summary()
    assert "BLOCK" in summary, "format_summary() should contain 'BLOCK' for SANDWORM_MODE"


# ---------------------------------------------------------------------------
# Script exit code test
# ---------------------------------------------------------------------------

def test_script_exits_zero():
    """Running simulate/run_demo.py as a subprocess should exit 0."""
    demo_path = str(Path(__file__).parent.parent / "simulate" / "run_demo.py")
    result = subprocess.run(
        [sys.executable, demo_path],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"run_demo.py exited {result.returncode}\n"
        f"stdout: {result.stdout[-500:]}\n"
        f"stderr: {result.stderr[-500:]}"
    )
