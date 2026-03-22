"""
sidecar/stage1_provenance.py — Stage 1a: npm Provenance Check

Catches: Packages without sigstore provenance attestation (SANDWORM_MODE delivery),
         packages with known CVEs in the OSV database.

Verdict: WARN only — never BLOCK (too many false positives; Stage 2 is the hard gate)
Network failure: PASS — advisory checks do not block on connectivity issues
No hardcoded malicious lists: OSV database is the live feed (already contains
SANDWORM_MODE and Glassworm entries, community-maintained, near-real-time)

OTel span emitted on WARN only.
"""

import json

import requests

from sidecar.span_emitter import emit_detection_span


def check_npm_provenance(package_name: str, _session=None) -> dict:
    """
    GET https://registry.npmjs.org/{package} and check for sigstore provenance.

    Provenance is signaled by any of:
      dist.attestations  — npm 9+ provenance format
      dist.signatures    — older sigstore format
      _attestations      — package-level attestation field

    Args:
        package_name: npm package name, scoped (e.g. "@scope/name") or plain.
        _session:     Injected requests.Session for testing; creates one if None.

    Returns:
        {"verdict": "WARN"|"PASS", "reason": str, "evidence": dict}
    """
    session = _session or requests.Session()
    url = f"https://registry.npmjs.org/{_encode_package(package_name)}"

    try:
        resp = session.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {
            "verdict": "PASS",
            "reason": "network_unavailable",
            "evidence": {"package": package_name, "network_error": True, "error": str(exc)},
        }

    latest = data.get("dist-tags", {}).get("latest")
    if not latest:
        evidence = {"package": package_name}
        result = {"verdict": "WARN", "reason": "no_latest_version", "evidence": evidence}
        _emit_warn(result)
        return result

    dist = data.get("versions", {}).get(latest, {}).get("dist", {})
    has_provenance = bool(
        dist.get("attestations")
        or dist.get("signatures")
        or data.get("_attestations")
    )

    if not has_provenance:
        evidence = {"package": package_name, "version": latest, "has_provenance": False}
        result = {"verdict": "WARN", "reason": "no_provenance_attestation", "evidence": evidence}
        _emit_warn(result)
        return result

    return {
        "verdict": "PASS",
        "reason": "provenance_verified",
        "evidence": {"package": package_name, "version": latest, "has_provenance": True},
    }


def check_osv(package_name: str, version: str = None, _session=None) -> dict:
    """
    POST https://api.osv.dev/v1/query for known vulnerabilities in the npm ecosystem.

    Args:
        package_name: npm package name.
        version:      Specific version to query; omit to query all versions.
        _session:     Injected requests.Session for testing.

    Returns:
        {"verdict": "WARN"|"PASS", "reason": str, "evidence": dict}
        evidence.vulnerability_ids is capped at 5 entries.
    """
    session = _session or requests.Session()
    body = {"package": {"name": package_name, "ecosystem": "npm"}}
    if version is not None:
        body["version"] = version

    try:
        resp = session.post("https://api.osv.dev/v1/query", json=body, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {
            "verdict": "PASS",
            "reason": "network_unavailable",
            "evidence": {"package": package_name, "network_error": True, "error": str(exc)},
        }

    vulns = data.get("vulns", [])
    if vulns:
        evidence = {
            "package": package_name,
            "vulnerability_count": len(vulns),
            "vulnerability_ids": [v.get("id") for v in vulns[:5]],
        }
        result = {"verdict": "WARN", "reason": "known_vulnerabilities", "evidence": evidence}
        _emit_warn(result)
        return result

    return {
        "verdict": "PASS",
        "reason": "no_known_vulnerabilities",
        "evidence": {"package": package_name, "vulnerability_count": 0},
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _encode_package(name: str) -> str:
    """URL-encode scoped package names so @scope/pkg hits the correct endpoint."""
    return name.replace("/", "%2F") if name.startswith("@") else name


def _emit_warn(result: dict) -> None:
    """Emit OTel span for WARN verdicts only."""
    if result["verdict"] == "WARN":
        emit_detection_span(
            stage=1,
            layer="Stage1a",
            verdict=result["verdict"],
            detection_type=result["reason"],
            evidence=result["evidence"],
        )
