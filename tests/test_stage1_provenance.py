"""
tests/test_stage1_provenance.py — Session 2: stage1_provenance.py (Stage 1a)
npm registry provenance + OSV vulnerability checks.
"""

import unittest.mock as mock

import pytest

from sidecar.stage1_provenance import check_npm_provenance, check_osv


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _npm_resp(package_name="supports-color", latest="9.4.0",
              dist_attestations=None, dist_signatures=None, pkg_attestations=None):
    dist = {"tarball": f"https://example.com/{package_name}.tgz"}
    if dist_attestations is not None:
        dist["attestations"] = dist_attestations
    if dist_signatures is not None:
        dist["signatures"] = dist_signatures
    body = {
        "name": package_name,
        "dist-tags": {"latest": latest},
        "versions": {latest: {"dist": dist}},
    }
    if pkg_attestations is not None:
        body["_attestations"] = pkg_attestations
    return body


def _mock_get(json_body=None, status=200, raises=None):
    session = mock.MagicMock()
    if raises:
        session.get.side_effect = raises
        session.post.side_effect = raises
        return session
    resp = mock.MagicMock()
    resp.json.return_value = json_body or {}
    if status >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status}")
    else:
        resp.raise_for_status.return_value = None
    session.get.return_value = resp
    return session


def _mock_post(json_body=None, status=200, raises=None):
    session = mock.MagicMock()
    if raises:
        session.post.side_effect = raises
        return session
    resp = mock.MagicMock()
    resp.json.return_value = json_body or {}
    if status >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status}")
    else:
        resp.raise_for_status.return_value = None
    session.post.return_value = resp
    return session


def _osv_resp(vuln_ids=None):
    if vuln_ids:
        return {"vulns": [{"id": v, "summary": "test"} for v in vuln_ids]}
    return {}


# ---------------------------------------------------------------------------
# check_npm_provenance
# ---------------------------------------------------------------------------

class TestCheckNpmProvenance:
    def test_dist_attestations_present_returns_pass(self):
        body = _npm_resp(dist_attestations={"url": "https://example.com/attestation"})
        result = check_npm_provenance("supports-color", _session=_mock_get(body))
        assert result["verdict"] == "PASS"
        assert result["evidence"]["has_provenance"] is True

    def test_dist_signatures_present_returns_pass(self):
        body = _npm_resp(dist_signatures=[{"keyid": "SHA256:abc", "sig": "xyz"}])
        result = check_npm_provenance("supports-color", _session=_mock_get(body))
        assert result["verdict"] == "PASS"
        assert result["evidence"]["has_provenance"] is True

    def test_pkg_level_attestations_present_returns_pass(self):
        body = _npm_resp(pkg_attestations={"url": "https://example.com"})
        result = check_npm_provenance("supports-color", _session=_mock_get(body))
        assert result["verdict"] == "PASS"

    def test_no_provenance_returns_warn(self):
        body = _npm_resp()  # no attestations or signatures
        result = check_npm_provenance("suport-color", _session=_mock_get(body))
        assert result["verdict"] == "WARN"
        assert result["reason"] == "no_provenance_attestation"
        assert result["evidence"]["has_provenance"] is False

    def test_connection_error_returns_pass(self):
        result = check_npm_provenance("pkg", _session=_mock_get(raises=ConnectionError("refused")))
        assert result["verdict"] == "PASS"
        assert result["reason"] == "network_unavailable"
        assert result["evidence"]["network_error"] is True

    def test_http_404_returns_pass(self):
        result = check_npm_provenance("nonexistent", _session=_mock_get(status=404))
        assert result["verdict"] == "PASS"
        assert result["evidence"]["network_error"] is True

    def test_no_dist_tags_returns_warn(self):
        body = {"name": "weird-pkg", "dist-tags": {}, "versions": {}}
        result = check_npm_provenance("weird-pkg", _session=_mock_get(body))
        assert result["verdict"] == "WARN"
        assert result["reason"] == "no_latest_version"

    def test_verdict_never_block(self):
        body = _npm_resp()
        result = check_npm_provenance("suport-color", _session=_mock_get(body))
        assert result["verdict"] != "BLOCK"

    def test_evidence_contains_package_name(self):
        body = _npm_resp()
        result = check_npm_provenance("suport-color", _session=_mock_get(body))
        assert result["evidence"]["package"] == "suport-color"

    def test_evidence_contains_version(self):
        body = _npm_resp(latest="9.4.0")
        result = check_npm_provenance("suport-color", _session=_mock_get(body))
        assert result["evidence"].get("version") == "9.4.0"

    def test_registry_url_called(self):
        body = _npm_resp()
        session = _mock_get(body)
        check_npm_provenance("supports-color", _session=session)
        url = session.get.call_args[0][0]
        assert "registry.npmjs.org" in url
        assert "supports-color" in url

    def test_scoped_package_url_does_not_contain_raw_slash(self):
        """@ scoped packages must be encoded so the request hits the right endpoint."""
        body = _npm_resp(package_name="@modelcontextprotocol/server-filesystem")
        session = _mock_get(body)
        check_npm_provenance("@modelcontextprotocol/server-filesystem", _session=session)
        url = session.get.call_args[0][0]
        assert "registry.npmjs.org" in url
        # The URL should either encode the slash or use the full scoped path
        assert "modelcontextprotocol" in url

    def test_warn_emits_otel_span(self):
        mock_span = mock.MagicMock()
        cm = mock.MagicMock()
        cm.__enter__ = mock.MagicMock(return_value=mock_span)
        cm.__exit__ = mock.MagicMock(return_value=False)
        mock_tracer = mock.MagicMock()
        mock_tracer.start_as_current_span.return_value = cm
        mock_trace = mock.MagicMock()
        mock_trace.get_tracer.return_value = mock_tracer

        body = _npm_resp()  # no provenance → WARN
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            result = check_npm_provenance("suport-color", _session=_mock_get(body))

        assert result["verdict"] == "WARN"
        attrs = {c[0][0]: c[0][1] for c in mock_span.set_attribute.call_args_list}
        assert attrs["security.verdict"] == "WARN"
        assert attrs["security.stage"] == 1

    def test_pass_does_not_emit_otel_span(self):
        mock_trace = mock.MagicMock()
        body = _npm_resp(dist_attestations={"url": "x"})
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            result = check_npm_provenance("supports-color", _session=_mock_get(body))
        assert result["verdict"] == "PASS"
        mock_trace.get_tracer.assert_not_called()


# ---------------------------------------------------------------------------
# check_osv
# ---------------------------------------------------------------------------

class TestCheckOsv:
    def test_known_vuln_returns_warn(self):
        session = _mock_post(_osv_resp(["GHSA-xxxx-1234-5678"]))
        result = check_osv("vulnerable-pkg", _session=session)
        assert result["verdict"] == "WARN"
        assert result["reason"] == "known_vulnerabilities"
        assert "GHSA-xxxx-1234-5678" in result["evidence"]["vulnerability_ids"]

    def test_no_vulns_returns_pass(self):
        session = _mock_post(_osv_resp())
        result = check_osv("clean-pkg", _session=session)
        assert result["verdict"] == "PASS"
        assert result["reason"] == "no_known_vulnerabilities"
        assert result["evidence"]["vulnerability_count"] == 0

    def test_network_failure_returns_pass(self):
        result = check_osv("pkg", _session=_mock_post(raises=ConnectionError("osv down")))
        assert result["verdict"] == "PASS"
        assert result["reason"] == "network_unavailable"
        assert result["evidence"]["network_error"] is True

    def test_http_error_returns_pass(self):
        result = check_osv("pkg", _session=_mock_post(status=503))
        assert result["verdict"] == "PASS"
        assert result["evidence"]["network_error"] is True

    def test_multiple_vulns_counted(self):
        ids = ["GHSA-aaa-001", "GHSA-bbb-002", "GHSA-ccc-003"]
        session = _mock_post(_osv_resp(ids))
        result = check_osv("multi-vuln", _session=session)
        assert result["evidence"]["vulnerability_count"] == 3

    def test_vuln_ids_capped_at_five(self):
        ids = [f"GHSA-{i:04d}-0000" for i in range(10)]
        session = _mock_post(_osv_resp(ids))
        result = check_osv("many-vulns", _session=session)
        assert result["evidence"]["vulnerability_count"] == 10
        assert len(result["evidence"]["vulnerability_ids"]) == 5

    def test_correct_endpoint_called(self):
        session = _mock_post(_osv_resp())
        check_osv("pkg", _session=session)
        url = session.post.call_args[0][0]
        assert "api.osv.dev" in url

    def test_body_uses_npm_ecosystem(self):
        session = _mock_post(_osv_resp())
        check_osv("my-pkg", _session=session)
        body = session.post.call_args[1]["json"]
        assert body["package"]["ecosystem"] == "npm"
        assert body["package"]["name"] == "my-pkg"

    def test_version_in_body_when_provided(self):
        session = _mock_post(_osv_resp())
        check_osv("pkg", version="1.2.3", _session=session)
        body = session.post.call_args[1]["json"]
        assert body.get("version") == "1.2.3"

    def test_version_absent_from_body_when_not_provided(self):
        session = _mock_post(_osv_resp())
        check_osv("pkg", _session=session)
        body = session.post.call_args[1]["json"]
        assert "version" not in body

    def test_verdict_never_block(self):
        session = _mock_post(_osv_resp(["GHSA-xxxx-0001"]))
        result = check_osv("bad-pkg", _session=session)
        assert result["verdict"] != "BLOCK"

    def test_evidence_contains_package_name(self):
        session = _mock_post(_osv_resp())
        result = check_osv("my-pkg", _session=session)
        assert result["evidence"]["package"] == "my-pkg"

    def test_warn_emits_otel_span(self):
        mock_span = mock.MagicMock()
        cm = mock.MagicMock()
        cm.__enter__ = mock.MagicMock(return_value=mock_span)
        cm.__exit__ = mock.MagicMock(return_value=False)
        mock_tracer = mock.MagicMock()
        mock_tracer.start_as_current_span.return_value = cm
        mock_trace = mock.MagicMock()
        mock_trace.get_tracer.return_value = mock_tracer

        session = _mock_post(_osv_resp(["GHSA-xxxx-0001"]))
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            result = check_osv("bad-pkg", _session=session)

        assert result["verdict"] == "WARN"
        attrs = {c[0][0]: c[0][1] for c in mock_span.set_attribute.call_args_list}
        assert attrs["security.verdict"] == "WARN"
        assert attrs["security.stage"] == 1

    def test_pass_does_not_emit_otel_span(self):
        mock_trace = mock.MagicMock()
        session = _mock_post(_osv_resp())
        with mock.patch("sidecar.span_emitter.trace", mock_trace):
            result = check_osv("clean-pkg", _session=session)
        assert result["verdict"] == "PASS"
        mock_trace.get_tracer.assert_not_called()
