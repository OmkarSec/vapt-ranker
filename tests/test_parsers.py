"""
tests/test_parsers.py – Unit tests for parsers, features, and ranker.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from vapt_ranker.parsers import parse_burp, parse_zap
from vapt_ranker.features import finding_to_features, FEATURE_NAMES
from vapt_ranker.ranker import rank_findings


BURP_SAMPLE = os.path.join(os.path.dirname(__file__), "../sample_inputs/burp_sample.xml")
ZAP_SAMPLE  = os.path.join(os.path.dirname(__file__), "../sample_inputs/zap_sample.xml")


class TestBurpParser:
    def test_parse_returns_list(self):
        findings = parse_burp(BURP_SAMPLE)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_finding_schema(self):
        findings = parse_burp(BURP_SAMPLE)
        required = {"url", "host", "path", "method", "parameter",
                    "param_type", "issue_type", "severity", "confidence", "source"}
        for f in findings:
            assert required.issubset(f.keys()), f"Missing keys in finding: {f}"

    def test_severity_normalised(self):
        findings = parse_burp(BURP_SAMPLE)
        valid = {"Critical", "High", "Medium", "Low", "Informational"}
        for f in findings:
            assert f["severity"] in valid

    def test_source_is_burp(self):
        findings = parse_burp(BURP_SAMPLE)
        assert all(f["source"] == "burp" for f in findings)


class TestZAPParser:
    def test_parse_returns_list(self):
        findings = parse_zap(ZAP_SAMPLE)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_finding_schema(self):
        findings = parse_zap(ZAP_SAMPLE)
        required = {"url", "host", "path", "method", "parameter",
                    "param_type", "issue_type", "severity", "confidence", "source"}
        for f in findings:
            assert required.issubset(f.keys())

    def test_source_is_zap(self):
        findings = parse_zap(ZAP_SAMPLE)
        assert all(f["source"] == "zap" for f in findings)

    def test_sql_injection_found(self):
        findings = parse_zap(ZAP_SAMPLE)
        types = [f["issue_type"].lower() for f in findings]
        assert any("sql" in t for t in types)


class TestFeatureExtraction:
    def _make_finding(self, **overrides):
        base = {
            "url": "http://example.com/test?id=1",
            "host": "example.com",
            "path": "/test",
            "method": "GET",
            "parameter": "id",
            "param_type": "query",
            "issue_type": "SQL Injection",
            "severity": "High",
            "confidence": "Certain",
            "evidence": "You have an error in your SQL syntax",
            "cve_list": [],
            "cve_count": 3,
            "max_cvss": 9.8,
            "avg_cvss": 8.5,
        }
        base.update(overrides)
        return base

    def test_feature_vector_length(self):
        f = self._make_finding()
        vec = finding_to_features(f)
        assert len(vec) == len(FEATURE_NAMES)

    def test_sensitive_param_detected(self):
        f = self._make_finding(parameter="password")
        vec = finding_to_features(f)
        assert vec[9] == 1  # is_sensitive_param

    def test_injection_flag(self):
        f = self._make_finding(issue_type="SQL Injection")
        vec = finding_to_features(f)
        assert vec[7] == 1  # is_injection

    def test_severity_score_high(self):
        f = self._make_finding(severity="Critical")
        vec = finding_to_features(f)
        assert vec[0] == 4


class TestRanker:
    def _findings_with_scores(self):
        """Create pre-scored findings for ranking tests."""
        return [
            {"host": "a.com", "path": "/x", "parameter": "q", "issue_type": "XSS",
             "severity": "High", "exploit_label": "High", "exploit_score": 70.0,
             "max_cvss": 7.0, "cve_list": []},
            {"host": "a.com", "path": "/y", "parameter": "id", "issue_type": "SQLi",
             "severity": "Critical", "exploit_label": "Critical", "exploit_score": 95.0,
             "max_cvss": 9.8, "cve_list": []},
            {"host": "a.com", "path": "/z", "parameter": "page", "issue_type": "Info",
             "severity": "Low", "exploit_label": "Low", "exploit_score": 15.0,
             "max_cvss": 3.0, "cve_list": []},
        ]

    def test_returns_sorted_descending(self):
        ranked = rank_findings(self._findings_with_scores())
        scores = [f["rank_score"] for f in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_rank_field_assigned(self):
        ranked = rank_findings(self._findings_with_scores())
        assert ranked[0]["rank"] == 1

    def test_min_risk_filter(self):
        ranked = rank_findings(self._findings_with_scores(), min_risk="High")
        labels = {f["exploit_label"] for f in ranked}
        assert "Low" not in labels

    def test_deduplication(self):
        findings = self._findings_with_scores()
        # Add a duplicate of the first
        dup = dict(findings[0])
        dup["exploit_score"] = 80.0  # higher score → should replace
        findings.append(dup)
        ranked = rank_findings(findings, deduplicate=True)
        # Should have 3 unique entries, not 4
        assert len(ranked) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
