"""
features.py – Convert normalised findings into numeric feature vectors
for the scikit-learn model.

Feature vector (14 features):
  0  severity_score      : Critical=4, High=3, Medium=2, Low=1, Info=0
  1  confidence_score    : Certain=3, Firm=2, Tentative=1, else=0
  2  cve_count           : number of matching CVEs (capped at 20)
  3  max_cvss            : highest CVSS score (0–10)
  4  avg_cvss            : average CVSS score (0–10)
  5  param_type_score    : body=4, query=3, cookie=3, header=2, path=1
  6  method_score        : POST=3, PUT=3, PATCH=2, DELETE=2, GET=1
  7  is_injection        : 1 if issue looks like an injection type
  8  is_auth             : 1 if issue is auth-related
  9  is_sensitive_param  : 1 if param name looks sensitive (password, token…)
  10 path_depth          : number of path segments (rough attack surface)
  11 has_evidence        : 1 if evidence string is non-empty
  12 param_length        : len(parameter name), proxy for complexity
  13 issue_type_score    : known dangerous type ordinal (0–5)
"""

import re
from typing import List, Dict

import numpy as np

# ── Ordinal maps ──────────────────────────────────────────────────────────────

SEVERITY_SCORES = {
    "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0
}

CONFIDENCE_SCORES = {
    "Certain": 3, "Firm": 2, "Tentative": 1
}

PARAM_TYPE_SCORES = {
    "body": 4, "query": 3, "cookie": 3, "header": 2, "path": 1
}

METHOD_SCORES = {
    "POST": 3, "PUT": 3, "PATCH": 2, "DELETE": 2, "GET": 1
}

# Known issue type → ordinal danger score (higher = more dangerous / common exploit)
ISSUE_TYPE_DANGER: Dict[str, int] = {
    "sql injection":              5,
    "sqli":                       5,
    "remote code execution":      5,
    "rce":                        5,
    "command injection":          5,
    "os command injection":       5,
    "server-side template injection": 5,
    "ssti":                       5,
    "xxe":                        4,
    "xml external entity":        4,
    "ssrf":                       4,
    "server-side request forgery": 4,
    "insecure deserialization":   4,
    "cross-site scripting":       3,
    "xss":                        3,
    "path traversal":             3,
    "directory traversal":        3,
    "open redirect":              2,
    "csrf":                       2,
    "idor":                       2,
    "broken authentication":      3,
    "sensitive data exposure":    2,
    "ldap injection":             4,
    "xpath injection":            4,
}

# Sensitive parameter name patterns
SENSITIVE_PARAM_RE = re.compile(
    r"(password|passwd|pwd|token|secret|key|auth|session|api[_-]?key|"
    r"credit|card|cvv|ssn|otp|pin|private|admin|root|bearer|access[_-]?token)",
    re.IGNORECASE,
)

# Injection-related issue keywords
INJECTION_RE = re.compile(
    r"(injection|traversal|overflow|deserialization|template|xxe|ssrf|rce|"
    r"command|xss|scripting)",
    re.IGNORECASE,
)

AUTH_RE = re.compile(
    r"(auth|session|token|login|password|bypass|privilege|access control|idor)",
    re.IGNORECASE,
)


# ── Feature extraction ────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "severity_score",
    "confidence_score",
    "cve_count",
    "max_cvss",
    "avg_cvss",
    "param_type_score",
    "method_score",
    "is_injection",
    "is_auth",
    "is_sensitive_param",
    "path_depth",
    "has_evidence",
    "param_length",
    "issue_type_score",
]


def finding_to_features(finding: Dict) -> List[float]:
    """Convert a single finding dict into a numeric feature vector."""

    issue_lower = finding.get("issue_type", "").lower()

    severity_score  = SEVERITY_SCORES.get(finding.get("severity", "Informational"), 0)
    confidence_score = CONFIDENCE_SCORES.get(finding.get("confidence", "Tentative"), 0)
    cve_count       = min(finding.get("cve_count", 0), 20)
    max_cvss        = float(finding.get("max_cvss", 0.0))
    avg_cvss        = float(finding.get("avg_cvss", 0.0))
    param_type_score = PARAM_TYPE_SCORES.get(finding.get("param_type", "query"), 1)
    method_score    = METHOD_SCORES.get(finding.get("method", "GET").upper(), 1)
    is_injection    = 1 if INJECTION_RE.search(issue_lower) else 0
    is_auth         = 1 if AUTH_RE.search(issue_lower) else 0
    is_sensitive    = 1 if SENSITIVE_PARAM_RE.search(finding.get("parameter", "")) else 0
    path            = finding.get("path", "/")
    path_depth      = len([p for p in path.split("/") if p])
    has_evidence    = 1 if finding.get("evidence", "").strip() else 0
    param_length    = len(finding.get("parameter", ""))

    # Match issue type to known danger ordinal
    issue_type_score = 0
    for pattern, score in ISSUE_TYPE_DANGER.items():
        if pattern in issue_lower:
            issue_type_score = max(issue_type_score, score)

    return [
        severity_score,
        confidence_score,
        cve_count,
        max_cvss,
        avg_cvss,
        param_type_score,
        method_score,
        is_injection,
        is_auth,
        is_sensitive,
        path_depth,
        has_evidence,
        param_length,
        issue_type_score,
    ]


def findings_to_matrix(findings: List[Dict]) -> np.ndarray:
    """Convert a list of findings into a (N, 14) feature matrix."""
    return np.array([finding_to_features(f) for f in findings], dtype=float)
