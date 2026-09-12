"""
fetcher.py – Fetch CVE data from the NVD REST API v2.

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  - Without API key : 5 requests / 30 seconds
  - With API key    : 50 requests / 30 seconds

Usage:
  fetcher = NVDFetcher(api_key="your-key")          # api_key optional
  cve_data = fetcher.enrich_findings(findings)
"""

import time
import logging
from typing import List, Dict, Optional, Tuple

import requests

logger = logging.getLogger("vapt_ranker.fetcher")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Maps common vulnerability keywords → NVD keyword searches
ISSUE_KEYWORD_MAP: Dict[str, List[str]] = {
    "sql injection":          ["sql injection"],
    "sqli":                   ["sql injection"],
    "xss":                    ["cross-site scripting"],
    "cross-site scripting":   ["cross-site scripting"],
    "xxe":                    ["xxe", "xml external entity"],
    "ssrf":                   ["server-side request forgery", "ssrf"],
    "ssti":                   ["server-side template injection"],
    "open redirect":          ["open redirect"],
    "path traversal":         ["path traversal", "directory traversal"],
    "rce":                    ["remote code execution"],
    "command injection":      ["command injection", "os command injection"],
    "idor":                   ["insecure direct object reference", "idor"],
    "csrf":                   ["cross-site request forgery", "csrf"],
    "broken authentication":  ["authentication bypass"],
    "sensitive data":         ["information disclosure"],
    "insecure deserialization": ["deserialization"],
    "ldap injection":         ["ldap injection"],
}


class NVDFetcher:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})
        # Rate-limit tracking
        self._request_times: List[float] = []
        self._rate_window = 30.0  # seconds
        self._rate_limit = 50 if api_key else 5

    # ── Rate limiting ─────────────────────────────────────────────────────

    def _wait_for_rate_limit(self):
        now = time.time()
        # Remove timestamps outside the window
        self._request_times = [t for t in self._request_times if now - t < self._rate_window]
        if len(self._request_times) >= self._rate_limit:
            sleep_for = self._rate_window - (now - self._request_times[0]) + 0.5
            if sleep_for > 0:
                logger.debug(f"Rate limit: sleeping {sleep_for:.1f}s")
                time.sleep(sleep_for)
        self._request_times.append(time.time())

    # ── Single CVE query ──────────────────────────────────────────────────

    def _fetch_cves(self, keyword: str, results_per_page: int = 5) -> List[Dict]:
        """Query NVD for CVEs matching keyword. Returns simplified CVE list."""
        self._wait_for_rate_limit()
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        }
        try:
            resp = self.session.get(NVD_BASE_URL, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.warning(f"NVD API error for '{keyword}': {exc}")
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_meta = item.get("cve", {})
            cve_id = cve_meta.get("id", "")
            description = ""
            for desc in cve_meta.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS scores
            base_score_v3, base_score_v2 = None, None
            metrics = cve_meta.get("metrics", {})
            for entry in metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", []):
                base_score_v3 = entry.get("cvssData", {}).get("baseScore")
                break
            for entry in metrics.get("cvssMetricV2", []):
                base_score_v2 = entry.get("cvssData", {}).get("baseScore")
                break

            cves.append({
                "cve_id":       cve_id,
                "description":  description[:200],
                "cvss_v3":      base_score_v3,
                "cvss_v2":      base_score_v2,
                "published":    cve_meta.get("published", ""),
            })

        return cves

    # ── Map issue types to NVD keywords ──────────────────────────────────

    def _get_keywords(self, issue_type: str) -> List[str]:
        lower = issue_type.lower()
        for key, keywords in ISSUE_KEYWORD_MAP.items():
            if key in lower:
                return keywords
        # Generic fallback: use first two words of issue type
        words = issue_type.split()
        return [" ".join(words[:2])] if words else []

    # ── Main enrichment entry point ───────────────────────────────────────

    def enrich_findings(self, findings: List[Dict], verbose: bool = False) -> List[Dict]:
        """
        For each finding, fetch matching CVEs from NVD and attach:
          - cve_list        : list of CVE dicts
          - cve_count       : int
          - max_cvss        : float (highest CVSS score found, or 0.0)
          - avg_cvss        : float
        """
        # Deduplicate issue types to minimise API calls
        issue_cache: Dict[str, Tuple[List[Dict], float, float]] = {}

        unique_issues = {f["issue_type"] for f in findings}
        total = len(unique_issues)

        for idx, issue_type in enumerate(unique_issues, 1):
            if verbose:
                print(f"  [{idx}/{total}] Fetching CVEs for: {issue_type}")

            keywords = self._get_keywords(issue_type)
            all_cves: List[Dict] = []

            for kw in keywords[:2]:  # cap at 2 queries per issue type
                cves = self._fetch_cves(kw)
                # Deduplicate by CVE ID
                seen_ids = {c["cve_id"] for c in all_cves}
                all_cves.extend(c for c in cves if c["cve_id"] not in seen_ids)

            scores = [
                c["cvss_v3"] or c["cvss_v2"] or 0.0
                for c in all_cves
                if c["cvss_v3"] is not None or c["cvss_v2"] is not None
            ]
            max_cvss = max(scores, default=0.0)
            avg_cvss = (sum(scores) / len(scores)) if scores else 0.0

            issue_cache[issue_type] = (all_cves, max_cvss, avg_cvss)

        # Attach to findings
        for finding in findings:
            cve_list, max_cvss, avg_cvss = issue_cache.get(
                finding["issue_type"], ([], 0.0, 0.0)
            )
            finding["cve_list"]  = cve_list
            finding["cve_count"] = len(cve_list)
            finding["max_cvss"]  = max_cvss
            finding["avg_cvss"]  = avg_cvss

        return findings
