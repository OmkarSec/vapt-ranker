"""
ranker.py – Sort, filter, and deduplicate findings after ML scoring.

The final rank_score blends:
  - exploit_score  (ML prediction, 0-100)   → 60 %
  - severity_score (human-reported, 0-100)  → 25 %
  - cvss_score     (NVD max CVSS, 0-100)    → 15 %
"""

from typing import List, Dict, Optional


SEVERITY_RANK = {
    "Critical": 100,
    "High": 75,
    "Medium": 50,
    "Low": 25,
    "Informational": 5,
}


def _composite_score(finding: Dict) -> float:
    exploit  = finding.get("exploit_score", 0.0)
    severity = SEVERITY_RANK.get(finding.get("severity", "Informational"), 5)
    cvss     = finding.get("max_cvss", 0.0) * 10  # scale 0-10 → 0-100

    return (exploit * 0.60) + (severity * 0.25) + (cvss * 0.15)


def rank_findings(
    findings: List[Dict],
    min_risk: Optional[str] = None,
    deduplicate: bool = True,
) -> List[Dict]:
    """
    Compute composite rank score, filter by min_risk, deduplicate, and sort.

    Parameters
    ----------
    findings    : enriched + ML-scored findings
    min_risk    : minimum risk level to include (Low / Medium / High / Critical)
    deduplicate : collapse identical (host, path, parameter, issue_type) tuples
    """
    risk_order = ["Informational", "Low", "Medium", "High", "Critical"]
    min_rank   = risk_order.index(min_risk) if min_risk in risk_order else 0

    # Filter by min_risk based on exploit_label
    filtered = []
    for f in findings:
        label = f.get("exploit_label", "Low")
        if label not in risk_order:
            label = "Low"
        if risk_order.index(label) >= min_rank:
            filtered.append(f)

    # Deduplicate: keep the highest-scored entry per unique key
    if deduplicate:
        seen: Dict[tuple, int] = {}   # key → index in deduped list
        deduped: List[Dict]    = []
        for f in filtered:
            key = (
                f.get("host", ""),
                f.get("path", ""),
                f.get("parameter", ""),
                f.get("issue_type", ""),
            )
            score = _composite_score(f)
            if key in seen:
                existing_score = _composite_score(deduped[seen[key]])
                if score > existing_score:
                    deduped[seen[key]] = f
            else:
                seen[key] = len(deduped)
                deduped.append(f)
        filtered = deduped

    # Compute and attach composite score
    for f in filtered:
        f["rank_score"] = round(_composite_score(f), 1)

    # Sort by rank_score descending
    filtered.sort(key=lambda f: f["rank_score"], reverse=True)

    # Assign rank position
    for i, f in enumerate(filtered, 1):
        f["rank"] = i

    return filtered
