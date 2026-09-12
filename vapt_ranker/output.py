"""
output.py – Render ranked findings to the terminal or export to file.

Terminal output uses coloured risk labels and a rich tabulate table.
Export supports JSON and CSV.
"""

import csv
import json
import sys
from typing import List, Dict, Optional

from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

colorama_init(autoreset=True)

# ── Colour helpers ────────────────────────────────────────────────────────────

LABEL_COLOURS = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High":     Fore.YELLOW + Style.BRIGHT,
    "Medium":   Fore.CYAN,
    "Low":      Fore.GREEN,
}

SEVERITY_COLOURS = {
    "Critical": Fore.RED,
    "High":     Fore.YELLOW,
    "Medium":   Fore.CYAN,
    "Low":      Fore.GREEN,
    "Informational": Fore.WHITE,
}


def _c(text: str, colour: str) -> str:
    return colour + str(text) + Style.RESET_ALL


def _label_str(label: str) -> str:
    colour = LABEL_COLOURS.get(label, Fore.WHITE)
    padded = f"{label:<8}"
    return _c(padded, colour)


def _severity_str(severity: str) -> str:
    colour = SEVERITY_COLOURS.get(severity, Fore.WHITE)
    return _c(f"{severity:<14}", colour)


def _score_bar(score: float, width: int = 10) -> str:
    filled = int(round(score / 100 * width))
    bar = "█" * filled + "░" * (width - filled)
    if score >= 75:
        colour = Fore.RED
    elif score >= 50:
        colour = Fore.YELLOW
    elif score >= 25:
        colour = Fore.CYAN
    else:
        colour = Fore.GREEN
    return _c(bar, colour) + f" {score:5.1f}"


# ── Terminal output ───────────────────────────────────────────────────────────

def print_banner():
    banner = f"""
{Fore.RED + Style.BRIGHT}
 ██╗   ██╗ █████╗ ██████╗ ████████╗    ██████╗  █████╗ ███╗   ██╗██╗  ██╗███████╗██████╗
 ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝    ██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██╔════╝██╔══██╗
 ██║   ██║███████║██████╔╝   ██║       ██████╔╝███████║██╔██╗ ██║█████╔╝ █████╗  ██████╔╝
 ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║       ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██╔══╝  ██╔══██╗
  ╚████╔╝ ██║  ██║██║        ██║       ██║  ██║██║  ██║██║ ╚████║██║  ██╗███████╗██║  ██║
   ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}{Fore.WHITE}  ML-Powered VAPT Finding Ranker  |  NVD CVE Enrichment  |  Burp & ZAP Support{Style.RESET_ALL}
"""
    print(banner)


def print_summary(findings: List[Dict], source: str = ""):
    total     = len(findings)
    critical  = sum(1 for f in findings if f.get("exploit_label") == "Critical")
    high      = sum(1 for f in findings if f.get("exploit_label") == "High")
    medium    = sum(1 for f in findings if f.get("exploit_label") == "Medium")
    low       = sum(1 for f in findings if f.get("exploit_label") == "Low")

    print(f"\n{Style.BRIGHT}── Scan Summary {'─' * 50}{Style.RESET_ALL}")
    if source:
        print(f"  Source     : {source}")
    print(f"  Total      : {total} findings (after deduplication)")
    print(f"  Critical   : {_c(critical, Fore.RED + Style.BRIGHT)}")
    print(f"  High       : {_c(high, Fore.YELLOW + Style.BRIGHT)}")
    print(f"  Medium     : {_c(medium, Fore.CYAN)}")
    print(f"  Low        : {_c(low, Fore.GREEN)}")
    print()


def print_findings_table(findings: List[Dict], max_rows: int = 50):
    """Print findings as a coloured tabulate table."""
    rows = []
    for f in findings[:max_rows]:
        rows.append([
            str(f.get("rank", "?")),
            _label_str(f.get("exploit_label", "Low")),
            _score_bar(f.get("rank_score", 0)),
            _severity_str(f.get("severity", "Informational")),
            f.get("host", "")[:30],
            f.get("path", "")[:35],
            f.get("parameter", "")[:20],
            f.get("issue_type", "")[:30],
            str(f.get("cve_count", 0)),
            f"{f.get('max_cvss', 0.0):.1f}",
        ])

    headers = [
        "#", "ML Label", "Rank Score", "Severity",
        "Host", "Path", "Parameter", "Issue Type",
        "CVEs", "MaxCVSS"
    ]

    print(f"{Style.BRIGHT}── Ranked Findings {'─' * 48}{Style.RESET_ALL}")
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    if len(findings) > max_rows:
        print(f"\n  … {len(findings) - max_rows} more findings (use --export to see all)")
    print()


def print_top_cves(findings: List[Dict], top_n: int = 5):
    """Print the most critical CVEs found across all findings."""
    seen = set()
    cves = []
    for f in findings:
        for cve in f.get("cve_list", []):
            cid = cve.get("cve_id", "")
            if cid and cid not in seen:
                seen.add(cid)
                cves.append(cve)

    if not cves:
        return

    cves.sort(key=lambda c: (c.get("cvss_v3") or c.get("cvss_v2") or 0), reverse=True)
    top = cves[:top_n]

    print(f"{Style.BRIGHT}── Top CVEs {'-' * 55}{Style.RESET_ALL}")
    rows = []
    for c in top:
        score = c.get("cvss_v3") or c.get("cvss_v2") or "N/A"
        rows.append([
            _c(c["cve_id"], Fore.RED if (score != "N/A" and float(score) >= 7) else Fore.YELLOW),
            f"{score}",
            c.get("description", "")[:70],
        ])
    print(tabulate(rows, headers=["CVE ID", "CVSS", "Description"], tablefmt="simple"))
    print()


def print_feature_importances(importances: List):
    print(f"{Style.BRIGHT}── Model Feature Importances {'-' * 39}{Style.RESET_ALL}")
    rows = [(name, f"{imp:.4f}", "█" * int(imp * 100)) for name, imp in importances]
    print(tabulate(rows, headers=["Feature", "Importance", "Visual"], tablefmt="simple"))
    print()


# ── File export ───────────────────────────────────────────────────────────────

EXPORT_FIELDS = [
    "rank", "exploit_label", "exploit_score", "rank_score",
    "severity", "host", "path", "method", "parameter", "param_type",
    "issue_type", "confidence", "cve_count", "max_cvss", "avg_cvss",
    "url",
]


def export_csv(findings: List[Dict], filepath: str):
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            writer.writerow({k: finding.get(k, "") for k in EXPORT_FIELDS})
    print(f"[+] CSV exported → {filepath}")


def export_json(findings: List[Dict], filepath: str):
    # Remove bulky internal fields for export
    clean = []
    for f in findings:
        row = {k: f.get(k, "") for k in EXPORT_FIELDS}
        row["class_proba"] = f.get("class_proba", {})
        row["cve_ids"]     = [c["cve_id"] for c in f.get("cve_list", [])]
        clean.append(row)

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(clean, fh, indent=2)
    print(f"[+] JSON exported → {filepath}")
