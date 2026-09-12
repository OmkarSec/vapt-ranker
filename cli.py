#!/usr/bin/env python3
"""
cli.py – VAPT Ranker entry point.

Usage examples:
  python cli.py --input burp.xml --format burp
  python cli.py --input zap.xml  --format zap --nvd-api-key YOUR_KEY
  python cli.py --input burp.xml --format auto --min-risk HIGH --export csv --output out.csv
  python cli.py --train
"""

import argparse
import sys
import os

from vapt_ranker.parsers   import parse_burp, parse_zap, parse_auto
from vapt_ranker.fetcher   import NVDFetcher
from vapt_ranker.model     import load_or_train, predict, get_feature_importances
from vapt_ranker.ranker    import rank_findings
from vapt_ranker.output    import (
    print_banner, print_summary, print_findings_table,
    print_top_cves, print_feature_importances,
    export_csv, export_json,
)


def parse_args():
    p = argparse.ArgumentParser(
        description="VAPT Ranker – ML-powered exploitability ranking for Burp/ZAP findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --input burp.xml --format burp
  python cli.py --input zap.xml  --format zap
  python cli.py --input burp.xml --format burp --nvd-api-key abc123
  python cli.py --input burp.xml --format burp --min-risk HIGH
  python cli.py --input burp.xml --format burp --export csv --output results.csv
  python cli.py --train
  python cli.py --feature-importance
        """,
    )

    p.add_argument("--input",  "-i",  help="Path to Burp Suite or ZAP XML file")
    p.add_argument("--format", "-f",  choices=["burp", "zap", "auto"], default="auto",
                   help="Input format (default: auto-detect)")
    p.add_argument("--nvd-api-key",   help="NVD API key for higher rate limits")
    p.add_argument("--no-nvd",        action="store_true",
                   help="Skip NVD CVE enrichment (faster, lower accuracy)")
    p.add_argument("--min-risk",      choices=["Low", "Medium", "High", "Critical"],
                   help="Only show findings at or above this ML-predicted risk level")
    p.add_argument("--export",        choices=["csv", "json"],
                   help="Export results to file")
    p.add_argument("--output", "-o",  help="Output file path (for --export)")
    p.add_argument("--train",         action="store_true",
                   help="Retrain the ML model and exit")
    p.add_argument("--feature-importance", action="store_true",
                   help="Print model feature importances and exit")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Verbose output")

    return p.parse_args()


def main():
    args = parse_args()
    print_banner()

    # ── Retrain mode ──────────────────────────────────────────────────────
    if args.train:
        print("[*] Training mode activated …\n")
        from vapt_ranker.model import train
        train(verbose=True)
        return

    # ── Feature importance mode ───────────────────────────────────────────
    if args.feature_importance:
        pipeline = load_or_train(verbose=args.verbose)
        print_feature_importances(get_feature_importances(pipeline))
        return

    # ── Require --input for everything else ───────────────────────────────
    if not args.input:
        print("[!] Please supply --input <file> or use --train / --feature-importance")
        sys.exit(1)

    if not os.path.isfile(args.input):
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    # ── Step 1: Parse ─────────────────────────────────────────────────────
    print(f"[1/4] Parsing {args.format.upper()} scan output: {args.input}")
    try:
        if args.format == "burp":
            findings = parse_burp(args.input)
        elif args.format == "zap":
            findings = parse_zap(args.input)
        else:
            findings = parse_auto(args.input)
    except (ValueError, FileNotFoundError) as exc:
        print(f"[!] Parse error: {exc}")
        sys.exit(1)

    if not findings:
        print("[!] No findings parsed from input file.")
        sys.exit(0)

    print(f"    → {len(findings)} raw findings extracted")

    # ── Step 2: NVD enrichment ────────────────────────────────────────────
    if args.no_nvd:
        print("[2/4] NVD enrichment skipped (--no-nvd)")
        for f in findings:
            f.setdefault("cve_list",  [])
            f.setdefault("cve_count", 0)
            f.setdefault("max_cvss",  0.0)
            f.setdefault("avg_cvss",  0.0)
    else:
        key_hint = "(with API key)" if args.nvd_api_key else "(no API key – rate limited)"
        print(f"[2/4] Fetching CVE data from NVD {key_hint} …")
        fetcher = NVDFetcher(api_key=args.nvd_api_key)
        findings = fetcher.enrich_findings(findings, verbose=args.verbose)

    # ── Step 3: ML scoring ────────────────────────────────────────────────
    print("[3/4] Loading ML model and scoring findings …")
    pipeline = load_or_train(verbose=args.verbose)
    findings = predict(pipeline, findings)

    # ── Step 4: Rank & output ─────────────────────────────────────────────
    print(f"[4/4] Ranking findings (min-risk={args.min_risk or 'all'}) …\n")
    ranked = rank_findings(findings, min_risk=args.min_risk, deduplicate=True)

    source_label = f"{args.format.upper()} – {os.path.basename(args.input)}"
    print_summary(ranked, source=source_label)
    print_findings_table(ranked)
    print_top_cves(ranked)

    if args.verbose:
        print_feature_importances(get_feature_importances(pipeline))

    # ── Export ────────────────────────────────────────────────────────────
    if args.export:
        out_path = args.output or f"vapt_results.{args.export}"
        if args.export == "csv":
            export_csv(ranked, out_path)
        else:
            export_json(ranked, out_path)


if __name__ == "__main__":
    main()
