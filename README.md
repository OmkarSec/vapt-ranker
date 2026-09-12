# VAPT Ranker 🔍

A CLI tool that parses Burp Suite or OWASP ZAP scan output, fetches CVE data from the NVD API, and uses a trained ML model to rank parameters by exploitability likelihood.

## Project Structure

```
vapt-ranker/
├── vapt_ranker/
│   ├── __init__.py
│   ├── parsers.py        # Burp XML / ZAP XML / JSON parsers
│   ├── fetcher.py        # NVD CVE API fetcher
│   ├── features.py       # Feature extraction for ML
│   ├── model.py          # scikit-learn model training & inference
│   ├── ranker.py         # Scoring & ranking logic
│   └── output.py         # Terminal output (tables, colours, JSON/CSV export)
├── sample_inputs/
│   ├── burp_sample.xml   # Example Burp Suite export
│   └── zap_sample.xml    # Example ZAP export
├── tests/
│   └── test_parsers.py
├── cli.py                # Entry point
├── requirements.txt
└── README.md
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Parse Burp XML, auto-detect format
python cli.py --input sample_inputs/burp_sample.xml --format burp

# Parse ZAP XML
python cli.py --input sample_inputs/zap_sample.xml --format zap

# With NVD API key (higher rate limits: 50 req/30s vs 5 req/30s)
python cli.py --input burp.xml --format burp --nvd-api-key YOUR_KEY

# Export results to CSV
python cli.py --input burp.xml --format burp --export csv --output results.csv

# Export as JSON
python cli.py --input burp.xml --format burp --export json --output results.json

# Retrain the model with custom data
python cli.py --train

# Show only HIGH/CRITICAL risk findings
python cli.py --input burp.xml --format burp --min-risk HIGH
```

## How It Works

1. **Parse** – Extracts endpoints, parameters, issue types, and severity hints from Burp/ZAP XML exports.
2. **Enrich** – Queries the NVD API for CVEs matching parameter names and vulnerability types found.
3. **Feature Engineering** – Builds a numeric feature vector per finding (severity, parameter type, CVE count, CVSS scores, injection surface heuristics, etc.).
4. **ML Ranking** – A Random Forest model (trained on a built-in synthetic dataset reflecting real OWASP patterns) scores each finding for exploitability likelihood.
5. **Output** – Ranked table printed to terminal with colour coding; optional CSV/JSON export.

## NVD API Key

Get a free key at https://nvd.nist.gov/developers/request-an-api-key  
Without a key the tool still works but is rate-limited to 5 requests per 30 seconds.
