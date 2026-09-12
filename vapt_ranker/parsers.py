"""
parsers.py – Parse Burp Suite and OWASP ZAP XML exports into a
normalised list of Finding dicts.

Finding schema:
  {
    "url":        str,
    "host":       str,
    "path":       str,
    "method":     str,            # GET / POST / …
    "parameter":  str,            # parameter / input name
    "param_type": str,            # query / body / header / cookie / path
    "issue_type": str,            # e.g. "SQL Injection"
    "severity":   str,            # Critical / High / Medium / Low / Informational
    "confidence": str,            # Certain / Firm / Tentative / …
    "evidence":   str,            # raw snippet if available
    "source":     str,            # "burp" | "zap"
  }
"""

import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
from typing import List, Dict


# ── helpers ──────────────────────────────────────────────────────────────────

def _normalise_severity(raw: str) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
        "false positive": "Informational",
    }
    return mapping.get(raw.strip().lower(), "Informational")


def _extract_params_from_url(url: str) -> List[Dict]:
    """Extract query-string parameters from a URL."""
    parsed = urlparse(url)
    params = []
    for name in parse_qs(parsed.query):
        params.append({"parameter": name, "param_type": "query"})
    return params


def _text(element, tag: str, default: str = "") -> str:
    el = element.find(tag)
    if el is None:
        return default
    return (el.text or "").strip()


# Burp Scanner numeric type IDs → human-readable names
# Source: Burp Suite issue definitions
BURP_TYPE_MAP: Dict[int, str] = {
    # Injection
    1048832:  "SQL Injection",
    1048833:  "SQL Injection (second order)",
    1049088:  "SQL Injection (second order)",
    1049344:  "SQL Injection (time-based)",
    2097920:  "Cross-site scripting (reflected)",
    2097921:  "Cross-site scripting (stored)",
    2097922:  "Cross-site scripting (DOM-based)",
    2097152:  "Cross-site scripting (reflected)",
    2097408:  "Cross-site scripting (stored)",
    16777472: "XML/SOAP injection",
    16777536: "Path traversal",
    33554432: "HTTP header injection",
    33554688: "HTTP response splitting",
    67108992: "SMTP injection",
    134217984: "OS command injection",
    134217728: "Password field submitted using GET method",
    # Auth / Session
    16777728: "Cookie without HttpOnly flag",
    16777984: "Cookie without secure flag",
    16778240: "Session token in URL",
    33555456: "Cleartext submission of password",
    # Info / Misc
    5244416:  "Open redirection (reflected)",
    5244672:  "Open redirection (stored)",
    8389632:  "File path manipulation",
    8390144:  "XML external entity injection",
    8388608:  "XXE injection",
    4194304:  "LDAP injection",
    4194816:  "XPath injection",
    33555200: "Cross-site request forgery",
    33556224: "Broken access control",
    16777216: "Directory listing",
    4194048:  "Server-side template injection",
    # Passive
    10485760: "Cacheable HTTPS response",
    10485504: "SSL certificate",
    10486272: "Strict transport security not enforced",
    10485248: "Clickjacking (UI redressing)",
    10486784: "Content type incorrectly stated",
    10487808: "Browser cross-site scripting filter disabled",
    2359296:  "SSRF (server-side request forgery)",
}


def _resolve_burp_issue_type(element) -> str:
    """
    Resolve the human-readable issue name from a Burp <issue> element.
    Priority: <name> tag → <n> tag → numeric <type> lookup → raw <type> value
    """
    # Try <name> first (standard tag)
    name = _text(element, "name")
    if name and not name.isdigit():
        return name
    # Try <n> (short alias used by some exports)
    n_tag = _text(element, "n")
    if n_tag and not n_tag.isdigit():
        return n_tag
    # Numeric type lookup
    type_str = _text(element, "type")
    if type_str.isdigit():
        numeric_id = int(type_str)
        if numeric_id in BURP_TYPE_MAP:
            return BURP_TYPE_MAP[numeric_id]
        return f"Issue type {numeric_id}"
    # Fall back to raw type string
    return type_str or "Unknown"


# ── Burp Suite XML parser ─────────────────────────────────────────────────────

def parse_burp(filepath: str) -> List[Dict]:
    """
    Parse a Burp Suite 'Save items' or 'Issue activity' XML export.

    Burp exports two main XML schemas:
      - <issues> root  (Scanner → Save all issues)
      - <items>  root  (Proxy → Save items)

    We handle both.
    """
    try:
        tree = ET.parse(filepath)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML in {filepath}: {exc}") from exc

    root = tree.getroot()
    findings: List[Dict] = []

    # ── Schema 1: Scanner issues ──────────────────────────────────────────
    if root.tag == "issues":
        for issue in root.findall("issue"):
            url       = _text(issue, "url")
            host_el   = issue.find("host")
            host      = host_el.text.strip() if host_el is not None else ""
            path      = urlparse(url).path if url else ""
            issue_type = _resolve_burp_issue_type(issue)
            severity  = _normalise_severity(_text(issue, "severity"))
            confidence = _text(issue, "confidence", "Tentative")
            evidence  = _text(issue, "issueDetail") or _text(issue, "issueBackground")
            method    = "GET"

            # Try to find parameter names inside <requestresponse> blocks
            params_found: List[Dict] = []
            for rr in issue.findall(".//requestresponse"):
                request_el = rr.find("request")
                if request_el is not None and request_el.text:
                    req_text = request_el.text
                    # grab method from first line
                    first_line = req_text.splitlines()[0] if req_text else ""
                    if first_line:
                        method = first_line.split()[0].upper() if first_line.split() else "GET"
                    # extract query params from GET
                    if "?" in first_line:
                        raw_url = first_line.split()[1] if len(first_line.split()) > 1 else ""
                        params_found.extend(_extract_params_from_url("http://x" + raw_url))
                    # extract POST body params (handle both CRLF and LF)
                    separator = "\r\n\r\n" if "\r\n\r\n" in req_text else "\n\n"
                    if separator in req_text:
                        body = req_text.split(separator, 1)[1]
                        for kv in body.split("&"):
                            name = kv.split("=")[0].strip()
                            if name:
                                params_found.append({"parameter": name, "param_type": "body"})

            # Also try URL-level params
            if not params_found and url:
                params_found.extend(_extract_params_from_url(url))

            # If still nothing, create one synthetic entry for the path
            if not params_found:
                params_found = [{"parameter": "(none)", "param_type": "path"}]

            for p in params_found:
                findings.append({
                    "url":        url,
                    "host":       host,
                    "path":       path,
                    "method":     method,
                    "parameter":  p["parameter"],
                    "param_type": p["param_type"],
                    "issue_type": issue_type,
                    "severity":   severity,
                    "confidence": confidence,
                    "evidence":   evidence[:300],
                    "source":     "burp",
                })

    # ── Schema 2: Proxy items ─────────────────────────────────────────────
    elif root.tag == "items":
        for item in root.findall("item"):
            url    = _text(item, "url")
            host   = _text(item, "host")
            path   = urlparse(url).path
            method = _text(item, "method", "GET").upper()

            params_found = _extract_params_from_url(url)

            request_el = item.find("request")
            if request_el is not None and request_el.text:
                body_part = request_el.text.split("\r\n\r\n", 1)
                if len(body_part) > 1:
                    for kv in body_part[1].split("&"):
                        name = kv.split("=")[0].strip()
                        if name:
                            params_found.append({"parameter": name, "param_type": "body"})

            if not params_found:
                params_found = [{"parameter": "(none)", "param_type": "path"}]

            for p in params_found:
                findings.append({
                    "url":        url,
                    "host":       host,
                    "path":       path,
                    "method":     method,
                    "parameter":  p["parameter"],
                    "param_type": p["param_type"],
                    "issue_type": "Unknown (proxy item)",
                    "severity":   "Informational",
                    "confidence": "Tentative",
                    "evidence":   "",
                    "source":     "burp",
                })
    else:
        raise ValueError(
            f"Unrecognised Burp XML root element <{root.tag}>. "
            "Expected <issues> or <items>."
        )

    return findings


# ── OWASP ZAP XML parser ──────────────────────────────────────────────────────

def parse_zap(filepath: str) -> List[Dict]:
    """
    Parse an OWASP ZAP XML report (File → Generate Report → XML).

    ZAP XML schema (OWASPZAPReport):
      <OWASPZAPReport>
        <site ...>
          <alerts>
            <alertitem>
              <alert>XSS</alert>
              <riskdesc>High (Medium)</riskdesc>
              <instances>
                <instance>
                  <uri>...</uri>
                  <method>GET</method>
                  <param>q</param>
                  <evidence>...</evidence>
                </instance>
              </instances>
            </alertitem>
          </alerts>
        </site>
      </OWASPZAPReport>
    """
    try:
        tree = ET.parse(filepath)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML in {filepath}: {exc}") from exc

    root = tree.getroot()
    findings: List[Dict] = []

    # Support both <OWASPZAPReport> and <report> as root
    for site in root.iter("site"):
        site_name = site.get("name", "")
        for alertitem in site.iter("alertitem"):
            issue_type = _text(alertitem, "alert") or _text(alertitem, "name")
            riskdesc   = _text(alertitem, "riskdesc", "Informational")
            # riskdesc is like "High (Medium)" — take first word
            severity   = _normalise_severity(riskdesc.split()[0])
            confidence = _text(alertitem, "confidence", "Medium")

            for instance in alertitem.iter("instance"):
                url       = _text(instance, "uri")
                method    = _text(instance, "method", "GET").upper()
                parameter = _text(instance, "param", "(none)")
                evidence  = _text(instance, "evidence", "")
                parsed    = urlparse(url)
                host      = parsed.netloc or site_name
                path      = parsed.path

                # Determine param_type heuristically
                if parameter == "(none)":
                    param_type = "path"
                elif method in ("POST", "PUT", "PATCH"):
                    param_type = "body"
                else:
                    param_type = "query"

                findings.append({
                    "url":        url,
                    "host":       host,
                    "path":       path,
                    "method":     method,
                    "parameter":  parameter,
                    "param_type": param_type,
                    "issue_type": issue_type,
                    "severity":   severity,
                    "confidence": confidence,
                    "evidence":   evidence[:300],
                    "source":     "zap",
                })

    if not findings:
        raise ValueError(
            "No alert instances found in ZAP XML. "
            "Make sure you exported via Reports → Generate Report → XML."
        )

    return findings


# ── Auto-detect ───────────────────────────────────────────────────────────────

def parse_auto(filepath: str) -> List[Dict]:
    """Try Burp first, then ZAP. Raise if neither works."""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as exc:
        raise ValueError(f"File is not valid XML: {exc}") from exc

    if root.tag in ("issues", "items"):
        return parse_burp(filepath)
    elif root.tag in ("OWASPZAPReport", "report"):
        return parse_zap(filepath)
    else:
        # Try both
        try:
            return parse_burp(filepath)
        except Exception:
            return parse_zap(filepath)
