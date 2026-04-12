import json
import os
import re
import argparse
import urllib.parse
import time
import subprocess
import tempfile

import ipaddress
import sys
from pathlib import Path
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress SSL warnings if your ELK uses self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── ANSI Color Helpers ────────────────────────────────────────────────────────
# Enable ANSI escape codes on Windows 10+ terminals
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_YEL  = "\033[43m"
    BG_GRN  = "\033[42m"


def severity_color(sev) -> str:
    """Return an ANSI color based on Suricata severity (1 = highest)."""
    try:
        sev = int(sev)
    except (TypeError, ValueError):
        return C.WHITE
    if sev <= 1:
        return C.RED
    if sev == 2:
        return C.YELLOW
    return C.GREEN


def abuse_score_color(score) -> str:
    """Return an ANSI color based on AbuseIPDB confidence score (0-100)."""
    try:
        score = int(score)
    except (TypeError, ValueError):
        return C.WHITE
    if score >= 75:
        return C.RED
    if score >= 40:
        return C.YELLOW
    if score >= 10:
        return C.BLUE
    return C.GREEN

BANNER = (
    f"\n{C.BOLD}{C.CYAN}"
    r"  _  ___ _                                    _    ____  _   _ ____  _____ ___ ____  ____  ____   " "\n"
    r" | |/ (_) |__   __ _ _ __   __ _     _       / \  | __ )| | | / ___|| ____|_ _|  _ \|  _ \| __ )  " "\n"
    r" | ' /| | '_ \ / _` | '_ \ / _` |  _| |_    / _ \ |  _ \| | | \___ \|  _|  | || |_) | | | |  _ \  " "\n"
    r" | . \| | |_) | (_| | | | | (_| | |_   _|  / ___ \| |_) | |_| |___) | |___ | ||  __/| |_| | |_) | " "\n"
    r" |_|\_\_|_.__/ \__,_|_| |_|\__,_|   |_|   /_/   \_\____/ \___/|____/|_____|___|_|   |____/|____/  " "\n"
    f"{C.RESET}"
    f"{C.DIM}  Suricata Alert Query + AbuseIPDB Enrichment Tool{C.RESET}\n"
)

# --- Configuration ---
def _rstrip_slash(url: str) -> str:
    return url.rstrip("/") if url else url


# With OPENSEARCH_TRANSPORT=dev_tools this is the OpenSearch Dashboards origin (same as Dev Tools).
# With transport=cluster this is the OpenSearch REST API base URL.
OPENSEARCH_BASE_URL = _rstrip_slash(
    os.getenv("OPENSEARCH_BASE_URL", "https://pisces-opensearch.cyberrangepoulsbo.com")
)
OPENSEARCH_INDEX_PATTERN = os.getenv(
    "OPENSEARCH_INDEX_PATTERN",
    "arkime_sessions3-*",
)
# If the API is mounted under a subpath (e.g. "opensearch" → .../opensearch/<index>/_search).
OPENSEARCH_PATH_PREFIX = os.getenv("OPENSEARCH_PATH_PREFIX", "").strip().strip("/")
# Many reverse proxies return 404 for a literal "*" in the path; encoding as %2A fixes that.
OPENSEARCH_RAW_INDEX_IN_URL = os.getenv("OPENSEARCH_RAW_INDEX_IN_URL", "0") == "1"
# HTTP verb forwarded to OpenSearch for the _search call (Dev Tools: GET _search { ... }).
_os_http_method = os.getenv("OPENSEARCH_SEARCH_HTTP_METHOD", "GET").strip().upper()
OPENSEARCH_SEARCH_HTTP_METHOD = _os_http_method if _os_http_method in ("GET", "POST") else "GET"

# dev_tools = POST to Dashboards /api/console/proxy?path=...&method=... (same as Dev Tools console).
# cluster = call OpenSearch REST API on OPENSEARCH_BASE_URL (GET/POST per OPENSEARCH_SEARCH_HTTP_METHOD).
_op_tr = os.getenv("OPENSEARCH_TRANSPORT", "dev_tools").strip().lower()
if _op_tr in ("cluster", "direct"):
    OPENSEARCH_TRANSPORT = "cluster"
else:
    OPENSEARCH_TRANSPORT = "dev_tools"

# Optional multi-data-source Console param (query string dataSourceId).
OPENSEARCH_DATA_SOURCE_ID = os.getenv("OPENSEARCH_DATA_SOURCE_ID", "").strip()


def _normalize_lucene_query(query: str) -> str:
    """Normalize Lucene pasted from the UI (curly quotes, spaces after ':')."""
    query = query.strip()
    for bad, good in (
        ("\u201c", '"'),
        ("\u201d", '"'),
        ("\u2018", "'"),
        ("\u2019", "'"),
    ):
        query = query.replace(bad, good)
    # "field: \"value\"" breaks query_string; Lucene expects field:\"value\" or field:value
    query = re.sub(r":\s+\"", ':"', query)
    query = re.sub(r":\s+'", ":'", query)
    return query


def _parse_whole_query_event_kind(query: str) -> Optional[str]:
    """If the line is only event.kind = X, return X for a keyword ``term`` query (GUI-style)."""
    m = re.match(
        r"^\s*event\.kind\s*:\s*(?:\"([^\"]+)\"|(\S+))\s*$",
        query,
        re.IGNORECASE,
    )
    if not m:
        return None
    return (m.group(1) or m.group(2) or "").strip() or None


def opensearch_search_url() -> str:
    """Full URL for the _search request (index pattern segment is URL-encoded by default)."""
    if OPENSEARCH_RAW_INDEX_IN_URL:
        segment = OPENSEARCH_INDEX_PATTERN
    else:
        segment = urllib.parse.quote(OPENSEARCH_INDEX_PATTERN, safe="")
    parts = [OPENSEARCH_BASE_URL]
    if OPENSEARCH_PATH_PREFIX:
        parts.append(OPENSEARCH_PATH_PREFIX)
    parts.append(segment)
    parts.append("_search")
    return "/".join(parts)

# Optional OpenSearch Dashboards (for clickable Discover document links).
OPENSEARCH_DASHBOARDS_BASE_URL = _rstrip_slash(
    os.getenv("OPENSEARCH_DASHBOARDS_BASE_URL", "")
)
OPENSEARCH_DISCOVER_INDEX_PATTERN_ID = os.getenv(
    "OPENSEARCH_DISCOVER_INDEX_PATTERN_ID", ""
)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 90
DEFAULT_QUERY = 'event.kind:alert'
DEFAULT_RESULT_COUNT = 10
DEFAULT_TIME_RANGE = "now-48h"

SECRETS_DIR = Path(__file__).resolve().parent / "secrets"


def resolve_opensearch_cred_path() -> Path:
    """Prefer explicit env, then wa_opensearch.json, then legacy wa_kibana.json."""
    explicit = os.getenv("WA_OPENSEARCH_CRED_PATH") or os.getenv("WA_KIBANA_CRED_PATH")
    if explicit:
        return Path(explicit)
    preferred = SECRETS_DIR / "wa_opensearch.json"
    legacy = SECRETS_DIR / "wa_kibana.json"
    if preferred.exists():
        return preferred
    if legacy.exists():
        return legacy
    return preferred


WA_OPENSEARCH_CRED_PATH = resolve_opensearch_cred_path()
ABUSEIPDB_KEY_PATH = Path(
    os.getenv("ABUSEIPDB_KEY_PATH", SECRETS_DIR / "abuseipdb.json")
)
GEMINI_KEY_PATH = Path(
    os.getenv("GEMINI_KEY_PATH", SECRETS_DIR / "gemini.json")
)
MANTIS_CRED_PATH = Path(
    os.getenv("MANTIS_CRED_PATH", SECRETS_DIR / "mantis.json")
)

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
PROMPT_TEMPLATE_PATH = Path(__file__).resolve().parent / "prompts" / "gemini_prompt.md"

MANTIS_PROJECTS = [
    {"id": 36, "name": "bainbridge"},
    {"id": 37, "name": "benton"},
    {"id": 56, "name": "bitterroot"},
    {"id": 38, "name": "bonney-lake"},
    {"id": 7,  "name": "burien"},
    {"id": 54, "name": "chewelah"},
    {"id": 9,  "name": "cle-elum"},
    {"id": 46, "name": "college-place"},
    {"id": 34, "name": "colville"},
    {"id": 1,  "name": "covington"},
    {"id": 61, "name": "dawson"},
    {"id": 45, "name": "dixon"},
    {"id": 27, "name": "east-sammamish"},
    {"id": 22, "name": "east-wenatchee"},
    {"id": 14, "name": "edgewood"},
    {"id": 28, "name": "fife"},
    {"id": 23, "name": "franklin"},
    {"id": 58, "name": "hawaii"},
    {"id": 32, "name": "health-first"},
    {"id": 50, "name": "KIBANA Issues"},
    {"id": 15, "name": "kittitas"},
    {"id": 19, "name": "liberty-lake"},
    {"id": 55, "name": "miles-city"},
    {"id": 62, "name": "missoula"},
    {"id": 21, "name": "othello"},
    {"id": 16, "name": "pacific"},
    {"id": 60, "name": "polson"},
    {"id": 43, "name": "port-angeles"},
    {"id": 17, "name": "port-townsend"},
    {"id": 26, "name": "poulsbo"},
    {"id": 59, "name": "sheridan"},
    {"id": 35, "name": "stevens-pud"},
    {"id": 52, "name": "Student Help Center"},
    {"id": 41, "name": "union-gap"},
    {"id": 40, "name": "washington-county"},
    {"id": 39, "name": "whitefish"},
    {"id": 47, "name": "whitefish-city-hall"},
    {"id": 57, "name": "wsipc"},
    {"id": 48, "name": "yelm"},
]


DEBUG_PRINT_OPENSEARCH_REQUEST = (
    os.getenv("DEBUG_PRINT_OPENSEARCH_REQUEST", "0") == "1"
    or os.getenv("DEBUG_PRINT_KIBANA_REQUEST", "0") == "1"
)


def print_opensearch_request(
    http_method: str,
    url: str,
    headers: dict,
    payload: dict,
    username: str,
    query_params: Optional[dict] = None,
):
    """Print debug details for the OpenSearch request (password redacted)."""
    body_preview = json.dumps(payload, indent=2, default=str)
    if len(body_preview) > 12000:
        body_preview = body_preview[:12000] + "\n  ... (truncated)"
    print(f"{C.DIM}--- DEBUG OpenSearch request ---{C.RESET}")
    print(f"  HTTP: {http_method}")
    print(f"  URL: {url}")
    if query_params:
        print(f"  Query: {query_params}")
    print(f"  Auth: HTTP Basic ({username!r} / ***)")
    print(f"  Headers: {headers}")
    print(f"  Body:\n{body_preview}")
    print(f"{C.DIM}--- end debug ---{C.RESET}")


# Load secrets JSON from disk and validate required keys exist.
def load_json_file(path: Path, required_keys: set, example_name: str):
    """Load a JSON secrets file and validate required keys exist."""
    if not path.exists():
        raise FileNotFoundError(
            f"Missing secrets file: {path}. "
            f"Create it from secrets/{example_name}."
        )
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    missing = required_keys - set(data.keys())
    if missing:
        raise ValueError(f"Missing keys in {path}: {', '.join(sorted(missing))}")
    return data

    
# Parse CLI flags like --ip and --abuse-verbose.
def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Query Suricata alerts from OpenSearch and check IPs via AbuseIPDB, "
            "or manually check IPs in AbuseIPDB."
        )
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        help=(
            "Manually check an IP in AbuseIPDB (skips OpenSearch query). "
            "Can be repeated, or pass comma-separated values."
        ),
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=ABUSEIPDB_MAX_AGE_DAYS,
        help="AbuseIPDB maxAgeInDays parameter (default: 90).",
    )
    parser.add_argument(
        "--abuse-verbose",
        action="store_true",
        help="Request verbose AbuseIPDB output (includes extra fields when available).",
    )
    return parser.parse_args()


# Normalize and validate IPs from user input; skip invalid/private ranges.
def normalize_ips(ip_args):
    """Normalize/validate IPs from CLI/prompt input and de-dupe while preserving order."""
    raw = []
    for item in ip_args or []:
        raw.extend([x.strip() for x in str(item).split(",") if x.strip()])

    ips = []
    for ip_str in raw:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                print(f"{C.YELLOW}[!] Skipping private IP: {ip_str}{C.RESET}")
                continue
            ips.append(str(ip_obj))
        except ValueError:
            print(f"{C.YELLOW}[!] Skipping invalid IP: {ip_str}{C.RESET}")

    # de-dupe while preserving order
    return list(dict.fromkeys(ips))


# Interactive menu: choose OpenSearch mode or manual AbuseIPDB lookup.
def prompt_user_mode_and_inputs():
    """Prompt user to choose OpenSearch query mode or manual AbuseIPDB lookup and collect inputs."""
    print(f"\n{C.BOLD}{C.WHITE}Select mode:{C.RESET}")
    print(f"  {C.CYAN}1){C.RESET} Query OpenSearch (then check IPs in AbuseIPDB)")
    print(f"  {C.CYAN}2){C.RESET} Manual AbuseIPDB lookup (enter IP address(es))")

    while True:
        choice = input(f"{C.BOLD}Enter 1 or 2: {C.RESET}").strip()
        if choice in {"1", "2"}:
            break
        print(f"{C.YELLOW}[!] Please enter 1 or 2.{C.RESET}")

    if choice == "1":
        return "opensearch", []

    # Option 2: force valid IP input so we never accidentally fall through to OpenSearch mode
    while True:
        ip_text = input(f"{C.BOLD}Enter IP(s) (comma-separated): {C.RESET}").strip()
        manual_ips = normalize_ips([ip_text])
        if manual_ips:
            return "manual", manual_ips
        print(f"{C.YELLOW}[!] No valid IPs entered. Try again (or press Ctrl+C to cancel).{C.RESET}")


# Prompt user for custom query and result count when querying OpenSearch.
def prompt_opensearch_options():
    """Prompt the user for a custom Lucene query, timeframe, and how many results to return."""
    print(f"\n{C.BOLD}{C.WHITE}Query Configuration{C.RESET}")
    print(f"{C.CYAN}{'─' * 70}{C.RESET}")
    print(f"  {C.DIM}Default query:{C.RESET} {C.YELLOW}{DEFAULT_QUERY}{C.RESET}")
    print(f"  {C.DIM}Default time range:{C.RESET} {DEFAULT_TIME_RANGE} to now")

    print(f"\n  {C.BOLD}{C.WHITE}Example queries (Lucene syntax):{C.RESET}")
    print(f"  {C.DIM}─────────────────────────────────────────────────────────────{C.RESET}")
    print(f"  {C.YELLOW}event.kind:\"alert\"{C.RESET}")
    print(f"    {C.DIM}ECS / Malcolm (same idea as the Discover bar){C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\"{C.RESET}")
    print(f"    {C.DIM}Legacy Suricata-style field{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\" AND alert.severity:[0 TO 1]{C.RESET}")
    print(f"    {C.DIM}High severity alerts only (severity 0 or 1){C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\" AND alert.signature:ET*{C.RESET}")
    print(f"    {C.DIM}Emerging Threats alerts{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\" AND alert.signature:(*MALWARE* OR *TROJAN*){C.RESET}")
    print(f"    {C.DIM}Malware / Trojan related alerts{C.RESET}")
    print(f"  {C.YELLOW}src_ip:\"192.168.1.100\" AND event_type:\"alert\"{C.RESET}")
    print(f"    {C.DIM}Alerts from a specific source IP{C.RESET}")
    print(f"  {C.YELLOW}dest_ip:\"10.0.0.5\" AND alert.severity:1{C.RESET}")
    print(f"    {C.DIM}Severity 1 alerts targeting a specific dest IP{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\" AND alert.signature:(*C2* OR *BOTNET* OR *EXPLOIT*){C.RESET}")
    print(f"    {C.DIM}C2, botnet, or exploit activity{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"dns\" AND dns.query.rrname:*.ru{C.RESET}")
    print(f"    {C.DIM}DNS queries to .ru domains{C.RESET}")
    print(f"  {C.DIM}─────────────────────────────────────────────────────────────{C.RESET}")

    # Timeframe selection (standard presets + custom)
    presets = [
        ("15m", "Last 15 minutes"),
        ("1h", "Last 1 hour"),
        ("6h", "Last 6 hours"),
        ("24h", "Last 24 hours"),
        ("48h", "Last 48 hours"),
        ("7d", "Last 7 days"),
        ("30d", "Last 30 days"),
        ("custom", "Custom (e.g., 2h, 12h, 3d)"),
    ]
    print(f"\n  {C.BOLD}{C.WHITE}Time range presets:{C.RESET}")
    for i, (key, desc) in enumerate(presets, start=1):
        default_tag = f"{C.DIM} (default){C.RESET}" if key == DEFAULT_TIME_RANGE.replace("now-", "") else ""
        print(f"    {C.CYAN}{i}){C.RESET} {C.YELLOW}{key}{C.RESET} - {C.DIM}{desc}{C.RESET}{default_tag}")

    choice = input(
        f"\n{C.BOLD}Select a time range{C.RESET} {C.DIM}(1-{len(presets)}, Enter for default){C.RESET}: "
    ).strip()
    selected = None
    if choice:
        try:
            idx = int(choice)
            if 1 <= idx <= len(presets):
                selected = presets[idx - 1][0]
        except ValueError:
            selected = None

    if not selected:
        # DEFAULT_TIME_RANGE is like "now-48h" → keep as-is
        time_gte = DEFAULT_TIME_RANGE
    elif selected == "custom":
        custom_tf = input(
            f"{C.BOLD}Enter custom time window{C.RESET} {C.DIM}(examples: 2h, 12h, 3d){C.RESET}: "
        ).strip()
        custom_tf = custom_tf if custom_tf else DEFAULT_TIME_RANGE.replace("now-", "")
        time_gte = f"now-{custom_tf}"
    else:
        time_gte = f"now-{selected}"

    custom = input(
        f"\n{C.BOLD}Enter a custom Lucene query{C.RESET} "
        f"{C.DIM}(or press Enter for default){C.RESET}: "
    ).strip()
    query = custom if custom else DEFAULT_QUERY

    count_input = input(
        f"{C.BOLD}How many results?{C.RESET} "
        f"{C.DIM}(default {DEFAULT_RESULT_COUNT}){C.RESET}: "
    ).strip()
    try:
        count = int(count_input) if count_input else DEFAULT_RESULT_COUNT
        if count < 1:
            count = DEFAULT_RESULT_COUNT
    except ValueError:
        print(f"{C.YELLOW}[!] Invalid number, using default ({DEFAULT_RESULT_COUNT}).{C.RESET}")
        count = DEFAULT_RESULT_COUNT

    print(f"\n{C.GREEN}[✓] Query:{C.RESET}   {C.YELLOW}{query}{C.RESET}")
    print(f"{C.GREEN}[✓] Time:{C.RESET}    {time_gte} → now")
    print(f"{C.GREEN}[✓] Results:{C.RESET} {count}")
    return query, count, time_gte


def build_query_payload(query: str = DEFAULT_QUERY, size: int = DEFAULT_RESULT_COUNT, time_gte: str = DEFAULT_TIME_RANGE):
    """Build the ``_search`` JSON body.

    Tested against ``arkime_sessions3-*`` on pisces-opensearch.  The exact shape below
    returns 10 000+ hits for ``event.kind:alert`` with ``@timestamp`` sort + range.
    """
    query = _normalize_lucene_query(query)

    kind_val = _parse_whole_query_event_kind(query)
    if kind_val is not None:
        must_clause: dict = {"term": {"event.kind": kind_val}}
    else:
        must_clause = {
            "query_string": {
                "query": query,
                "lenient": True,
                "analyze_wildcard": True,
            }
        }

    return {
        "size": size,
        "track_total_hits": True,
        "_source": True,
        "query": {
            "bool": {
                "must": [must_clause],
                "filter": [
                    {"range": {"@timestamp": {"gte": time_gte, "lte": "now"}}},
                ],
            }
        },
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }


def _search_total_hits(data: dict):
    """Normalize hits.total (int or OpenSearch 7+ {value, relation}) to an int for display."""
    total = (data.get("hits") or {}).get("total")
    if isinstance(total, dict):
        try:
            return int(total.get("value", 0))
        except (TypeError, ValueError):
            return 0
    try:
        return int(total) if total is not None else 0
    except (TypeError, ValueError):
        return 0


# Query OpenSearch for recent Suricata alert hits.
def get_suricata_logs(username: str, password: str, payload: dict):
    """Query OpenSearch _search for the latest Suricata alert hits and return the hits list."""
    try:
        print(f"{C.CYAN}[*] Querying OpenSearch for latest Suricata alerts...{C.RESET}")
        if os.getenv("OPENSEARCH_ECHO_SEARCH_BODY", "0").strip() == "1":
            compact = json.dumps(payload, separators=(",", ":"), default=str)
            cap = 2500
            tail = "…" if len(compact) > cap else ""
            print(f"{C.DIM}    JSON body (paste into Dev Tools): {compact[:cap]}{tail}{C.RESET}")

        if OPENSEARCH_TRANSPORT == "dev_tools":
            # Same mechanism as Dev Tools: POST to Dashboards with path + verb in query string.
            proxy_url = f"{OPENSEARCH_BASE_URL}/api/console/proxy"
            idx = OPENSEARCH_INDEX_PATTERN.strip().strip("/")
            proxy_path = f"/{idx}/_search" if idx else "/_search"
            print(
                f"{C.DIM}    Transport: Dev Tools proxy  →  "
                f"path={proxy_path!r}  opensearch_method={OPENSEARCH_SEARCH_HTTP_METHOD}{C.RESET}"
            )
            print(
                f"{C.DIM}    Index pattern env: OPENSEARCH_INDEX_PATTERN={OPENSEARCH_INDEX_PATTERN!r}{C.RESET}"
            )
            query_params = {
                "method": OPENSEARCH_SEARCH_HTTP_METHOD,
                "path": proxy_path,
            }
            if OPENSEARCH_DATA_SOURCE_ID:
                query_params["dataSourceId"] = OPENSEARCH_DATA_SOURCE_ID
            headers = {
                "Content-Type": "application/json",
                "osd-xsrf": "true",
            }
            if DEBUG_PRINT_OPENSEARCH_REQUEST:
                print_opensearch_request(
                    "POST",
                    proxy_url,
                    headers,
                    payload,
                    username,
                    query_params=query_params,
                )
            response = requests.post(
                proxy_url,
                params=query_params,
                data=json.dumps(payload, default=str),
                auth=HTTPBasicAuth(username, password),
                headers=headers,
                verify=False,
                timeout=120,
            )
        else:
            headers = {"Content-Type": "application/json"}
            search_url = opensearch_search_url()
            method = OPENSEARCH_SEARCH_HTTP_METHOD
            print(
                f"{C.DIM}    Transport: cluster  →  {method} {search_url}{C.RESET}"
            )
            print(
                f"{C.DIM}    Index pattern env: OPENSEARCH_INDEX_PATTERN={OPENSEARCH_INDEX_PATTERN!r}{C.RESET}"
            )
            if DEBUG_PRINT_OPENSEARCH_REQUEST:
                print_opensearch_request(
                    method, search_url, headers, payload, username
                )
            req_kwargs = {
                "method": method,
                "url": search_url,
                "auth": HTTPBasicAuth(username, password),
                "headers": headers,
                "verify": False,
                "timeout": 120,
            }
            if method == "GET":
                req_kwargs["data"] = json.dumps(payload, default=str)
            else:
                req_kwargs["json"] = payload
            response = requests.request(**req_kwargs)

        response.raise_for_status()
        try:
            data = response.json()
        except json.JSONDecodeError:
            snippet = (response.text or "")[:400].replace("\n", " ")
            print(
                f"{C.RED}[!] Response was not JSON (wrong URL or login page?).{C.RESET}\n"
                f"  {C.DIM}{snippet}{'…' if len(response.text or '') > 400 else ''}{C.RESET}"
            )
            return []

        if not isinstance(data, dict):
            print(f"{C.RED}[!] Unexpected response shape from OpenSearch.{C.RESET}")
            return []

        # Accessing the list of logs (hits)
        hits = data.get("hits", {}).get("hits", []) or []
        total = _search_total_hits(data)
        print(
            f"{C.GREEN}[✓] Retrieved {len(hits)} document(s) in this page "
            f"({total} total matches in index scope).{C.RESET}"
        )
        if total == 0 and len(hits) == 0:
            print(
                f"{C.YELLOW}[!] Zero hits — the Lucene query is in the JSON body (query_string). "
                f"If Dev Tools works with a different index name, set e.g.{C.RESET}\n"
                f"  {C.DIM}export OPENSEARCH_INDEX_PATTERN='your-index-*'{C.RESET}\n"
                f"  {C.DIM}Run in Dev Tools: GET _cat/indices?v  (to see real index names){C.RESET}"
            )
        return hits

    except requests.HTTPError as e:
        resp = e.response
        url = getattr(resp, "url", "") or "(unknown URL)"
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        if resp is not None and resp.status_code == 404:
            print(
                f"{C.YELLOW}[!] 404 usually means wrong path, index pattern, or transport.{C.RESET}\n"
                f"  {C.DIM}• Default is Dev Tools proxy (OPENSEARCH_TRANSPORT=dev_tools). "
                f"If your host is raw OpenSearch only, try OPENSEARCH_TRANSPORT=cluster{C.RESET}\n"
                f"  {C.DIM}• Cluster mode: some gateways block POST to _search — use "
                f"OPENSEARCH_SEARCH_HTTP_METHOD=GET or POST as needed{C.RESET}\n"
                f"  {C.DIM}• Try OPENSEARCH_INDEX_PATTERN if indices are not named {OPENSEARCH_INDEX_PATTERN!r}{C.RESET}\n"
                f"  {C.DIM}• Cluster subpath: OPENSEARCH_PATH_PREFIX; wildcards: OPENSEARCH_RAW_INDEX_IN_URL=1{C.RESET}\n"
                f"  {C.DIM}• Failed URL: {url}{C.RESET}"
            )
        return []
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        return []


# Extract unique public source IPs from search hits (ECS source.ip, fallback src_ip).
def extract_ips(logs):
    """Extract unique public source IPs from OpenSearch hit _source fields."""
    ips = set()
    for hit in logs:
        source = hit.get("_source", {})
        ip_value = _deep(source, "source", "ip") or source.get("src_ip")
        if not ip_value:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            continue
        if ip_obj.is_private:
            continue
        ips.add(str(ip_obj))
    return sorted(ips)


# Call AbuseIPDB "check" API for a single IP.
def check_ip_abuse(ip_address: str, api_key: str, max_age_days: int, verbose: bool):
    """Call AbuseIPDB 'check' API for one IP and return the response 'data' dict."""
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "verbose": "true" if verbose else "false",
    }
    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=30)
    response.raise_for_status()
    return response.json().get("data", {})


# Print a clean, color-coded AbuseIPDB report.
def print_abuseipdb_report(ip_address: str, data: dict, match_context=None):
    """Print a clean, color-coded AbuseIPDB report for one IP.

    match_context: list of dicts with keys: idx, signature, severity, timestamp
    """
    score = data.get("abuseConfidenceScore", 0)
    sc = abuse_score_color(score)

    # Header
    print(f"\n{C.BOLD}{C.MAGENTA}{'═' * 70}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}AbuseIPDB Report:{C.RESET}  {C.CYAN}{ip_address}{C.RESET}")

    if match_context:
        print(f"\n  {C.BOLD}{C.WHITE}Triggered by:{C.RESET}")
        for m in match_context:
            sev = m.get("severity")
            sev_col = severity_color(sev)
            sev_tag = f"{sev_col}SEV {sev}{C.RESET}" if sev is not None else f"{C.DIM}SEV ?{C.RESET}"
            sig = m.get("signature") or "Unknown signature"
            ts = m.get("timestamp") or ""
            print(f"    {C.BOLD}Match {m['idx']}{C.RESET}  {sev_tag}  {C.YELLOW}{sig}{C.RESET}")
            if ts:
                print(f"             {C.DIM}{ts}{C.RESET}")
    print(f"{C.MAGENTA}{'─' * 70}{C.RESET}")

    # Abuse score (prominent)
    score_bar = "█" * (score // 5) + "░" * (20 - score // 5)
    risk_label = "CRITICAL" if score >= 75 else "HIGH" if score >= 40 else "MODERATE" if score >= 10 else "LOW"
    print(f"  {C.BOLD}Abuse Score:{C.RESET}  {sc}{C.BOLD}{score}%{C.RESET}  {sc}{score_bar}{C.RESET}  {sc}{C.BOLD}[{risk_label}]{C.RESET}")

    # Whitelisted?
    wl = data.get("isWhitelisted")
    if wl:
        print(f"  {C.GREEN}{C.BOLD}✓ WHITELISTED{C.RESET}")

    # Location
    country = data.get("countryName") or data.get("countryCode")
    region = data.get("region")
    if country:
        loc_parts = [country]
        if region:
            loc_parts.append(region)
        print(f"\n  {C.BOLD}{C.WHITE}Location{C.RESET}     {', '.join(loc_parts)}")

    # Network info
    isp = data.get("isp")
    domain = data.get("domain")
    usage = data.get("usageType")
    if isp:
        print(f"  {C.BOLD}{C.WHITE}ISP{C.RESET}          {isp}")
    if domain:
        print(f"  {C.BOLD}{C.WHITE}Domain{C.RESET}       {C.YELLOW}{domain}{C.RESET}")
    if usage:
        print(f"  {C.BOLD}{C.WHITE}Usage Type{C.RESET}   {usage}")

    # Reports
    total = data.get("totalReports", 0)
    last_reported = data.get("lastReportedAt")
    report_color = C.RED if total >= 50 else C.YELLOW if total >= 10 else C.GREEN
    print(f"\n  {C.BOLD}{C.WHITE}Reports{C.RESET}      {report_color}{total}{C.RESET} total")
    if last_reported:
        print(f"  {C.BOLD}{C.WHITE}Last Seen{C.RESET}    {last_reported}")

    print(f"{C.MAGENTA}{'─' * 70}{C.RESET}")


# Flatten nested dict/list structures into dotted keys for readable printing.
def _flatten(obj, prefix=""):
    """Flatten nested dict/list structures into dotted keys for readable printing."""
    flat = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flat.update(_flatten(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            flat.update(_flatten(v, key))
    else:
        flat[prefix] = obj
    return flat


# Convert bytes to a human-friendly string (B, KB, MB, GB).
def _bytes_human(value) -> str:
    """Convert bytes to a human-readable string."""
    try:
        b = float(value)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def build_opensearch_discover_url(doc_id: str, index: str) -> str:
    """Build OpenSearch Dashboards Discover URL for one document, or '' if not configured.

    Set OPENSEARCH_DISCOVER_INDEX_PATTERN_ID (saved object id of the data view). If
    OPENSEARCH_DASHBOARDS_BASE_URL is unset and transport is dev_tools, the same host
    as OPENSEARCH_BASE_URL is used for links.
    """
    base = OPENSEARCH_DASHBOARDS_BASE_URL or (
        OPENSEARCH_BASE_URL if OPENSEARCH_TRANSPORT == "dev_tools" else ""
    )
    pattern_id = OPENSEARCH_DISCOVER_INDEX_PATTERN_ID
    if not (base and pattern_id and doc_id and index):
        return ""
    encoded_id = urllib.parse.quote(doc_id, safe="")
    encoded_index = urllib.parse.quote(index, safe="")
    return f"{base}/app/discover#/doc/{pattern_id}/{encoded_index}?id={encoded_id}"


def _deep(obj, *keys, default=None):
    """Walk nested dicts by key path, returning *default* if any step is missing."""
    for k in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(k)
        if obj is None:
            return default
    return obj


def _first(*values):
    """Return the first non-None value."""
    for v in values:
        if v is not None:
            return v
    return None


# Print a clean, color-coded summary of one Suricata search hit.
def print_suricata_hit(idx: int, hit: dict):
    """Print one alert hit (ECS / Malcolm / Arkime layout) in a clean, color-coded format."""
    source = hit.get("_source", {})
    doc_id = hit.get("_id", "")
    doc_index = hit.get("_index", "")

    ts = source.get("@timestamp") or source.get("timestamp")

    # ECS: source.ip / destination.ip — fallback to legacy src_ip / dest_ip
    src_ip = _deep(source, "source", "ip") or source.get("src_ip")
    dest_ip = _deep(source, "destination", "ip") or source.get("dest_ip")
    src_port = _deep(source, "source", "port") or source.get("src_port")
    dest_port = _deep(source, "destination", "port") or source.get("dest_port")

    # Protocol / transport
    net = source.get("network") or {}
    proto = net.get("transport") or source.get("proto")
    app_proto = net.get("application") or source.get("app_proto")

    # Rule / signature (ECS rule.name, fallback to suricata.alert, then legacy alert)
    rule = source.get("rule") or {}
    suricata = source.get("suricata") or {}
    suricata_alert = suricata.get("alert") or {}
    legacy_alert = source.get("alert") or {}
    suricata_eve_alert = _deep(source, "suricata", "eve", "alert") or {}

    rule_name = rule.get("name")
    if isinstance(rule_name, list):
        rule_name = ", ".join(str(r) for r in rule_name)
    signature = _first(
        rule_name,
        suricata_eve_alert.get("signature"),
        legacy_alert.get("signature"),
    )
    signature_id = _first(
        rule.get("id"),
        suricata_eve_alert.get("signature_id"),
        legacy_alert.get("signature_id"),
    )
    category = rule.get("category") or suricata_eve_alert.get("category") or legacy_alert.get("category")
    if isinstance(category, list):
        category = ", ".join(str(c) for c in category)
    severity = _first(
        suricata_alert.get("severity"),
        suricata_eve_alert.get("severity"),
        legacy_alert.get("severity"),
    )

    # GeoIP — ECS source.geo / destination.geo, fallback to geoip.*
    src_country = (
        _deep(source, "source", "geo", "country_name")
        or _deep(source, "source", "geo", "country_iso_code")
        or _deep(source, "geoip", "src_country", "name")
        or _deep(source, "geoip", "src_country", "iso_code")
    )
    dest_country = (
        _deep(source, "destination", "geo", "country_name")
        or _deep(source, "destination", "geo", "country_iso_code")
        or _deep(source, "geoip", "dest_country", "name")
        or _deep(source, "geoip", "dest_country", "iso_code")
    )
    src_city = _deep(source, "source", "geo", "city_name")
    src_asn = _deep(source, "source", "as", "full")

    # Traffic — ECS network / client+server / suricata.flow / legacy flow
    suri_flow = suricata.get("flow") or {}
    legacy_flow = source.get("flow") or {}
    pkts_to = _first(suri_flow.get("pkts_toserver"), legacy_flow.get("pkts_toserver"), net.get("packets"))
    pkts_from = _first(suri_flow.get("pkts_toclient"), legacy_flow.get("pkts_toclient"))
    bytes_to = _first(
        _deep(source, "client", "bytes"),
        suri_flow.get("bytes_toserver"),
        legacy_flow.get("bytes_toserver"),
    )
    bytes_from = _first(
        _deep(source, "server", "bytes"),
        suri_flow.get("bytes_toclient"),
        legacy_flow.get("bytes_toclient"),
    )

    # Community ID
    community_id = net.get("community_id") or source.get("community_id")
    flow_id = _first(
        _deep(source, "suricata", "flow_id"),
        source.get("flow_id"),
        source.get("rootId"),
    )

    # Severity tag
    sev_col = severity_color(severity)
    sev_label = f"{sev_col}{C.BOLD} SEV {severity} {C.RESET}" if severity is not None else ""

    # ── Header ──
    print(f"\n{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  MATCH {idx}{C.RESET}  {sev_label}  {C.DIM}{ts or ''}{C.RESET}")
    print(f"{C.CYAN}{'─' * 70}{C.RESET}")

    # ── Alert Signature ──
    if signature:
        print(f"  {C.BOLD}{C.RED}SIGNATURE{C.RESET}  {C.YELLOW}{signature}{C.RESET}")
    if signature_id is not None:
        print(f"  {C.DIM}SID{C.RESET}        {signature_id}")
    if category:
        print(f"  {C.BOLD}{C.MAGENTA}CATEGORY{C.RESET}   {category}")

    # ── Flow ID ──
    if flow_id:
        print(f"\n  {C.BOLD}{C.WHITE}FLOW ID{C.RESET}    {C.CYAN}{flow_id}{C.RESET}")
    if community_id:
        print(f"  {C.DIM}Community: {community_id}{C.RESET}")

    # ── Network Flow ──
    print(f"\n  {C.BOLD}{C.WHITE}FLOW{C.RESET}")
    src_geo = f"  ({src_country}" + (f", {src_city}" if src_city else "") + ")" if src_country else ""
    dst_geo = f"  ({dest_country})" if dest_country else ""
    print(f"    {C.CYAN}{src_ip}:{src_port}{C.RESET}{C.DIM}{src_geo}{C.RESET}")
    print(f"      {C.BOLD}→{C.RESET}  {proto or '?'}/{app_proto or '?'}")
    print(f"    {C.CYAN}{dest_ip}:{dest_port}{C.RESET}{C.DIM}{dst_geo}{C.RESET}")
    if src_asn:
        print(f"    {C.DIM}ASN: {src_asn}{C.RESET}")

    # ── Traffic stats ──
    if any(v is not None for v in [pkts_to, pkts_from, bytes_to, bytes_from]):
        print(f"\n  {C.BOLD}{C.WHITE}TRAFFIC{C.RESET}")
        if pkts_to is not None or pkts_from is not None:
            print(f"    Packets:  {C.GREEN}→ {pkts_to or 0}{C.RESET}  /  {C.BLUE}← {pkts_from or 0}{C.RESET}")
        if bytes_to is not None or bytes_from is not None:
            b_to = _bytes_human(bytes_to)
            b_from = _bytes_human(bytes_from)
            print(f"    Bytes:    {C.GREEN}→ {b_to}{C.RESET}  /  {C.BLUE}← {b_from}{C.RESET}")

    # ── Host / node ──
    host = source.get("host") or {}
    hostname = host.get("name") or host.get("hostname")
    node_name = source.get("node")
    if hostname:
        print(f"\n  {C.BOLD}{C.WHITE}HOST{C.RESET}       {hostname}")
    elif node_name:
        print(f"\n  {C.BOLD}{C.WHITE}NODE{C.RESET}       {node_name}")

    # ── Discover / document reference ──
    if doc_id and doc_index:
        discover_url = build_opensearch_discover_url(doc_id, doc_index)
        if discover_url:
            print(f"\n  {C.BOLD}{C.BLUE}DISCOVER{C.RESET}   {C.DIM}{discover_url}{C.RESET}")
        else:
            print(f"\n  {C.BOLD}{C.BLUE}DOCUMENT{C.RESET}  {C.DIM}index={doc_index}  id={doc_id}{C.RESET}")

    print(f"{C.CYAN}{'─' * 70}{C.RESET}")


# ── Editor + Data Preview Helpers ─────────────────────────────────────────────

def open_in_editor(text, suffix=".txt"):
    """Open text in the user's default text editor and return the edited result."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(text)
        tmp_path = tmp.name

    try:
        if sys.platform == "win32":
            editor = os.getenv("EDITOR", "notepad")
        else:
            editor = os.getenv("EDITOR", "nano")
        subprocess.call([editor, tmp_path])
        with open(tmp_path, "r", encoding="utf-8") as f:
            return f.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def pretty_message(message):
    """Try to pretty-print the message if it's JSON, otherwise return as-is."""
    try:
        parsed = json.loads(message)
        return json.dumps(parsed, indent=2, default=str)
    except (json.JSONDecodeError, TypeError):
        return message


def preview_and_cleanse_data(message):
    """Display the data that will be sent to Gemini and let the user cleanse it.

    Returns the (possibly edited) message string, or None if the user cancels.
    Loops until the user confirms the final version or cancels.
    """
    current = pretty_message(message)

    while True:
        print(f"\n{C.BOLD}{C.WHITE}Data to be sent to Gemini AI:{C.RESET}")
        print(f"{C.CYAN}{'─' * 70}{C.RESET}")
        for line in current.split("\n"):
            print(f"  {C.DIM}{line}{C.RESET}")
        print(f"{C.CYAN}{'─' * 70}{C.RESET}")

        print(f"\n  {C.GREEN}1){C.RESET} Confirm and send")
        print(f"  {C.CYAN}2){C.RESET} Edit / cleanse in text editor")
        print(f"  {C.RED}3){C.RESET} Cancel")

        choice = input(f"\n{C.BOLD}  Choose (1-3): {C.RESET}").strip()

        if choice == "1":
            return current
        elif choice == "2":
            edited = open_in_editor(current)
            if edited.strip():
                current = edited.strip()
                print(f"{C.GREEN}[+] Data updated from editor. Showing updated preview...{C.RESET}")
            else:
                print(f"{C.YELLOW}[!] Editor returned empty — keeping previous version.{C.RESET}")
        elif choice == "3":
            return None
        else:
            print(f"{C.YELLOW}[!] Invalid choice.{C.RESET}")


def edit_text_field(current_value, field_name):
    """Prompt the user to edit a text field inline or in a text editor."""
    print(f"\n  {C.CYAN}1){C.RESET} Type new value")
    print(f"  {C.CYAN}2){C.RESET} Open in text editor")
    print(f"  {C.CYAN}3){C.RESET} Keep current")

    choice = input(f"{C.BOLD}  Choose (1-3): {C.RESET}").strip()

    if choice == "1":
        print(f"{C.DIM}Type new {field_name} (multi-line). Enter 'END' on its own line when done:{C.RESET}")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        return "\n".join(lines) if lines else current_value
    elif choice == "2":
        edited = open_in_editor(current_value)
        return edited.strip() if edited.strip() else current_value
    else:
        return current_value


# ── Gemini AI Analysis ────────────────────────────────────────────────────────

def build_gemini_prompt(message_text):
    """Build the Gemini prompt by loading the template from prompts/gemini_prompt.md."""
    if not PROMPT_TEMPLATE_PATH.exists():
        raise FileNotFoundError(
            f"Missing prompt template: {PROMPT_TEMPLATE_PATH}. "
            "Please ensure prompts/gemini_prompt.md exists."
        )
    template = PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8")
    return template.replace("{ALERT_MESSAGE}", message_text)


def analyze_with_gemini(message_text, api_key, max_retries=5):
    """Send alert message to Gemini API and return the structured analysis dict.

    Retries automatically on 429 (rate-limit) with increasing wait times.
    Free-tier limits reset per-minute, so longer waits give the best chance.
    """
    prompt = build_gemini_prompt(message_text)

    url = f"{GEMINI_URL}?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }

    wait_schedule = [10, 30, 60, 60, 120]  # seconds to wait per retry

    for attempt in range(max_retries):
        response = requests.post(url, json=payload, timeout=90)

        if response.status_code == 429:
            wait = wait_schedule[min(attempt, len(wait_schedule) - 1)]
            print(
                f"{C.YELLOW}[!] Rate limited by Gemini API (free tier). "
                f"Waiting {wait}s before retry ({attempt + 1}/{max_retries})...{C.RESET}"
            )
            time.sleep(wait)
            continue

        response.raise_for_status()

        result = response.json()
        text = result["candidates"][0]["content"]["parts"][0]["text"]

        # Strip potential markdown code fences
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            text = text.rsplit("```", 1)[0]

        return json.loads(text)

    # All retries exhausted
    raise Exception(
        "Gemini API rate limit (429) — all retries exhausted. "
        "Wait a few minutes and try again. "
        "You can also try a different model by setting GEMINI_MODEL env var "
        "(e.g. set GEMINI_MODEL=gemini-1.5-flash)."
    )


def format_description_text(analysis):
    """Format the Gemini analysis dict into the Mantis description field text."""
    sep = "─" * 40
    lines = [
        f"{'═' * 50}",
        f"  NETWORK DETAILS",
        f"{'─' * 50}",
        f"  Time and Date      : {analysis.get('time_and_date', 'N/A')}",
        f"  Network Protocol   : {analysis.get('network_protocol', 'N/A')}",
        f"  Flow ID            : {analysis.get('flow_id', 'N/A')}",
        f"  Client ID          : {analysis.get('client_id', 'N/A')}",
        "",
        f"  Source IP           : {analysis.get('source_ip', 'N/A')}",
        f"  Source Port         : {analysis.get('source_port', 'N/A')}",
        f"  Source Bytes        : {analysis.get('source_bytes', 'N/A')}",
        f"  Source Country      : {analysis.get('source_geo_country_name', 'N/A')}",
        "",
        f"  Destination IP      : {analysis.get('destination_ip', 'N/A')}",
        f"  Destination Port    : {analysis.get('destination_port', 'N/A')}",
        f"  Destination Bytes   : {analysis.get('destination_bytes', 'N/A')}",
        "",
        f"{'═' * 50}",
        f"  INCIDENT ANALYSIS",
        f"{'─' * 50}",
        f"  Event              : {analysis.get('event', 'N/A')}",
        f"  Target Asset       : {analysis.get('target_asset', 'N/A')}",
        "",
        f"  What Occurred:",
        f"    {analysis.get('what_occurred', 'N/A')}",
        "",
        f"  Why it Happened:",
        f"    {analysis.get('why_it_happened', 'N/A')}",
        "",
        f"  The Result:",
        f"    {analysis.get('the_result', 'N/A')}",
        "",
        f"  Key Details:",
        f"    {analysis.get('key_details', 'N/A')}",
        "",
        f"{'═' * 50}",
        f"  RECOMMENDED ACTION",
        f"{'─' * 50}",
        f"  {analysis.get('security_action', 'N/A')}",
        f"{'═' * 50}",
    ]
    return "\n".join(lines)


def display_analysis(analysis):
    """Display the Gemini AI analysis in a clean, color-coded format."""
    print(f"\n{C.BOLD}{C.GREEN}{'═' * 70}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}GEMINI AI INCIDENT REPORT{C.RESET}")
    print(f"{C.GREEN}{'═' * 70}{C.RESET}")

    print(f"\n  {C.BOLD}{C.YELLOW}Summary{C.RESET}")
    print(f"  {analysis.get('summary', 'N/A')}")

    # ── Network Details ──
    print(f"\n  {C.BOLD}{C.CYAN}Network Details{C.RESET}")
    print(f"  {C.CYAN}{'─' * 50}{C.RESET}")
    net_fields = [
        ("Time and Date",    "time_and_date"),
        ("Network Protocol", "network_protocol"),
        ("Flow ID",          "flow_id"),
        ("Client ID",        "client_id"),
    ]
    for label, key in net_fields:
        val = analysis.get(key, "N/A")
        print(f"    {C.WHITE}{label:20s}{C.RESET}  {val}")

    print(f"\n    {C.BOLD}{C.GREEN}Source{C.RESET}")
    src_fields = [
        ("IP",      "source_ip"),
        ("Port",    "source_port"),
        ("Bytes",   "source_bytes"),
        ("Country", "source_geo_country_name"),
    ]
    for label, key in src_fields:
        val = analysis.get(key, "N/A")
        print(f"      {C.WHITE}{label:10s}{C.RESET}  {val}")

    print(f"\n    {C.BOLD}{C.RED}Destination{C.RESET}")
    dst_fields = [
        ("IP",    "destination_ip"),
        ("Port",  "destination_port"),
        ("Bytes", "destination_bytes"),
    ]
    for label, key in dst_fields:
        val = analysis.get(key, "N/A")
        print(f"      {C.WHITE}{label:10s}{C.RESET}  {val}")

    # ── Incident Analysis ──
    print(f"\n  {C.BOLD}{C.MAGENTA}Incident Analysis{C.RESET}")
    print(f"  {C.MAGENTA}{'─' * 50}{C.RESET}")
    print(f"    {C.BOLD}{C.RED}Event:{C.RESET}           {analysis.get('event', 'N/A')}")
    print(f"    {C.BOLD}{C.WHITE}Target Asset:{C.RESET}   {analysis.get('target_asset', 'N/A')}")

    analysis_fields = [
        ("What Occurred",  "what_occurred"),
        ("Why it Happened","why_it_happened"),
        ("The Result",     "the_result"),
        ("Key Details",    "key_details"),
    ]
    for label, key in analysis_fields:
        val = analysis.get(key, "N/A")
        print(f"\n    {C.BOLD}{C.WHITE}{label}:{C.RESET}")
        print(f"    {C.DIM}{val}{C.RESET}")

    # ── Recommended Action ──
    print(f"\n  {C.BOLD}{C.YELLOW}Recommended Action{C.RESET}")
    print(f"  {C.YELLOW}{'─' * 50}{C.RESET}")
    print(f"    {analysis.get('security_action', 'N/A')}")

    # ── Additional Info ──
    addl = analysis.get("additional_information", "N/A")
    if addl and addl != "N/A":
        print(f"\n  {C.BOLD}{C.BLUE}Additional Info{C.RESET}")
        print(f"  {C.BLUE}{'─' * 50}{C.RESET}")
        print(f"    {addl}")

    print(f"\n{C.GREEN}{'═' * 70}{C.RESET}")


# ── Mantis Ticket Submission ─────────────────────────────────────────────────

def match_hostname_to_project(hostname):
    """Try to match a hostname from the alert to a Mantis project.

    Uses fuzzy matching: strips trailing digits, normalises separators,
    and checks if the hostname *starts with* a project name (or vice-versa).
    Returns the best-matching project dict, or None.
    """
    if not hostname:
        return None

    import re
    # Normalise: lowercase, strip trailing digits, replace common separators
    norm = hostname.lower().strip()
    norm_no_digits = re.sub(r"\d+$", "", norm)          # bonney-lake2 → bonney-lake
    norm_flat = norm_no_digits.replace("-", "").replace("_", "").replace(" ", "")  # bonneylake

    best = None
    best_len = 0  # prefer longest match

    for proj in MANTIS_PROJECTS:
        pname = proj["name"].lower()
        pflat = pname.replace("-", "").replace("_", "").replace(" ", "")

        # Exact match (after stripping trailing digits)
        if norm_no_digits == pname or norm_flat == pflat:
            return proj

        # Hostname starts with project name or vice-versa
        if norm_flat.startswith(pflat) or pflat.startswith(norm_flat):
            if len(pflat) > best_len:
                best = proj
                best_len = len(pflat)

    return best


def prompt_select_project(suggested=None):
    """Display available Mantis projects and let user select one.

    If *suggested* is provided (a project dict), offer it as the default choice.
    """
    if suggested:
        print(f"\n{C.GREEN}[✓] Auto-detected project from hostname: "
              f"{C.BOLD}{suggested['name']}{C.RESET}{C.GREEN} (ID: {suggested['id']}){C.RESET}")
        confirm = input(
            f"{C.BOLD}Use this project? {C.RESET}{C.DIM}(Y/n): {C.RESET}"
        ).strip().lower()
        if confirm in ("", "y", "yes"):
            print(f"{C.GREEN}[+] Selected: {suggested['name']} (ID: {suggested['id']}){C.RESET}")
            return suggested
        print(f"{C.DIM}Showing full project list...{C.RESET}")

    print(f"\n{C.BOLD}{C.WHITE}Select a project (city/location):{C.RESET}")

    cols = 3
    for i, proj in enumerate(MANTIS_PROJECTS):
        num = f"{i + 1:>2}"
        name = proj["name"]
        end = "\n" if (i + 1) % cols == 0 else ""
        print(f"  {C.CYAN}{num}){C.RESET} {name:<25s}", end=end)
    if len(MANTIS_PROJECTS) % cols != 0:
        print()

    while True:
        choice = input(f"\n{C.BOLD}Enter project number (1-{len(MANTIS_PROJECTS)}): {C.RESET}").strip()
        try:
            idx = int(choice)
            if 1 <= idx <= len(MANTIS_PROJECTS):
                selected = MANTIS_PROJECTS[idx - 1]
                print(f"{C.GREEN}[+] Selected: {selected['name']} (ID: {selected['id']}){C.RESET}")
                return selected
        except ValueError:
            pass
        print(f"{C.YELLOW}[!] Invalid choice. Try again.{C.RESET}")


def display_draft_ticket(ticket):
    """Display the draft Mantis ticket for user review."""
    vis = ticket.get("view_state", "private")
    vis_color = C.GREEN if vis == "public" else C.YELLOW
    vis_icon = "🌐" if vis == "public" else "🔒"

    print(f"\n{C.BOLD}{C.MAGENTA}{'═' * 70}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}DRAFT MANTIS TICKET{C.RESET}")
    print(f"{C.MAGENTA}{'─' * 70}{C.RESET}")

    # ── Metadata ──
    print(f"  {C.BOLD}{C.WHITE}Project:{C.RESET}        {C.CYAN}{ticket['project_name']}{C.RESET} {C.DIM}(ID: {ticket['project_id']}){C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}Visibility:{C.RESET}     {vis_color}{vis_icon}  {vis.upper()}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}Category:{C.RESET}       Bellevue College")
    print(f"  {C.BOLD}{C.WHITE}Priority:{C.RESET}       normal")
    print(f"  {C.BOLD}{C.WHITE}Severity:{C.RESET}       minor")

    # ── Summary ──
    print(f"\n{C.MAGENTA}{'─' * 70}{C.RESET}")
    print(f"  {C.BOLD}{C.YELLOW}Summary{C.RESET}")
    print(f"  {ticket['summary']}")

    # ── Description ──
    print(f"\n{C.MAGENTA}{'─' * 70}{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}Description{C.RESET}")
    for line in ticket["description"].split("\n"):
        print(f"  {line}")

    # ── Steps to Reproduce (e.g. Discover permalink) ──
    print(f"\n{C.MAGENTA}{'─' * 70}{C.RESET}")
    print(f"  {C.BOLD}{C.BLUE}Steps to Reproduce{C.RESET}")
    print(f"  {ticket['steps_to_reproduce']}")

    # ── Additional Info ──
    addl = ticket.get("additional_information", "")
    if addl:
        print(f"\n{C.MAGENTA}{'─' * 70}{C.RESET}")
        print(f"  {C.BOLD}{C.GREEN}Additional Info{C.RESET}")
        print(f"  {addl}")

    print(f"{C.MAGENTA}{'═' * 70}{C.RESET}")


def prompt_edit_ticket(ticket):
    """Allow user to review and edit the draft ticket. Returns ticket dict or None if cancelled."""
    while True:
        display_draft_ticket(ticket)

        vis = ticket.get("view_state", "private")
        toggle_label = "public" if vis == "private" else "private"

        print(f"\n  {C.BOLD}{C.WHITE}Actions:{C.RESET}")
        print(f"  {C.CYAN}{'─' * 40}{C.RESET}")
        print(f"    {C.GREEN}1){C.RESET}  {C.GREEN}Submit ticket{C.RESET}")
        print(f"    {C.CYAN}2){C.RESET}  Edit summary")
        print(f"    {C.CYAN}3){C.RESET}  Edit description")
        print(f"    {C.CYAN}4){C.RESET}  Edit steps to reproduce")
        print(f"    {C.CYAN}5){C.RESET}  Edit additional information")
        print(f"    {C.CYAN}6){C.RESET}  Change project")
        print(f"    {C.CYAN}7){C.RESET}  Toggle visibility → {C.YELLOW}{toggle_label}{C.RESET}")
        print(f"    {C.RED}8){C.RESET}  {C.RED}Cancel{C.RESET}")

        choice = input(f"\n{C.BOLD}  Choose an option (1-8): {C.RESET}").strip()

        if choice == "1":
            return ticket
        elif choice == "2":
            new_val = input(f"{C.BOLD}Enter new summary: {C.RESET}").strip()
            if new_val:
                ticket["summary"] = new_val
        elif choice == "3":
            ticket["description"] = edit_text_field(
                ticket["description"], "description"
            )
        elif choice == "4":
            new_val = input(f"{C.BOLD}Enter new steps to reproduce: {C.RESET}").strip()
            if new_val:
                ticket["steps_to_reproduce"] = new_val
        elif choice == "5":
            ticket["additional_information"] = edit_text_field(
                ticket["additional_information"], "additional information"
            )
        elif choice == "6":
            proj = prompt_select_project()
            ticket["project_id"] = proj["id"]
            ticket["project_name"] = proj["name"]
        elif choice == "7":
            ticket["view_state"] = toggle_label
            print(f"{C.GREEN}[+] Visibility set to: {C.BOLD}{toggle_label.upper()}{C.RESET}")
        elif choice == "8":
            return None
        else:
            print(f"{C.YELLOW}[!] Invalid choice.{C.RESET}")


def submit_mantis_ticket(ticket, api_url, api_token):
    """Submit a ticket to Mantis via REST API and return the response JSON."""
    url = f"{api_url}/api/rest/issues/"
    headers = {
        "Authorization": api_token,
        "Content-Type": "application/json",
    }

    payload = {
        "summary": ticket["summary"],
        "description": ticket["description"],
        "steps_to_reproduce": ticket["steps_to_reproduce"],
        "additional_information": ticket["additional_information"],
        "project": {"id": ticket["project_id"]},
        "category": {"name": "Bellevue College"},
        "priority": {"name": "normal"},
        "severity": {"name": "minor"},
        "reproducibility": {"name": "have not tried"},
        "view_state": {"name": ticket.get("view_state", "private")},
    }

    response = requests.post(url, json=payload, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()


# ── Gemini + Mantis Combined Flow ────────────────────────────────────────────

def gemini_and_mantis_flow(hits, ip_to_abuseipdb):
    """After OpenSearch results, offer Gemini AI analysis and Mantis ticket submission."""
    while True:
        print(f"\n{C.BOLD}{C.WHITE}Would you like to analyze a match with Gemini AI?{C.RESET} ", end="")
        choice = input(f"{C.DIM}(y/n): {C.RESET}").strip().lower()
        if choice != "y":
            break

        # Load Gemini API key
        try:
            gemini_secrets = load_json_file(GEMINI_KEY_PATH, {"api_key"}, "gemini.example.json")
        except (FileNotFoundError, ValueError) as exc:
            print(f"{C.RED}[!] {exc}{C.RESET}")
            break

        # Select match
        while True:
            match_input = input(
                f"{C.BOLD}Enter match number (1-{len(hits)}): {C.RESET}"
            ).strip()
            try:
                match_idx = int(match_input)
                if 1 <= match_idx <= len(hits):
                    break
            except ValueError:
                pass
            print(f"{C.YELLOW}[!] Invalid match number. Try again.{C.RESET}")

        hit = hits[match_idx - 1]
        message = hit.get("_source", {}).get("message", "")

        if not message:
            print(f"{C.YELLOW}[!] Match {match_idx} has no 'message' field in _source. Skipping.{C.RESET}")
            continue

        # Preview data and let user cleanse before sending
        cleansed = preview_and_cleanse_data(message)
        if cleansed is None:
            print(f"{C.YELLOW}[*] Cancelled.{C.RESET}")
            continue

        # Send to Gemini
        print(f"{C.CYAN}[*] Sending match {match_idx} to Gemini AI for analysis...{C.RESET}")
        try:
            analysis = analyze_with_gemini(cleansed, gemini_secrets["api_key"])
            display_analysis(analysis)
        except Exception as exc:
            print(f"{C.RED}[!] Gemini API error: {exc}{C.RESET}")
            continue

        # Offer Mantis submission
        print(f"\n{C.BOLD}{C.WHITE}Would you like to submit this as a Mantis ticket?{C.RESET} ", end="")
        mantis_choice = input(f"{C.DIM}(y/n): {C.RESET}").strip().lower()
        if mantis_choice != "y":
            continue

        # Load Mantis credentials
        try:
            mantis_creds = load_json_file(
                MANTIS_CRED_PATH, {"api_url", "api_token"}, "mantis.example.json"
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"{C.RED}[!] {exc}{C.RESET}")
            continue

        # Auto-detect project from hostname in the selected hit
        hit_hostname = (hit.get("_source", {}).get("host") or {}).get("hostname")
        suggested_project = match_hostname_to_project(hit_hostname)
        project = prompt_select_project(suggested=suggested_project)

        discover_link = input(
            f"\n{C.BOLD}Enter OpenSearch Discover permalink (steps to reproduce){C.RESET} "
            f"{C.DIM}(paste from Dashboards → Share, or any relevant URL): {C.RESET}"
        ).strip()

        # Ticket visibility
        print(f"\n  {C.CYAN}1){C.RESET} {C.YELLOW}🔒 Private{C.RESET} {C.DIM}(default — only your team can see it){C.RESET}")
        print(f"  {C.CYAN}2){C.RESET} {C.GREEN}🌐 Public{C.RESET}  {C.DIM}(visible to all MantisBT users){C.RESET}")
        vis_choice = input(f"{C.BOLD}Visibility (1/2, Enter for private): {C.RESET}").strip()
        view_state = "public" if vis_choice == "2" else "private"

        # Build draft ticket
        ticket = {
            "summary": analysis.get("summary", "Incident Report"),
            "description": format_description_text(analysis),
            "steps_to_reproduce": discover_link,
            "additional_information": analysis.get("additional_information", ""),
            "project_id": project["id"],
            "project_name": project["name"],
            "view_state": view_state,
        }

        # Let user review / edit
        final_ticket = prompt_edit_ticket(ticket)
        if final_ticket is None:
            print(f"{C.YELLOW}[*] Ticket submission cancelled.{C.RESET}")
            continue

        # Submit to Mantis
        print(f"{C.CYAN}[*] Submitting ticket to Mantis...{C.RESET}")
        try:
            result = submit_mantis_ticket(
                final_ticket, mantis_creds["api_url"], mantis_creds["api_token"]
            )
            ticket_id = result.get("issue", {}).get("id", "unknown")
            print(f"{C.GREEN}{C.BOLD}[+] Ticket submitted successfully! Ticket ID: #{ticket_id}{C.RESET}")
        except Exception as exc:
            print(f"{C.RED}[!] Mantis API error: {exc}{C.RESET}")


# Entrypoint: interactive selection, OpenSearch query, and/or manual AbuseIPDB checks.
def main():
    """Program entrypoint: interactive mode selection, OpenSearch query, and/or AbuseIPDB checks."""
    print(BANNER)
    args = parse_args()
    manual_ips = normalize_ips(args.ip)

    # If user provided no CLI flags, prompt interactively (when possible)
    max_age_days = args.max_age_days
    abuse_verbose = args.abuse_verbose
    custom_query = DEFAULT_QUERY
    result_count = DEFAULT_RESULT_COUNT
    time_gte = DEFAULT_TIME_RANGE

    if not manual_ips and len(sys.argv) == 1 and sys.stdin.isatty():
        try:
            mode, manual_ips = prompt_user_mode_and_inputs()
            # In interactive mode, don't ask for max age; always use default.
            max_age_days = ABUSEIPDB_MAX_AGE_DAYS
            if mode == "opensearch":
                manual_ips = []
                custom_query, result_count, time_gte = prompt_opensearch_options()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.YELLOW}[*] Cancelled.{C.RESET}")
            return

    # Manual AbuseIPDB mode (skips OpenSearch query)
    if manual_ips:
        abuseipdb = load_json_file(
            ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
        )
        print(f"{C.CYAN}[*] Checking {len(manual_ips)} manual IP(s) against AbuseIPDB...{C.RESET}")
        for ip_address in manual_ips:
            try:
                data = check_ip_abuse(
                    ip_address, abuseipdb["api_key"], max_age_days, abuse_verbose
                )
                print_abuseipdb_report(ip_address, data)
            except Exception as exc:
                print(f"{C.RED}[!] AbuseIPDB error for {ip_address}: {exc}{C.RESET}")
        return

    # Normal mode: OpenSearch query + AbuseIPDB checks for extracted IPs
    opensearch_creds = load_json_file(
        WA_OPENSEARCH_CRED_PATH, {"username", "password"}, "wa_opensearch.example.json"
    )
    abuseipdb = load_json_file(
        ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
    )

    payload = build_query_payload(query=custom_query, size=result_count, time_gte=time_gte)
    logs = get_suricata_logs(
        opensearch_creds["username"], opensearch_creds["password"], payload
    )
    if logs:
        ip_to_context = {}  # {ip: [{idx, signature, severity, timestamp}, ...]}
        for idx, hit in enumerate(logs, start=1):
            print_suricata_hit(idx, hit)
            source = hit.get("_source", {})
            src_ip = _deep(source, "source", "ip") or source.get("src_ip")
            if src_ip:
                rule = source.get("rule") or {}
                suricata_alert = _deep(source, "suricata", "alert") or {}
                suricata_eve_alert = _deep(source, "suricata", "eve", "alert") or {}
                legacy_alert = source.get("alert") or {}
                rule_name = rule.get("name")
                if isinstance(rule_name, list):
                    rule_name = ", ".join(str(r) for r in rule_name)
                sig = _first(
                    rule_name,
                    suricata_eve_alert.get("signature"),
                    legacy_alert.get("signature"),
                )
                sev = _first(
                    suricata_alert.get("severity"),
                    suricata_eve_alert.get("severity"),
                    legacy_alert.get("severity"),
                )
                ts = source.get("@timestamp") or source.get("timestamp")
                ip_to_context.setdefault(src_ip, []).append({
                    "idx": idx,
                    "signature": sig,
                    "severity": sev,
                    "timestamp": ts,
                })

        ips = extract_ips(logs)
        ip_to_abuseipdb = {}
        if ips:
            print(f"\n{C.CYAN}[*] Checking {len(ips)} unique public IP(s) against AbuseIPDB...{C.RESET}")
            for ip_address in ips:
                try:
                    data = check_ip_abuse(
                        ip_address, abuseipdb["api_key"], max_age_days, abuse_verbose
                    )
                    ip_to_abuseipdb[ip_address] = data
                    print_abuseipdb_report(
                        ip_address, data, match_context=ip_to_context.get(ip_address)
                    )
                except Exception as exc:
                    print(f"{C.RED}[!] AbuseIPDB error for {ip_address}: {exc}{C.RESET}")
        else:
            print(f"{C.YELLOW}[*] No public IPs found in results to check.{C.RESET}")

        # Offer Gemini AI analysis and Mantis ticket submission
        try:
            gemini_and_mantis_flow(logs, ip_to_abuseipdb)
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.YELLOW}[*] Cancelled.{C.RESET}")


if __name__ == "__main__":
    main()