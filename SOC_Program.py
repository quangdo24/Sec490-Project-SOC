import json
import os
import argparse

import ipaddress
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress SSL warnings if your ELK uses self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
  _  ___ _                                    _    ____  _   _ ____  _____ ___ ____  ____  ____   
 | |/ (_) |__   __ _ _ __   __ _     _       / \  | __ )| | | / ___|| ____|_ _|  _ \|  _ \| __ )  
 | ' /| | '_ \ / _` | '_ \ / _` |  _| |_    / _ \ |  _ \| | | \___ \|  _|  | || |_) | | | |  _ \  
 | . \| | |_) | (_| | | | | (_| | |_   _|  / ___ \| |_) | |_| |___) | |___ | ||  __/| |_| | |_) | 
 |_|\_\_|_.__/ \__,_|_| |_|\__,_|   |_|   /_/   \_\____/ \___/|____/|_____|___|_|   |____/|____/  
                                                                                                  
"""

# --- Configuration ---
ELASTIC_URL = "https://wa-kibana.cyberrangepoulsbo.com/api/console/proxy?path=/suricata-*/_search&method=POST"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 90

SECRETS_DIR = Path(__file__).resolve().parent / "secrets"
WA_KIBANA_CRED_PATH = Path(
    os.getenv("WA_KIBANA_CRED_PATH", SECRETS_DIR / "wa_kibana.json")
)
ABUSEIPDB_KEY_PATH = Path(
    os.getenv("ABUSEIPDB_KEY_PATH", SECRETS_DIR / "abuseipdb.json")
)


DEBUG_PRINT_KIBANA_REQUEST = os.getenv("DEBUG_PRINT_KIBANA_REQUEST", "0") == "1"


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


def print_kibana_request(url: str, headers: dict, payload: dict, username: str):
    """
    Pretty-print the Kibana request for debugging without leaking secrets.
    """
    print("\n=== Kibana Request (sanitized) ===")
    print(f"URL: {url}")
    print(f"Auth: Basic (username={username}, password=<redacted>)")
    print("Headers:")
    print(json.dumps(headers, indent=2, sort_keys=True))
    print("JSON Body:")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print("=== End Kibana Request ===\n")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Query Suricata alerts from Kibana/Elasticsearch and check IPs via AbuseIPDB, "
            "or manually check IPs in AbuseIPDB."
        )
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        help=(
            "Manually check an IP in AbuseIPDB (skips Kibana query). "
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
                print(f"[!] Skipping private IP: {ip_str}")
                continue
            ips.append(str(ip_obj))
        except ValueError:
            print(f"[!] Skipping invalid IP: {ip_str}")

    # de-dupe while preserving order
    return list(dict.fromkeys(ips))


def prompt_user_mode_and_inputs():
    """
    Interactive prompt to choose between:
    1) Kibana query mode
    2) Manual AbuseIPDB IP lookup mode

    Returns: (mode, manual_ips)
      - mode: "kibana" or "manual"
    """
    print("\nSelect mode:")
    print("  1) Query Kibana / Elasticsearch (then check IPs in AbuseIPDB)")
    print("  2) Manual AbuseIPDB lookup (enter IP address(es))")

    while True:
        choice = input("Enter 1 or 2: ").strip()
        if choice in {"1", "2"}:
            break
        print("[!] Please enter 1 or 2.")

    if choice == "1":
        return "kibana", []

    # Option 2: force valid IP input so we never accidentally fall through to Kibana mode
    while True:
        ip_text = input("Enter IP(s) (comma-separated): ").strip()
        manual_ips = normalize_ips([ip_text])
        if manual_ips:
            return "manual", manual_ips
        print("[!] No valid IPs entered. Try again (or press Ctrl+C to cancel).")

# Your Exact Postman JSON Body
query_payload = {
  "size": 5,
  "_source": [
    "@timestamp", "timestamp", "src_ip", "dest_ip", "src_port", "dest_port",
    "proto", "app_proto", "traffic_type", "in_iface", "geoip.src_country.*",
    "geoip.dest_country.*", "geoip.src.*", "geoip.dest.*", "frame.length",
    "frame.direction", "frame.stream_offset", "frame.payload",
    "frame.payload_printable", "host.hostname", "host.os.*",
    "host.architecture", "host.containerized", "host.ip", "flow_id",
    "community_id", "flow.pkts_toserver", "flow.pkts_toclient",
    "flow.bytes_toserver", "flow.bytes_toclient", "dns.query.*",
    "suricata.eve.alert.*", "alert.*", "log.file.path", "tags", "message"
  ],
  "query": {
    "bool": {
      "should": [
        { "exists": { "field": "suricata.eve.alert.signature" } }
      ]
    }
  },
  "sort": [ { "@timestamp": { "order": "desc" } } ]
}

def get_suricata_logs(username: str, password: str):
    """Query Kibana/Elasticsearch for the latest Suricata alert hits and return the hits list."""
    try:
        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        }

        print("[*] Querying Kibana / Elasticsearch for latest Suricata alerts...")
        if DEBUG_PRINT_KIBANA_REQUEST:
            print_kibana_request(ELASTIC_URL, headers, query_payload, username)

        # Mimicking Postman POST request with Basic Auth
        response = requests.post(
            ELASTIC_URL,
            json=query_payload,
            auth=HTTPBasicAuth(username, password),
            headers=headers,
            verify=False # Equivalent to turning off SSL verification in Postman
        )

        response.raise_for_status()
        data = response.json()
        
        # Accessing the list of logs (hits)
        hits = data.get('hits', {}).get('hits', [])
        print(f"[*] Successfully retrieved {len(hits)} logs from Suricata.")
        return hits

    except Exception as e:
        print(f"[!] Error: {e}")
        return []

def extract_ips(logs):
    """Extract unique source IPs (src_ip) from Kibana hit sources."""
    ips = set()
    for hit in logs:
        source = hit.get("_source", {})
        ip_value = source.get("src_ip")
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


def print_abuseipdb_report(ip_address: str, data: dict, match_indices=None):
    """Print a compact AbuseIPDB report for one IP."""
    print(f"\n--- AbuseIPDB: {ip_address} ---")
    if match_indices:
        match_list = ", ".join(str(idx) for idx in sorted(set(match_indices)))
        print(f"Matches in Kibana query: {match_list}")
    location_fields = ["countryName", "countryCode", "region"]
    for field in location_fields:
        value = data.get(field)
        if value:
            print(f"{field}: {value}")

    fields = [
        "abuseConfidenceScore",
        "isp",
        "domain",
        "usageType",
        "totalReports",
        "lastReportedAt",
        "isWhitelisted",
    ]
    for field in fields:
        print(f"{field}: {data.get(field)}")


def _flatten(obj, prefix=""):
    """
    Flatten nested dict/list structures into dotted keys for readable printing.
    Example: {"a": {"b": 1}} -> {"a.b": 1}
    """
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


def _bytes_to_gb(value) -> float | None:
    """
    Convert bytes to decimal gigabytes (GB, 1 GB = 1,000,000,000 bytes).
    Returns None if value is not a number.
    """
    try:
        return float(value) / 1_000_000_000
    except (TypeError, ValueError):
        return None


def print_suricata_hit(idx: int, source: dict):
    """
    Nicely print a Suricata/Kibana hit in a readable, non-JSON format.
    Includes a compact summary plus a full flattened key/value dump.
    """
    ts = source.get("@timestamp") or source.get("timestamp")
    src_ip = source.get("src_ip")
    dest_ip = source.get("dest_ip")
    src_port = source.get("src_port")
    dest_port = source.get("dest_port")
    proto = source.get("proto")
    app_proto = source.get("app_proto")

    # Suricata alert fields can appear in different places depending on pipeline
    alert = source.get("alert") or {}
    suricata_alert = (
        (((source.get("suricata") or {}).get("eve") or {}).get("alert")) or {}
    )
    signature = (
        suricata_alert.get("signature")
        or alert.get("signature")
        or source.get("suricata.eve.alert.signature")
    )
    category = suricata_alert.get("category") or alert.get("category")
    severity = suricata_alert.get("severity") or alert.get("severity")
    signature_id = suricata_alert.get("signature_id") or alert.get("signature_id")

    # GeoIP (best effort)
    geoip = source.get("geoip") or {}
    src_country = (
        ((geoip.get("src_country") or {}).get("name"))
        or ((geoip.get("src_country") or {}).get("iso_code"))
    )
    dest_country = (
        ((geoip.get("dest_country") or {}).get("name"))
        or ((geoip.get("dest_country") or {}).get("iso_code"))
    )

    print(f"\n=== Match {idx} ===")
    print(f"Time: {ts}")
    print(f"Flow: {src_ip}:{src_port}  ->  {dest_ip}:{dest_port}")
    print(f"Proto: {proto}   App: {app_proto}")
    if src_country or dest_country:
        print(f"Geo: {src_country or '?'}  ->  {dest_country or '?'}")
    if signature or category or severity is not None:
        print("Alert:")
        if signature:
            print(f"  Signature: {signature}")
        if signature_id is not None:
            print(f"  Signature ID: {signature_id}")
        if category:
            print(f"  Category: {category}")
        if severity is not None:
            print(f"  Severity: {severity}")

    message = source.get("message")
    if message:
        print(f"Message: {message}")

    # Full details without JSON formatting
    print("\nAll fields:")
    flat = _flatten(source)
    for key in sorted(flat.keys()):
        value = flat[key]
        if value is None:
            continue
        if isinstance(value, str) and value.strip() == "":
            continue
        suffix = ""
        if (
            "bytes" in key
            and isinstance(value, (int, float))
            and ("flow.bytes_" in key or ".bytes_" in key or key.endswith("bytes"))
        ):
            gb = _bytes_to_gb(value)
            if gb is not None:
                suffix = f" ({gb:.2f} GB)"

        print(f"- {key} = {value}{suffix}")


def main():
    """Program entrypoint: interactive mode selection, Kibana query, and/or AbuseIPDB checks."""
    print(BANNER)
    args = parse_args()
    manual_ips = normalize_ips(args.ip)

    # If user provided no CLI flags, prompt interactively (when possible)
    max_age_days = args.max_age_days
    abuse_verbose = args.abuse_verbose
    if not manual_ips and len(sys.argv) == 1 and sys.stdin.isatty():
        try:
            mode, manual_ips = prompt_user_mode_and_inputs()
            # In interactive mode, don't ask for max age; always use default.
            max_age_days = ABUSEIPDB_MAX_AGE_DAYS
            if mode == "kibana":
                manual_ips = []
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Cancelled.")
            return

    # Manual AbuseIPDB mode (skips Kibana query)
    if manual_ips:
        abuseipdb = load_json_file(
            ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
        )
        print(f"[*] Checking {len(manual_ips)} manual IP(s) against AbuseIPDB...")
        for ip_address in manual_ips:
            try:
                data = check_ip_abuse(
                    ip_address, abuseipdb["api_key"], max_age_days, abuse_verbose
                )
                print_abuseipdb_report(ip_address, data)
            except Exception as exc:
                print(f"[!] AbuseIPDB error for {ip_address}: {exc}")
        return

    # Normal mode: Kibana query + AbuseIPDB checks for extracted IPs
    wa_kibana = load_json_file(
        WA_KIBANA_CRED_PATH, {"username", "password"}, "wa_kibana.example.json"
    )
    abuseipdb = load_json_file(
        ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
    )

    logs = get_suricata_logs(wa_kibana["username"], wa_kibana["password"])
    if logs:
        ip_to_matches = {}
        for idx, hit in enumerate(logs, start=1):
            source = hit.get("_source", {})
            print_suricata_hit(idx, source)
            src_ip = source.get("src_ip")
            if src_ip:
                ip_to_matches.setdefault(src_ip, []).append(idx)

        ips = extract_ips(logs)
        if ips:
            print(f"\n[*] Checking {len(ips)} IPs against AbuseIPDB...")
            for ip_address in ips:
                try:
                    data = check_ip_abuse(
                        ip_address, abuseipdb["api_key"], max_age_days, abuse_verbose
                    )
                    print_abuseipdb_report(
                        ip_address, data, match_indices=ip_to_matches.get(ip_address)
                    )
                except Exception as exc:
                    print(f"[!] AbuseIPDB error for {ip_address}: {exc}")
        else:
            print("[*] No IPs found in logs to check.")


if __name__ == "__main__":
    main()