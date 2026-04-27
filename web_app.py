"""Flask-based browser GUI for SOC Sentinel.

Reuses the logic in SOC_Program.py so the CLI and the web UI stay in sync.

Run directly:
    python web_app.py
Or via the CLI wrapper:
    python SOC_Program.py --web
"""

from __future__ import annotations

import contextlib
import io
import ipaddress
import json
import os
import sys
import threading
import webbrowser
from typing import Any, Optional

from flask import Flask, jsonify, render_template, request

import SOC_Program as soc


@contextlib.contextmanager
def _quiet():
    """Redirect stdout/stderr to a StringIO during SOC function calls.

    SOC_Program.py uses print() for its terminal output.  When those calls
    run inside a Flask request handler the Windows console encoding (cp1252)
    can't encode Unicode box-drawing characters, raising UnicodeEncodeError.
    Redirecting to StringIO (which is encoding-agnostic) avoids that entirely
    and keeps the server logs clean — the browser UI has its own indicators.
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield


app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates",
)


# ── Small helpers ─────────────────────────────────────────────────────────────

def _json_error(message: str, status: int = 400, **extra) -> Any:
    payload = {"ok": False, "error": message}
    payload.update(extra)
    return jsonify(payload), status


def _safe_load_secrets(path, required: set, example: str):
    """Wrap soc.load_json_file and return (data, err_string)."""
    try:
        return soc.load_json_file(path, required, example), None
    except (FileNotFoundError, ValueError) as exc:
        return None, str(exc)


def _deep(obj, *keys, default=None):
    return soc._deep(obj, *keys, default=default)


def _first(*values):
    return soc._first(*values)


def _bytes_human(value) -> str:
    return soc._bytes_human(value)


def _build_alert_message(source: dict, fields: dict) -> str:
    """Build a structured alert message for Gemini from available fields.

    Uses the raw ``message`` field from _source when present; otherwise
    assembles a plain-text summary from the extracted alert fields so that
    every alert can be sent to Gemini regardless of index mapping.
    """
    raw = (source.get("message") or "").strip()
    if raw:
        return raw

    def _v(val) -> Optional[str]:
        """Stringify a field value; flatten lists; return None for blanks."""
        if val is None or val == "" or val == []:
            return None
        if isinstance(val, list):
            joined = ", ".join(str(x) for x in val if x is not None and x != "")
            return joined or None
        return str(val)

    lines = ["=== Suricata Alert ==="]
    pairs = [
        ("Timestamp",        fields.get("timestamp")),
        ("Signature",        fields.get("signature")),
        ("Signature ID",     fields.get("signature_id")),
        ("Category",         fields.get("category")),
        ("Severity",         fields.get("severity")),
        ("Protocol",         " / ".join(x for x in [_v(fields.get("proto")), _v(fields.get("app_proto"))] if x) or None),
        ("Source IP",        _v(fields.get("src_ip"))),
        ("Source Port",      _v(fields.get("src_port"))),
        ("Source Country",   " ".join(x for x in [_v(fields.get("src_country")), _v(fields.get("src_city"))] if x) or None),
        ("Source ASN",       _v(fields.get("src_asn"))),
        ("Destination IP",   _v(fields.get("dest_ip"))),
        ("Destination Port", _v(fields.get("dest_port"))),
        ("Dest Country",     _v(fields.get("dest_country"))),
        ("Bytes →",          _v(fields.get("bytes_to_h"))),
        ("Bytes ←",          _v(fields.get("bytes_from_h"))),
        ("Pkts →",           _v(fields.get("pkts_to"))),
        ("Pkts ←",           _v(fields.get("pkts_from"))),
        ("Flow ID",          _v(fields.get("flow_id"))),
        ("Community ID",     _v(fields.get("community_id"))),
        ("Hostname",         _v(fields.get("hostname"))),
        ("Node",             _v(fields.get("node"))),
        ("Signature Severity", _v(fields.get("sig_severity"))),
        ("Flowbits",         _v(fields.get("flowbits"))),
        ("Tags",             _v(fields.get("tags"))),
        ("Dest Device",      _v(fields.get("dest_device"))),
        ("HTTP Method",      _v(fields.get("http_method"))),
        ("HTTP URL",         _v(fields.get("http_url"))),
        ("HTTP Status",      _v(fields.get("http_status"))),
        ("HTTP Host",        _v(fields.get("http_hostname"))),
        ("HTTP User-Agent",  _v(fields.get("http_ua"))),
    ]
    for label, val in pairs:
        if val is not None:
            lines.append(f"{label}: {val}")
    return "\n".join(lines)


# Turn a raw OpenSearch hit into a SIEM-friendly flat dict the UI can render.
def summarize_hit(idx: int, hit: dict) -> dict:
    source = hit.get("_source", {}) or {}
    doc_id = hit.get("_id", "")
    doc_index = hit.get("_index", "")

    ts = source.get("@timestamp") or source.get("timestamp")

    src_ip = _deep(source, "source", "ip") or source.get("src_ip")
    dest_ip = _deep(source, "destination", "ip") or source.get("dest_ip")
    src_port = _deep(source, "source", "port") or source.get("src_port")
    dest_port = _deep(source, "destination", "port") or source.get("dest_port")

    net = source.get("network") or {}
    proto = net.get("transport") or source.get("proto")
    app_proto = net.get("application") or source.get("app_proto")

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

    community_id = net.get("community_id") or source.get("community_id")
    flow_id = _first(
        _deep(source, "suricata", "flow_id"),
        source.get("flow_id"),
        source.get("rootId"),
    )

    host = source.get("host") or {}
    hostname = host.get("name") or host.get("hostname")
    node_name = source.get("node")

    # ── HTTP layer (suricata.http) ──────────────────────────────────────────
    suri_http = suricata.get("http") or {}
    http_method   = suri_http.get("http_method")
    http_url      = suri_http.get("url")
    http_status   = suri_http.get("status")
    http_hostname = suri_http.get("hostname")
    http_ua       = suri_http.get("http_user_agent")
    http_ct       = suri_http.get("http_content_type")

    # ── Extra alert metadata ────────────────────────────────────────────────
    alert_meta = suricata_alert.get("metadata") or {}
    sig_severity_list = alert_meta.get("signature_severity") or []
    sig_severity = sig_severity_list[0] if sig_severity_list else None

    suri_meta = suricata.get("metadata") or {}
    flowbits_raw = suri_meta.get("flowbits") or []
    flowbits = ", ".join(str(f) for f in flowbits_raw) if flowbits_raw else None

    # ── Tags ───────────────────────────────────────────────────────────────
    tags_raw = source.get("tags") or []
    tags = ", ".join(str(t) for t in tags_raw) if tags_raw else None

    # ── Destination device ─────────────────────────────────────────────────
    dest_device_raw = _deep(source, "destination", "device", "name") or []
    dest_device = dest_device_raw[0] if isinstance(dest_device_raw, list) and dest_device_raw else (
        dest_device_raw if isinstance(dest_device_raw, str) else None
    )

    discover_url = ""
    if doc_id and doc_index:
        discover_url = soc.build_opensearch_discover_url(doc_id, doc_index)

    # Is the source IP a public address we can enrich?
    src_is_public = False
    if src_ip:
        try:
            src_is_public = not ipaddress.ip_address(src_ip).is_private
        except ValueError:
            src_is_public = False

    return {
        "idx": idx,
        "doc_id": doc_id,
        "doc_index": doc_index,
        "timestamp": ts,
        "severity": severity,
        "signature": signature,
        "signature_id": signature_id,
        "category": category,
        "src_ip": src_ip,
        "src_port": src_port,
        "src_country": src_country,
        "src_city": src_city,
        "src_asn": src_asn,
        "src_is_public": src_is_public,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "dest_country": dest_country,
        "proto": proto,
        "app_proto": app_proto,
        "pkts_to": pkts_to,
        "pkts_from": pkts_from,
        "bytes_to": bytes_to,
        "bytes_from": bytes_from,
        "bytes_to_h": _bytes_human(bytes_to) if bytes_to is not None else None,
        "bytes_from_h": _bytes_human(bytes_from) if bytes_from is not None else None,
        "flow_id": flow_id,
        "community_id": community_id,
        "hostname": hostname,
        "node": node_name,
        "http_method":   http_method,
        "http_url":      http_url,
        "http_status":   http_status,
        "http_hostname": http_hostname,
        "http_ua":       http_ua,
        "http_ct":       http_ct,
        "sig_severity":  sig_severity,
        "flowbits":      flowbits,
        "tags":          tags,
        "dest_device":   dest_device,
        "discover_url": discover_url,
        "message": _build_alert_message(source, {
            "timestamp": ts, "signature": signature, "signature_id": signature_id,
            "category": category, "severity": severity, "sig_severity": sig_severity,
            "src_ip": src_ip, "src_port": src_port,
            "src_country": src_country, "src_city": src_city, "src_asn": src_asn,
            "dest_ip": dest_ip, "dest_port": dest_port, "dest_country": dest_country,
            "dest_device": dest_device,
            "proto": proto, "app_proto": app_proto,
            "pkts_to": pkts_to, "pkts_from": pkts_from,
            "bytes_to_h": _bytes_human(bytes_to) if bytes_to is not None else None,
            "bytes_from_h": _bytes_human(bytes_from) if bytes_from is not None else None,
            "flow_id": flow_id, "community_id": community_id,
            "hostname": hostname, "node": node_name,
            "http_method": http_method, "http_url": http_url,
            "http_status": http_status, "http_hostname": http_hostname,
            "http_ua": http_ua,
            "flowbits": flowbits, "tags": tags,
        }),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template(
        "index.html",
        defaults={
            "query": soc.DEFAULT_QUERY,
            "size": soc.DEFAULT_RESULT_COUNT,
            "time": soc.DEFAULT_TIME_RANGE,
        },
    )


@app.get("/api/config")
def api_config():
    """Return defaults + a secret-presence summary so the UI can warn early."""
    secrets_status = {
        "opensearch": soc.WA_OPENSEARCH_CRED_PATH.exists(),
        "abuseipdb": soc.ABUSEIPDB_KEY_PATH.exists(),
        "gemini": soc.GEMINI_KEY_PATH.exists(),
        "mantis": soc.MANTIS_CRED_PATH.exists(),
    }
    return jsonify({
        "ok": True,
        "defaults": {
            "query": soc.DEFAULT_QUERY,
            "size": soc.DEFAULT_RESULT_COUNT,
            "time": soc.DEFAULT_TIME_RANGE,
        },
        "opensearch": {
            "base_url": soc.OPENSEARCH_BASE_URL,
            "index_pattern": soc.OPENSEARCH_INDEX_PATTERN,
            "transport": soc.OPENSEARCH_TRANSPORT,
        },
        "secrets": secrets_status,
        "mantis_projects": soc.MANTIS_PROJECTS,
        "time_presets": [
            {"key": "15m", "label": "Last 15 minutes"},
            {"key": "1h", "label": "Last 1 hour"},
            {"key": "6h", "label": "Last 6 hours"},
            {"key": "24h", "label": "Last 24 hours"},
            {"key": "48h", "label": "Last 48 hours"},
            {"key": "7d", "label": "Last 7 days"},
            {"key": "30d", "label": "Last 30 days"},
        ],
        "example_queries": [
            {"query": 'event.kind:"alert"',
             "description": "All Suricata alerts (ECS field — works with Malcolm / Arkime)"},
            {"query": 'suricata.alert.severity:[1 TO 2]',
             "description": "High / critical severity alerts (sev 1 or 2)"},
            {"query": 'suricata.alert.severity:1',
             "description": "Critical severity only (sev 1 — highest priority)"},
            {"query": 'rule.name:ET* AND event.kind:"alert"',
             "description": "Emerging Threats rule matches"},
            {"query": 'rule.name:(*MALWARE* OR *TROJAN*) AND event.kind:"alert"',
             "description": "Malware / Trojan related alerts"},
            {"query": 'rule.name:(*C2* OR *BOTNET* OR *EXPLOIT*)',
             "description": "C2, botnet, or exploit activity"},
            {"query": 'event.kind:"alert" AND _exists_:source.ip AND NOT source.ip:[10.0.0.0 TO 10.255.255.255] AND NOT source.ip:[172.16.0.0 TO 172.31.255.255] AND NOT source.ip:[192.168.0.0 TO 192.168.255.255]',
             "description": "Alerts with external (non-RFC-1918) source IPs only"},
            {"query": 'event.kind:"alert" AND network.application:"dns"',
             "description": "DNS-related alerts"},
        ],
    })


@app.post("/api/query")
def api_query():
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or soc.DEFAULT_QUERY).strip() or soc.DEFAULT_QUERY
    try:
        size = int(data.get("size") or soc.DEFAULT_RESULT_COUNT)
    except (TypeError, ValueError):
        size = soc.DEFAULT_RESULT_COUNT
    if size < 1:
        size = soc.DEFAULT_RESULT_COUNT
    time_gte = data.get("time") or soc.DEFAULT_TIME_RANGE
    if not str(time_gte).startswith("now-"):
        time_gte = f"now-{time_gte}"

    creds, err = _safe_load_secrets(
        soc.WA_OPENSEARCH_CRED_PATH,
        {"username", "password"},
        "wa_opensearch.example.json",
    )
    if err:
        return _json_error(err, 400, missing_secret="opensearch")

    payload = soc.build_query_payload(query=query, size=size, time_gte=time_gte)

    try:
        with _quiet():
            hits = soc.get_suricata_logs(
                creds["username"], creds["password"], payload
            ) or []
    except soc.requests.exceptions.ConnectionError:
        host = soc.OPENSEARCH_BASE_URL
        return _json_error(
            f"Cannot reach OpenSearch at {host}. "
            "Check your VPN connection and try again.",
            503,
        )
    except soc.requests.HTTPError as exc:
        return _json_error(
            f"OpenSearch returned HTTP {exc.response.status_code}: {exc}",
            502,
        )
    except Exception as exc:
        return _json_error(f"OpenSearch request failed: {exc}", 502)

    summaries = [summarize_hit(i + 1, h) for i, h in enumerate(hits)]

    return jsonify({
        "ok": True,
        "query": query,
        "size": size,
        "time": time_gte,
        "count": len(summaries),
        "hits": summaries,
    })


@app.post("/api/enrich")
def api_enrich():
    """Look up a list of IPs on AbuseIPDB and return the results."""
    data = request.get_json(silent=True) or {}
    ips_in = data.get("ips") or []
    try:
        max_age_days = int(data.get("max_age_days") or soc.ABUSEIPDB_MAX_AGE_DAYS)
    except (TypeError, ValueError):
        max_age_days = soc.ABUSEIPDB_MAX_AGE_DAYS
    verbose = bool(data.get("verbose"))

    # Keep only unique, valid public IPv4/IPv6 addresses.
    clean_ips: list[str] = []
    seen = set()
    for raw in ips_in:
        if not raw or raw in seen:
            continue
        try:
            obj = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if obj.is_private:
            continue
        seen.add(raw)
        clean_ips.append(str(obj))

    if not clean_ips:
        return jsonify({"ok": True, "results": {}, "skipped": "no public IPs"})

    secrets, err = _safe_load_secrets(
        soc.ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
    )
    if err:
        return _json_error(err, 400, missing_secret="abuseipdb")

    results: dict[str, dict] = {}
    errors: dict[str, str] = {}
    for ip in clean_ips:
        try:
            with _quiet():
                results[ip] = soc.check_ip_abuse(
                    ip, secrets["api_key"], max_age_days, verbose
                )
        except Exception as exc:
            errors[ip] = str(exc)

    return jsonify({"ok": True, "results": results, "errors": errors})


@app.post("/api/analyze")
def api_analyze():
    """Run a message through Gemini and return the structured analysis."""
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return _json_error("No message provided for analysis.", 400)

    secrets, err = _safe_load_secrets(
        soc.GEMINI_KEY_PATH, {"api_key"}, "gemini.example.json"
    )
    if err:
        return _json_error(err, 400, missing_secret="gemini")

    try:
        with _quiet():
            analysis = soc.analyze_with_gemini(message, secrets["api_key"])
    except Exception as exc:
        return _json_error(f"Gemini analysis failed: {exc}", 502)

    return jsonify({
        "ok": True,
        "analysis": analysis,
        "description_text": soc.format_description_text(analysis),
    })


@app.post("/api/mantis/suggest-project")
def api_mantis_suggest():
    data = request.get_json(silent=True) or {}
    hostname = (data.get("hostname") or "").strip()
    suggested = soc.match_hostname_to_project(hostname) if hostname else None
    return jsonify({"ok": True, "suggested": suggested})


@app.post("/api/mantis/submit")
def api_mantis_submit():
    data = request.get_json(silent=True) or {}
    required = {"summary", "description", "project_id"}
    missing = required - set(k for k, v in data.items() if v)
    if missing:
        return _json_error(
            f"Missing required ticket fields: {', '.join(sorted(missing))}", 400
        )

    creds, err = _safe_load_secrets(
        soc.MANTIS_CRED_PATH, {"api_url", "api_token"}, "mantis.example.json"
    )
    if err:
        return _json_error(err, 400, missing_secret="mantis")

    try:
        project_id = int(data["project_id"])
    except (TypeError, ValueError):
        return _json_error("project_id must be an integer", 400)

    project_name = data.get("project_name") or ""
    if not project_name:
        for proj in soc.MANTIS_PROJECTS:
            if proj["id"] == project_id:
                project_name = proj["name"]
                break

    ticket = {
        "summary": data["summary"],
        "description": data["description"],
        "steps_to_reproduce": data.get("steps_to_reproduce", ""),
        "additional_information": data.get("additional_information", ""),
        "project_id": project_id,
        "project_name": project_name,
        "view_state": (data.get("view_state") or "private").lower(),
    }
    if ticket["view_state"] not in ("public", "private"):
        ticket["view_state"] = "private"

    try:
        with _quiet():
            result = soc.submit_mantis_ticket(
                ticket, creds["api_url"], creds["api_token"]
            )
    except Exception as exc:
        return _json_error(f"Mantis submission failed: {exc}", 502)

    issue = (result or {}).get("issue") or {}
    issue_id = issue.get("id")
    # Many Mantis installs expose /view.php?id=N for the ticket.
    ticket_url = ""
    base = creds["api_url"].rstrip("/")
    if issue_id:
        ticket_url = f"{base}/view.php?id={issue_id}"

    return jsonify({
        "ok": True,
        "issue_id": issue_id,
        "ticket_url": ticket_url,
        "raw": result,
    })


# ── Entrypoint ────────────────────────────────────────────────────────────────

def run(
    host: str = "127.0.0.1",
    port: int = 5001,
    open_browser: bool = True,
    debug: bool = False,
) -> None:
    """Start the Flask dev server and optionally open the browser."""
    url = f"http://{host}:{port}/"
    print(f"\n  SOC Sentinel — browser GUI running at {url}")
    print("  (press Ctrl+C to stop)\n")

    if open_browser and not debug:
        def _open():
            try:
                webbrowser.open_new(url)
            except Exception:
                pass
        threading.Timer(1.0, _open).start()

    # use_reloader=False keeps the browser-opener from firing twice
    app.run(host=host, port=port, debug=debug, use_reloader=debug)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SOC Sentinel web GUI")
    parser.add_argument("--host", default=os.getenv("SOC_WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SOC_WEB_PORT", "5001")))
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open a browser")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode")
    cli = parser.parse_args()
    run(host=cli.host, port=cli.port, open_browser=not cli.no_browser, debug=cli.debug)
