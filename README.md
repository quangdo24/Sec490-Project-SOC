# SOC Sentinel

A terminal-based security tool that pulls network alerts from **OpenSearch**, checks suspicious IPs against **AbuseIPDB**, analyzes incidents with **Gemini AI**, and files tickets in **MantisBT** — all in one workflow.

---

## What It Does

1. **Searches for network alerts** — Queries your OpenSearch instance for Suricata IDS alerts
2. **Shows color-coded results** — Displays severity, source/destination IPs, protocols, and location info
3. **Checks IPs for threats** — Automatically looks up public IPs in AbuseIPDB and shows a risk score
4. **AI-powered analysis** — Optionally sends an alert to Gemini AI for a plain-English incident report
5. **Creates support tickets** — Submits the analysis as a MantisBT ticket with one command

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Add Your Credentials

Copy the example files and fill in your real values:

```bash
cp secrets/wa_opensearch.example.json secrets/wa_opensearch.json
cp secrets/abuseipdb.example.json     secrets/abuseipdb.json
cp secrets/gemini.example.json        secrets/gemini.json
cp secrets/mantis.example.json        secrets/mantis.json
```

| File | What to put in it |
|------|-------------------|
| `secrets/wa_opensearch.json` | Your OpenSearch username and password |
| `secrets/abuseipdb.json` | Your AbuseIPDB API key ([sign up here](https://www.abuseipdb.com/)) |
| `secrets/gemini.json` | *(optional)* Google Gemini API key for AI analysis |
| `secrets/mantis.json` | *(optional)* MantisBT API URL and token for ticket submission |

> Credential files are git-ignored — they never get pushed to GitHub.

### 3. Run It

You can use **either** the terminal UI or the browser GUI — they share the same code.

**Terminal (original CLI):**

```bash
python SOC_Program.py
```

The tool will ask you to pick a time range, enter a search query, and choose how many results to show. After that, everything runs automatically.

**Browser GUI:**

```bash
python SOC_Program.py --web        # or: python web_app.py
```

That starts a local Flask server on <http://127.0.0.1:5001/> and opens your default browser. The web UI gives you:

- Light & dark themes (toggle in the bottom-left, or press `T`)
- A Search tab with timerange presets, Lucene examples, and keyboard shortcut <kbd>Ctrl</kbd>+<kbd>Enter</kbd> to run
- A SIEM-style Alerts tab with severity pills, source/destination flows, GeoIP, traffic stats, and expandable raw JSON
- One-click AbuseIPDB enrichment of any public source IP
- Gemini-powered AI analysis with an in-page redaction step before sending
- Drafting + submitting MantisBT tickets, with automatic project detection from the host name
- A built-in Manual tab with documentation and keyboard shortcuts

Useful flags for `--web`:

| Flag | What it does |
|------|--------------|
| `--host 0.0.0.0` | Bind on all interfaces (default is loopback only) |
| `--port 8000` | Use a different port (default 5001) |
| `--no-browser` | Don't auto-open a browser tab |
| `--debug` | Run Flask in debug mode (only when running `web_app.py` directly) |

---

## Example Queries

| Query | What it finds |
|-------|---------------|
| `event.kind:"alert"` | All alerts |
| `event.kind:"alert" AND suricata.eve.alert.severity:[1 TO 2]` | High severity alerts only |
| `suricata.alert.severity:1` | Critical severity only (sev 1 — highest priority) |
| `rule.name:ET* AND event.kind:"alert"` | Emerging Threats matches |
| `rule.name:(*MALWARE* OR *TROJAN*)` | Malware / Trojan alerts |
| `source.ip:"192.168.1.100" AND event.kind:"alert"` | Alerts from a specific IP |
| `destination.ip:"10.0.0.5" AND suricata.eve.alert.severity:1` | Severity 1 alerts targeting a specific destination |
| `rule.name:(*C2* OR *BOTNET* OR *EXPLOIT*)` | C2, botnet, or exploit activity |
| `event.kind:"alert" AND network.application:"dns"` | DNS-related alerts |
| `event.kind:"alert" AND _exists_:source.ip AND NOT source.ip:[10.0.0.0 TO 10.255.255.255] AND NOT source.ip:[192.168.0.0 TO 192.168.255.255]` | Alerts from external (non-RFC-1918) source IPs only |

> **Tip:** CIDR notation (e.g. `source.ip:10.0.0.0/8`) and IP wildcards (e.g. `source.ip:10.*`) are automatically converted to bracket range notation before the query is sent.

---

## Project Structure

```
SOC_Program.py          # CLI entry point; all core logic lives here
web_app.py              # Flask browser GUI (reuses SOC_Program.py logic)
requirements.txt        # Python dependencies
prompts/
  gemini_prompt.md      # Prompt template sent to Gemini AI (customizable)
secrets/
  wa_opensearch.example.json   # Template — copy to wa_opensearch.json
  abuseipdb.example.json       # Template — copy to abuseipdb.json
  gemini.example.json          # Template — copy to gemini.json
  mantis.example.json          # Template — copy to mantis.json
templates/              # Jinja2 templates for the web UI
static/                 # CSS / JS assets for the web UI
.github/workflows/
  bandit.yml            # Automated Bandit security scan on every push/PR
```

---

## Advanced Configuration (Environment Variables)

These are optional. The defaults work out of the box for the Pisces OpenSearch instance.

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_BASE_URL` | `https://pisces-opensearch.cyberrangepoulsbo.com` | OpenSearch or Dashboards base URL |
| `OPENSEARCH_INDEX_PATTERN` | `arkime_sessions3-*` | Index pattern to search |
| `OPENSEARCH_TRANSPORT` | `dev_tools` | `dev_tools` (Dashboards proxy) or `cluster` (direct REST API) |
| `OPENSEARCH_SEARCH_HTTP_METHOD` | `GET` | HTTP verb for the `_search` call (`GET` or `POST`) |
| `OPENSEARCH_PATH_PREFIX` | *(empty)* | Subpath prefix if the API is mounted under a path |
| `OPENSEARCH_DATA_SOURCE_ID` | *(empty)* | Optional multi-data-source Console param |
| `OPENSEARCH_DASHBOARDS_BASE_URL` | *(empty)* | Base URL for clickable Discover document links |
| `OPENSEARCH_DISCOVER_INDEX_PATTERN_ID` | *(empty)* | Saved-object ID of the data view for direct doc links |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Gemini model to use for AI analysis |
| `SOC_WEB_HOST` | `127.0.0.1` | Default host for `--web` |
| `SOC_WEB_PORT` | `5001` | Default port for `--web` |
| `DEBUG_PRINT_OPENSEARCH_REQUEST` | `0` | Set to `1` to print full request details before each query |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Missing secrets file` | Copy the example templates (see step 2 above) |
| `401 Unauthorized` | Check username/password in `secrets/wa_opensearch.json` |
| `403` from AbuseIPDB | Check your API key in `secrets/abuseipdb.json` |
| `Cannot reach OpenSearch` (DNS/connection error) | Make sure you are connected to the VPN |
| No results | Try a wider time range or a broader query |
| `404` from OpenSearch | Wrong path or index — try setting `OPENSEARCH_TRANSPORT=cluster` or changing `OPENSEARCH_INDEX_PATTERN` |
| Zero hits but no error | Run `GET _cat/indices?v` in Dev Tools to confirm the real index name, then set `OPENSEARCH_INDEX_PATTERN` |
| Gemini rate limit (429) | The free tier has per-minute limits; the tool retries automatically — wait a moment and try again, or set `GEMINI_MODEL` to a different model |

---

## CI

Every push and pull request to `main` runs a **Bandit** static security scan (`.github/workflows/bandit.yml`). Results appear under the **Security** tab of the repository.
