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

That starts a local Flask server on <http://127.0.0.1:5000/> and opens your default browser. The web UI gives you:

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
| `--port 8000` | Use a different port (default 5000) |
| `--no-browser` | Don't auto-open a browser tab |

---

## Example Queries

| Query | What it finds |
|-------|---------------|
| `event.kind:"alert"` | All alerts |
| `event.kind:"alert" AND suricata.eve.alert.severity:[1 TO 2]` | High severity alerts only |
| `rule.name:ET* AND event.kind:"alert"` | Emerging Threats matches |
| `rule.name:(*MALWARE* OR *TROJAN*)` | Malware / Trojan alerts |
| `source.ip:"192.168.1.100" AND event.kind:"alert"` | Alerts from a specific IP |
| `rule.name:(*C2* OR *BOTNET* OR *EXPLOIT*)` | C2, botnet, or exploit activity |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Missing secrets file` | Copy the example templates (see step 2 above) |
| `401 Unauthorized` | Check username/password in `secrets/wa_opensearch.json` |
| `403` from AbuseIPDB | Check your API key in `secrets/abuseipdb.json` |
| No results | Try a wider time range or a broader query |
