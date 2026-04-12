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

```bash
python SOC_Program.py
```

The tool will ask you to pick a time range, enter a search query, and choose how many results to show. After that, everything runs automatically.

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
