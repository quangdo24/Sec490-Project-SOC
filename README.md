<<<<<<< HEAD
# Kibana + AbuseIPDB SOC Tool

A command-line SOC (Security Operations Center) tool that queries **Suricata alerts from Kibana/Elasticsearch** and enriches source IPs with **AbuseIPDB** threat intelligence — all from your terminal.
=======
# OpenSearch + AbuseIPDB SOC Tool

A command-line SOC (Security Operations Center) tool that queries **Suricata alerts from OpenSearch** and enriches source IPs with **AbuseIPDB** threat intelligence — all from your terminal.
>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)

---

## What It Does

<<<<<<< HEAD
1. **Query Kibana/Elasticsearch** for recent Suricata IDS alerts (using Lucene syntax)
2. **Display color-coded alert details** — signature, severity, network flow, GeoIP, traffic stats, DNS, and a direct Kibana link
3. **Extract public source IPs** from the alerts
4. **Check each IP against AbuseIPDB** and display a threat report (abuse score, ISP, location, report count)
5. **Manual IP lookup mode** — skip Kibana and check any IP(s) directly in AbuseIPDB
=======
1. **Query OpenSearch** for recent Suricata IDS alerts (using Lucene syntax)
2. **Display color-coded alert details** — signature, severity, network flow, GeoIP, traffic stats, DNS, and an optional OpenSearch Dashboards link
3. **Extract public source IPs** from the alerts
4. **Check each IP against AbuseIPDB** and display a threat report (abuse score, ISP, location, report count)
5. **Manual IP lookup mode** — skip OpenSearch and check any IP(s) directly in AbuseIPDB
>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)

---

## Project Structure

```
SOC_Program_SEC490/
├── SOC_Program.py                  # Main program
├── README.md                       # This file
└── secrets/
    ├── README.md                   # Setup instructions for secrets
<<<<<<< HEAD
    ├── wa_kibana.example.json      # Template for Kibana credentials
    ├── abuseipdb.example.json      # Template for AbuseIPDB API key
    ├── wa_kibana.json              # Your Kibana credentials (git-ignored)
=======
    ├── wa_opensearch.example.json  # Template for OpenSearch credentials
    ├── abuseipdb.example.json      # Template for AbuseIPDB API key
    ├── wa_opensearch.json          # Your OpenSearch credentials (git-ignored)
>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)
    └── abuseipdb.json              # Your AbuseIPDB API key (git-ignored)
```

---

## Setup

### 1. Install Python Dependencies

```bash
pip install requests urllib3
```

### 2. Configure Secrets

Copy the example templates and fill in your real credentials:

```bash
cp secrets/wa_opensearch.example.json secrets/wa_opensearch.json
cp secrets/abuseipdb.example.json secrets/abuseipdb.json
```

Edit `secrets/wa_opensearch.json`:
```json
{
  "username": "YOUR_OPENSEARCH_USERNAME",
  "password": "YOUR_OPENSEARCH_PASSWORD"
}
```

The program defaults to `https://pisces-opensearch.cyberrangepoulsbo.com` with index pattern `arkime_sessions3-*`. Override with environment variables if your deployment differs:

- **`OPENSEARCH_TRANSPORT`** — `dev_tools` (**default**) uses the same **Dev Tools console proxy** as the UI: `POST …/api/console/proxy?path=/…/_search&method=GET` with Basic auth and `osd-xsrf` (like running `GET _search { … }` in Dev Tools). Use `cluster` only if you call the OpenSearch REST API directly on this host.
- `OPENSEARCH_BASE_URL` — OpenSearch **Dashboards** URL when using `dev_tools` (same origin as `/app/dev_tools`), or cluster root when using `cluster`.
- `OPENSEARCH_INDEX_PATTERN` — comma-separated patterns (default `malcolm_beats_*,arkime_session3-*`). Becomes the `path` segment `/<pattern>/_search` in Dev Tools mode.
- `OPENSEARCH_DATA_SOURCE_ID` — optional; set if Dev Tools sends a `dataSourceId` query parameter (multi-cluster Dashboards).
- `OPENSEARCH_TIME_FIELDS` — comma-separated date fields for the time filter (default `@timestamp,timestamp`). OR across fields. Set `OPENSEARCH_SKIP_TIME_RANGE=1` to send **only** your Lucene string (no time clause) so you can match Dev Tools exactly, then turn the time filter back on.
- `OPENSEARCH_SORT` — `none` (default, safest for multi-index), `timestamp`, or `doc`.
- `OPENSEARCH_ECHO_SEARCH_BODY=1` — print the exact JSON request body so you can paste it under `GET …/_search` in Dev Tools and compare.
- **`cluster` mode only:** `OPENSEARCH_PATH_PREFIX`, `OPENSEARCH_RAW_INDEX_IN_URL`, and `OPENSEARCH_SEARCH_HTTP_METHOD` (`GET` vs `POST` to the cluster).

Queries use Lucene `query_string` like Dev Tools, except a **whole line** that is only `event.kind:…` (with or without spaces after `:` or quotes) is sent as a **`term`** on `event.kind` / `event.kind.keyword` so it matches the GUI. Set `OPENSEARCH_USE_TERM_FOR_EVENT_KIND=0` to force raw `query_string` only. Spaces after `:` before a quoted value are normalized (e.g. `event.kind: "alert"` → `event.kind:"alert"`).

Optional: set `OPENSEARCH_DISCOVER_INDEX_PATTERN_ID` so each alert prints a clickable Discover URL (with `dev_tools` transport, the link host defaults to `OPENSEARCH_BASE_URL`). Override the link host with `OPENSEARCH_DASHBOARDS_BASE_URL` if it differs.

Edit `secrets/abuseipdb.json`:
```json
{
  "api_key": "YOUR_ABUSEIPDB_API_KEY"
}
```

> **Note:** The real `*.json` files are git-ignored so your credentials are never pushed to GitHub.

### 3. Get an AbuseIPDB API Key

1. Sign up at [abuseipdb.com](https://www.abuseipdb.com/)
2. Go to your account → API → Create Key
3. Paste it into `secrets/abuseipdb.json`

---

## Usage

### Interactive Mode (recommended)

```bash
python3 SOC_Program.py
```

You'll see a menu:
<<<<<<< HEAD
- **Option 1** — Query Kibana for Suricata alerts, then check extracted IPs in AbuseIPDB
- **Option 2** — Manually enter IP address(es) to check in AbuseIPDB

When using Option 1 (Kibana mode), the tool will prompt you to:
=======
- **Option 1** — Query OpenSearch for Suricata alerts, then check extracted IPs in AbuseIPDB
- **Option 2** — Manually enter IP address(es) to check in AbuseIPDB

When using Option 1 (OpenSearch mode), the tool will prompt you to:
>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)
- Select a **time range** (15m, 1h, 6h, 24h, 48h, 7d, 30d, or custom)
- Enter a **custom Lucene query** (or use the default)
- Choose **how many results** to return

### CLI Mode

```bash
<<<<<<< HEAD
# Check specific IPs directly (skips Kibana)
=======
# Check specific IPs directly (skips OpenSearch)
>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)
python3 SOC_Program.py --ip 8.8.8.8
python3 SOC_Program.py --ip 1.2.3.4 --ip 5.6.7.8
python3 SOC_Program.py --ip "1.2.3.4,5.6.7.8,9.10.11.12"

# Change AbuseIPDB lookback window (default: 90 days)
python3 SOC_Program.py --ip 8.8.8.8 --max-age-days 30

# Verbose AbuseIPDB output
python3 SOC_Program.py --ip 8.8.8.8 --abuse-verbose
```

---

## Example Lucene Queries (OpenSearch mode)

| Query | Description |
|-------|-------------|
| `event_type:"alert"` | All alerts |
| `event_type:"alert" AND alert.severity:[0 TO 1]` | High severity only |
| `event_type:"alert" AND alert.signature:ET*` | Emerging Threats alerts |
| `event_type:"alert" AND alert.signature:(*MALWARE* OR *TROJAN*)` | Malware / Trojan alerts |
| `src_ip:"192.168.1.100" AND event_type:"alert"` | Alerts from a specific source IP |
| `event_type:"alert" AND alert.signature:(*C2* OR *BOTNET* OR *EXPLOIT*)` | C2, botnet, or exploit activity |
| `event_type:"dns" AND dns.query.rrname:*.ru` | DNS queries to .ru domains |

---

## Output

### Suricata Alert Output Includes:
- Timestamp and severity (color-coded: red = critical, yellow = medium, green = low)
- Alert signature, SID, and category
- Network flow (source IP:port → dest IP:port)
- Protocol and application protocol
- GeoIP location (if available)
- Traffic stats (packets and bytes in each direction)
- Host info and DNS queries (if available)
- Document reference (index + id), or a clickable Discover link if Dashboards env vars are set

### AbuseIPDB Report Includes:
- Abuse confidence score with visual bar (color-coded: red = critical, yellow = high, blue = moderate, green = low)
- Risk label (CRITICAL / HIGH / MODERATE / LOW)
- Country, ISP, domain, and usage type
- Total reports and last reported date
- Which Suricata match(es) triggered the lookup

---

## How It Works (Architecture)

```
User runs SOC_Program.py
        │
<<<<<<< HEAD
        ├── Mode 1: Kibana Query
        │     │
        │     ├── Builds Elasticsearch query (Lucene + time range)
        │     ├── Sends POST to Kibana API (Basic Auth)
=======
        ├── Mode 1: OpenSearch query
        │     │
        │     ├── Builds search query (Lucene + time range)
        │     ├── Sends POST to Dashboards `/api/console/proxy` (default), or direct `_search` if `OPENSEARCH_TRANSPORT=cluster`
>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)
        │     ├── Displays color-coded Suricata alert hits
        │     ├── Extracts unique public source IPs
        │     └── Checks each IP against AbuseIPDB API
        │
        └── Mode 2: Manual IP Lookup
              │
              ├── Validates and de-dupes input IPs
              ├── Skips private/invalid IPs
              └── Checks each IP against AbuseIPDB API
```

---

## Technologies Used

- **Python 3** — main language
<<<<<<< HEAD
- **Kibana / Elasticsearch** — Suricata alert data source
=======
- **OpenSearch** — Suricata alert data source
>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)
- **Suricata IDS** — intrusion detection system generating the alerts
- **AbuseIPDB API** — IP threat intelligence enrichment
- **Lucene Query Syntax** — flexible alert filtering
- **ANSI Colors** — clean, readable terminal output

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Missing secrets file` | Copy the example templates (see Setup step 2) |
| `NameResolutionError` for AbuseIPDB | Check your internet connection / DNS |
| `401 Unauthorized` from OpenSearch | Verify username/password in `secrets/wa_opensearch.json` (or legacy `wa_kibana.json`) |
| `403` from AbuseIPDB | Verify your API key in `secrets/abuseipdb.json` |
| No alerts returned | Try a wider time range or broader query |
| `404` from OpenSearch | With **`dev_tools`** (default), check `OPENSEARCH_INDEX_PATTERN` and credentials. With **`cluster`**, check path prefix / wildcard encoding / GET vs POST (see env vars above) |
