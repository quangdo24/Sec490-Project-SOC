# Secrets

This folder contains **local-only** secrets (ignored by git) and **safe templates** (committed).

## Safe to commit
<<<<<<< HEAD
- `wa_kibana.example.json`
- `abuseipdb.example.json`

## Local only (DO NOT COMMIT)
- `wa_kibana.json`
=======
- `wa_opensearch.example.json`
- `wa_kibana.example.json` (legacy filename; prefer `wa_opensearch.json`)
- `abuseipdb.example.json`

## Local only (DO NOT COMMIT)
- `wa_opensearch.json` (preferred)
- `wa_kibana.json` (still supported if `wa_opensearch.json` is absent)
>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)
- `abuseipdb.json`

## Setup
1. Copy the templates:
<<<<<<< HEAD
   - `wa_kibana.example.json` → `wa_kibana.json`
   - `abuseipdb.example.json` → `abuseipdb.json`
2. Fill in real values in the `*.json` files.

=======
   - `wa_opensearch.example.json` → `wa_opensearch.json`
   - `abuseipdb.example.json` → `abuseipdb.json`
2. Fill in real values in the `*.json` files.

If you already have `wa_kibana.json` from the old stack, you can keep using it until you rename/copy to `wa_opensearch.json`.

>>>>>>> 93b0a59 (Implemented OpenSearch and deprecated Kibana)
Git protection is handled by the repo `.gitignore` which ignores `secrets/*.json` but allows `secrets/*.example.json`.
