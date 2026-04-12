# Secrets

This folder contains **local-only** secrets (ignored by git) and **safe templates** (committed).

## Safe to commit
- `wa_opensearch.example.json`
- `wa_kibana.example.json` (legacy filename; prefer `wa_opensearch.json`)
- `abuseipdb.example.json`

## Local only (DO NOT COMMIT)
- `wa_opensearch.json` (preferred)
- `wa_kibana.json` (still supported if `wa_opensearch.json` is absent)
- `abuseipdb.json`

## Setup
1. Copy the templates:
   - `wa_opensearch.example.json` → `wa_opensearch.json`
   - `abuseipdb.example.json` → `abuseipdb.json`
2. Fill in real values in the `*.json` files.

If you already have `wa_kibana.json` from the old stack, you can keep using it until you rename/copy to `wa_opensearch.json`.

Git protection is handled by the repo `.gitignore` which ignores `secrets/*.json` but allows `secrets/*.example.json`.
