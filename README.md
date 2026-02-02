# Secrets

This folder contains **local-only** secrets (ignored by git) and **safe templates** (committed).

## Safe to commit
- `wa_kibana.example.json`
- `abuseipdb.example.json`

## Local only (DO NOT COMMIT)
- `wa_kibana.json`
- `abuseipdb.json`

## Setup
1. Copy the templates:
   - `wa_kibana.example.json` → `wa_kibana.json`
   - `abuseipdb.example.json` → `abuseipdb.json`
2. Fill in real values in the `*.json` files.

Git protection is handled by the repo `.gitignore` which ignores `secrets/*.json` but allows `secrets/*.example.json`.
