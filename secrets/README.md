# Secrets

This folder contains **local-only** secrets (ignored by git) and **safe templates** (committed).

## Safe to commit

- `wa_opensearch.example.json`
- `abuseipdb.example.json`
- `gemini.example.json`
- `mantis.example.json`

## Local only (DO NOT COMMIT)

- `wa_opensearch.json`
- `abuseipdb.json`
- `gemini.json`
- `mantis.json`

## Setup

1. Copy the templates:
   - `wa_opensearch.example.json` → `wa_opensearch.json`
   - `abuseipdb.example.json` → `abuseipdb.json`
   - `gemini.example.json` → `gemini.json` *(optional — needed for AI analysis)*
   - `mantis.example.json` → `mantis.json` *(optional — needed for ticket submission)*
2. Fill in real values in the `*.json` files.

Git protection is handled by the repo `.gitignore` which ignores `secrets/*.json` but allows `secrets/*.example.json`.
