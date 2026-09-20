# Sentinel IOC Analyzer

A clean SOC-style IOC investigation dashboard for IPs, domains, URLs and file hashes.

## What it does

- Detects IOC type automatically
- Presents a polished investigation dashboard
- Demo enrichment works without API keys
- Optional server-side VirusTotal + AbuseIPDB enrichment through Vercel Functions
- WHOIS/RDAP-style context and DNS-oriented fields in the UI
- Investigation priority and evidence breakdown
- Splunk / KQL query generation
- Bulk IOC queue
- Analyst notes and exportable JSON report
- No secrets are shipped to the browser

## Run locally

```bash
npm install
npm run dev
```

Open the local Vite URL shown in the terminal.

## Build

```bash
npm run build
npm run preview
```

## Deploy to Vercel

1. Push this folder to GitHub.
2. Import the repository in Vercel.
3. Vercel detects Vite automatically.
4. Add `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY` under Project Settings → Environment Variables.
5. Redeploy.

Without keys, the app remains fully usable in Demo Mode with realistic sample results.

## API route

`/api/analyze.js` is a Vercel-compatible serverless function. It performs lightweight IOC detection and optional provider enrichment. Keep provider keys in Vercel Environment Variables, never in frontend code.

## Production roadmap

- PostgreSQL/Supabase investigation history
- Real MXToolbox integration if you have a licensed API
- TheHive case creation
- Authentication / RBAC
- SIEM connectors
- Background jobs and rate-limit queues
- Audit logging
