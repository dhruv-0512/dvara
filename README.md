# dvara

> High-speed malicious URL detection using a Bloom Filter. Checks 3 million URLs in 5MB of RAM.

[![PyPI version](https://badge.fury.io/py/dvara.svg)](https://badge.fury.io/py/dvara)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

```bash
pip install dvara

dvara check https://suspicious-site.com
🚨 MALICIOUS | urlhaus | malware_download | 2.5ms | online

dvara check https://google.com
✅ CLEAN | 0.1ms | online
```

---

## What is dvara?

dvara is a Python CLI and library for detecting malicious URLs using a **Bloom Filter** — the same probabilistic data structure used internally by Chrome Safe Browsing.

It ingests threat feeds from URLhaus, PhishTank, and OpenPhish (~86,000 URLs updated daily), stores them in a 5MB Bloom Filter, and checks any URL in under 1ms — without touching a database for clean URLs.

---

## Architecture

```
Daily ingestion job
→ Pulls URLhaus + PhishTank + OpenPhish (~86k–3M URLs)
→ Builds Bloom Filter (5.2MB, 0.1% FPR)
→ Saves to ~/.dvara/filter.bin

dvara check [url]  (online mode)
→ FastAPI backend
→ Hash URL → check 10 bit positions in Bloom Filter
→ All bits OFF → CLEAN instantly (0.1ms, DB never touched)
→ All bits ON  → query PostgreSQL confirmed_urls table
→ Found        → MALICIOUS + source + category
→ Not found    → SUSPICIOUS (false positive)

dvara check [url] --offline
→ Loads filter from ~/.dvara/filter.bin
→ Checks locally, zero network calls
→ dvara update to refresh
```

### Two-stage design (the key insight)

| Stage | What | Latency | When |
|-------|------|---------|------|
| 1 — Bloom Filter | Redis bitstring, 10 hash lookups | 0.1ms | Every request |
| 2 — PostgreSQL | confirmed_urls table lookup | 1–3ms | Only on bloom hits |

Clean URLs **never touch the database**. False negatives are mathematically impossible.

---

## Benchmarks

| Metric | Result |
|--------|--------|
| Clean URL check | 0.1ms |
| Malicious URL check (full pipeline) | 2.5ms |
| URLs stored | 85,976 (scales to 3M) |
| Filter size | 5.14 MB |
| False negative rate | 0% (guaranteed) |
| Target false positive rate | 0.1% |
| Actual false positive rate | ~0% at current fill |

---

## Installation

```bash
pip install dvara
```
## Quick Start (no server needed)

dvara ships with a built-in filter. After installing, offline checks work immediately:

    dvara check https://suspicious-site.com --offline

No API key, no Docker, no setup. Just install and check.


### For running the backend server

```bash
pip install dvara[server]
```

---

## CLI Usage

### Check a URL (online mode — hits API)
```bash
dvara check https://suspicious-site.com
```

### Check a URL (offline mode — local filter, zero network)
```bash
dvara check https://suspicious-site.com --offline
```

### Show filter and API stats
```bash
dvara stats
```

### Update local filter cache
```bash
dvara update
```

### Run ingestion manually
```bash
dvara ingest
dvara ingest --dry-run
```

---

## Running the Backend

### With Docker Compose (recommended)

```bash
git clone https://github.com/dhruv-0512/dvara
cd dvara
docker compose up --build
```

This starts:
- **FastAPI** — API server on port 8000
- **Redis** — Bloom filter bitstring cache
- **PostgreSQL** — confirmed URLs table

### Manually

```bash
pip install dvara[server]

# Build the filter
python -m dvara.ingestion

# Start the API
python -m uvicorn dvara.app:app --reload
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/check?url=...` | GET | Two-stage URL check |
| `/api/confirm?url=...` | GET | Direct DB lookup |
| `/api/stats` | GET | Filter + connection stats |
| `/api/reload` | POST | Reload filter from disk |
| `/health` | GET | Health check |

### Example response

```json
{
  "url": "http://110.36.95.252:49267/bin.sh",
  "result": "MALICIOUS",
  "source": "urlhaus",
  "category": "malware_download",
  "latency_ms": 2.5,
  "stage": "db",
  "checked_at": "2026-05-02T13:01:04.767776+00:00"
}
```

---

## The Math

- **n** = 3,000,000 URLs, **p** = 0.001 (0.1% FPR)
- Bit array size: **m** = -(n × ln(p)) / (ln(2))² = ~43M bits = **5.2MB**
- Hash count: **k** = (m/n) × ln(2) = **10 hash functions**
- Hash algorithm: MurmurHash3 with seeds 0–9

### Why Bloom Filter and not a hash set?

3M URLs in a Python hash set = 500MB+. A Bloom Filter at 0.1% FPR = 5.2MB. False positives just trigger the DB confirm — acceptable. False negatives are mathematically impossible. The Bloom Filter is the right tool.

### Why Redis and not disk?

Multiple FastAPI workers need to read the same filter simultaneously. Disk requires locking. Redis bitstring is shared memory across all workers — horizontal scaling for free.

---

## Threat Feed Sources

| Feed | Format | URLs |
|------|--------|------|
| [URLhaus](https://urlhaus.abuse.ch) | CSV | ~26,000 |
| [PhishTank](https://phishtank.org) | JSON (gzipped) | ~59,000 |
| [OpenPhish](https://openphish.com) | Plaintext | ~300 |

---

## Project Structure

```
dvara/
├── bloom.py        ← BloomFilter class (core)
├── ingestion.py    ← Fetch feeds, build filter
├── app.py          ← FastAPI backend
├── cli.py          ← Click CLI commands
└── config.py       ← Constants and env vars
```

---
## Why "dvara"?

*Dvara* (द्वार) is the Sanskrit word for **gateway** or **door**.

Every URL is a gateway — dvara stands at that door and decides what gets through.


---

## License

MIT
