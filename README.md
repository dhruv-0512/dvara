# dvara

> High-speed malicious URL detection using a Bloom Filter accelerated verification pipeline backed by PostgreSQL, Redis, FastAPI, and AWS infrastructure.

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

[→ Live Demo](http://13.61.0.125:8000)

---

## What is dvara?

dvara is a Python CLI and library for detecting malicious URLs using a Bloom Filter — the same probabilistic data structure used internally by Chrome Safe Browsing.

It ingests threat feeds from URLhaus, PhishTank, OpenPhish, and CERT Polska (268,970+ URLs), stores them in a 5 MB Bloom Filter, and checks any URL in under 1ms — without touching a database for clean URLs.

---

## Architecture

```
Threat Intelligence Feeds
→ Normalization & Deduplication
→ Bloom Filter Generation (5.14MB, 0.1% FPR)
→ Saved to PostgreSQL verification database

dvara check [url]  (online mode)
→ FastAPI backend
→ Hash URL → check bit positions in Bloom Filter
→ All bits OFF → ✅ CLEAN instantly (DB never touched)
→ All bits ON  → query PostgreSQL confirmed_urls table
→ Found        → 🚨 MALICIOUS + source + category
→ Not found    → SUSPICIOUS (false positive)

dvara check [url] --offline
→ Loads filter from ~/.dvara/filter.bin
→ Checks locally, zero network calls
→ dvara update to refresh
```

### Two-stage design

| Stage | What | Latency | When |
|-------|------|---------|------|
| 1 — Bloom Filter | In-memory bit lookups | ~0.003ms | Every request |
| 2 — PostgreSQL | confirmed_urls table lookup | 1–3ms | Only on bloom hits |

Clean URLs never touch the database. False negatives are mathematically impossible.

---

## Benchmarks

| Metric | Result |
|--------|--------|
| Bloom lookup latency | ~0.003ms (3 μs) |
| Throughput | ~145,000 URLs/sec |
| Threats indexed | 268,970+ |
| Filter size | 5.14 MB |
| Peak RAM usage | ~10.53 MB |
| Bloom capacity | 3,000,000 URLs |
| False negatives | 0 observed |
| False positives | 0 / 100,000 tested |

> Benchmark latency refers to local in-memory Bloom Filter checks. Network requests naturally incur additional latency.

---

## Installation

```bash
pip install dvara
```

dvara ships with a built-in filter. After installing, offline checks work immediately — no API key, no Docker, no setup:

```bash
dvara check https://suspicious-site.com --offline
```

### For running the backend server

```bash
pip install dvara[server]
```

---

## CLI Usage

```bash
# Check a URL (online mode — hits API)
dvara check https://suspicious-site.com

# Check a URL (offline mode — local filter, zero network)
dvara check https://suspicious-site.com --offline

# Show filter and API stats
dvara stats

# Update local filter cache
dvara update

# Run ingestion manually
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
- **PostgreSQL** — confirmed URLs table
- **Redis** — cache layer

### Manually

```bash
pip install dvara[server]

# Build the filter
python -m dvara.ingestion

# Start the API
uvicorn dvara.app:app --reload
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
- Bit array size: **m** = -(n × ln(p)) / (ln(2))² = ~43M bits = **5.2 MB**
- Hash count: **k** = (m/n) × ln(2) = **10 hash functions**
- Hash algorithm: MurmurHash3 with seeds 0–9

3M URLs in a Python hash set = 500MB+. A Bloom Filter at 0.1% FPR = 5.2MB. False positives just trigger the DB confirm — acceptable. False negatives are mathematically impossible.

---

## Threat Feed Sources

| Feed | Format | URLs |
|------|--------|------|
| [URLhaus](https://urlhaus.abuse.ch) | CSV | ~26,000 |
| [PhishTank](https://phishtank.org) | JSON (gzipped) | ~59,000 |
| [OpenPhish](https://openphish.com) | Plaintext | ~300 |
| [CERT Polska](https://cert.pl) | JSON | ~183,000 |

---

## Infrastructure

Deployed as a fully self-hosted cybersecurity service on AWS. Migrated from Render + Supabase + Upstash to a single EC2 instance — full control, no managed service costs.

```
AWS EC2
├── FastAPI          (REST API)
├── PostgreSQL       (verification database)
├── Redis            (cache layer)
├── Bloom Filter     (in-memory URL index)
└── Docker Compose   (orchestration)
```

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

*Dvara* (द्वार) is the Sanskrit word for gateway or door. Every URL is a gateway — dvara stands at that door and decides what gets through.

---

## License

MIT
