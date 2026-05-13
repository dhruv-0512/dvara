# dvara

> High-speed malicious URL detection using a probabilistic Bloom Filter pipeline.

[![PyPI version](https://badge.fury.io/py/dvara.svg)](https://badge.fury.io/py/dvara)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-Visit-brightgreen)](https://dvara-t19n.onrender.com/)

```bash
pip install dvara

dvara check https://google.com
✅ CLEAN | 0.03ms | online

dvara check "http://xn--90abegbttpjb3bzb2j.xn--p1ai/doc/En/ACCOUNT/Auditor-of-State-Notification-of-EFT-Deposit"
🚨 MALICIOUS | 213.2ms | online
```

---

# What is dvara?

dvara is a Python CLI and backend system for malicious URL detection using a probabilistic Bloom Filter architecture inspired by systems like Google Safe Browsing.

It ingests live threat intelligence feeds from:

* URLhaus
* PhishTank
* OpenPhish
* Cert.pl

and currently indexes:

```text
268,970 confirmed malicious URLs
```

inside a compressed Bloom Filter occupying only:

```text
5.14 MB
```

Most clean URLs are resolved entirely in-memory without touching the database.

Only Bloom filter hits trigger PostgreSQL confirmation.

---

# Architecture

```text
Threat feeds
    ↓
URL normalization + deduplication
    ↓
Bloom Filter generation
    ↓
PostgreSQL confirmed_urls database
    ↓
FastAPI backend deployment
    ↓
CLI / API URL checks
```

## URL check pipeline

```text
dvara check [url]
    ↓
Bloom Filter lookup (~3µs local)
    ↓
No match
    → CLEAN instantly

Possible match
    ↓
SHA256(url)
    ↓
PostgreSQL confirmation lookup
    ↓
MALICIOUS or SUSPICIOUS
```

---

# Why Bloom Filters?

Traditional hash sets for millions of URLs consume hundreds of MBs of RAM.

Bloom Filters allow:

* massive memory compression
* constant-time lookups
* zero false negatives
* extremely high throughput

Tradeoff:

* small false positive probability

False positives are resolved using PostgreSQL confirmation.

---

# Benchmarks

Generated using:

```bash
python -m dvara.benchmarks
```

| Metric                     | Result             |
| -------------------------- | ------------------ |
| Local Bloom lookup latency | ~0.003ms (3µs)     |
| Throughput                 | ~145k URLs/sec     |
| Indexed malicious URLs     | 268,970            |
| Filter size                | 5.14 MB            |
| Peak RAM usage             | ~10.53 MB          |
| False negatives            | 0 observed         |
| False positives            | 0 / 100,000 tested |
| Bloom capacity             | 3,000,000 URLs     |

> Benchmark latency refers to local in-memory Bloom Filter checks. Network/API requests are naturally slower due to HTTP and database confirmation stages.

---

# Threat Intelligence Sources

| Feed      | Type                   |
| --------- | ---------------------- |
| URLhaus   | Malware URLs           |
| PhishTank | Verified phishing URLs |
| OpenPhish | Active phishing feeds  |
| Cert.pl   | Malicious domains      |

---

# Installation

## CLI only

```bash
pip install dvara
```

## Backend/server dependencies

```bash
pip install dvara[server]
```

---

# CLI Usage

## Check URL (online)

```bash
dvara check https://example.com
```

## Check URL (offline)

```bash
dvara check https://example.com --offline
```

## Show stats

```bash
dvara stats
```

## Update local filter

```bash
dvara update
```

## Run ingestion

```bash
dvara ingest
```

---

# Running the Backend

## Docker Compose

```bash
git clone https://github.com/dhruv-0512/dvara
cd dvara

docker compose up --build
```

Services:

* FastAPI
* PostgreSQL
* Redis

---

## Manual setup

```bash
pip install dvara[server]

python -m dvara.ingestion

uvicorn dvara.app:app --reload
```

---

# API Endpoints

| Endpoint       | Description              |
| -------------- | ------------------------ |
| `/api/check`   | Full two-stage URL check |
| `/api/confirm` | Direct PostgreSQL lookup |
| `/api/stats`   | Bloom + backend stats    |
| `/api/reload`  | Reload filter            |
| `/health`      | Health check             |

---

# Example API Response

```json
{
  "url": "http://malicious-site.com",
  "result": "MALICIOUS",
  "latency_ms": 213.2,
  "stage": "db",
  "checked_at": "2026-05-09T09:08:32.663182+00:00"
}
```

---

# Project Structure

```text
dvara/
├── app.py
├── bloom.py
├── cli.py
├── config.py
├── ingestion.py
├── benchmarks.py
```

---

# Technical Details

## Bloom Filter Parameters

```text
Capacity:            3,000,000 URLs
Target FPR:          0.1%
Hash functions (k):  10
Current fill ratio:  ~6%
Filter size:         5.14 MB
```

## Hashing

* MurmurHash3 for Bloom lookups
* SHA256 for PostgreSQL confirmation keys

---

# Deployment Stack

| Component       | Service                          |
| --------------- | -------------------------------- |
| API             | Render                           |
| Live Demo       | https://dvara-t19n.onrender.com/ |
| Database        | Supabase PostgreSQL              |
| Redis           | Upstash Redis                    |
| Package hosting | PyPI                             |

---

# Why "dvara"?

*dvara* (द्वार) is the Sanskrit word for:

> gateway / doorway

Every URL is a gateway.

dvara stands at that gateway and decides what gets through.

---

# Security Note

dvara is intended for defensive cybersecurity research, malicious URL analysis, and educational purposes.

While the system uses real threat intelligence feeds and probabilistic detection techniques, it should not be treated as a replacement for enterprise secure web gateways, antivirus engines, or production threat prevention systems.

# License

MIT
