# dvara

> High-speed malicious URL detection using a Bloom Filter accelerated verification pipeline backed by PostgreSQL, Redis, FastAPI, and AWS infrastructure.

[![PyPI version](https://badge.fury.io/py/dvara.svg)](https://badge.fury.io/py/dvara)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[Live Demo](http://13.61.0.125:8000)
```bash
pip install dvara

dvara check https://google.com
✅ CLEAN | 0.03ms | online

dvara check "http://xn--90abegbttpjb3bzb2j.xn--p1ai/doc/En/ACCOUNT/Auditor-of-State-Notification-of-EFT-Deposit"
🚨 MALICIOUS | 213.2ms | online
```

---

# What is dvara?

dvara is a malicious URL detection platform inspired by large-scale safe browsing systems.

It combines:

* Probabilistic Bloom Filters
* PostgreSQL verification
* Redis caching
* FastAPI APIs
* AWS-hosted infrastructure

to provide extremely fast malicious URL lookups while maintaining a small memory footprint.

Threat intelligence is continuously aggregated from:

* URLhaus
* PhishTank
* OpenPhish
* CERT Polska

The current dataset contains:

```text
268,970+ confirmed malicious URLs
```

compressed into a Bloom Filter occupying only:

```text
5.14 MB
```

Most benign URLs are resolved entirely in memory without touching the database.

Only Bloom Filter hits trigger PostgreSQL verification.

---

# Key Features

* Bloom Filter accelerated malicious URL detection
* Two-stage verification architecture
* PostgreSQL-backed confirmation database
* Redis integration
* FastAPI REST API
* Python CLI client
* AWS-hosted deployment
* Dockerized infrastructure
* Threat intelligence feed aggregation
* Memory-efficient large-scale URL indexing

---

# Architecture

```text
Threat Intelligence Feeds
        ↓
Normalization & Deduplication
        ↓
Bloom Filter Generation
        ↓
PostgreSQL Verification Database
        ↓
FastAPI Backend
        ↓
CLI / REST API
```

## URL Check Pipeline

```text
dvara check [url]
        ↓
Bloom Filter Lookup
        ↓
No Match
        └──► CLEAN

Possible Match
        ↓
SHA256(URL)
        ↓
PostgreSQL Verification
        ↓
MALICIOUS / SUSPICIOUS
```

---

# Infrastructure

Dvara is deployed as a fully self-hosted cybersecurity service on AWS.

Production architecture:

```text
AWS EC2
├── FastAPI API
├── PostgreSQL Database
├── Redis Cache
├── Bloom Filter Storage
└── Docker Compose
```

Infrastructure stack:

| Component            | Technology              |
| -------------------- | ----------------------- |
| API Server           | FastAPI                 |
| Infrastructure       | AWS EC2                 |
| Containerization     | Docker + Docker Compose |
| Database             | PostgreSQL              |
| Cache Layer          | Redis                   |
| URL Index            | Bloom Filter            |
| Package Distribution | PyPI                    |

The deployment is fully containerized and operates without managed database or cache providers.

Features:

* Self-hosted AWS deployment
* Dockerized infrastructure
* PostgreSQL-backed malicious URL verification
* Redis caching layer
* Bloom Filter accelerated lookups
* Persistent volume storage
* REST API + CLI support

---

# Why Bloom Filters?

Traditional hash sets containing millions of URLs require hundreds of megabytes of memory.

Bloom Filters provide:

* Massive memory compression
* Constant-time lookups
* Zero false negatives
* Extremely high throughput

Tradeoff:

* Small false positive probability

False positives are resolved through PostgreSQL verification.

---

# Benchmarks

| Metric                     | Result             |
| -------------------------- | ------------------ |
| Local Bloom Lookup Latency | ~0.003 ms (3 μs)   |
| Throughput                 | ~145k URLs/sec     |
| Indexed Malicious URLs     | 268,970+           |
| Filter Size                | 5.14 MB            |
| Peak RAM Usage             | ~10.53 MB          |
| False Negatives            | 0 observed         |
| False Positives            | 0 / 100,000 tested |
| Bloom Capacity             | 3,000,000 URLs     |

> Benchmark latency refers to local in-memory Bloom Filter checks. Network requests naturally incur additional latency.
