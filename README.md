# dvara

> *dvāra* — Sanskrit for gateway. A filter at the door, not behind it.

[![PyPI version](https://badge.fury.io/py/dvara.svg)](https://badge.fury.io/py/dvara)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

High-speed malicious URL detection. Bloom Filter in memory. PostgreSQL verification behind it. 268,970+ threats indexed in 5 MB.

```bash
pip install dvara
```

```bash
$ dvara check https://google.com
✅ CLEAN | 0.03ms | online

$ dvara check "http://xn--90abegbttpjb3bzb2j.xn--p1ai/doc/En/ACCOUNT/Auditor-of-State-Notification-of-EFT-Deposit"
🚨 MALICIOUS | 213.2ms | online
```

[→ Live Demo](http://13.61.0.125:8000)

---

## Benchmarks

| Metric | Result |
|---|---|
| Bloom lookup latency | ~0.003 ms (3 μs) |
| Throughput | ~145,000 URLs/sec |
| Threats indexed | 268,970+ |
| Filter size | 5.14 MB |
| Peak RAM usage | ~10.53 MB |
| Bloom capacity | 3,000,000 URLs |
| False negatives | 0 observed |
| False positives | 0 / 100,000 tested |

> Benchmark latency refers to local in-memory Bloom Filter checks. Network requests naturally incur additional latency.

---

## Detection Pipeline

```
URL in
  └─► Bloom Filter
        ├─► No match   →  ✅ CLEAN  (never touches the database)
        └─► Hit
              └─► SHA256(URL)
                    └─► PostgreSQL verification
                          └─► 🚨 MALICIOUS / SUSPICIOUS
```

Most benign URLs are resolved entirely in memory. False positives from the filter are caught by verified hash lookup.

---

## Why Bloom Filters?

Traditional hash sets containing millions of URLs require hundreds of megabytes of memory. Bloom Filters provide constant-time lookups, zero false negatives, and ~145k URLs/sec throughput — compressed into 5 MB.

The tradeoff is a small false positive probability, which is fully resolved by the PostgreSQL verification stage. In practice: 0 false positives observed across 100,000 test URLs.

---

## Threat Intelligence

Continuously aggregated, normalized, and deduplicated from:

- [URLhaus](https://urlhaus.abuse.ch/)
- [PhishTank](https://phishtank.org/)
- [OpenPhish](https://openphish.com/)
- [CERT Polska](https://cert.pl/)

---

## Infrastructure

Self-hosted on a single AWS EC2 instance. Migrated from Render + Supabase + Upstash — one machine, full control, no managed service costs.

```
AWS EC2
├── FastAPI          (REST API)
├── PostgreSQL       (verification database)
├── Redis            (cache layer)
├── Bloom Filter     (in-memory URL index)
└── Docker Compose   (orchestration)
```

---

## REST API

The FastAPI backend exposes a simple check endpoint:

```bash
curl http://13.61.0.125:8000/check?url=https://google.com
```

Swagger docs available at `/docs`.

---

## License

MIT © dvara contributors
