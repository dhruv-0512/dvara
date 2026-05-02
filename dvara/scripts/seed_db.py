"""
seed_db.py — bulk seed confirmed_urls from URLhaus into PostgreSQL
Run from the dvara/dvara folder:
    python seed_db.py
"""
import asyncio
import csv
import requests
import asyncpg


async def seed():
    print("Fetching URLhaus...")
    resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/")
    lines = [l for l in resp.text.splitlines() if not l.startswith("#")]
    rows = list(csv.reader(lines))

    records = []
    for r in rows:
        if len(r) >= 3 and r[2].strip():
            url = r[2].strip()
            category = r[5].strip() if len(r) > 5 and r[5].strip() else "malware"
            records.append((url, "urlhaus", category))

    print(f"Fetched {len(records)} URLs. Connecting to PostgreSQL...")
    conn = await asyncpg.connect("postgresql://dvara:dvara@localhost:5432/dvara")

    # Bulk insert using copy — orders of magnitude faster than row-by-row
    # First wipe existing urlhaus rows so we can re-seed cleanly
    await conn.execute("DELETE FROM confirmed_urls WHERE source = 'urlhaus'")

    await conn.copy_records_to_table(
        "confirmed_urls",
        records=records,
        columns=["url", "source", "category"],
    )

    count = await conn.fetchval("SELECT COUNT(*) FROM confirmed_urls")
    await conn.close()
    print(f"Done. {count} URLs now in confirmed_urls.")


asyncio.run(seed())
