import asyncio
import asyncpg
import requests
import zipfile
import io
import csv
import hashlib

DATABASE_URL = "postgresql://postgres.mqyynimufylcmudmbluo:Dhruvtri20%40@aws-1-ap-south-1.pooler.supabase.com:5432/postgres"

FEEDS = [
    "https://urlhaus.abuse.ch/downloads/csv/",
    "https://data.phishtank.com/data/online-valid.csv",
    "https://openphish.com/feed.txt",
    "https://hole.cert.pl/domains/domains.txt",
]


def parse_urlhaus(content: bytes):
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        name = zf.namelist()[0]

        with zf.open(name) as f:
            text = f.read().decode("utf-8", errors="ignore")

    reader = csv.reader(io.StringIO(text))

    for row in reader:
        if not row or row[0].startswith("#"):
            continue

        if len(row) >= 3:
            url = row[2].strip().strip('"')

            if url:
                yield url


def parse_phishtank(text: str):
    reader = csv.DictReader(io.StringIO(text))

    for row in reader:
        url = row.get("url")

        if url:
            yield url.strip()


def parse_openphish(text: str):
    for line in text.splitlines():
        line = line.strip()

        if line:
            yield line


def parse_certpl(text: str):
    for line in text.splitlines():
        line = line.strip()

        if line:
            yield f"http://{line}"


async def main():
    conn = await asyncpg.connect(DATABASE_URL)

    urls = set()

    print("Fetching URLHaus...")
    r = requests.get(FEEDS[0], timeout=120)
    urls.update(parse_urlhaus(r.content))

    print("Fetching PhishTank...")
    r = requests.get(FEEDS[1], timeout=120)
    urls.update(parse_phishtank(r.text))

    print("Fetching OpenPhish...")
    r = requests.get(FEEDS[2], timeout=120)
    urls.update(parse_openphish(r.text))

    print("Fetching Cert.pl...")
    r = requests.get(FEEDS[3], timeout=120)
    urls.update(parse_certpl(r.text))

    print(f"Total unique URLs collected: {len(urls)}")

    batch = [
        (
            hashlib.sha256(u.encode()).hexdigest(),
            u
        )
        for u in urls
    ]

    print("Inserting into PostgreSQL...")

    await conn.executemany(
        """
        INSERT INTO confirmed_urls(url_hash, url)
        VALUES($1, $2)
        ON CONFLICT DO NOTHING
        """,
        batch
    )

    print(f"Inserted {len(batch)} URLs into confirmed_urls")

    await conn.close()


asyncio.run(main())