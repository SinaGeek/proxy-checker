import asyncio
import aiohttp
import csv
import socket
import sys
from pathlib import Path
from datetime import datetime, timezone
from aiohttp import ClientTimeout
from aiohttp_socks import ProxyConnector
import ipaddress

# ─────────────────────────────────────────────────────────────
# CONFIGURATION SECTION
# Reason:
#   All tunable parameters are centralized here so performance
#   characteristics can be adjusted without touching logic.
# ─────────────────────────────────────────────────────────────

# External service used ONLY after a proxy is confirmed working
# (GeoIP is expensive: TLS + JSON + latency)
API_URL = "https://api.ip.sb/geoip"

# Fast TCP pre-check timeout
# Short on purpose: only checking if port accepts connections
TIMEOUT_TCP = 5.0

# Full proxy test timeout (HTTP / SOCKS handshake + request)
TIMEOUT_PROXY = 10

# Async concurrency limit
# 50 is a good balance between speed and OS socket limits
CONCURRENT = 100

# Proxy protocols to auto-detect
# Order matters: cheap → expensive
SCHEMES = ["http", "https", "socks4", "socks5"]

# Country exclusion filter
IRAN = {"IR", "IRAN"}

# Input / output files
PROXY_FILE = Path("proxies.txt")
ALIVE_FILE = Path("alive.txt")          # Fast text output (cheap I/O)
GOOD_RAW = Path("good_raw.csv")         # Append-only (power-cut safe)
GOOD_SORTED = Path("good_sorted.csv")   # Final sorted output

# CSV schema
CSV_HEADER = [
    "proxy", "scheme", "ip", "port", "tested_at",
    "country", "country_code",
    "region", "city",
    "isp", "asn", "asn_organization",
    "latitude", "longitude", "timezone",
    "ip_returned"
]

# ─────────────────────────────────────────────────────────────
# GLOBAL COUNTERS
# Reason:
#   Used for progress bar without locks (single-threaded asyncio)
# ─────────────────────────────────────────────────────────────

total = 0
done = 0
good = 0


# ─────────────────────────────────────────────────────────────
# PROGRESS BAR
# Reason:
#   Avoids logging overhead while still giving live feedback.
# ─────────────────────────────────────────────────────────────
def progress():
    pct = (done / total * 100) if total else 0
    bar = "█" * int(pct) + "░" * (100 - int(pct))
    sys.stdout.write(
        f"\r[{bar}] {good} good | {done}/{total} {pct:5.1f}%"
    )
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────
# NORMALIZATION
# Reason:
#   Proxies may have wrong schemes or none at all.
#   We strip scheme entirely and treat input as ip:port.
# ─────────────────────────────────────────────────────────────
def normalize(line: str):
    line = line.strip()
    if not line:
        return None
    if "://" in line:
        _, line = line.split("://", 1)
    return line


# ─────────────────────────────────────────────────────────────
# SPLIT IP AND PORT
# Reason:
#   Needed for TCP pre-check and final CSV sorting.
# ─────────────────────────────────────────────────────────────
def split_ip_port(ip_port: str):
    ip, port = ip_port.rsplit(":", 1)
    return ip, int(port)


# ─────────────────────────────────────────────────────────────
# TCP ALIVE CHECK (FAST FILTER)
# Reason:
#   This is the single biggest speed improvement.
#   A dead port is discarded BEFORE any proxy or API logic.
# ─────────────────────────────────────────────────────────────
async def tcp_alive(ip_port: str) -> bool:
    ip, port = split_ip_port(ip_port)
    try:
        # asyncio.open_connection performs a raw TCP handshake
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, TIMEOUT_TCP)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# PROXY TEST FUNCTION
# Reason:
#   Tries a SINGLE protocol against the GeoIP endpoint.
#   Returns JSON only if proxy truly works.
# ─────────────────────────────────────────────────────────────
async def try_proxy(ip_port: str, scheme: str):
    proxy_url = f"{scheme}://{ip_port}"
    timeout = ClientTimeout(total=TIMEOUT_PROXY)

    # SOCKS requires a custom connector
    if scheme.startswith("socks"):
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        ) as s:
            async with s.get(API_URL, ssl=False) as r:
                if r.status != 200:
                    return None
                return await r.json()

    # HTTP / HTTPS use native aiohttp proxy support
    else:
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(
                API_URL,
                proxy=proxy_url,
                ssl=False
            ) as r:
                if r.status != 200:
                    return None
                return await r.json()


# ─────────────────────────────────────────────────────────────
# MAIN CHECK LOGIC PER PROXY
# Reason:
#   Pipeline:
#     1. TCP alive check
#     2. Save alive port (cheap I/O)
#     3. Detect correct protocol
#     4. GeoIP filtering
#     5. Persist result safely
# ─────────────────────────────────────────────────────────────
async def check(ip_port: str):
    global done, good

    try:
        # Step 1: Cheap TCP pre-filter
        if not await tcp_alive(ip_port):
            return

        # Step 2: Save alive ports immediately
        # (text write is fastest possible disk I/O)
        with open(ALIVE_FILE, "a", encoding="utf-8") as f:
            f.write(ip_port + "\n")

        # Step 3: Detect correct proxy protocol
        for scheme in SCHEMES:
            try:
                data = await try_proxy(ip_port, scheme)
                if not data:
                    continue

                # Step 4: Country filter
                cc = str(data.get("country_code", "")).upper()
                country = str(data.get("country", "")).upper()

                if cc in IRAN or "IRAN" in country:
                    return

                ip, port = split_ip_port(ip_port)

                # Step 5: Persist result (append-only = crash safe)
                row = [
                    f"{scheme}://{ip_port}",
                    scheme,
                    ip,
                    port,
                    datetime.now(timezone.utc).isoformat(),
                    data.get("country", ""),
                    cc,
                    data.get("region", ""),
                    data.get("city", ""),
                    data.get("isp", ""),
                    data.get("asn", ""),
                    data.get("asn_organization", ""),
                    data.get("latitude", ""),
                    data.get("longitude", ""),
                    data.get("timezone", ""),
                    data.get("ip", "")
                ]

                write_header = not GOOD_RAW.exists()
                with open(GOOD_RAW, "a", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    if write_header:
                        w.writerow(CSV_HEADER)
                    w.writerow(row)

                good += 1
                return  # stop after first working protocol

            except Exception:
                continue

    finally:
        done += 1
        progress()


# ─────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# Reason:
#   Handles normalization, deduplication, concurrency control,
#   and final deterministic sorting.
# ─────────────────────────────────────────────────────────────
async def main():
    global total

    # Read, normalize, deduplicate input
    raw = [
        normalize(l)
        for l in PROXY_FILE.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()
        if l.strip() and not l.startswith(("#", "//"))
    ]

    proxies = sorted(set(filter(None, raw)))

    # Overwrite normalized input (clean source of truth)
    PROXY_FILE.write_text("\n".join(proxies) + "\n")

    total = len(proxies)
    print(f"Testing {total} proxies...")
    progress()

    # Semaphore limits concurrent sockets
    sem = asyncio.Semaphore(CONCURRENT)

    async def guarded(p):
        async with sem:
            await check(p)

    # Fan-out execution
    await asyncio.gather(*(guarded(p) for p in proxies))

    print("\nSorting output...")

    # Final deterministic sort:
    #   IP address → Country code
    with open(GOOD_RAW, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    rows.sort(
        key=lambda r: (
            ipaddress.ip_address(r["ip"]),
            r["country_code"]
        )
    )

    with open(GOOD_SORTED, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, CSV_HEADER)
        w.writeheader()
        w.writerows(rows)

    print(f"Done. Saved: {GOOD_SORTED.resolve()}")


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# Reason:
#   asyncio.run() ensures clean loop lifecycle.
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    asyncio.run(main())
