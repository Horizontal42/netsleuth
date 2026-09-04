import asyncio
import httpx
import time
from netsleuth.config import Speedtest
from netsleuth.speed import tier_cloudflare, throughput_from_samples

async def main():
    cfg = Speedtest(
        download_sizes_bytes=[],
        upload_sizes_bytes=[100000, 200000, 500000, 1000000, 2000000],
        cloudflare_base_url="https://speed.cloudflare.com",
    )
    async with httpx.AsyncClient() as client:
        began = time.perf_counter()
        res = await tier_cloudflare(client, cfg, 30.0)
        elapsed = time.perf_counter() - began
        print(f"Elapsed: {elapsed:.3f}s")
        print(f"Upload mbps: {res.upload_mbps}")

if __name__ == "__main__":
    asyncio.run(main())
