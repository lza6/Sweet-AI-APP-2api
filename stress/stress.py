#!/usr/bin/env python3
"""本地网关压测（aiohttp 异步压测器）

示例::

    python stress/stress.py -c 32 -n 2000                  # 2000 请求, 32 并发
    python stress/stress.py -c 16 -d 30 --stream           # 压 30 秒, 流式
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from collections import Counter

import aiohttp

PROMPTS = [
    "Say OK", "hello", "用一句话介绍你自己", "1+1=?",
    "tell me a joke", "你叫什么名字", "test message", "hi there",
]


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = min(len(xs) - 1, int(len(xs) * p))
    return round(xs[k], 1)


async def one(session, url, model, prompt, stream, timeout):
    payload = {"model": model,
               "messages": [{"role": "user", "content": prompt}],
               "stream": stream}
    t0 = time.perf_counter()
    try:
        async with session.post(url, json=payload,
                                timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            body = await r.text()
            dt = (time.perf_counter() - t0) * 1000
            ok = r.status == 200
            if ok and stream:
                ok = "data:" in body
            elif ok:
                try:
                    j = json.loads(body)
                    ok = bool(j.get("choices"))
                except ValueError:
                    ok = False
            return dt, r.status, ok
    except Exception as e:  # noqa: BLE001
        return (time.perf_counter() - t0) * 1000, type(e).__name__, False


async def worker(name, session, args, idx, lat, status, okc):
    while True:
        try:
            i = next(idx)
        except StopIteration:
            return
        dt, st, ok = await one(session, args.url, args.model,
                               PROMPTS[i % len(PROMPTS)], args.stream, args.timeout)
        lat.append(dt)
        status[st] += 1
        if ok:
            okc[0] += 1


async def main_async(args):
    idx = iter(range(args.total))
    lat, status, okc = [], Counter(), [0]
    conn = aiohttp.TCPConnector(limit=args.concurrency * 2)
    async with aiohttp.ClientSession(connector=conn) as s:
        t0 = time.perf_counter()
        await asyncio.gather(*[worker(f"w{i}", s, args, idx, lat, status, okc)
                               for i in range(args.concurrency)])
        wall = time.perf_counter() - t0
    total = len(lat)
    print(f"\n=== 压测结果 ===")
    print(f"目标      : {args.url}  (model={args.model}, stream={args.stream})")
    print(f"并发/总数 : {args.concurrency} / {total}")
    print(f"墙钟耗时  : {wall:.2f}s")
    print(f"吞吐      : {total / wall:.1f} req/s")
    print(f"成功      : {okc[0]}  ({okc[0] / total * 100:.1f}%)")
    print(f"延迟 ms   : p50={pct(lat,0.5)} p90={pct(lat,0.9)} "
          f"p95={pct(lat,0.95)} p99={pct(lat,0.99)} max={round(max(lat),1)} "
          f"avg={round(statistics.fmean(lat),1)}")
    print(f"状态分布  : {dict(status)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", default="http://127.0.0.1:8901/v1/chat/completions")
    ap.add_argument("-c", "--concurrency", type=int, default=16)
    ap.add_argument("-n", "--total", type=int, default=500)
    ap.add_argument("-m", "--model", default="gpt-4o-mini")
    ap.add_argument("-t", "--timeout", type=float, default=60)
    ap.add_argument("--stream", action="store_true")
    args = ap.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
