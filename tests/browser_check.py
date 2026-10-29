#!/usr/bin/env python3
"""浏览器真实路径验证：打开 demo 页 -> 输入 -> 发送 -> 等 AI 气泡 -> 截图。

前置：SWEET_MOCK=1 python gateway/server.py (默认 :8911)
"""
import asyncio
import sys
from pathlib import Path

from playwright.async_api import async_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8911/"
OUT = Path(__file__).resolve().parents[1] / "docs" / "shots"
OUT.mkdir(parents=True, exist_ok=True)


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        page = await b.new_page(viewport={"width": 1280, "height": 900})
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        await page.goto(URL, wait_until="networkidle")
        await page.screenshot(path=str(OUT / "01-initial.png"))
        health = await page.inner_text("#health")
        mock = await page.inner_text("#mockTag")

        await page.fill("#input", "你好，做个自我介绍")
        await page.click("#send")
        await page.wait_for_selector(".msg.ai:not(:empty)", timeout=15000)
        reply = await page.inner_text(".msg.ai")
        await page.screenshot(path=str(OUT / "02-reply.png"))

        # 流式路径
        await page.check("#stream")
        await page.fill("#input", "流式测试")
        await page.click("#send")
        await page.wait_for_timeout(1500)
        await page.screenshot(path=str(OUT / "03-stream.png"))
        count = await page.eval_on_selector_all(".msg.ai", "els => els.length")

        print(f"health={health!r} mock={mock!r}")
        print(f"reply={reply!r}")
        print(f"ai_bubbles={count} page_errors={errors}")
        await b.close()


asyncio.run(main())
