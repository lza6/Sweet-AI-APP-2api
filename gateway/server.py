#!/usr/bin/env python3
"""Sweet AI 本地网关 — OpenAI 兼容层

把标准 OpenAI /v1/chat/completions 请求转成 Sweet AI 加密信封，
再把上游返回统一成 OpenAI 响应格式。

用法::

    python gateway/server.py                 # 真实上游（当前返回 system_error）
    SWEET_MOCK=1 python gateway/server.py    # 本地 mock 上游，自测/压测用
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import sweetapi as sweet  # noqa: E402

MOCK = os.getenv("SWEET_MOCK") == "1"
PORT = int(os.getenv("SWEET_PORT", "8901"))
WEB_DIR = Path(__file__).resolve().parents[1] / "web"

app = FastAPI(title="Sweet AI Gateway", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])

STATS = {"requests": 0, "ok": 0, "failed": 0, "upstream_ms": []}


def _mock_body(model: str, text: str) -> dict:
    """模拟上游返回，形状同 ChatGPTOut。"""
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "system_fingerprint": "mock",
        "choices": [{
            "index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": f"[mock] {text[:80]}"},
        }],
        "usage": {"prompt_tokens": len(text), "completion_tokens": 8,
                  "total_tokens": len(text) + 8},
    }


async def call_upstream(payload: dict, model: str) -> tuple[int, Any]:
    """调用 Sweet AI 上游；MOCK 模式下直接返回本地构造结果。"""
    if MOCK:
        await asyncio.sleep(float(os.getenv("SWEET_MOCK_DELAY", "0.05")))
        txt = payload["messages"][-1].get("content", "") if payload.get("messages") else ""
        return 200, _mock_body(model, txt)

    env = sweet.envelope(payload)
    async with httpx.AsyncClient(timeout=httpx.Timeout(120, connect=20),
                                 trust_env=True) as client:
        r = await client.post(sweet.chat_url(model), headers=sweet.headers(),
                              content=json.dumps(env))
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def _to_openai(up_body: Any, model: str) -> dict:
    """把上游 ChatGPTOut 转成标准 OpenAI chat.completion。"""
    if isinstance(up_body, dict) and up_body.get("choices"):
        ch = up_body["choices"][0]
        msg = ch.get("message") or {}
        if not msg and "text" in ch:
            msg = {"role": "assistant", "content": ch["text"]}
        return {
            "id": up_body.get("id") or f"chatcmpl-{uuid.uuid4().hex[:24]}",
            "object": "chat.completion",
            "created": up_body.get("created") or int(time.time()),
            "model": up_body.get("model") or model,
            "choices": [{"index": 0, "finish_reason": ch.get("finish_reason", "stop"),
                         "message": {"role": msg.get("role", "assistant"),
                                     "content": msg.get("content", "")}}],
            "usage": up_body.get("usage") or {},
        }
    raise ValueError(f"unexpected upstream body: {str(up_body)[:200]}")


def _err(status: int, msg: str, code: str = "upstream_error") -> JSONResponse:
    return JSONResponse(status_code=status, content={
        "error": {"message": msg, "type": code, "code": code, "params": ""}})


@app.get("/health")
async def health():
    return {"status": "ok", "mock": MOCK,
            "upstream": sweet.BASE, "model": sweet.MODEL}


@app.get("/stats")
async def stats():
    lat = STATS["upstream_ms"]
    lat_sorted = sorted(lat)
    def q(p):
        return round(lat_sorted[int(len(lat_sorted) * p)], 1) if lat_sorted else None
    return {"requests": STATS["requests"], "ok": STATS["ok"],
            "failed": STATS["failed"], "p50_ms": q(0.5),
            "p95_ms": q(0.95), "max_ms": lat_sorted[-1] if lat_sorted else None}


@app.get("/v1/models")
async def models():
    return {"object": "list", "data": [
        {"id": sweet.MODEL, "object": "model", "owned_by": "sweetai"},
    ]}


async def _sse(body: dict) -> AsyncIterator[bytes]:
    """把整包结果拆成 OpenAI 风格 SSE 流。"""
    content = body["choices"][0]["message"]["content"]
    base = {"id": body["id"], "object": "chat.completion.chunk",
            "created": body["created"], "model": body["model"]}
    for i in range(0, len(content), 12):
        chunk = {**base, "choices": [{"index": 0, "delta": {"content": content[i:i + 12]},
                                     "finish_reason": None}]}
        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode()
    yield f"data: {json.dumps({**base, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n".encode()
    yield b"data: [DONE]\n\n"


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    STATS["requests"] += 1
    try:
        req = await request.json()
        messages = req.get("messages") or []
        if not messages:
            STATS["failed"] += 1
            return _err(400, "messages is required", "invalid_request_error")
        model = req.get("model") or sweet.MODEL
        payload = {"model": model, "messages": messages,
                   "stream": bool(req.get("stream", False))}
        for k in ("initmate", "inspiration", "initmate_data", "user_info",
                  "response_format", "inspiration_data"):
            if k in req:
                payload[k] = req[k]

        t0 = time.perf_counter()
        status, body = await call_upstream(payload, model)
        STATS["upstream_ms"].append(round((time.perf_counter() - t0) * 1000, 1))
        if len(STATS["upstream_ms"]) > 5000:
            del STATS["upstream_ms"][:2500]

        if status != 200:
            STATS["failed"] += 1
            msg = body
            if isinstance(body, dict):
                msg = (body.get("error") or {}).get("message") or body.get("msg") or body
            return _err(502 if status >= 500 else status, str(msg))

        try:
            out = _to_openai(body, model)
        except ValueError as e:
            STATS["failed"] += 1
            return _err(502, str(e), "bad_upstream_response")

        STATS["ok"] += 1
        if payload["stream"]:
            return StreamingResponse(_sse(out), media_type="text/event-stream")
        return JSONResponse(out)
    except Exception as e:  # noqa: BLE001
        STATS["failed"] += 1
        return _err(500, f"{type(e).__name__}: {e}", "gateway_error")


@app.get("/", response_class=HTMLResponse)
async def index():
    return (WEB_DIR / "index.html").read_text(encoding="utf-8")


if __name__ == "__main__":
    import uvicorn
    print(f"gateway on :{PORT}  mock={MOCK}")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")
