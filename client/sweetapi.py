#!/usr/bin/env python3
"""Sweet AI (com.mxxtech.sweetai) v1.9.8 — 协议客户端 / SDK

协议总览（全部为静态 RE + Unicorn 仿真还原，见 docs/01-protocol.md）
------------------------------------------------------------------
真实聊天走 Volley（不是 Retrofit）：

    POST https://api.callershow.com/v1/chat/completions
         ?v=1.9.8&os=android&m=<model>&app=<md5("182")>&lang=<locale>

    Headers: lang / app / os / ver（服务端实际只强校验 query 里的 app）
    Body   : {"mv":26091802,"mr":<rand40>,"mt":<epoch_ms>,"mm":1,"md":<b64>}

    md      = base64( AES-256-CFB( key, iv=00..0f, utf8(json) ) )
    key     = sha1( f"{secret}_{mv}_{mm}_{mt}_{mr}" ).hexdigest()[:32]
    secret  = sha1( f"182_0_{mt}_{mr}" ).hexdigest()[:32]
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import string
import time
from typing import Any

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BASE = "https://api.callershow.com"
CHAT_PATH = "/v1/chat/completions"

APP_ID = 182                    # 服务端校验的 app 编号
APP_KEY = hashlib.md5(str(APP_ID).encode()).hexdigest()   # 4c5bde74...
VERSION_CODE = 26091802         # = C18367c.f73594d (envelope 的 mv)
VERSION_NAME = "1.9.8"
METHOD = 1                      # envelope 的 mm
MODEL = "gpt-4o-mini"           # = C21610m4.f84992f
IV = bytes(range(16))           # = C21616n2.f85028g

CHARSET = string.ascii_letters + string.digits


# ------------------------------------------------------------------ crypto
def aes_cfb(key: bytes, data: bytes, decrypt: bool = False) -> bytes:
    """AES/CFB/NoPadding（CFB-128）。decrypt=True 走解密方向。"""
    ctx = Cipher(algorithms.AES(key), modes.CFB(IV))
    c = ctx.decryptor() if decrypt else ctx.encryptor()
    return c.update(data) + c.finalize()


def rand_str(n: int = 40) -> str:
    return ''.join(random.choice(CHARSET) for _ in range(n))


def app_secret(stamp: int, rs: str) -> str:
    """libprmp.so :: PromptHelper.getAppSecret(stamp, rs) 的等价实现。

    已用 Unicorn 仿真真实 so 交叉校验（tools/emulate_appsecret.py）。
    """
    return hashlib.sha1(f"{APP_ID}_0_{stamp}_{rs}".encode()).hexdigest()[:32]


def session_key(stamp: int, rs: str, method: int = METHOD) -> str:
    """C21616n2.m81774h() 的等价实现。"""
    secret = app_secret(stamp, rs)
    return hashlib.sha1(
        f"{secret}_{VERSION_CODE}_{method}_{stamp}_{rs}".encode()
    ).hexdigest()[:32]


def envelope(payload: dict, method: int = METHOD) -> dict:
    """把业务 JSON 包成服务端要求的加密信封。"""
    stamp = int(time.time() * 1000)
    rs = rand_str(40)
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    ct = aes_cfb(session_key(stamp, rs, method).encode(), raw)
    return {"mv": VERSION_CODE, "mr": rs, "mt": stamp, "mm": method,
            "md": base64.b64encode(ct).decode()}


def decrypt_envelope(env: dict) -> str:
    """反向解密（自测用）。"""
    key = session_key(int(env["mt"]), env["mr"], int(env.get("mm", METHOD)))
    return aes_cfb(key.encode(), base64.b64decode(env["md"]), decrypt=True).decode()


# ------------------------------------------------------------------ HTTP
def chat_url(model: str = MODEL, lang: str = "en") -> str:
    return (f"{BASE}{CHAT_PATH}?v={VERSION_NAME}&os=android"
            f"&m={model}&app={APP_KEY}&lang={'he' if lang == 'iw' else lang}")


def headers(lang: str = "en") -> dict:
    return {"Content-Type": "application/json; charset=utf-8",
            "lang": "he" if lang == "iw" else lang,
            "app": APP_KEY, "os": "android", "ver": VERSION_NAME,
            "User-Agent": "okhttp/4.12.0"}


def chat(messages: list[dict], *, stream: bool = False, model: str = MODEL,
         timeout: int = 90, session: requests.Session | None = None,
         **extra: Any) -> tuple[int, Any]:
    """发一次聊天请求，返回 (http_status, 解析后的响应)。"""
    payload = {"model": model, "messages": messages, "stream": stream}
    payload.update(extra)
    body = json.dumps(envelope(payload))
    s = session or requests
    r = s.post(chat_url(model), headers=headers(), data=body, timeout=timeout)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


if __name__ == "__main__":
    print("APP_KEY :", APP_KEY)
    st = int(time.time() * 1000)
    print("secret  :", app_secret(st, "A" * 40))
    print("sesskey :", session_key(st, "A" * 40))
    env = envelope({"model": MODEL, "messages": [{"role": "user", "content": "hi"}],
                    "stream": False})
    print("roundtrip:", decrypt_envelope(env)[:80])
    print("live:", chat([{"role": "user", "content": "Say OK"}]))
