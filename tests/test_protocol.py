#!/usr/bin/env python3
"""协议自测：加密链 / 信封 / 与真实 so 仿真交叉校验。

直接运行:  python tests/test_protocol.py
或 pytest: pytest tests/test_protocol.py -v
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))

import sweetapi as S  # noqa: E402

# 固定向量（由 tools/emulate_appsecret.py 对真实 libprmp.so 仿真得到，非自证）
VECTORS = [
    (1756800000000, "A" * 40,
     "f952e1f27e70206fc6f9e2347aa7fcfb", "dbbf20683433312371c71d2928105a01"),
    (1756800000001, "b7Kd9xQ2",
     "2de969568b4c4f3e104d86f5a8b2e50c", "d0fa657f9a9dd49460c1babc75b7bacf"),
]


def test_app_key_is_md5_of_app_id():
    assert S.APP_KEY == hashlib.md5(b"182").hexdigest()
    assert S.APP_KEY == "4c5bde74a8f110656874902f07378009"


def test_known_vectors():
    for stamp, rs, secret, sess in VECTORS:
        assert S.app_secret(stamp, rs) == secret, (stamp, rs)
        assert S.session_key(stamp, rs) == sess, (stamp, rs)


def test_aes_cfb_matches_openssl():
    """AES-256-CFB 与 OpenSSL 已知结果一致（iv=00..0f）。"""
    key = b"0123456789abcdef0123456789abcdef"
    assert S.aes_cfb(key, b"hello world 12345").hex() == \
        "3b38b099f9ef410b7350e36db4bb881583"


def test_envelope_roundtrip():
    payload = {"model": S.MODEL, "messages": [{"role": "user", "content": "你好"}],
               "stream": False}
    env = S.envelope(payload)
    assert set(env) == {"mv", "mr", "mt", "mm", "md"}
    assert env["mv"] == S.VERSION_CODE and env["mm"] == 1
    assert len(env["mr"]) == 40
    assert S.decrypt_envelope(env) == \
        '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"你好"}],"stream":false}'


def test_key_changes_per_request():
    """secret / key 必须随 (stamp, mr) 变化，否则等于明文。"""
    a = S.session_key(1756800000000, "A" * 40)
    b = S.session_key(1756800000001, "A" * 40)
    assert a != b


def test_chat_url_shape():
    u = S.chat_url("gpt-4o-mini", "en")
    assert u.startswith("https://api.callershow.com/v1/chat/completions?v=1.9.8")
    assert f"app={S.APP_KEY}" in u and "m=gpt-4o-mini" in u and "os=android" in u
    assert S.chat_url("gpt-4o-mini", "iw").endswith("lang=he")   # iw -> he 修正


def test_emulator_matches_implementation():
    """用 Unicorn 跑真实 libprmp.so，与纯 Python 实现逐条比对。"""
    lib = ROOT / "raw" / "lib" / "arm64-v8a" / "libprmp.so"
    if not lib.exists():
        print("  (skip) 缺少 libprmp.so")
        return
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        from emulate_appsecret import Harness
    except Exception as e:  # noqa: BLE001
        print("  (skip) 无法加载仿真器:", e)
        return
    h = Harness()
    samples = [(1756800000000, "A" * 40), (1700000000000, "zz"),
               (1792399362971, "3DyucHE6x9" + "Q" * 30)]
    for stamp, rs in samples:
        assert h.get_app_secret(stamp, rs) == S.app_secret(stamp, rs), (stamp, rs)


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except AssertionError as e:
                fails += 1
                print(f"FAIL  {name}: {e}")
            except Exception as e:  # noqa: BLE001
                fails += 1
                print(f"ERROR {name}: {type(e).__name__}: {e}")
    print("\n" + ("全部通过" if not fails else f"{fails} 项失败"))
    sys.exit(1 if fails else 0)
