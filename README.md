# Sweet AI v1.9.8 — APK 逆向 / 2API（R1）

`com.mxxtech.sweetai`（aifox 白标）AI 女友聊天 App 的协议还原 + 本地网关 + Demo。

## 结论速览

| 项 | 状态 |
|---|---|
| 协议还原（URL / header / 加密信封 / native 签名） | ✅ 完成，有交叉校验 |
| 本地 OpenAI 兼容网关 + Demo 页 | ✅ 可用（mock 与真实两种模式） |
| 压测 | ✅ 472 req/s / p95 81ms（mock 上游，32 并发） |
| 真实上游可用性 | ❌ **上游 platform 全线不可用**（`system_error / server is currently busy`） |

详细：[协议](docs/01-protocol.md) · [native 逆向](docs/02-native-re.md) · [验证记录](docs/03-verification.md)

## 协议一句话

```text
POST https://api.callershow.com/v1/chat/completions
     ?v=1.9.8&os=android&m=gpt-4o-mini&app=<md5("182")>&lang=en

body = {"mv":26091802,"mr":<rand40>,"mt":<ms>,"mm":1,"md":<b64>}
md   = base64( AES-256-CFB( sha1(f"{secret}_{mv}_{mm}_{mt}_{mr}")[:32],
                            iv=00..0f, utf8(json) ) )
secret = sha1(f"182_0_{mt}_{mr}")[:32]      # ← libprmp.so getAppSecret
```

## 目录

```
sweet-ai/
├── client/sweetapi.py          # SDK：加密信封 + 请求（可直接 import）
├── gateway/server.py           # FastAPI OpenAI 兼容网关（SWEET_MOCK=1 走本地 mock）
├── web/index.html              # Demo 页（聊天 UI + 网关状态/延迟面板）
├── stress/stress.py            # aiohttp 压测器
├── tests/test_protocol.py      # 协议自测（含真实 so 仿真交叉校验）
├── tests/browser_check.py      # Playwright 真实浏览器路径验证
├── tools/
│   ├── xor_dec.py              # 字符串异或解密器
│   ├── pltmap.py               # PLT→导入符号映射
│   ├── constemu.py             # Unicorn 跑常量解密函数
│   └── emulate_appsecret.py    # libprmp.so getAppSecret 完整仿真
├── docs/                       # 协议 / native / 验证 / 截图
└── raw/ jadx-out/ apktool-out/ # 反编译产物
```

## 快速开始

```bash
pip install fastapi uvicorn httpx cryptography requests aiohttp playwright

# 1) 自测
python tests/test_protocol.py

# 2) 网关 + Demo（mock 上游，不依赖外网）
SWEET_MOCK=1 SWEET_PORT=8911 python gateway/server.py
# 浏览器打开 http://127.0.0.1:8911/

# 3) 接真实上游（当前会返回 system_error）
SWEET_PORT=8912 python gateway/server.py

# 4) 压测
python stress/stress.py -c 32 -n 800
```

网关接口：`POST /v1/chat/completions`、`GET /v1/models`、`GET /health`、`GET /stats`。

## 已知风险

- 上游当前不可用，若其恢复，网关无需改动即可工作（加密链已与服务端 `app` 校验对齐）。
- 该通道依赖第三方未公开 API，随时可能变更或封禁；不做承诺。
