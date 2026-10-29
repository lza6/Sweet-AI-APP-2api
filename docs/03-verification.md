# 验证记录（R1）

环境：Windows 10 + Python 3.14，模拟器 `tfgy_e2e`（API 35 / x86_64，无 ARM 翻译，故未跑 App 本体）。
所有命令均在 `D:\apk-analysis\sweet-ai` 下执行。

## 1. 静态还原

```bash
jadx -d jadx-out --no-res -j 8 "Sweet AI v1.9.8 (Premium).apk"     # 31669 个 java 文件
java -jar apktool.jar d "Sweet AI v1.9.8 (Premium).apk" -o apktool-out --no-src
```
- 包名 `com.mxxtech.sweetai`，versionCode `26091802` — 静态确认。
- 字符串解密器 `p331dc.C18370f.m68184a()` = 循环异或（`p409hb.C19322a.decrypt`）。

## 2. native 层（`libprmp.so`）

```bash
python tools/constemu.py            # 常量解密
python tools/emulate_appsecret.py   # 整函数仿真
```

常量解密输出：

```text
className    regs='java/lang/Long'
methodName   regs='toString'
signature    mem='(J)Ljava/lang/String;'
formatStr    str b'%d_%d_%s_%s\x00...'
alg(0x5b278) b'SHA1\x00...'
```

## 3. 协议自测

```bash
$ python tests/test_protocol.py
PASS  test_aes_cfb_matches_openssl
PASS  test_app_key_is_md5_of_app_id
PASS  test_chat_url_shape
PASS  test_emulator_matches_implementation
PASS  test_envelope_roundtrip
PASS  test_key_changes_per_request
PASS  test_known_vectors

全部通过
```

覆盖：已知向量（由真实 so 仿真产出）、AES-256-CFB 与 OpenSSL 一致、
信封往返、URL/header 形状（含 `iw→he` 修正）、每请求密钥必须变化、仿真↔实现一致。

## 4. 真实上游行为

```bash
# 无 query 参数：任意 md 都是 -103
POST /v1/chat/completions                    -> 200 {"code":-103,"msg":"error, post json platform"}
# app 校验真实存在
POST /v1/chat/completions?…&app=deadbeef…    -> 200 {"code":-1,"msg":"error, app not found"}
# app 正确：所有 md（合规密文 / 非法 base64 / 空 / 随机）都同一错误
POST /v1/chat/completions?…&app=<正确>        -> 500 {"error":{"code":"system_error",
                                                 "message":"The server is currently busy, please try again later."}}
# Retrofit 里那批 /api/* 路由
/api/bot/list, /api/bot/types, /api/report, /api/voice/tts  -> 404 page not found
```

→ **瓶颈在上游 "platform" 转发层，不在加密。** 因此 R1 无法做真实内容级 E2E。

## 5. 网关 + Demo

```bash
SWEET_MOCK=1 SWEET_PORT=8911 python gateway/server.py &
curl http://127.0.0.1:8911/health
```

浏览器真实路径（Playwright Chromium，截图见 `docs/shots/`）：

```text
$ python tests/browser_check.py
health='ok' mock='MOCK 模式'
reply='[mock] 你好，做个自我介绍'
ai_bubbles=2 page_errors=[]
```

`01-initial.png` / `02-reply.png`（非流式）/ `03-stream.png`（SSE）均正常渲染。

真实上游模式（`:8912`，`SWEET_MOCK` 未开）：

```text
POST /v1/chat/completions -> 502
{"error":{"message":"The server is currently busy, please try again later.",
          "type":"upstream_error","code":"upstream_error"}}
/stats -> {"requests":1,"ok":0,"failed":1,"p50_ms":4042.5}
```

## 6. 压测（本地 mock 上游，排除外网噪声）

| 场景 | 并发 | 请求数 | 吞吐 | 成功 | p50 | p95 | p99 |
|---|---|---|---|---|---|---|---|
| 非流式 | 32 | 800 | **472.5 req/s** | 100% | 65.3 ms | 81.5 ms | 85.6 ms |
| SSE 流式 | 16 | 300 | **221.9 req/s** | 100% | 71.7 ms | 79.4 ms | 84.9 ms |

（mock 上游固有延迟 50 ms，故 p50≈65 ms 中约 15 ms 为网关+HTTP 开销。）

信封加密本身的开销：

```text
envelope  (200B 负载): 22349 ops/s, 0.045 ms/op
envelope  (4KB  负载):  9660 ops/s, 0.104 ms/op
```

→ 加密不是瓶颈；真实吞吐上限取决于上游（当前不可用）。

## 7. 未验证 / 受限项

| 项 | 原因 |
|---|---|
| 真实聊天内容 E2E（服务端是否成功解密我们的 md） | 上游 platform 全线 `system_error`，任何 `md` 都同一响应，无法区分 |
| App 本体运行态抓包 | 本机 AVD 均为 x86_64 且无 ARM 翻译，`arm64-v8a`/`armeabi-v7a` 的 `libprmp.so` 无法加载 |
| `/api/bot/*`、`/api/voice/*` 语义 | 线上 404 |
