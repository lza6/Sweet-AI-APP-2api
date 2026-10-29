# new-api 对接指南 — Sweet AI v1.9.8（com.mxxtech.sweetai）

> 本文给"另一个会话/另一位工程师"直接照做用。读完不需要回问协议细节。
> 协议源头：`docs/01-protocol.md`（本仓库）。

- 上游：`https://api.callershow.com`
- 鉴权：**无账号体系**，只有 query 里的 `app` 应用 ID + 请求体 AES 信封
- 模型：**单模型 `gpt-4o-mini`**
- 能力：文本聊天（SSE 流式 / 非流式 JSON）。无生图、无视觉、无语音可用
- **当前状态：上游 platform 层不可用**，任何请求返回 `500 system_error`，见 §6

---

## 0. 先看清楚这条通道的特殊性（不看清会浪费一天）

1. **真实聊天入口不是 Retrofit 那个 `/v1/chat/completions`，而是带 query 的同名路径。**
   APK 里两套并存：Retrofit 版 `/api/bot/*`、`/api/voice/*` **线上全是 404**；
   真实聊天由 Volley 打
   `/v1/chat/completions?v=1.9.8&os=android&m=<model>&app=<appkey>&lang=<locale>`。
   **query 少一个参数，服务端一律返回 `{"code":-103,"msg":"error, post json platform"}`**，
   和密钥错误的表现完全一样，极易误判成"加密没对上"。
2. **请求体不是 OpenAI JSON，是一个加密信封**，整个 body 只有 5 个字段。
3. **`app` 是 `md5("182")`，运行期密钥是两层 SHA-1** —— 两套算法，别混。
4. **上游转发层当前是死的**，`app` 校验通过后立刻 `system_error`；无法用它验证内容级正确性。

---

## 1. 协议速查（实现时照抄这张表）

| 项 | 值 |
|---|---|
| 方法/路径 | `POST /v1/chat/completions` |
| query | `v=1.9.8` `os=android` `m=<model>` `app=4c5bde74a8f110656874902f07378009` `lang=<locale>` |
| header `app` | `4c5bde74a8f110656874902f07378009`（= md5("182")） |
| header `lang` | 语言码；Android 的 `iw` 必须改成 `he` |
| header `os` / `ver` | `android` / `1.9.8` |
| Content-Type | `application/json; charset=utf-8` |
| versionCode `mv` | `26091802` |
| method `mm` | `1`（聊天固定） |
| AES | `AES/CFB/NoPadding`（CFB-128），IV = `00 01 02 … 0f` |
| 密钥 | `sha1(f"{secret}_{mv}_{mm}_{mt}_{mr}")[:32]` 的 **ASCII 32 字节**（AES-256） |
| secret | `sha1(f"182_0_{mt}_{mr}")[:32]` |

### 1.1 信封

```json
{"mv":26091802,"mr":"<40位[A-Za-z0-9]>","mt":1793311115000,"mm":1,"md":"<base64>"}
```

`md = base64( AES-256-CFB( key, iv, utf8(业务JSON) ) )`，业务 JSON 即 §1.3。

### 1.2 Go 参考实现（可直接放进 `relay/channel/<name>/`）

```go
var sweetIV = []byte{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}

const (
    sweetVersionCode = 26091802
    sweetAppID       = "182"
    sweetAppKey      = "4c5bde74a8f110656874902f07378009" // md5("182")
    sweetMethod      = 1
)

func sweetHex32(b []byte) string { return hex.EncodeToString(b)[:32] }

// secret = sha1("182_0_{mt}_{mr}")[:32]
func sweetAppSecret(mt int64, mr string) string {
    s := sha1.Sum([]byte(fmt.Sprintf("%s_0_%d_%s", sweetAppID, mt, mr)))
    return sweetHex32(s[:])
}

// key = sha1("{secret}_{mv}_{mm}_{mt}_{mr}")[:32]
func sweetSessionKey(secret string, mt int64, mr string) string {
    s := sha1.Sum([]byte(fmt.Sprintf("%s_%d_%d_%d_%s",
        secret, sweetVersionCode, sweetMethod, mt, mr)))
    return sweetHex32(s[:])
}

func sweetSeal(plain []byte) (string, error) {
    mt := time.Now().UnixMilli()
    mr := sweetRandStr(40)
    key := sweetSessionKey(sweetAppSecret(mt, mr), mt, mr)

    block, err := aes.NewCipher([]byte(key))            // 32 字节 -> AES-256
    if err != nil { return "", err }
    ct := make([]byte, len(plain))
    cipher.NewCFBEncrypter(block, sweetIV).XORKeyStream(ct, plain) // CFB-128

    env, _ := json.Marshal(map[string]any{
        "mv": sweetVersionCode, "mr": mr, "mt": mt,
        "mm": sweetMethod, "md": base64.StdEncoding.EncodeToString(ct),
    })
    return string(env), nil
}
```

`mr` 必须每次重新随机（`[A-Za-z0-9]` 40 位）；`mt` 用毫秒。

### 1.3 业务 JSON（信封内）

```json
{
  "model": "gpt-4o-mini",
  "messages": [{"role":"user","content":"hi"}],
  "stream": true,
  "initmate": true,
  "inspiration": false,
  "response_format": {"type":"json_object"},
  "initmate_data": {"current_time":"2026-10-30 05:00:00","language":"English",
                    "user_level":1,"output_json":""},
  "user_info": {"afId":"","country":"English"}
}
```

- `initmate` / `initmate_data` / `user_info` / `response_format` 是角色扮演场景用的，
  **纯文本聊天可以不带**（只留 `model` `messages` `stream`）。带与不带都不影响 app 校验。
- `stream: true` 时上游按 SSE 返回；`false` 返回整包。

---

## 2. 两种接入形态（先选，别混着做）

| | 形态 A：Sidecar（强烈推荐先做） | 形态 B：原生 Go 渠道 |
|---|---|---|
| 做法 | 把本仓库 `gateway/server.py` 跑在 new-api 同机，new-api 用**现有 OpenAI 渠道类型**指过去 | 新增 `type` 渠道 + `relay/channel/sweetai` 适配器 |
| 代码量 | **0 行 Go** | 约 200–300 行 Go + 单测 |
| 优点 | 10 分钟通；加密/信封/SSE 已在 Python 侧实现并压测过（472 req/s）；错误已统一成 OpenAI 形状 | 少一个进程；可复用 new-api 计费/限流/日志 |
| 缺点 | 多一个进程 | 得把信封逻辑搬进 Go（照抄 §1.2 即可） |
| 适用 | 先验证、快速上线 | 长期生产 |

**建议：先 A。** 协议在 `docs/01-protocol.md`，Go 侧只有 §1.2 那 40 行需要抄。

---

## 3. 形态 A：Sidecar（0 行 Go）

### 3.1 起 sidecar

```bash
pip install fastapi uvicorn httpx cryptography
cd <repo>/gateway
SWEET_PORT=8911 python server.py            # 真实上游模式（SWEET_MOCK 不设）
```

生产建议 systemd / pm2 守护。自检：

```bash
curl -s http://127.0.0.1:8911/health      # {"status":"ok","mock":false,...}
curl -s http://127.0.0.1:8911/stats       # 计数 / p50 / p95
```

### 3.2 在 new-api 里加渠道

| 字段 | 值 |
|---|---|
| 类型 | **OpenAI**（`type = 1`） |
| Base URL | `http://127.0.0.1:8911` |
| 密钥 | 任意非空（如 `sweet-local`，网关不校验） |
| 模型 | `gpt-4o-mini`（只能这一个） |

Base URL **不要**带 `/v1`——new-api 的 OpenAI 渠道自己拼 `/v1/chat/completions`，
网关正好暴露该路径（已验证）。

### 3.3 模型映射

只有 `gpt-4o-mini`。若业务要多个模型名，在渠道「模型重定向」里全部指向
`gpt-4o-mini`，计费按 mini 定价。**不要**把 `gpt-4o` 之类当高配卖——上游不认识会怎么回，
当前无法验证（上游已死），别赌。

---

## 4. 形态 B：原生 Go 渠道要点

新增 `relay/channel/sweetai/`，`constant.ChannelTypeSweetAI`：

1. **`adaptor.go`**：`ConvertOpenAIRequest` 不算 OpenAI 体，直接
   `json.Marshal(需求子集)` → `sweetSeal()` → 得到信封字符串；`GetRequestURL` 必须带全 5 个 query 参数。
2. **`do_request.go`**：body 是信封；header 至少给 `app/os/ver/lang/Content-Type`。
3. **`do_response.go`**：非流式把上游 `ChatGPTOut` 映射成 `dto.Usage` + `dto.Choice`；
   流式把上游 SSE 分块拼成 `dto.StreamResponse`。
   ⚠️ 本项目踩过的坑（`onesearch` 渠道）：`DoResponse` 里 `dto.Usage` 要么值要么指针，
   类型不匹配会在中继断言处 panic；非流式响应别写成「JSON + SSE 两段」。
4. **错误映射**（关键，照做）：
   | 上游表现 | 含义 | 映射 |
   |---|---|---|
   | HTTP 200 + `{"code":-1,"msg":"error, app not found"}` | query `app` 不对 | 400 参数错误（是**我们**的锅） |
   | HTTP 200 + `{"code":-103,"msg":"error, post json platform"}` | **query 参数缺失**（不是密钥错！） | 502，并把 msg 原样带出 |
   | HTTP 500 + `{"error":{"code":"system_error",...}}` | 上游 platform 不可用 | 502 + 触发渠道自动禁用 |
   | HTTP 404 文本 `404 page not found` | 打到了 `/api/*` 那批已下线路由 | 404，报配置错误 |
5. **不要把 `system_error` 当成功计费**——它是 HTTP 500，但有些网关会包成 200，务必按 body 判定。

---

## 5. 验收清单（上线前逐条打勾）

- [ ] `python tests/test_protocol.py` 7/7 通过（含与真实 `libprmp.so` 仿真的交叉校验）
- [ ] sidecar `/health` 返回 `"status":"ok"`、`"mock":false`
- [ ] new-api 渠道「测试」按钮通过（**上游恢复后**才有意义，见 §6）
- [ ] 非流式请求能拿到 `choices[0].message.content`
- [ ] 流式请求能收到 `data:` 分块并以 `[DONE]` 结束
- [ ] 上游宕机时渠道被自动禁用，而不是把 500 当成功记账
- [ ] `mr` 每请求不同（抓两条日志比对，防止实现里写死导致密钥可预测）

---

## 6. 当前阻塞：上游 platform 层不可用（2026-10-30 实测）

| 探测 | 结果 |
|---|---|
| `POST /v1/chat/completions` 不带 query | 200 `{"code":-103,...}`（任何 `md` 都这样） |
| `...&app=deadbeef…` | 200 `{"code":-1,"msg":"error, app not found"}` ← app 校验真实生效 |
| `...&app=<正确>` | **500 `{"error":{"code":"system_error","message":"The server is currently busy, please try again later."}}`** |
| 同上但 `md` 换成非法 base64 / 空 / 随机字节 | **完全相同的 500** |
| `/api/bot/*`、`/api/voice/*`、`/api/report` | 404 page not found |
| `/v1/models`、`/healthz`、`/api/config` 等 | 大量 502（Cloudflare → 源站） |

含义：**加密链和 app 校验已经对齐，卡在服务端「转发到 platform」这一步**。
所以现在把渠道接上只会稳定返回 502/`system_error` —— 属于"就绪但阻塞"，不是我们实现有问题。

**恢复后的验证方式**（一条命令）：

```bash
python tests/test_protocol.py           # 先确认本地密码学没坏
curl -s -m 90 -X POST http://127.0.0.1:8911/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say OK"}]}'
# 期望：{"id":"chatcmpl-...","choices":[{"message":{"content":"OK"}}]}
```

若恢复后仍 `-103`：**先查 query 5 个参数是否齐全**（`v/os/m/app/lang`），不要怀疑密钥。

---

## 7. 安全与合规边界（必须遵守）

- 该通道依赖第三方未公开接口，随时可能变更/封禁；不要对用户承诺 SLA。
- 上游没有账号体系，因此**没有"号池"概念**，也没有额度可刷——这点与其他 2API 渠道不同，
  不要照抄号池逻辑。
- 对外提供时请自行确认当地法律与上游条款；本仓库只做协议还原记录。
