# Sweet AI v1.9.8（com.mxxtech.sweetai）协议还原

> 全部结论来源于对 `Sweet AI v1.9.8 (Premium).apk` 的静态反编译 + `libprmp.so` 的 Unicorn 仿真，
> 并有真实服务端行为作为旁证（见 §7）。未标注"已验证"的条目为静态确认。

## 1. 概览

| 项 | 值 |
|---|---|
| 包名 | `com.mxxtech.sweetai`（代码包 `com.mxxtech.aifox`，白标模板 aifox） |
| 版本 | versionName `1.9.8`，versionCode `26091802` |
| 后端 | `https://api.callershow.com/` |
| 支持邮箱 | `support@smartxlib.com`（native 库 `com.smartxlib.*`，`com.zelqora.vanix.*`） |
| 鉴权 | **无账号体系**。仅 `app` 应用 ID + 请求体 AES 加密信封 |
| 模型 | `gpt-4o-mini` |
| 形态 | AI 女友/角色扮演聊天（亲密度、礼物、朋友圈、TTS/STT） |

APK 里的 Retrofit 接口（`vc.InterfaceC24198b`）只是**一部分**：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/bot/types` | 机器人类目 — 线上 404 |
| POST | `/api/bot/list` | 机器人列表 — 线上 404 |
| POST | `/api/bot/moments` | 朋友圈 — 线上 404 |
| POST | `/api/voice/stt` `tts` | 语音 — 线上 404 |
| POST | `api/report` | 举报 — 线上 404 |
| POST | `v1/chat/completions` | **真实聊天不走这里**（见 §3） |

## 2. 关键常量

| 常量 | 值 | 出处 |
|---|---|---|
| base url | `https://api.callershow.com/` | `p331dc.C18367c.f73599i` |
| app 编号 | `182` | `getAppSecret` 内 snprintf 第一参数 |
| app 头/query 值 | `4c5bde74a8f110656874902f07378009` = `md5("182")` | `C18367c.f73598h` |
| versionCode（信封 mv） | `26091802` | `C18367c.f73594d` |
| AES IV | `00 01 02 … 0f` | `nc.C21616n2.f85028g` |
| 算法 | `AES/CFB/NoPadding` + `SHA-1` | `C21616n2.m81770d` / `m81777k` |

## 3. 真实聊天请求（Volley，不是 Retrofit）

`nc.C21610m4.m81744p()` 在 `MyApplication` 启动时拼好 URL：

```
POST https://api.callershow.com/v1/chat/completions
     ?v=1.9.8&os=android&m=gpt-4o-mini&app=4c5bde74a8f110656874902f07378009&lang=en
```

`m81763x()` → `C21690w4(1, url, envelopeJSONObject, listener)`，即 Volley POST。

**请求头**（`vc.C24203g` 里的 OkHttp 拦截器，对 Retrofit 通道生效；Volley 通道同样带上更稳妥）：

```
Content-Type: application/json; charset=utf-8
lang: <设备语言，Android 的 iw 会被修正成 he>
app : 4c5bde74a8f110656874902f07378009
os  : android
ver : 1.9.8
```

## 4. 请求体：加密信封

OkHttp 拦截器 `vc.C24203g$b` 会把整个业务 JSON 换掉：

```json
{"mv":26091802,"mr":"<40位随机串>","mt":1793311115000,"mm":1,"md":"<base64>"}
```

| 字段 | 含义 |
|---|---|
| `mv` | versionCode |
| `mr` | 40 位 `[A-Za-z0-9]` 随机串（每请求重生成） |
| `mt` | 毫秒时间戳 |
| `mm` | 方法号，聊天固定 `1` |
| `md` | 密文 |

生成链（`nc.C21616n2`）：

```text
secret  = SHA1( f"182_0_{mt}_{mr}" ).hex()[:32]              # ← native getAppSecret
key     = SHA1( f"{secret}_{mv}_{mm}_{mt}_{mr}" ).hex()[:32]  # ← C21616n2.m81774h
md      = base64( AES-256-CFB(key.ascii, iv=00..0f, utf8(business_json)) )
```

> 两层都由 Java 的 `SHA-1` 生成，hex 为小写，取前 32 字符后**按 ASCII 当作 32 字节 AES-256 密钥**。
> 注意：`app` 头用的是 `md5("182")`，与运行期 `secret` 用的 SHA-1 是**两套**东西，容易踩坑。

业务 JSON（`com.mxxtech.aifox.model.ChatGPTRequest`，Gson 序列化）：

```json
{
  "model": "gpt-4o-mini",
  "messages": [{"role":"user","content":"hi"}],
  "stream": true,
  "initmate": true,
  "inspiration": false,
  "response_format": {"type":"json_object"},
  "initmate_data": {"current_time":"2026-10-30 05:00:00","language":"English",
                    "user_level":1,"output_json":"…"},
  "user_info": {"afId":"<AppsFlyer UID>","country":"English"}
}
```

`stream` 在 App 里恒为 `true`（SSE），但服务端对 `stream=false` 也能返回整包 JSON。

## 5. 响应

- 正常：`ChatGPTOut` 形状（`id/created/model/system_fingerprint/choices[]`），或 SSE 分块。
- 中间层错误（明文 JSON）：

| code | msg | 触发 |
|---|---|---|
| `-1` | `error, app not found` | query `app` 不匹配 |
| `-103` | `error, post json platform` | **不带 query 参数**时任意信封都返回该错误 |
| HTTP 500 | `{"error":{"code":"system_error","message":"The server is currently busy, please try again later."}}` | app 校验通过后，**上游平台不可用**（当前状态） |

## 6. native 签名函数 `getAppSecret`

见 [`02-native-re.md`](02-native-re.md)。结论：

```
secret = SHA1(f"182_0_{stamp}_{rand}").hex()[:32]
```

（`libprmp.so` 里 `%d_%d_%s_%s` 的第二个 `%d` 读的是 4 字节全局 `WhMdHBD6M`，运行时为 0。）

## 7. 线上行为（本次实测，2026-10-30）

| 探测 | 结果 |
|---|---|
| `POST /api/bot/list`、`/api/bot/types`、`/api/report`、`/api/voice/*` | 404 page not found（线上没有这些路由） |
| `POST /v1/chat/completions`（无 query） | 200 `{"code":-103,...}`，**无论密钥/明文是否正确都是它** |
| `POST /v1/chat/completions?...&app=deadbeef…` | 200 `{"code":-1,"msg":"error, app not found"}` ← **app 校验真实存在** |
| `POST /v1/chat/completions?...&app=<正确>` | **500 `system_error / The server is currently busy`**，对任意 `md`（含非法 base64、空串、随机字节）都一样 |
| 其他路径（`/v1/models`、`/healthz`、`/api/config` …） | 大量 502（Cloudflare → 源站） |

结论：**加密链与 app 校验已打通，但业务转发层（"platform"）当前不可用**，
故无法用真实响应做最终端到端内容比对。密码学部分改用
"真实 `libprmp.so` 仿真 ↔ Python 实现" 交叉校验（6 组随机输入全部一致，见 `tests/test_protocol.py`）。
