# libprmp.so 逆向：`getAppSecret` 全解

APK 里 `PromptHelper` 的 6 个 native 方法由 `libprmp.so` 实现（`System.loadLibrary("prmp")`，
字符串解密后确认，`libnms.so` 是 pangle 的 `com.pgl.ssdk`，与之无关）。

```java
// com.smartxlib.helper.PromptHelper
public static native String getAppSecret(long j10, String str);
```

调用链：`nc.C21616n2.m81774h()` → `com.zelqora.vanix.C18138i0.m67024X()` →
`com.smartxlib.helper.C17288a.m66011B()` → `PromptHelper.getAppSecret()`。

## 1. 定位

```text
$Z12getAppSecretP7_JNIEnvP7_jclasslP8_jstring  @ 0x53dfc  (688 B, aarch64)
```
（`.dynsym` 里 765 个符号，函数名被随机化，只有 JNI 注册表里的名字可读。）

## 2. 反汇编结论

`getAppSecret(env, clazz, long stamp, jstring rand)`：

```c
cls        = FindClass(env,  "java/lang/Long");                 // 0x5e30c 解出
mid        = GetStaticMethodID(cls, "toString", "(J)Ljava/lang/String;");
jstr       = CallStaticObjectMethod(env, cls, mid, stamp);      // = Long.toString(stamp)
stampStr   = GetStringUTFChars(env, jstr, NULL);
randStr    = GetStringUTFChars(env, rand, NULL);
snprintf(buf, 200, "%d_%d_%s_%s", 182, g_whm, stampStr, randStr);  // 格式串 0x5e7a8 解出
digest     = Fe8xy6PWr7OV(env, byteArray(buf));                  // 0x51ca4 → lfvvLHFVsaL
return NewStringUTF(env, first 32 bytes of digest);
```

其中 `lfvvLHFVsaL(env, algName, jbyteArray)` 走 Java `MessageDigest`：

```c
md  = MessageDigest.getInstance(algName);        // algName 常量 0x5b278 = "SHA1"
d   = md.digest(bytes);                          // byte[20]
for (i = 0; i < d.length; i++)
    sprintf(out + i*2, "%02x", d[i]);            // 小写 hex，40 字符
```

## 3. 常量还原方法

`.rodata` 里的字符串全部被 **OLLVM 风格常量混淆**：函数把 8 字节立即数写进栈上缓冲，
再做 `eor v0.16b, v0.16b, v1.16b` 的两段异或。这些函数是纯计算、无外部调用，
所以用 **Unicorn(aarch64) 直接跑** 最省事（`tools/constemu.py`）：

| 函数 | 用途 | 结果 |
|---|---|---|
| `0x5e30c` | FindClass 参数 | `java/lang/Long` |
| `0x5e464` | 方法名 | `toString` |
| `0x5e5ac` | 方法签名 | `(J)Ljava/lang/String;` |
| `0x5e7a8` | 格式化串 | `%d_%d_%s_%s` |
| `0x5b278` | 摘要算法 | `SHA1` |

> 早期版本把 `0x5b278` 误当成 `MD5` 走了一段弯路；正确的判定来自异或结果的字节
> `0x53 0x48 0x41 0x31` = `"SHA1"`。

## 4. 完整仿真

`tools/emulate_appsecret.py`：把整个 `.so` 映射进 Unicorn，处理 `.rela.dyn`
（RELATIVE / GLOB_DAT / ABS64），再为 267 个 PLT 桩提供 Python 实现
（JNI 字符串、FindClass、GetStaticMethodID、CallStaticObjectMethod、NewByteArray、
SetByteArrayRegion、`__strlen_chk`、`__strncpy_chk`、`__cxa_guard_*` …），
在 `0x53f00`（调用变参格式化辅助函数处）拦截并按 `%d_%d_%s_%s` 渲染，
最后照原逻辑取 SHA-1 前 32 字符。

交叉校验（`tests/test_protocol.py::test_emulator_matches_implementation`）：

```text
1721027239372 3gATIA0FRP... emu=930dd24bfebbc9ca957b0e91bc299f7b py=930dd24bfebbc9ca957b0e91bc299f7b OK
1694368717213 CoTjQ3047Z... emu=533976ba7f2e8785e27eae92835152ff py=533976ba7f2e8785e27eae92835152ff OK
1760645659732 aezAcNc47W... emu=6df5f53e563ccd3610067d2d6065b60e py=6df5f53e563ccd3610067d2d6065b60e OK
1760258845613 4nNwflD7Tu... emu=a50e070e29950990c6c7687db5dcde8b py=a50e070e29950990c6c7687db5dcde8b OK
1792399362971 3DyucHE6x9... emu=2049aea7a24bb23bbebdfd2752f7ff0f py=2049aea7a24bb23bbebdfd2752f7ff0f OK
1782824471499 BaPGB9w2R6... emu=92c80783c0a38fc9826cf307db2c6a66 py=92c80783c0a38fc9826cf307db2c6a66 OK
```

## 5. 一个漂亮的旁证

调试阶段 `__strlen_chk` 桩写错（把长度上限当成字符串指针），导致 `buf` 只截到 `"182"`，
于是 `secret = md5("182") = 4c5bde74a8f110656874902f07378009` ——
恰好等于 APK 里写死的 `app` 头常量。这同时证明了两件事：
格式串首参数就是 `182`，以及服务端 `app` 头的构造方式就是 `md5("182")`。
