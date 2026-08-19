# Android SDK 集成指南

本仓库通过 `pkg/mobile` 提供 **gomobile 可绑定 API**。用 `gomobile bind` 可生成 AAR，供独立的 Android 工程引用。

## 范围

**本仓库只提供 SDK 绑定与文档，不包含：**

- Android Studio 工程、Gradle 工程、Sample App
- `TorService` / `VpnService` / APK
- 系统级 VPN 或透明代理

Android 应用工程由调用方自行创建。本仓库的产物是 `gotor.aar`（及配套 `gotor-sources.jar`）。

---

## ⚠️ 安全声明

**这是非官方、实验性软件**，未经 [The Tor Project](https://www.torproject.org/) 监督或背书，**不应视为安全或可用于生产**。

**真实匿名与隐私需求请使用官方软件：**

- **用户**：使用 [Tor Browser](https://www.torproject.org/download/)
- **开发者**：使用 [Arti](https://gitlab.torproject.org/tpo/core/arti) 或 [C Tor 参考实现](https://github.com/torproject/tor)

**不要依赖本软件来：**

- 保障人身安全或匿名
- 对抗监控
- 访问敏感信息
- 任何生产环境
- 任何安全取决于匿名性的场景

本指南仅供学习与研究。

---

## 绑定 API

`pkg/mobile` 只使用 gomobile 可绑定类型（`string` / `int` / `bool` / `error` / 简单方法 / listener 接口），不导出 `*client.Client`、`context`、`map`、`channel`。

```
mobile.Tor
  Start(dataDir string, socksPort int) error
  Stop() error
  IsReady() bool
  SocksAddr() string          // "127.0.0.1:port"
  BootstrapPercent() int
  StatusText() string
  SetListener(StatusListener)

StatusListener
  OnBootstrap(percent int, msg string)
  OnReady()
  OnError(msg string)
  OnStopped()
```

内部约束：

- `dataDir` **必须**由调用方传入；空值会报错，不会回退到 `~/.config/go-tor`
- SOCKS **只绑定** `127.0.0.1`，禁止 `0.0.0.0`
- Control / Metrics / DNSPort / HTTPTunnel / 中继 / 洋葱托管：默认全关（ControlPort=0 且无 ControlSocket）
- 电路池按移动端缩小（min=1，max=3）
- `Start` 会阻塞至电路可用且本机 SOCKS 已监听，或失败；**不要在主线程调用**。`OnReady` 只在此时触发，不要把它理解成 `client.Start` 一返回就可以发流量。

---

## 构建 AAR

### 依赖

- Go 1.25+（与本仓库 `go.mod` 一致）
- [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile)：`go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init`
- Android NDK（设置 `ANDROID_NDK_HOME` 或通过 Android SDK 的 ndk）
- 启用 CGO 的 C 编译器（gomobile 生成 JNI 胶水；go-tor 业务代码本身仍是纯 Go）

### 命令

```bash
# 推荐：Makefile
make android-aar

# 或直接调用 gomobile（arm64 + armeabi-v7a）
gomobile bind \
  -target=android/arm,android/arm64 \
  -androidapi=21 \
  -ldflags="-s -w" \
  -javapkg=org.opdai.gotor \
  -o bin/gotor.aar \
  github.com/opd-ai/go-tor/pkg/mobile
```

说明：

- `-target=android/arm,android/arm64` 对应 `armeabi-v7a` 与 `arm64-v8a`
- `-androidapi=21` 为最低 API 21（可按应用需要提高）
- `-ldflags="-s -w"` 去掉符号表与 DWARF，缩小体积
- `-javapkg` 可选；不指定时 Java 包名默认为 `mobile`
- 产物：`bin/gotor.aar`

需要 x86 模拟器时可改为 `-target=android`（额外包含 x86 / x86_64）。

---

## Gradle 引用本地 AAR

将 `gotor.aar` 放到应用模块的 `libs/`，例如 `app/libs/gotor.aar`。

`settings.gradle.kts`（或 Groovy 等价配置）无需特殊处理。在 `app/build.gradle.kts`：

```kotlin
android {
    defaultConfig {
        minSdk = 21
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a")
        }
    }
}

dependencies {
    // AAR 内已含 jni/armeabi-v7a 与 jni/arm64-v8a，不必再把 libs/ 设为 jniLibs
    implementation(files("libs/gotor.aar"))
}
```

Groovy 写法：

```groovy
dependencies {
    implementation files('libs/gotor.aar')
}
```

---

## Kotlin 调用示例

```kotlin
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mobile.StatusListener
import mobile.Tor
import java.net.InetSocketAddress
import java.net.Proxy
import okhttp3.OkHttpClient

class TorHolder(context: Context) : StatusListener {
    private val tor = Tor()
    private val dataDir = context.noBackupFilesDir.resolve("go-tor").absolutePath

    init {
        tor.setListener(this)
    }

    suspend fun start(socksPort: Int = 9050) = withContext(Dispatchers.IO) {
        tor.start(dataDir, socksPort.toLong())
    }

    fun socksProxy(): Proxy {
        val addr = tor.socksAddr() // "127.0.0.1:9050"
        val hostPort = addr.split(':')
        return Proxy(
            Proxy.Type.SOCKS,
            InetSocketAddress(hostPort[0], hostPort[1].toInt()),
        )
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        tor.stop()
    }

    override fun onBootstrap(percent: Long, msg: String) {
        // 更新通知栏或 UI（切回主线程）
    }

    override fun onReady() {}
    override fun onError(msg: String) {}
    override fun onStopped() {}
}
```

注意：gomobile 会把 Go 的 `int` 映射为 Java/Kotlin 的 `long`。

---

## Java 调用示例

```java
import android.content.Context;
import mobile.StatusListener;
import mobile.Tor;

public final class TorClient implements StatusListener {
    private final Tor tor = new Tor();
    private final String dataDir;

    public TorClient(Context context) {
        this.dataDir = new java.io.File(context.getNoBackupFilesDir(), "go-tor").getAbsolutePath();
        tor.setListener(this);
    }

    /** 必须在后台线程调用。gomobile 将 Go int 映射为 Java long。 */
    public void start(long socksPort) throws Exception {
        tor.start(dataDir, socksPort);
    }

    public String socksAddr() {
        return tor.socksAddr(); // "127.0.0.1:9050"
    }

    public boolean isReady() {
        return tor.isReady();
    }

    public void stop() throws Exception {
        tor.stop();
    }

    @Override public void onBootstrap(long percent, String msg) {}
    @Override public void onReady() {}
    @Override public void onError(String msg) {}
    @Override public void onStopped() {}
}
```

---

## OkHttp 使用本机 SOCKS

```kotlin
val proxy = Proxy(
    Proxy.Type.SOCKS,
    InetSocketAddress("127.0.0.1", 9050), // 或解析 tor.socksAddr()
)
val client = OkHttpClient.Builder()
    .proxy(proxy)
    .build()

// 仅在 IsReady() == true 之后发请求
val response = client.newCall(
    Request.Builder().url("https://check.torproject.org").build()
).execute()
```

SOCKS 只监听 `127.0.0.1`，不要改成 `0.0.0.0`，也不要把该端口暴露到局域网。

---

## 集成注意

1. **DataDir**：使用 `context.noBackupFilesDir`（或 `filesDir`）下的子目录，例如 `noBackupFilesDir/go-tor`。不要用外部存储，不要省略 `dataDir`。`noBackupFilesDir` 可避免备份同步把守卫状态等敏感文件上传到云端。
2. **后台保活**：进程在后台会被杀。若需要持续代理，请由**你的应用**自行实现前台服务（`FOREGROUND_SERVICE`）；本仓库不提供 `TorService`。
3. **不要阻塞主线程**：`Start` / `Stop` 会阻塞。放到 `Dispatchers.IO`、`Executor` 或前台服务工作线程。
4. **不要绑定 0.0.0.0**：SDK 强制 SOCKS 绑定 `127.0.0.1`。应用侧代理配置也必须指向本机。
   Android 上回环地址由各 UID 共享：其它应用也能连接 `127.0.0.1:socksPort`。请使用应用自己选定的高位端口，不要把端口告诉其它 App；本 API 不提供 SOCKS 用户名口令。SDK 默认按目的地隔离电路（SOCKS `IsolationMode=strict`），但不能阻止其它应用借用该代理。
5. **首次引导**：第一次启动可能需要数十秒（共识与建路）。用 `StatusListener` 或 `BootstrapPercent()` / `StatusText()` 更新 UI。
6. **重复 Start**：已经启动或正在启动时会返回明确错误；先 `Stop` 再 `Start`。
7. **重复 Stop**：安全，可多次调用。
8. **日志**：包本身不依赖 Android。标准输出通常会被 logcat 收集。默认不是 debug，避免打印敏感电路细节。
9. **DataDirectory 锁**：同一 `dataDir` 同时只能有一个实例（沿用现有 client flock 逻辑）。

---

## 非目标

- **VpnService / 系统 VPN**：不在本仓库实现。若应用要做 VPN 模式，需自行写 `VpnService` 并把流量转到 `SocksAddr()`。
- **Sample App / APK**：不提供。请在自己的 Android 工程中集成 AAR。
- **官方匿名保证**：见上文安全声明。
