# GhostRoot (dev.yt.ghostroot) — Ghost 风格的 root 前端（fork）

## 它是什么

一个单页、一键的 root 前端，外观/交互对标 GhostLock：一个大状态灯 + 三个按钮
（一键获取 Root / 修复框架注入 / 刷新）。

## 关键约束（决定了它是"控制器"而不是"执行器"）

CVE-2026-98260 的利用必须跑在 **uid 2000 (shell)** 下（tracefs、`/proc/*/pagemap`、
shell 域）。普通 APK 装上去是 `u0_aXXX`，SELinux 直接拒绝，**任何独立 App 都不可能
自己完成提权**。所以架构是分层的：

```
   GhostRoot.apk (UI, u0_aXXX)
        │  写 /sdcard/Android/data/dev.yt.ghostroot/files/ytrl.cmd
        ▼
   root 侧轮询 (ytrl.sh ghost, 2 s)  ← 已实现并验证
        │  执行 start / modules / apps
        ▼
   plant → rootd → ksud late-load → Zygisk 注入 → vectord
        │  回写 ytrl.status / ytrl.modules
        ▼
   GhostRoot.apk 读状态，2 s 刷新
```

也就是说 APK 只做"显示 + 投递命令"，真正干活的是已经在跑的那套 shell/root 启动器。
如果你要"点一下 APK 就能 root"，那 APK 必须借到一个 shell 身份，现实里只有两条路：
1. **AxManager**（本机已装，插件以 shell 身份运行）——把 GhostRoot 做成 AxManager 插件入口；
2. **Shizuku**（本机已装）——APK 通过 Shizuku 的 binder 以 shell 身份执行 `ytrl.sh`。

## 通道协议

目录：`/sdcard/Android/data/dev.yt.ghostroot/files/`

| 文件 | 方向 | 内容 |
|---|---|---|
| `ytrl.cmd` | App → root | `start` / `modules` / `apps`（执行后清空） |
| `ytrl.status` | root → App | `{"state":"ready","detail":"ksu-online","elapsed":2,...}` |
| `ytrl.modules` | root → App | `{"zn":"…","zygote":"…","injected":"6"}` |

root 侧实现见 `launcher/ytrl.sh` 的 `ghost_bridge()` / `ghost_loop()`，开机随
`watch` 一起启动。实测：

```
[19:59:04] ghost: cmd=modules
{"state":"ready","detail":"ksu-online","elapsed":2}
```

## 构建

```sh
# 需要 Android SDK build-tools + platforms/android-34/android.jar + JDK 17+
ANDROID_SDK=~/Library/Android/sdk ./build.sh
adb install -r GhostRoot.apk
```

本机目前 **没有** build-tools（`~/Library/Android/sdk` 只有 platform-tools），
也没有 Gradle/AGP 缓存，且 host 无外网；所以 APK 二进制还没生成。
拿到 build-tools 后一条命令即可出包。
