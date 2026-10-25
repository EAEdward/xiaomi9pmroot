# xiaomi9pmroot

小米平板 9 Pro Max（`yingtian` / M367FC）一键 root，**只做三件事**：

1. 用 `CVE-2026-98260` 拿到 root（一次 UAF，写一个完整 root cred + 关 SELinux）；
2. 用这份 root 把 **KernelSU** 的 `kernelsu.ko` late-load 进内核（`su` 立刻可用，管理器可装模块但不参与 root）；
3. 以 root 身份跑你自己的脚本（`/data/local/tmp/yt-scripts/*.sh`）。

**不涉及** Zygisk / LSPosed / 模块文件挂载 —— 那套在 late-load 架构下本来也不成立，这里直接不碰。

## 前置：一个 shell 身份

漏洞利用必须跑在 **uid 2000 (shell)** 下（tracefs、`/proc/*/pagemap`、shell 域），所以需要下面二选一：

| 提供者 | 用途 | 备注 |
|---|---|---|
| **AxManager** | 插件形式，开机自启 | 推荐，装一次以后全自动 |
| **Shizuku** | 手动/脚本触发 | 适合已经用 adb 或无线调试跑了 Shizuku 的场景 |

## 安装流程 A：AxManager（开机自动 root）

1. 安装 **AxManager**，打开一次，允许后台运行。
2. AxManager → 插件/模块页 → 安装 `xiaomi9pmroot-v1.0.zip`。装完列表里会出现 `xiaomi9pmroot`。
3. 安装 **KernelSU 管理器**（Release 里的 `KernelSU-v3.3.1.apk`）。**不要**点“安装内核” —— 内核由本插件 late-load。
4. 重启平板。约 10 秒内自动完成：提权 → rootd → KSU 上线 → 跑脚本。

验证：

```sh
cat /data/local/tmp/ytrl.status      # {"state":"ready","detail":"ksu-online"}
su -c id                             # uid=0(root) … context=u:r:ksu:s0
tail /data/local/tmp/root.log
```

## 安装流程 B：Shizuku（手动触发）

1. 装 Shizuku，用 adb 或无线调试把它的服务跑起来（`adb shell sh /storage/emulated/0/Android/data/moe.shizuku.privileged.api/start.sh`）。
2. 把 payload 推到设备并给执行权限：

```sh
adb push plant su98260 ksud ytrl.sh /data/local/tmp/
adb shell chmod 755 /data/local/tmp/plant /data/local/tmp/su98260 /data/local/tmp/ksud /data/local/tmp/ytrl.sh
```

3. 用 Shizuku 的 shell 跑：

```sh
rish -c "sh /data/local/tmp/ytrl.sh start"    # 或 Shizuku 终端里直接 sh /data/local/tmp/ytrl.sh start
```

4. 之后 `su` 可用，KSU 管理器可正常授权。

## 跑自己的脚本

提权成功后，`/data/local/tmp/yt-scripts/` 下每个 `*.sh` 会**按名字顺序、以 root 身份各执行一次**，输出写进 `/data/local/tmp/root.log`：

```sh
adb shell "mkdir -p /data/local/tmp/yt-scripts"
adb push my-setup.sh /data/local/tmp/yt-scripts/
adb shell "su -c 'sh /data/local/tmp/ytrl.sh scripts'"   # 也可以随时手动跑一遍
```

## 命令

```sh
ytrl.sh start      # 提权 → rootd → KSU → 脚本（幂等，已 root 时只跑脚本）
ytrl.sh force      # 强制重开一轮（清锁）
ytrl.sh scripts    # 只跑脚本
ytrl.sh status     # root / socket-only / none
ytrl.sh check      # 预检（内核、tracefs、页面大小）
```

## 适用环境

| 项 | 值 |
|---|---|
| 设备 | Xiaomi Pad 9 Pro Max，`yingtian`，`M367FC` |
| ROM | `OS4.0.16.0.XBMCNXM` / Android 17 |
| 内核 | `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k` |

内核符号、slab 布局、SELinux 策略都按这一版校准，**其它 ROM 不适用**；预检会 `blocked` 并拒绝执行。

## 构建

```sh
cd plant && make     # 需要 zig；或 zig cc -target aarch64-linux-musl -static -O2 -o plant uaf_plant_v6.c pc98260_rootd.c
```

启动器是纯 shell，无构建步骤；打包：

```sh
cd launcher && zip -X xiaomi9pmroot-v1.0.zip module.prop service.sh action.sh ytrl.sh plant su98260 ksud
```

## 机制（简版）

`begin_new_exec()` 里 `de_thread()` 先把旧 leader `release_task()` 掉，之后才走 4 个可失败步骤与计时器清理；`exec_mmap` 的 `down_read_killable` 被打断时，`exit_itimers()` 已经把 `k_itimer` 释放，而 `tsk->posix_cputimers` 三棵 rb-tree 里仍留着悬空节点。回收那一页之后 reap，`posix_cpu_timers_exit()` 就会用我们的 `rb_node` 做 `rb_erase`。

一次调用排空 **PROF / VIRT / SCHED 三棵树**，三个基座各 arm 一个 timer、落在同一块 slab 里，就得到三次独立写：装 `task->cred` + 关 SELinux。细节见 [`docs/HOW-IT-WORKS.md`](docs/HOW-IT-WORKS.md)。

## 已知边界

* **不是 100% 命中**：快时 1–5 秒，偶尔 miss。miss 后停住的 plant 不能 kill（会内核 panic），脚本会自动重启重来（每天上限 6 次）。
* 每次开机都要重新 late-load KSU（内核模块不持久），这是 late-load 的固有代价。
* 仅该 ROM / 该内核；bootloader 锁定，没有 fastboot 兜底，但所有改动都在 `/data`，重启即干净。

## License

MIT，见 [LICENSE](LICENSE)。
