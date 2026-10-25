# xiaomi9pmroot

小米平板 9 Pro Max 的 root 工具。开机自动提权，把 KernelSU 装进内核，然后执行你自己的脚本。

*One-tap root for Xiaomi Pad 9 Pro Max — boots rooted, loads KernelSU, then runs your scripts.*

[![Release](https://img.shields.io/github/v/release/EAEdward/xiaomi9pmroot?label=Release&logo=github)](https://github.com/EAEdward/xiaomi9pmroot/releases/latest)
[![License](https://img.shields.io/github/license/EAEdward/xiaomi9pmroot?logo=gnu)](LICENSE)

## 支持的设备

| | |
|---|---|
| 设备 | Xiaomi Pad 9 Pro Max · `yingtian` · M367FC |
| 系统 | OS4.0.16.0.XBMCNXM · Android 17 |
| 内核 | `6.18.21-android17-5-g805aa6adea19` |

内核符号、slab 布局、SELinux 策略都按这一版对齐。换系统或换机型，预检会拦下来。

## 功能

- 开机自动 root，冷启动 1–5 秒能用 `su`
- 自动 `ksud late-load`，KernelSU 管理器直接可用
- 提权后按名字顺序执行 `/data/local/tmp/yt-scripts/*.sh`，每个一次，以 root 身份
- 全程静默：不弹窗、不发通知

## 入口

漏洞跑在 shell 身份下，所以需要一个 shell 环境，两个都行：

| 入口 | 怎么用 |
|---|---|
| AxManager | 装插件 zip，开机自启 |
| Shizuku | `rish -c "sh /data/local/tmp/ytrl.sh start"` |

## 安装

### AxManager（开机自动）

1. 装 AxManager，打开一次
2. AxManager → 插件页 → 安装 Release 里的 `xiaomi9pmroot-v1.0.zip`
3. 装 Release 里的 `KernelSU-v3.3.1.apk`，不要点"安装内核"
4. 重启

### Shizuku（手动）

```sh
adb push plant su98260 ksud ytrl.sh /data/local/tmp/
adb shell chmod 755 /data/local/tmp/plant /data/local/tmp/su98260 /data/local/tmp/ksud /data/local/tmp/ytrl.sh
rish -c "sh /data/local/tmp/ytrl.sh start"
```

## 验证

```sh
cat /data/local/tmp/ytrl.status    # {"state":"ready","detail":"ksu-online"}
su -c id                           # uid=0(root) ... u:r:ksu:s0
tail /data/local/tmp/root.log
```

## 命令

```sh
ytrl.sh start      # 提权 → rootd → KSU → 跑脚本；已 root 时只跑脚本
ytrl.sh force      # 强制重来一轮
ytrl.sh scripts    # 只跑脚本
ytrl.sh status     # root / socket-only / none
ytrl.sh check      # 预检
```

## 自己的脚本

```sh
adb shell mkdir -p /data/local/tmp/yt-scripts
adb push setup.sh /data/local/tmp/yt-scripts/
adb shell "su -c 'sh /data/local/tmp/ytrl.sh scripts'"
```

输出都进 `/data/local/tmp/root.log`。

## 构建

```sh
cd plant && make
```

`plant` 是 aarch64 静态程序，用 [zig](https://ziglang.org) 交叉编译。启动器是纯 shell，无构建步骤。

打包：

```sh
cd launcher && zip -X xiaomi9pmroot-v1.0.zip module.prop service.sh action.sh ytrl.sh plant su98260 ksud
```

## 说明

提权走的是 `CVE-2026-98260`：`begin_new_exec()` 里 `de_thread()` 先 `release_task()`，之后才清 POSIX CPU timer；`exec_mmap` 被打断时计时器对象已经释放，而 rb-tree 还挂着它们。等父进程 reap，内核就会拿我们铺好的 `rb_node` 做 `rb_erase`。一次调用排空三棵树，三个时钟各挂一个 timer，一次回收换三次写。细节在 [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md)。

KernelSU 是 late-load，每次开机重新装一次，这是 late-load 的固有开销。

## 致谢

[KernelSU](https://github.com/tiann/KernelSU)、[AxManager](https://github.com/frb-axeron/AxManager)、[Shizuku](https://github.com/RikkaApps/Shizuku)、[zig](https://ziglang.org)。

## 许可

MIT
