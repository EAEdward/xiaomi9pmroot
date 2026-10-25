# yt-root-98260

小米平板 9 Pro Max（`yingtian` / M367FC）的一键 Root 工具链：**开机自动提权 → late-load KernelSU → Zygisk 注入 → Vector(Xposed) 框架**，正常情况 1–10 秒就绪。

针对 `CVE-2026-98260`（POSIX CPU timer UAF）实现，**一次 UAF 出三次写**：装一个完整 root cred + 关 SELinux。

## 目标环境

| 项 | 值 |
|---|---|
| 设备 | Xiaomi Pad 9 Pro Max，代号 `yingtian`，型号 `M367FC` |
| ROM | `OS4.0.16.0.XBMCNXM`，Android 17 |
| 内核 | `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k` |
| 其它 | 4K 页、10 核、bootloader 锁定（无 fastboot 兜底） |

> 内核符号、slab 布局、SELinux 策略全部按这一版校准。**其它机型/其它 ROM 不适用**，预检会直接 `blocked` 而不是硬上。

## 它做了什么

```
AxManager 插件（shell 身份，开机自启）
   └─ plant        漏洞利用：一次 UAF → task->cred 指向伪造 cred + 关 SELinux
   └─ su98260      rootd 客户端（拿到 root 后才能用）
   └─ ksud late-load  把 kernelsu.ko 塞进内核（每次开机一次）
   └─ ytrl.sh      编排：提权 → KSU → 模块阶段 → Zygisk 注入 → 框架 daemon → 守护
```

关键点：

* **一次 UAF 三处写**：`posix_cpu_timers_exit()` 会连续排空 PROF/VIRT/SCHED 三棵 rb-tree，每棵树的首个节点都是同一块被回收的 slab 里的对象 —— 三个基座各 arm 一个 timer，一次 reclaim 就换来三次独立的 `rb_erase`（`__rb_parent_color` / `rb_right` 全由攻击者指定）。
* **tile 对调**：把“要写入的值”放进 `rb_right`，`cred` 就不再压在 rb_node 上（`node+0x20`），`rb_erase` 的第二次写只落在 `cred->usage` 这个永不释放的引用计数上。
* **Zygisk 注入**：late-load 之后 Zygisk Next 的 daemon 只注入“下一代” zygote，所以流程是「刷 daemon → 重启一次框架 → 校验 `/proc/<pid>/maps` 出现 `libzygisk`」，system_server 随后继承。

细节、反汇编依据、5 次冷启动数据见 [`docs/ROOT-PATH.md`](docs/ROOT-PATH.md)。

## 快速开始

1. 安装 AxManager（shell 身份的插件宿主，是整条链的入口）。
2. 在 AxManager 里安装 `yt-root-plugin.zip`（本仓库 Release 附件）。
3. 安装 KernelSU 管理器 v3.3.1（**不要**点“安装内核”，内核由插件 late-load）。
4. 重启。

验证：

```sh
cat /data/local/tmp/ytrl.status      # {"state":"ready","detail":"ksu-online"}
tail /data/local/tmp/root.log        # 提权/注入时间线
/data/adb/modules/zygisk_vector/cli status   # Framework Version: 2.2 / API 102
```

一键重试（AxManager 里点插件动作也可以）：

```sh
su -c "sh /data/local/tmp/ytrl.sh force"     # 重新提权
su -c "sh /data/local/tmp/ytrl.sh modules"   # 补 KSU/注入/框架
su -c "sh /data/local/tmp/ytrl.sh apps"      # 预热指定 App（/data/local/tmp/ytrl.apps）
```

## 构建

`plant` 是静态链接的 aarch64 musl 程序，用 zig 交叉编译：

```sh
cd plant && make            # 需要 zig
# 或： zig cc -target aarch64-linux-musl -static -O2 -o plant uaf_plant_v6.c pc98260_rootd.c
```


### GhostRoot APK

`app/ghostfork/` 由 CI 构建（`.github/workflows/build.yml`）：`ubuntu-latest` 自带的 Android SDK，跑
`aapt2 + javac + d8 + zipalign + apksigner`，产物在 Actions 的 `GhostRoot-apk` artifact 里，也挂在 Release 上。

装的时候注意 MIUI/HyperOS 会拦 `adb install`（`INSTALL_FAILED_USER_RESTRICTED`）：

```sh
adb push GhostRoot.apk /data/local/tmp/
adb shell "su -c 'pm install -r -g /data/local/tmp/GhostRoot.apk'"   # 有 root 时走这条
```

或者开发者选项里打开「USB 调试（安全设置）」/「通过 USB 安装」。

`launcher/` 是纯 shell，无构建步骤。`app/ghostfork/` 是一个 Ghost 风格的前端工程（见其 README，需要 Android SDK build-tools）。

## 目录结构

```
plant/     漏洞利用源码（uaf_plant_v6.c）+ rootd/su 客户端
launcher/  AxManager 插件：module.prop / service.sh / action.sh / ytrl.sh
app/       GhostRoot 前端（Java，控制器：不能自己提权，只投递命令）
docs/      完整的机制与实测记录（ROOT-PATH.md）
dist/      发布附件说明（二进制不入库，走 Release）
```

## 已知边界

* **KSU 是 late-load**：模块的“文件挂载”（`mount:true`）不会发生 —— Zygisk 型模块（Vector / LSPosed 系）可用，改 `/system` 文件的 Magisk 型模块不可用。
* 每次开机需要**重启一次系统框架**（约 20 秒）完成 Zygisk 注入，插件自动做，用户无感。
* **不是 100% 命中**：快时 1–5 秒，偶尔 miss。miss 后停住的 plant 不能 kill（会内核 panic），脚本会自动重启重来（每天上限 6 次）。
* Xposed 框架只能用 [Vector](https://github.com/JingMatrix/Vector)（`org.matrix.vector.manager`）；原版 LSPosed 1.9.2 只支持到 Android 14，在本 ROM 上会拖崩 system_server。
* bootloader 锁定，出错没有 fastboot 兜底；所有改动都在 `/data`，重启即回到干净状态。

## 致谢

* [KernelSU](https://github.com/tiann/KernelSU) / [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next)
* [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext)
* [Vector](https://github.com/JingMatrix/Vector)（LSPosed 的活跃分支）
* [box_for_magisk](https://github.com/taamarin/box_for_magisk)（运行时模块的对照验证）

## License

MIT，见 [LICENSE](LICENSE)。
