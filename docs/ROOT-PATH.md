# 同系统任意小米平板的 Root 通路（CVE-2026-98260）

设备族：`yingtian` / M367FC · OS4.0.16.0.XBMCNXM · Android 17
内核：`6.18.21-android17-5-g805aa6adea19-abogki565292102-4k` · 4K 页 · 10 核

## 1. 结论

冷启动 → root 可用，全自动，**39~67 秒**，无需电脑、无需任何点击。
在**同一内核 build**的设备上，只要 shell 身份能执行 `plant`，通路成立。

## 2. 通路成立的全部条件（缺一即 blocked）

| 条件 | 判定方式 | 本机实测 |
|---|---|---|
| 内核 build 完全一致 | `uname -r` 字符串比对 | ✅ 6.18.21-…-4k |
| 4K 页 | `getconf PAGE_SIZE` = 4096 | ✅ 4096 |
| tracefs 可写 | `plant --check` 的 `tracefs/trigger/event` | ✅ 1/1/1 |
| shell 身份 + readtracefs | `id` 含 3012 | ✅ |
| KASLR slide 可测且 2MB 对齐 | 三次采样多数一致 | ✅ 6 次开机全对齐 |

一条命令判定任意同系统平板：

```sh
/data/local/tmp/plant --check
# {"uname":"6.18.21-…","page_size":4096,"cpus":10,…,"verdict":"ok"}
```

`verdict` 三态：`ok` 可跑 / `blocked` 内核形状不符，拒绝执行 / `inconclusive` slide 暂未测到，主流程仍会自己 fail-closed。

## 3. 冷启动回归数据（真机，全自动，无人工触发）

| # | boot_id | slide | 结果 | 耗时 |
|---|---|---|---|---|
| 1 | 652f2065 | 0x1022000000 | OK | – |
| 2 | 3b110184 | 0x1832a00000 | OK | ~67s |
| 3 | 335d87d4 | 0x2821800000 | OK | 57s |
| 4 | 1b99cea0 | 0x14e1800000 | OK | – |
| 5 | 567e4210 | 0x2e56600000 | OK | 40s |
| 6 | 0b185271 | 0x16cb200000 | OK（payload 自愈）| 39s |

6 个 slide 值互不相同，全部 2 MB 对齐——证明测量是运行时推导，不是绑死某次开机。

## 4. 本次为「跨机器」修掉的东西

1. **CPU 数硬编码**：`leak_task()` 原本固定扫 8 个 CPU，本机 10 核会漏掉 cpu8/9 的分配记录 → 改为 `cpu_count()` 动态。
2. **slide 无校验**：原来取第一条 384 字节分配就算，测错会往内核乱写 → 现在三次采样、2 MB 对齐校验、多数投票，不收敛直接 `return 7` 拒绝运行。
3. **无缓存**：同一 boot 内重复运行会反复测量 → 新增 `/data/local/tmp/.yt-slide`（按 boot_id 失效）。
4. **无预检**：新增 `--check`，输出机器可读 JSON，供启动器/App 判定是否放行。

## 5. 血泪禁忌（实测踩过）

- **绝不 kill 正在跑 `plant` 的进程**。它持有被 reclaim 的页，杀掉会释放页、破坏 rb_node → 内核直接 panic 重启（本次踩了 2 次）。v3 脚本遇到残留 plant 只报 `exit 4` 并要求重启。
- **不要在 boot 早期并发跑两份 plant**（同样崩）。
- **不要用 `timeout` 包主流程**：超时就是 SIGKILL，等价于上一条。
- AxManager 会 SIGTERM 掉 `service.sh`，所以子进程必须 `setsid` 脱离——已验证脱离后存活。

## 6. 部署到另一台同系统平板

前提：该机已装 AxManager 并以 ADB 模式激活过（插件体系才跑得起来）。

```sh
# 1. 把插件包推上去
adb push yt-root-plugin.zip /data/local/tmp/
# 2. AxManager 里安装该 zip（模块页 → 安装），首启会自动解出 payload 到 /data/local/tmp
# 3. 重启，等 40~70 秒
adb shell 'su -c id'
```

插件自带 `plant / su98260 / ksud / ytrl.sh`，`service.sh` 会自愈缺失文件，所以新机器不需要手工推二进制。

## 7. 单次手动触发（桌面图标 / action.sh）

```sh
sh /data/local/tmp/ytrl.sh force     # 忽略锁，强制重试
sh /data/local/tmp/ytrl.sh status    # root / socket-only / none
```

## 8. 已存在的能力上限

- root 是 **per-boot** 的：每次重启都要重打一次 UAF，这是漏洞形态决定的。
- 只给 `uid 0 + 满 caps`；**Zygisk/LSPosed/Vector 在 KSU late-load 模式下不可用**（模块不挂载，`/system/lib64/libzygisk.so` 不存在）。
- 内核 build 一旦变化（OTA），`TIMER_LINK/CRED_LINK/SELINUX_LINK/LINK_*` 必须重新从新内核提取，否则 `--check` 会 `blocked`。


## 9. 加速改造（第二轮）

实测：**39~81 s → 18~28 s**（同一台机器，同样冷启动）。

| 优化 | 改动 | 收益 |
|---|---|---|
| 预检不测 slide | `plant --check --quick`，slide 交给主流程并缓存 | 3 s → 0.02 s |
| slide 采样只读一页 4 KiB | `read_raw(..., 4096)` 提前退出，不再等 `alarm(1)` | 2 s → 0.08 s |
| 两次一致即收敛 | 3 次采样降为 2 次，不一致才补第 3 次 | 省 1 s |
| page miss 快速重试 | `page_freed` 等待 8 s → 2 s | 单次 miss 省 6 s |
| task 候选轮换 | 收集全部 5760 候选，每次 attempt 换一个 | 错候选只花 1 次 UAF，而非 3 次 |
| 先验证后修补 | `ask_child` 通过就跳过 uid/euid 两次修补 | 命中时省 2 次 UAF |
| ksud 轮询 | 1 s → 0.2 s | 省 ~3 s |
| 开机等待 | boot/adbd 等待上限 180 s → 60 s，sleep 3 → 1 | 省 ~2 s |
| payload 按内容同步 | `cmp` 比较而非"存在即跳过" | 修掉"新二进制不生效"的坑 |

### 试过但回退的方案

**先拿 cred、再用 CAP_MAC_ADMIN 关 SELinux**（理论上省掉一次整 UAF）。
假 cred 的 FULLCAP 确实包含 bit 33，child 也能成功写 `/sys/fs/selinux/enforce`（日志 `[selinux] cap_mac_admin write=1`）。
但它依赖 `g_task` 精确，而 `g_task` 来自 trace 里 5760 字节的分配记录——同尺寸的 task_struct 很多，取错就会把 `task->cred` 写到别的进程上。
在 `g_task` 不可靠的现状下，这个顺序会把"一次失败"放大成"整条链路失败"，所以保留"先关 SELinux"的保守顺序，把 CAP 路径作为兜底保留在 `cred_child` 里。

## 10. 还剩下的两个硬瓶颈

1. **单次 UAF ≈ 3~5 s**（fork + `prepare_vmas` 建 5 万个 VMA + 2048 个 timer + 页回收）。
   若缩短 `prepare_vmas`，窗口可能撑不住 `down_read_killable`，需要重新验证命中率。
2. **`g_task` 的选择仍是概率性的**。真正干净的做法是给 raw trace 记录加 `common_pid` 过滤，
   但 `copy_process` 在父进程上下文执行，pid 字段并不指向新 task，需要另找关联特征（如紧随其后的 `signal_struct` 分配）。


## 11. 第三轮：找到那 2 秒的真凶（10~12 s）

给 `one_uaf` 加了分阶段计时后，第一次看到真实分布：

```
[t] ready=0.1 timers=0.1 collect=2.1 reclaim=0.6 reap=0.0 total=2.9
```

`collect` 恒定 2.1 s，而 `reclaim` 只有 0.3~0.6 s。查下去发现：
**`collect_nth()` 自己另写了一份 `alarm(2)` + 阻塞 read 的读法，根本没走 `read_raw()`。**
我前面把 `read_raw` 改了两轮，全打在空处。

彻底改用共享读法后：

| 阶段 | 改前 | 改后 |
|---|---|---|
| ready (fork+child) | 0.1 s | 0.1 s |
| timers (2048 个) | 0.1 s | 0.1 s |
| **collect (读 trace + 扫描)** | **2.1 s** | **0.3 s** |
| reclaim (页回收) | 0.3~3.6 s | 0.5~0.6 s |
| reap | 0.0 s | 0.0 s |
| **单次 UAF 合计** | **2.6~5.9 s** | **1.0~1.1 s** |

端到端：**39~81 s → 18~28 s → 10~12 s**（5 次 UAF，全部命中）。

### 一个必须记住的坑

**`poll()` 在 `trace_pipe_raw` 上不可信。**
我用 poll(POLLIN) 等数据，结果 slide 三次采样全空、`plant` 直接拒绝运行（`measurement did not converge`）。
正确做法是 `O_NONBLOCK` + `read` 返回 `EAGAIN` 时 `usleep(1000)` 自旋重试，预算 150 次（≈150 ms）。
换成这个之后 slide 与 collect 都正常，且比原来的 `alarm(2)` 快一个数量级。

### 现在的耗时构成

```
preflight(--quick)  0.02 s
slide 采样          0.08 s
5 × UAF             5.0  s
ksud late-load      2~3  s
其他                1~2  s
----------------------------
合计                10~12 s
```

### 还能往下压的地方

1. **UAF 次数**：5 次是 selinux 1 次 + cred 多次候选轮换。若 `g_task` 一次就对，可到 2 次（≈2 s）。
2. **reclaim miss**：现在 miss 窗口 1 s，miss 时单次仍要 ~2.6 s。提高页回收命中率（更多 socket 对/更密的 write）可以直接消掉这部分抖动。
3. **ksud 加载 2~3 s**：这一步是为了换 `su` 二进制与模块生态，如果只要能执行 root 命令，rootd 在 UAF 结束瞬间就可用。


## 12. 第四轮：把 task 地址认准（8 s）

### 先排掉一条看起来更短的路

假 cred 里带着 `FULLCAP`，所以「拿到 root cred 后就不要 SELinux 那次 UAF」是成立的。
但更激进的设想是：只把 `cred->uid/euid` 写 0（两次 8 字节写），剩下的 capability 用 `capset()` 补回来——这样连假 cred 都不用铺。

实测否掉了：shell 进程的 `CapBnd = 0x8000c0`，只有 `SETGID / SETUID / SYS_NICE` 三位。
没有 `CAP_SETPCAP`，`capset()` 不能把 permitted 抬到边界以上；也没有 `CAP_SYS_MODULE`，补了也加载不了 ksud。
**capability 只能靠 UAF 写进去，于是 task 地址必须拿准。**

### 判据：call_site 分组

`task_struct` 的分配点在 `dup_task_struct → alloc_task_struct_node`，是**一个固定内核地址**；
其它同为 5760 字节的分配来自不同的 `kmem_cache_alloc` 调用点。

所以按 `call_site` 给候选分组，出现次数最多的那组就是 fork 路径：

```
[task] site=0xffffffe4d99f006c ptr=0xffffff825de29680
[task] 1 candidate(s), first=0xffffff825de29680
```

多数情况下窗口内只有我们这一次 fork，候选就 1 个；site 分组用来在系统繁忙、出现多个候选时把无关的 5760 分配排到后面。

### 结果

| 版本 | 端到端 | 单次 UAF |
|---|---|---|
| 最初 | 39~81 s | 2.6~5.9 s |
| 加速第一轮 | 18~28 s | 1.0~1.1 s |
| collect 修复 | 10~12 s | 1.0~1.1 s |
| **site 分组** | **8 s（×2）** | **0.9~1.2 s** |

```
[t] ready=0.1 timers=0.1 collect=0.3 reclaim=0.6 reap=0.0 total=1.1
```

### 8 秒现在的构成

```
preflight(--quick)   0.02 s
slide 采样           0.08 s
4 × UAF              4.4  s
ksud late-load       2~3  s
账目外               1~2  s
```

### 再往下只剩两块

1. **UAF 从 4 次降到 2 次**：selinux 那次是刚需；cred 若能一次命中就是 2 次（≈2.2 s）。
   剩下的是 `reclaim` 的偶发 miss（0.6 s → 2.7 s），提高页回收命中率即可。
2. **ksud 2~3 s**：纯为换 `su` 与模块生态。只要能跑 root 命令，rootd 在 UAF 结束瞬间就能用，把它挪到后台即可再省 2~3 s。

## 13. 全流程复盘与优化点（本轮）

### 13.1 把 8 秒拆成可下手的格子

一次冷启动（elapsed=8）的实测账本：

| 段 | 耗时 | 花在哪 |
|---|---|---|
| plant --check --quick | 0.02~0.05 s | 一次 fork+exec，读 tracefs/meminfo/selinux |
| slide 采样 | 0.08~0.10 s | 两次 tracefs 记录比对 + 2 MiB 对齐校验 |
| leak_task | 0.28 s | fork 待宰进程 + 从 raw ring 捞 5760 字节分配 |
| UAF #1 selinux | 0.90 s | 见下面的分解 |
| UAF #2 cred | 1.20 s | 同上 |
| UAF #3 修 uid | 1.10 s | 同上 |
| UAF #4 修 suid | 2.70 s | 命中页回收 miss，重试 |
| ksud late-load | 1.7 s | 内核模块装载 |
| ytrl 等待检测 | 0~2.0 s | sleep 2 轮询的量化误差 |
| cmd notification | 0.2~0.4 s | 起 app_process |

单次 UAF 内部（[t] 行）：ready 0.1 / timers 0.1 / collect 0.3 / reclaim 0.6 / reap 0.0。
只有 collect 和 reclaim 值得动，其余是内核的固定代价。

### 13.2 用 BTF 把 cred 摆正（本轮最硬的结论）

从 boot.kernel 的 BTF 取出真实布局（单位字节，usage 是 8 字节的 atomic_long_t）：

    usage 0 | uid 8 | gid 12 | suid 16 | sgid 20 | euid 24 | egid 28 | fsuid 32 | fsgid 36
    securebits 40 | cap_inheritable 48 | cap_permitted 56 | cap_effective 64 | cap_bset 72 | cap_ambient 80
    security 128 | user 136 | user_ns 144 | ucounts 152 | group_info 160 | sizeof 184

对照 reclaim_stream() 的摆放：caps 在 48/56/64/72/80 正确，security 在 128 正确，
user/user_ns/ucounts/group_info 在 136/144/152/160 正确 —— 全部没问题。

唯一被破坏的是两个 qword：rb_erase 把目标指针（task+0x908）写进 cred+8 和 cred+16，
也就是 uid/gid 与 suid/sgid。子进程报回的 uid=1299351816 gid=4294967169 euid=0 egid=0
正是 0xffffff...908 的高低半字，反证了这个落点。

两条硬结论：

1. 修 uid 是一次真 UAF，不是白摆。uid 和 gid 共用一个 qword，一次写 0 就够；
   suid/sgid 是纯装饰（exec 不查、rootd 不查），原来第三次 UAF 可以省掉 —— 4 次降到 3 次。
2. 在这张假 cred 上调用 setresuid() 会直接把内核打死（本轮实测 panic，
   sys.boot.reason=kernel_panic）。cred->user/ucounts 虽是真符号，但 prepare_creds()
   之后的 set_user()/set_cred_ucounts() 不认这张半真半假的 cred。任何"用系统调用把假
   cred 洗白"的念头都必须放弃，只能靠 UAF 写。

### 13.3 子进程的回报通道原本是个陷阱

cred_child 原来用继承来的 pipe 报告 uid。但假 cred 的 security 指向伪造的
task_security_struct，SID 解析不出策略，enforcing 下 read/write 直接被拒：

- read(g_wake[0]) 返回 -1 → 子进程 continue 空转 → State: R、100% CPU、永不回报；
- /proc/<pid>/status 的 Uid 读的是 real_cred，所以看起来"没提权成功"，其实 cred 已经换掉
  —— 这是最容易看错的地方。

改成匿名共享内存（struct ipc 加 req/rsp 计数和四个 id 字段）后：无 LSM 检查、微秒级回报、
ask_child 从 2000 ms poll 超时变成 1 ms 轮询。

同一个陷阱也解释了为什么 selinux 必须第一个打、不能"省掉"：策略关掉之前，持假 cred 的
子进程连管道都读不动。原代码那句注释是对的，本轮试图挪后，代价是子进程直接失联。

### 13.4 已落地的改动

| 位置 | 改动 | 收益 |
|---|---|---|
| wait_phase() | 50 ms 量化 → 0.2 ms/2 ms 两级 | 每次 UAF 省约 0.1 s |
| collect_nth / leak_task | 每次 malloc(8M) → mmap(MAP_POPULATE) 复用 | 省约 2000 次缺页 |
| buffer_size_kb | 16M→64M→7→16M 每轮抖动 → 全程 64M | 省 4 次环形缓冲重分配 |
| quiet_reclaim_trace | 不再把缓冲缩到 7 | 同上 |
| reclaim_stream 的 page_free 轮询 | 50 ms×20 → 5 ms×10 + 20 ms×20 | 命中时省约 45 ms |
| cred 修复 | 两次 UAF → 一次（uid/gid 同 qword） | 省 1.1 s |
| ask_child | pipe + 2 s poll → 共享内存 + 1 ms | 失联从 2 s 变 0 |
| ytrl.sh | sleep 2 → sleep 0.3；-S 探测改为真连接 | 省 0~1.8 s |
| ytrl.sh | cmd notification 全部后台化 | 省 0.2~0.4 s |
| plant | 启动时清掉上一轮遗留的 socket 文件 | 消除假就绪 |

### 13.5 还没做、但值得做的

| # | 想法 | 预期 | 风险 |
|---|---|---|---|
| 1 | ksud late-load 挪到后台，socket 一通就报 ready | -1.7 s | 无（su 只是模块生态需要） |
| 2 | 假 cred 的 SID 指向 SECINITSID_KERNEL(1)，复测 open(selinux/enforce) 在 enforcing 下能否成功 | 若能，selinux 那次 UAF 可省（-0.9 s） | 低（被拒只是 EACCES，可回退） |
| 3 | reclaim 的 miss 重试是现在最大方差源（0.8 s ↔ 3.4 s）：加 socket 对/写密度，或把 page_free 探测与写循环交错 | 消除 3 s 尖刺 | 中 |
| 4 | 一次 UAF 多个写：posix_cpu_timers_exit 遍历 3 个 base，若三个 k_itimer 同页，一次 free 拿 3 次 rb_erase | 2 次写 → 1 次 | 高（要控 slab 排布） |
| 5 | 删死代码（flush_timers / reclaim_pipe / reclaim_dgram / reclaim_and_plant / aio 全套，约 700 行） | 二进制更小，exec 更快 | 无 |

### 13.6 本轮踩的坑

- /data/local/tmp 里的文件在 panic 后会变成全空格（大小对、内容全零）。看日志"没更新"时
  先 md5sum 对两边，别信时间戳。
- adb shell '... &' 里的 plant 会随 adb 会话退出被 SIGHUP 打死；测时间必须 setsid nohup
  或让 adb 一直挂着，且输出别过 tail（它会攒到 EOF）。
- ytrl.sh 用 [ -S "$SOCK" ] 判就绪会被上一轮开机遗留的 socket 文件骗到（shell 无权 unlink
  root 留下的 660 文件），必须用真连接探。
- 复跑 plant 前一定要确认没有残留的 plant 在 pause()：杀它会连带 panic。

## 14. 第五轮：量化基线，并把 reclaim 的两次"想当然"证伪

### 14.1 测量台

`yt-test.sh` 一条命令跑一轮冷启动并给判定。三道防坑，都是踩出来的：

- 每轮重推 payload 并**比对 md5**（panic 后 `/data/local/tmp` 的文件会变成全 NUL，大小却不变）；
- 每轮**清空 root.log**（否则 UAF 计数和最慢阶段被历史污染）；
- adb 抖动**连续 8 次**才判掉线（这块板子每次开机前几秒 adbd 都会闪）。

### 14.2 真实基线（v4，5 次冷启动）

| 轮次 | rootd 就绪 | UAF 次数 | 最慢单次 |
|---|---|---|---|
| 1 | 6 s | 4 | 3.0 s |
| 2 | 19 s | 10 | 2.8 s |
| 3 | 11 s | 4 | 1.1 s |
| 4 | 21 s | 10 | 2.9 s |
| 5 | 5 s | 4 | 1.0 s |

均值 12.4 s，区间 5–21 s。**"8 秒"是一次运气好的样本**，不是常态；方差来自两处：cred 试几次、有没有撞上 reclaim 尖峰。

### 14.3 证伪一：`page_freed` 的等待是承重的

把它挪到 `YT_VERBOSE` 后面（省 450 ms），下次开机立刻 `kernel_panic`。

原因：`rb_erase` 发生在父进程 `waitpid` 时，所以计时器页必须**已经回到 buddy 且已被我们的 socket 抢回**才允许 reap。盲喷时 `release_task` 走的是 freelist 垃圾 → 野写。

### 14.4 证伪二：把喷洒固定到受害者核

`child_race()` 里 `pin_cpu(1)`，据此只扫 CPU 1 的环、并把父进程也钉到 CPU 1：两次运行都是 `no-root @ 95 s`，命中率归零。页的释放并不落在假设的那颗核上。

### 14.5 两条被 SELinux 关掉的路（别再试）

| 接口 | 结果 |
|---|---|
| `/sys/kernel/tracing/set_event_pid` | shell 无权写 |
| `events/kmem/mm_page_free/filter` | shell 无权写 |

shell 身份下只能整环读，无法按 pid 过滤。

### 14.6 改读二进制环（有效，但还差一步）

文本环每次探测要把整环记录格式化一遍（约 300 ms），所以名义上 450 ms 的探测窗口里实际只跑得了 1~3 次探测 —— 页在 t=400 ms 释放时，我们最后一次探测已经过去了。这是 miss 率的真正来源。

换成二阶段 + 原始环扫描：

1. 只开 `mm_page_free`，每 2 ms 扫一次各 CPU 的 `trace_pipe_raw`（memcpy + 字比较），一轮几十微秒；
2. 看到释放后立刻切到只开 `mm_page_alloc`、清环、开喷。

实测（3 次冷启动）：

| 轮次 | rootd | UAF | 最慢单次 | 结果 |
|---|---|---|---|---|
| 1 | 7 s | 4 | 1.1 s | PASS |
| 2 | 8 s | 5 | 1.1 s | PASS |
| 3 | — | — | — | kernel_panic |

尖峰彻底消失（所有阶段稳定在 1.0–1.1 s），但第三轮 panic。所以**还不能上生产**。

### 14.7 下一处必须修的：`mm_page_alloc` 不等于"这页是我的"

panic 的机制想清楚了：`page_event_seen(base)` 只证明**某个**分配拿到了这个 pfn，不证明是**我们**拿到的。页刚回到 pcp 链时，系统自己的分配完全可能先抢走，我们却因为看到 alloc 记录而以为成功 → `waitpid` → `rb_erase` 写在别人正在用的页上 → 野写。

原始环里没有 pid（pid 在事件头，不在 payload），所以"是我拿的"只能用文本环确认。代价可以接受：**只在 raw 探到 hit 之后做一次文本确认**（要求该行的 comm 是我们自己），每个 UAF 一次，约 +0.3 s，而不是在轮询里反复扫。

### 14.8 顺带清掉的东西

`/data/local/tmp` 里原本躺着 **两个完整的 plant 构建**（`uaf_ctl`、`uaf_plant_new`）和一堆探针（`probe`/`probe2`/`rawscan`/`leaktest`/`tmr`/`asuser`）与早期脚本（`root.sh`/`00-root.sh`/`boot-activate.sh` 等）。任何一个被误跑，两个 plant 同时存在就是 panic。现已清空，只剩 `plant` + `su98260` + `ytrl.sh`。

AxManager **不能卸**：它是目前唯一的开机自启入口和 shell 身份来源。`plugins_update/` 与 `zip/` 均为空，不会被重新解包。Termux:Boot 是 `notLaunched=true` 且无 home 目录，从未运行。

## 15. 第六轮：从反汇编里找到根因，UAF 从 4 次降到 2 次

### 15.1 先看 unlink 到底怎么写

`timerqueue_del`（`0xffffffc080149ec0`）在 `node->rb_left` 为空时走单子节点快路径，调 `rb_erase`（`0xffffffc080149f34`）：

    ldp  x8, x10, [x0, #8]     ; rb_right, rb_left
    cbnz x10, slow             ; 有左子 -> 慢路径
    ldr  x9,  [x0]             ; x9 = __rb_parent_color
    ands x10, x9, #~3          ; parent = pc & ~3
    ldr  x11, [x10, #0x10]     ; parent->rb_left
    cmp  x11, x0
    b.ne else
    str  x8,  [x10, #0x10]     ; A: parent->rb_left  = child
    str  x9,  [x8]             ; B: *(child)         = pc
  else:
    str  x8,  [x10, #8]        ; A: parent->rb_right = child
    ...
    str  x9,  [x8]             ; B: *(child)         = pc

**每次 erase 有两次写：一次写 child，一次写 pc。** `pc` 同时决定父指针（`pc & ~3`），所以这两次写是耦合的。

### 15.2 旧 tile 的附带损伤是结构性的

旧 tile 是 `node[0]=node_kva, node[1]=0, node[2]=&task->cred`：用"写 A"（child = `&task->cred`）把 cred 装上，同时"写 B"把 `child` 写进 `node_kva+8` —— 那正是 `cred+8`（uid/gid）。再加上 rb_node 的 24 字节压在 cred 头上，`usage/uid/gid` 必然被污染。

**所以那两个修复 UAF 不是流程缺陷，是 tile 布局的必然代价。**

### 15.3 对调之后：顺带拿到"值自由选择"

把角色对调：

    __rb_parent_color = &task->cred - 8     ; 父指针
    rb_right          = node_kva + 0x20     ; 要写入的值
    rb_left           = 0                   ; 单子节点快路径

于是"写 A"把 `node_kva+0x20` 装进 `task->cred`；"写 B"把 `pc` 写回 `node_kva+0x20`，落在 `cred->usage`（一个我们永不释放的原子引用计数）上，**不碰任何身份字段**。

更关键的是：写入值从"节点地址"变成了"rb_right"，也就是说 **cred 不必再压在 rb_node 上**，整体挪到 `node_kva+0x20`，184 字节全是我们的。

### 15.4 实测（3 次冷启动，只改 tile）

| 轮次 | rootd | ksu | UAF | cred 尝试 | 最慢单次 |
|---|---|---|---|---|---|
| 1 | 2 s | 3 s | 2 | 1 | 1.1 s |
| 2 | 2 s | 2 s | 2 | 1 | 0.9 s |
| 3 | 2 s | 3 s | 2 | 1 | 1.1 s |

日志里的判定句：

    [cred] node=0xffffff82bf848e60 cred=0xffffff82bf848e80 task+cred=0xffffff804e3f3608 off=0xe60
    [cred] installed at 0xffffff82bf848e80
    [cred] answer uid=0 euid=0 gid=0 egid=0

对比基线（5–21 s、均值 12.4 s、4 次 UAF、uid 要靠 2 次 UAF 擦）：**UAF 4→2，就绪 12.4 s→2 s，cred 一次成型。**

### 15.5 下一步：1 次 UAF

`posix_cpu_timers_exit`（`0xffffffc08014bfbc`）对三个时钟各跑一个 `while (next = rb_leftmost) { timerqueue_del(...) }` 排空循环 —— **一次调用能连续 unlink 多个节点**。

现在 2048 个 timer 里只有 index 1024 那个被 `timer_settime` 真正挂进队列，所以只有一次 erase。若把 3 个**相邻下标**的 timer 都 arm 起来（k_itimer 384 字节、一页 21 个，相邻对象几乎必然同页），一次 UAF 就有 3 次 erase → 可以一次做完 selinux + cred + 备用。

风险在排空循环本身：第一个节点被 erase 后树结构已坏，`rb_leftmost` 和 `rb_next` 都依赖被我们改写过的字段。必须先把 `timerqueue_del` 的 `rb_next`/左most 维护路径读透，再动手。

## 16. 第七轮：一次 UAF 三处写（UAF 2→1，就绪 2 s→1 s）

### 16.1 把"几次写"从流程问题变回结构问题

v5 一次 UAF 只出一次 rb_erase，所以 selinux 与 cred 必须分两轮。但
posix_cpu_timers_exit（0xffffffc08014bfbc）连着排空三棵独立的树：

    ldr x20,[x19,#0x878]        ; bases[PROF].tqhead.rb_leftmost
    while (x20) { timerqueue_del(&bases[PROF].tqhead, x20); str xzr,[x20,#0x20]; }
    ldr x20,[x19,#0x890]        ; bases[VIRT]
    ldr x20,[x19,#0x8a8]        ; bases[SCHED]

每个循环的第一个节点都是那棵树的 rb_leftmost，也就是我们 arm 过的 &it.cpu.node；
回收一页之后它的 __rb_parent_color / rb_right / rb_left 全由我们指定，而三棵树互不干扰。
也就是说：三个基座各挂一个 timer，一次 reclaim 就能拿到三次互不耦合的 rb_erase，
父指针与写入值各自独立。

### 16.2 让三个基座都真的挂上 timer（两个坑）

坑一：线程位。MAKE_THREAD_CPUCLOCK 的关键是 CPUCLOCK_PERTHREAD_MASK（4）。
只写 (~tid<<3)|base 会被内核按组钟解码，非 leader 线程直接 EINVAL
（现场表现：[uaf] timer was not created）。设备实测（tmr5）：

    (~tid<<3)|4|0/1/2   create+arm 全部成功     <- 对
    (~tid<<3)|0/1/2     EINVAL                  <- 错（被当成组钟，pid 是线程 tid）
    (~tid<<3)|8|base    等价于 ~tgid<<3|base（组钟）

坑二：第一块 slab 永远不会回 buddy。SLUB 把它当 cpu_slab 冻着，mm_page_free 一直等不到
（现场：连续 12 轮 page_freed=0、hit=0）。所以三元组必须钉在中间的 slab 上：
优先选 index 1024 所在那块（v5 已证明会释放），否则在中间三分之一里扫。

### 16.3 一页三个 tile

k_itimer 384 B、一块 slab 21 个对象、创建顺序决定 slab 归属，泄漏到的 KVA 直接给出
每个对象的页内偏移（kmem_cache_alloc 里 req==0x180 的记录顺序就是下标顺序）。
pick_triple() 在同一块 8 KB slab 内各取一个基座，然后才 timer_settime —— arm 时机被推迟到
泄漏之后（ipc->arm_idx[3] 握手）。这是必须的：先 arm 再泄漏就无从保证三个节点同页，
非同页的那个会去 erase 我们不控制的内存。

| 基座 | 排空顺序 | tile | 落点 |
|---|---|---|---|
| PROF | 第 1 个 | TILE_CRED | pc=&task->cred-8、rb_right=node+0x20、184 B 假 cred 同页 |
| VIRT | 第 2 个 | TILE_SELINUX | pc=0、rb_left=selinux_state-7，慢路径 str pc,[rb_left] 写 8 字节 0 |
| SCHED | 第 3 个 | TILE_NONE | 全零：rb_next=NULL、parent=0，空转 erase，安全吃掉这一轮 |

selinux_state 就在 0xffffffc082959630，enforcing 在 +0（sel_write_enforce 里
ldrb w20,[x24,#0x630] / strb w25,[x24,#0x630] 可证），所以写 8 字节 0 结束在
selinux_state+0 正好命中它。

### 16.4 实测：5 次冷启动，全部一次 UAF

| 轮次 | rootd | ksu | UAF | cred 尝试 | 最慢单次 |
|---|---|---|---|---|---|
| 1 | 1 s | 1 s | 1 | 1 | 1.0 s |
| 2 | 1 s | 1 s | 1 | 1 | 1.0 s |
| 3(SWAP) | 1 s | 1 s | 1 | 1 | 1.0 s |
| 4 | 1 s | 2 s | 1 | 1 | 1.0 s |
| 5 | 1 s | 2 s | 1 | 1 | 1.0 s |

关键判定（第 5 轮）：

    [triple] slab=0xffffff814a38c000 idx=1020/1018/1019 off=0xb60/0xe60/0x860
    [cred]   node=0xffffff814a38cb60 cred=0xffffff814a38cb80 off=0xb60
    [exec]   armed 1020/1018/1019
    [stream] page_freed=1  hit pfn=0x14a38c
    [t]      ready=0.2 timers=0.1 collect=0.2 reclaim=0.6 reap=0.0 total=1.0
    [uaf]    enforce after reap=0
    [cred]   installed at 0xffffff814a38cb80
    [child-cred] uid=0 euid=0 gid=0 egid=0

第 3 轮是对照：把 cred tile 换到第三个排空循环（SCHED）上，照样 uid=0。
三个循环都在走我们这一页，"一次 UAF 三次写"由此成立，不是只有第一个循环有效。

另外注意 enforce after reap=0：内核侧的 selinux 写确实落地了；结束之后再读
/sys/fs/selinux/enforce 又变回 1，是本机某个特权进程后来把它写回去的
（rootd、ksud 与我们的脚本都没碰它），不影响 root 通路。

### 16.5 还没用掉的余量

- 第三格目前空转，可换成第二个 task 候选或一次修复写。
- release_task 还会调 posix_cpu_timers_exit_group（0xffffffc0803035c0，sig+0x120/0x138/
  0x150 三棵树）。若同时 arm 组钟，理论上是六次 erase；风险是组钟的 it.cpu.task 指向
  de_thread 已经 release 掉的旧 leader，lock_task_sighand 会摸已释放的 task_struct，先不动。
- 现在一次 UAF 的成本构成：timers 0.1 s + collect 0.2 s + reclaim 0.6 s + reap ~0。
  再往下压只能从 reclaim 的 page_freed 轮询（50 ms 粒度，实测 0.5~0.6 s）入手。
