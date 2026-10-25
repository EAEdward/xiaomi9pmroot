## v1.0 — 只做 root

* **一次 UAF，三处写**：`posix_cpu_timers_exit()` 排空 PROF/VIRT/SCHED 三棵 rb-tree，三个基座各 arm 一个 timer 落在同一块 slab，一次 reclaim 换三次独立 `rb_erase`。
* **tile**：`pc = &task->cred - 8`、`child = node+0x20`，装完整 root cred；顺带把 `selinux_state.enforcing` 清零。
* **KernelSU**：`ksud late-load`，KMI 由 `uname -r` 自动推导（`android17-6.18`）。
* **跑脚本**：`/data/local/tmp/yt-scripts/*.sh`，提权后按名字顺序各执行一次（root 身份）。
* **不碰** Zygisk / LSPosed / 模块文件挂载 —— late-load 架构下它们本来也不成立。
* 入口二选一：**AxManager**（开机自启）或 **Shizuku**（手动 `rish -c "sh /data/local/tmp/ytrl.sh start"`）。
* 静默：默认无通知、无弹窗（`touch /data/local/tmp/ytrl.notify` 可恢复）。
* 卡死自愈：一次 miss 留下的停住 plant 不能 kill，改为自动重启重来（每天上限 6 次）。

实测（同机型同 ROM）：rootd 1–5 s，`su` 可用 1–5 s，冷启动 5/5 通过。
