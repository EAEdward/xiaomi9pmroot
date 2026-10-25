## v7.0

* **一次 UAF 出三次写**：`posix_cpu_timers_exit()` 三棵 rb-tree（PROF/VIRT/SCHED）各命中同一块回收 slab 里的节点，一次 reclaim 换三次独立 `rb_erase`。UAF 次数 2 → 1。
* **tile 对调**：写入值改放 `rb_right`，`cred` 移到 `node+0x20`，身份字段不被 `rb_erase` 的第二次写污染。
* **Zygisk 注入打通**：late-load 后刷新 daemon → 重启一次框架 → 校验 `libzygisk` 进 zygote，system_server 继承；Vector 2.2 框架实测 `API 102`。
* **开机全自动**：`AxManager 插件 → 自升权 → KSU → 模块阶段 → 注入 → 框架 daemon`，实测 1–10 秒；KMI 由 `uname -r` 自动推导。
* **卡死自愈**：一次 miss 留下的停住 plant 不能 kill，改为自动重启重来（每天上限 6 次）。
* **静默**：默认不发通知、不弹窗口（`touch /data/local/tmp/ytrl.notify` 可恢复通知）。

冷启动实测（同机型同 ROM）：rootd 1–5 s、KSU 在线 1–5 s、注入 4 s、`uaf=1`。
