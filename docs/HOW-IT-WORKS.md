# 机制

## 1. 漏洞在哪

`begin_new_exec()`（vmlinux `0xffffffc0802cf910`）把 `de_thread()` 内联了进来，执行顺序是：

```
zap_other_threads + schedule 等待
exchange_tids / transfer_pid
release_task(旧 leader)              <- 0x2d007c，之后回跳到后半段
unshare_files                        <- 第 1 个可失败步
down_read_killable                   <- exec_mmap，第 3 个可失败步（我们在这里打断）
exec_task_namespaces
posix_cpu_timers_exit                <- 0x2cfcb8，真正的清树
exit_itimers                         <- 0x2cfcc8，这里才 free k_itimer
```

`exec_mmap` 被打断时上面三步都没跑：进程随后 `do_exit` → `exit_itimers()` 把 `k_itimer` 释放，
而 `tsk->posix_cputimers` 的三棵 rb-tree 里还挂着这些已释放节点。等父进程 `waitpid` →
`release_task()` → `posix_cpu_timers_exit()`，它才拿悬空的 `rb_leftmost` 去 `timerqueue_del`。

## 2. 一次调用，三棵树

```
ldr x20,[x19,#0x878]   ; bases[PROF].tqhead.rb_leftmost
while (x20) { timerqueue_del(&bases[PROF].tqhead, x20); str xzr,[x20,#0x20]; }
ldr x20,[x19,#0x890]   ; bases[VIRT]
ldr x20,[x19,#0x8a8]   ; bases[SCHED]
```

每个循环的第一个节点都是 `rb_leftmost`，也就是我们 arm 过的 `&it.cpu.node`。回收一页之后它的
`__rb_parent_color` / `rb_right` / `rb_left` 全由我们指定，三棵树互不干扰 —— 三个基座各一个 timer，
一次 reclaim 换三次独立 `rb_erase`。

## 3. 每次 erase 的两次写

`rb_erase` 的快路径（`rb_left == 0`）在 `parent = pc & ~3` 上做两次写：

```
parent->rb_left/right = child     ; 写 A
*(child)              = pc        ; 写 B
```

tile 用 `pc = &task->cred - 8`、`child = node + 0x20`：

* 写 A 把 `node+0x20` 装进 `task->cred`；
* 写 B 把 `pc` 写回 `node+0x20`，落在 `cred->usage`（一个永不释放的原子引用计数）上；
* 于是 184 字节的假 cred 完整躺在我们的页里，身份字段一个都没被碰。

三个 tile：`PROF` 装 cred，`VIRT` 走慢路径把 `selinux_state - 7` 那 8 字节清零（`enforcing` 在 +0），
`SCHED` 留全零当空转（`rb_next = NULL`、`parent = 0`，安全地吃掉这一轮）。

## 4. 时序约束

* **必须等页真的回到 buddy 并被我们拿到**：`mm_page_free` → 喷洒 → `mm_page_alloc` 确认；提前 reap 会 panic。
* **停住的 plant 不能 kill**：它占着已回收的页，kill 掉内核会走过悬空节点。
* arm 时机必须在泄漏之后：先建 2048 个 timer，拿到 KVA 再挑同页的三个基座 arm。
