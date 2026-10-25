## v1.0

首个版本，只做 root。

- 开机自动提权，冷启动 1–5 秒拿到 `su`
- 自动 `ksud late-load` 装 KernelSU，KMI 按 `uname -r` 推导
- 提权后按顺序执行 `/data/local/tmp/yt-scripts/*.sh`
- 底层要 Shizuku 提供 shell；AxManager 装上是开机自启，不装就手动 `ytrl.sh start`
- 静默运行；一次没命中留下的停住进程不能杀，脚本会自己重启重来（每天最多 6 次）

适用 OS4.0.16.0.XBMCNXM / 6.18.21-android17。
