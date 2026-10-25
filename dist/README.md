# 发布附件（Release assets）

二进制不进仓库，挂在 Release 上：

| 文件 | 大小 | 说明 |
|---|---|---|
| `02-yt-root-plugin.zip`（建议改名 `yt-root-plugin-v7.0.zip`） | 4.2 MB | AxManager 插件：plant + su98260 + ksud + ytrl.sh |
| `03-KernelSU-v3.3.1.apk` | 13.6 MB | KSU 管理器 v3.3.1 (32680)，与内置 ksud 3.3.1 匹配 |
| `01-AxManager-2.0.1.apk` | 5.9 MB | 插件宿主（若官方渠道可获得，优先给链接） |

`ytrl.sh` 已经在仓库的 `launcher/` 里，不需要单独挂。

## 上传方式

```sh
gh release create v7.0 \
  "$HOME/Downloads/小米root/02-yt-root-plugin.zip" \
  "$HOME/Downloads/小米root/03-KernelSU-v3.3.1.apk" \
  --title "v7.0 — 一次 UAF 三处写 + 开机全自动" --notes-file RELEASE.md
```
