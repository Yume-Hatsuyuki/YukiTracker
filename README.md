# YukiTracker

YukiTracker 是基于 opentracker 2.2.1 的 C 语言 BitTorrent Tracker 增强版。  
客户端通过 HTTP 或 UDP 登记参与下载或做种的节点（peer），并查询其他节点。管理端通过 HTTP 查询统计、导出种子记录和读取诊断信息。

## 运行

发布包包含可执行文件和 [yukitracker.yaml](yukitracker.yaml)。Linux 可执行文件使用系统的 glibc、libyaml 和 zlib。macOS 构建静态链接 libyaml 和 zlib。以下命令在运行包的解压目录执行。

```sh
./yukitracker -v
./yukitracker -C -f yukitracker.yaml
./yukitracker -f yukitracker.yaml
```

`-C` 校验配置后退出。模板在 `127.0.0.1:6969` 同时监听 TCP 和 UDP。服务启动后，以下请求返回运行状态和版本。

```sh
curl --fail http://127.0.0.1:6969/healthz
```

## 配置与部署

服务启动时读取 YAML。键名中的点号属于键名。修改监听地址、工作线程数、协议参数、访问网段或接口路径后，重新校验配置并重启服务即可生效。

| 配置项 | 作用 |
| --- | --- |
| `listen.tcp`、`listen.udp` | 指定各协议的监听地址、端口和工作线程数。对外服务时填写部署主机的监听地址。 |
| `tracker.interval`、`tracker.jitter`、`tracker.peer_timeout` | 前两项以秒设置客户端上报周期及其随机偏移。节点过期时间以分钟计，范围为 1–255。 |
| `access.stats`、`access.fullscrape` | 分别指定统计与全量导出的允许网段。模板仅允许回环地址访问。 |
| `access.proxy`、`http.client_ip_header` | 设置信任的反向代理网段和客户端地址请求头。使用 HTTPS 时，由反向代理终止 TLS。 |
| `access.whitelist`、`access.blacklist` | 任选一项指定种子名单。每行包含一个 40 位十六进制种子标识（info hash）。替换名单文件后，发送 `SIGHUP` 可重新加载名单。 |
| `state.file`、`state.save_interval` | 指定完成次数快照的路径和保存间隔（秒）。间隔为 0 时仅在正常退出时保存。重启后，客户端重新上报节点地址。 |
| `export.min_interval`、`export.max_clients` | 指定同一地址两次导出之间的最短秒数和限频表的容量。间隔为 0 时关闭限频。 |

进程以 root 启动时默认降权为 `nobody`。运行账户需要名单的读取权限和快照目录的写入权限。相对路径按服务工作目录解析。Go 版嵌套 YAML 需要转换为模板中的键名，已有 JSON Lines v1 完成次数快照可通过 `state.file` 加载。

## HTTP 接口

以下路径采用模板默认值。各路径通过 `paths.*` 配置。

| GET 路径 | 返回内容 |
| --- | --- |
| `/announce`、`/scrape` | 客户端上报节点并获取节点列表，或按种子标识查询统计。无参数的 `/scrape` 受全量抓取权限控制。 |
| `/healthz` | 服务状态和版本。 |
| `/api/v1/stats` | 种子数、节点数、地址族分布、完成次数和 HTTP/UDP 计数。 |
| `/api/v1/stats/torrents` | 种子记录。每页 `limit` 为 1–1000，下一页使用响应的 `next_cursor` 作为 `cursor` 参数。 |
| `/api/v1/stats/top` | 按做种数（`seeders`）、下载节点数（`leechers`）或完成次数（`completed`）排名。`by` 选择字段，`limit` 为 1–100。 |
| `/api/v1/stats/networks` | 按节点数排列的 IPv4 /24 网段，`limit` 为 1–128。 |
| `/api/v1/export/torrents` | 每行一个 JSON 种子记录，支持 gzip 压缩。触发限频时返回 HTTP 429 和 `Retry-After`。 |
| `/metrics` | Prometheus 文本格式的指标。 |
| `/api/v1/diagnostics/requests` | 允许记录的网段内的近期请求。记录容量由 `diagnostics.log_entries` 设置。 |
| `/api/v1/diagnostics/busy-networks` | 按网段统计提前重复上报的次数。容量由 `diagnostics.busy_entries` 设置。 |

诊断接口的读取网段由 `access.diagnostics` 指定。模板将两类诊断容量设为 0。

## 从源码构建

Debian 或 Ubuntu 使用以下命令安装构建依赖并编译。

```sh
sudo apt-get install build-essential libyaml-dev zlib1g-dev
make
./yukitracker -C -f yukitracker.yaml
```

## 发布与许可

`VERSION` 保存版本号。推送与其匹配的 `v` 前缀标签会触发 GitHub Actions，为下表中的目标构建运行包，并向 GitHub Release 上传压缩包和 SHA-256 校验文件。

YukiTracker 修改部分使用 [GNU AGPL-3.0](LICENSE)。上游组件的作者和许可声明保留在对应源文件中。

## 发布平台

| 系统 | 发布目标 | 运行依赖 |
| --- | --- | --- |
| Linux | amd64、arm64 | glibc、libyaml、zlib |
| FreeBSD | amd64 | libyaml |
| macOS | Intel amd64、Apple Silicon arm64 | 系统运行库 |

项目采用上游的 POSIX 系统接口。Linux 使用 epoll，FreeBSD 和 macOS 使用 kqueue。事件后端在编译时选择。

工作流在 Linux、macOS 运行器和 FreeBSD 虚拟机中构建程序，并校验版本和随包配置。手动执行生成构建产物，推送匹配版本的标签生成 GitHub Release。当前本地实测平台为 Linux amd64，其他发布目标的验证结果由对应工作流记录。

## 自动验证

`.github/workflows/ci.yml` 在分支推送和 Pull Request 时调用 `verify.yml`。验证覆盖 Linux amd64、Linux arm64、macOS Intel、macOS Apple Silicon 和 FreeBSD amd64。

各平台先验证源码构建，再解压运行包并使用包内程序验证。检查包含配置解析、版本、HTTP announce/scrape、UDP connect/scrape、统计、分页、gzip 导出、权限拒绝、状态恢复、名单重载、导出限频和正常退出。Linux 还运行 AddressSanitizer 和 UndefinedBehaviorSanitizer，检查内存访问、泄漏和未定义行为。

`release.yml` 在版本标签推送时调用同一组验证。全部任务成功且五个平台的运行包齐全时，创建 GitHub Release。任一任务失败或取消会阻止发布。验证脚本存放在 `.github/checks/`，运行包仅包含程序、配置、README 和许可文件。
