# proc-sniffer 使用方法和注意事项

本文档对应当前机器上的安装：`D:\proc-sniffer`。官方说明见 [README.md](README.md)。

## 1. 工具用途

`proc-sniffer` 按**进程名**抓取 Windows 本机网络流量：

- **L3/L4**：用 `pktmon` 抓包，用 `Microsoft-Windows-Kernel-Network` ETW 事件取得 PID，再按 4 元组过滤，输出 `filtered.pcap` 和连接清单。
- **流重组**：把过滤后的 TCP 按序号重组成双向字节流，把 UDP 按五元组和数据报顺序保存到 `streams/`。
- **L7**：用 `mitmproxy` 做正向代理，按“客户端源端口 → PID”过滤，输出目标进程的 HTTP/HTTPS 明文 `http_traffic.jsonl`。

它适合分析**自己开发或已获授权分析**的软件，不用于抓取他人的流量。

## 2. 本机安装状态

| 项目 | 值 |
|---|---|
| 项目目录 | `D:\proc-sniffer` |
| 虚拟环境 | `D:\proc-sniffer\.venv` |
| Python | CPython 3.14.9（64 位） |
| psutil | 7.2.2 |
| scapy | 2.8.0 |
| fastmcp | 4.1.4 |
| mitmproxy | 12.3.1 |
| `pktmon` | Windows 内置，已确认可用 |
| L3/L4 地址族 | 支持 IPv4 + IPv6 |
| 数据流重组 | TCP 按序号重组；UDP 按数据报保存边界 |
| `pip check` | 通过，无依赖冲突 |

虚拟环境的 Python 是：

```text
D:\proc-sniffer\.venv\Scripts\python.exe
```

不需要激活虚拟环境；下面的命令都直接使用这个完整路径。

## 3. 最短使用路径

以**管理员身份**打开 PowerShell 或 Windows Terminal：

```powershell
Set-Location D:\proc-sniffer
$env:PROC_SNIFFER_WORKDIR = "D:\proc-sniffer\captures"

# 抓 chrome 的 L3/L4，30 秒
.\.venv\Scripts\python.exe proc_sniffer.py chrome 30 l3
```

然后在 30 秒内操作 Chrome，触发要观察的网络请求。结束后查看：

```text
D:\proc-sniffer\captures\exports\chrome\
```

TCP/UDP 重组结果在该目录下的 `streams\`。

## 4. 管理员权限

`pktmon` 抓包需要管理员权限。先检查当前终端：

```powershell
net session
```

如果提示“拒绝访问”，说明不是管理员。请右键 PowerShell / Windows Terminal，选择“以管理员身份运行”。

MCP 方式同理：**要执行抓包，MCP 客户端或服务进程必须具备管理员权限**。仅仅能列出进程、不能启动抓包，通常就是权限不够。

## 5. CLI 用法

### 5.1 命令格式

```powershell
.\.venv\Scripts\python.exe proc_sniffer.py <进程名或exe名> [秒数] [l3|l7|full]
```

| 参数 | 说明 |
|---|---|
| `<进程名或exe名>` | 优先精确匹配进程名（如 `dwrg` 匹配 `dwrg.exe`）；没有精确匹配时才按名称、exe 路径、命令行模糊匹配 |
| `[秒数]` | 抓取时长，默认 30 秒 |
| `[l3 / l7 / full]` | `l3` 只抓报文；`l7` 只抓 HTTP 明文；`full` 两者都开（默认） |

可以运行 `python proc_sniffer.py --help` 查看帮助，不会启动采集。CLI 的秒数必须大于 0；MCP/API 的 `duration=0` 表示手动停止。非法参数会在解析进程或启动采集前报错。

### 5.2 常用示例

```powershell
# 只抓 L3/L4：pcap + 连接清单
.\.venv\Scripts\python.exe proc_sniffer.py chrome.exe 30 l3

# 只抓 L7：需要目标走 127.0.0.1:8080 代理
.\.venv\Scripts\python.exe proc_sniffer.py chrome.exe 30 l7

# 同时抓 L3/L4 和 L7
.\.venv\Scripts\python.exe proc_sniffer.py chrome.exe 30 full

# 抓微信（本机进程名以实际为准）
.\.venv\Scripts\python.exe proc_sniffer.py Weixin.exe 60 l3
```

如果匹配到多个进程（例如多个 Chrome 子进程），工具会把这些 PID 一起纳入抓取范围。

### 5.3 输出文件

默认输出到：

```text
%USERPROFILE%\proc_sniffer_caps\exports\<进程名>\
```

本机通常是：

```text
C:\Users\MECHREVO\proc_sniffer_caps\exports\<进程名>\
```

| 文件 | 内容 |
|---|---|
| `requests.json` | L3/L4 连接清单和统计；**不是** HTTP 请求正文；每条连接带 `ip_version`（4 或 6） |
| `index.md` | 可读的抓取摘要、连接表、IPv4/IPv6 连接数、归因警告 |
| `filtered.pcap` | 按 PID 过滤后的报文，可用 Wireshark 打开；包含 IPv4 和 IPv6 |
| `streams/` | TCP 字节流和 UDP 数据报；是否完整须检查缺口、截断和冲突标记 |
| `http_traffic.jsonl` | L7 明文请求/响应；仅 L7 或 full 且代理生效时生成 |

`requests.json` 的 `attribution` 表示实际使用的归因来源：`etw` / `port-sample` / `none`。`attribution_counts` 分别报告 `exact`、`tuple_only`、`endpoint_only`、`peer_only`、`port_sample`。只有协议及双端 IP/端口与目标 PID 的 ETW 记录相符才标 `exact`；它仍是整个采集时段的元组证据，不是每包自带 PID，也未完全排除端口/PID 复用。

### 5.4 数据流重组

每次导出都会生成 `streams/` 目录：

```text
streams/
  index.json                 流元数据、缺口、完整性和文件映射
  flow-0001-a.tcp.bin        TCP 某一方向的完整字节流
  flow-0002-a.udp.bin        UDP 某一方向的 payload 拼接
  flow-0002.udp.jsonl        UDP 每个数据报的时间、方向和边界
```

IPv4/IPv6 完整分片组会在分流前重组；缺片、冲突重叠、截断或 ID 复用导致不明确的组会丢弃并计数，不能补造真实 payload。相同分片副本允许合并；完整 UDP 数据报即使内容相同也会保留。

**TCP：**

- 按 TCP 序号定位；有重叠时保留最先捕获的字节，并记录冲突。
- 重传不重复拼接；新的 SYN 将同一四元组的新连接分开。没有 SYN 的复用及跨度达到 2 GiB 的序号仍有歧义。
- 缺失字节（含抓包截断和 FIN 前尾部缺失）补 `0x00`，在 `gaps` 中列出。
- `gap_free: true` 只表示重组窗口没有缺口。每方向的 `complete: true` 还要求观察到 SYN/FIN 边界、无冲突和导出截断；它不证明完整三次握手、应用消息完整或认证成功。RST 不能单独证明完整。
- `capture_truncated_packets` 记录采集时截短的包；`truncated` 表示重组输出达到大小上限。缺失字节被完整重传补齐时，仍可形成无缺口输出。
- `retransmissions`、`conflicting_segments` 记录重传和冲突段。

**UDP：**

- UDP 没有序号，`.bin` 只按抓包时间顺序拼接 payload。
- 需要保留消息边界时，用 `flow-XXXX.udp.jsonl`；每行包含 `offset`、`length`、`ts`、`direction` 和 `payload_b64`，`offset` 可直接对应到同方向的 `.bin`。
- 游戏战斗 UDP 这类二进制协议，建议直接分析 `.jsonl` 里的 base64 数据，或从 `.bin` 按长度切分。

> TCP `.bin` 中的 `0x00` 可能是缺口填充；先检查 `gaps`/`gap_free`。UDP 也会标记 `declared_length`、`captured_length`、`missing_bytes`、`complete` 和 `truncated`。TCP/UDP 每方向导出最多 128 MiB；这不限制整个抓包及索引所需的内存。不能把有缺口的 gzip/TLS 数据硬拼后当作可靠明文。

## 6. L7 明文抓取

L7 不是“自动解密所有 HTTPS”。目标进程必须**主动走 mitmproxy 代理**，并信任 mitmproxy 的 CA。

### 6.1 第一步：确认代理端口空闲

默认端口是 `8080`。先检查：

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
```

有输出说明端口已被占用（Clash、其他代理或旧进程）。可以换端口：

```powershell
$env:PROC_SNIFFER_L7_PORT = "8081"
```

设置后，目标进程的代理也要改成 `127.0.0.1:8081`。

> L7 只监听 `127.0.0.1`。启动时通过私有状态文件确认 addon 初始化；端口被占用、进程提前退出、日志文件不可写或初始化超时会报错。归因同时核对客户端和代理的 IP/端口与 PID；实时 psutil 查询仍可能漏掉已经结束的短连接。

### 6.2 第二步：让目标走代理

任选一种：

**方式 A：Windows 系统代理**

设置 → 网络和 Internet → 代理 → 手动设置代理：

```text
地址：127.0.0.1
端口：8080
```

**方式 B：进程环境变量**

从同一个终端启动目标程序，或给目标设置：

```powershell
$env:HTTP_PROXY  = "http://127.0.0.1:8080"
$env:HTTPS_PROXY = "http://127.0.0.1:8080"
```

并非所有程序都读取环境变量；浏览器、Electron 应用通常更依赖系统代理。

### 6.3 第三步：信任 mitmproxy CA

首次运行 L7 后，CA 文件通常在：

```text
C:\Users\MECHREVO\.mitmproxy\mitmproxy-ca-cert.p12
```

双击该文件，或运行：

```powershell
Start-Process "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.p12"
```

导入到：

```text
“受信任的根证书颁发机构”
```

只在自己的测试机器上这样做。MITM CA 会削弱 HTTPS 的安全性；分析结束后建议从证书管理器删除它。

### 6.4 第四步：开始抓取并触发请求

```powershell
.\.venv\Scripts\python.exe proc_sniffer.py chrome.exe 30 l7
```

在 30 秒内操作目标程序。结束后检查：

```text
%PROC_SNIFFER_WORKDIR%\exports\<进程名>\http_traffic.jsonl
```

每行是一条 JSON，包含 `method`、`url`、请求头/请求体、响应状态/响应头/响应体。

### 6.5 L7 抓不到时的常见原因

- 目标没有走 `127.0.0.1:8080` 代理。
- 目标使用 QUIC/UDP，绕过了 HTTP 代理。
- 目标的 HTTPS 请求不信任 mitmproxy CA。
- 目标做了证书绑定（SSL Pinning），mitmproxy 无法解密。
- 8080 端口被占用，mitmdump 没有真正启动。
- 目标是本地回环地址，且程序自动绕过了代理。

## 7. MCP Server 用法

### 7.1 配置

把下面内容加入支持 stdio 的 MCP 客户端配置：

```json
{
  "mcpServers": {
    "proc-sniffer": {
      "command": "D:\\proc-sniffer\\.venv\\Scripts\\python.exe",
      "args": ["D:\\proc-sniffer\\server.py"],
      "env": {
        "PROC_SNIFFER_WORKDIR": "D:\\proc-sniffer\\captures"
      }
    }
  }
}
```

如果客户端不需要工作目录配置，可以删掉 `env`。

要让抓包成功，客户端进程必须有管理员权限。可以先用管理员终端手工验证服务能否启动：

```powershell
Set-Location D:\proc-sniffer
.\.venv\Scripts\python.exe server.py
```

该命令会阻塞等待 MCP 客户端连接，`Ctrl+C` 退出。

### 7.2 可用工具

| 工具 | 用途 |
|---|---|
| `list_monitorable_apps()` | 列出当前有网络连接的进程名 |
| `start_capture(app_name, duration, layers)` | 解析 PID 并启动抓取 |
| `stop_capture()` | 手动停止、转换、过滤 |
| `export_last(app_name)` | 导出最近一次结果 |

典型调用顺序：

```text
1. list_monitorable_apps()
2. start_capture("chrome.exe", 30, "l3")
3. 在 30 秒内操作目标程序
4. 等待自动停止，或调用 stop_capture()
5. export_last("chrome.exe")
```

`duration` 到期后会自动停止；如果你提前完成操作，可以调用 `stop_capture()`。`export_last` 的 `app_name` 主要决定导出目录和元数据，抓取已经由前面的调用完成。返回值里还会包含 `streams` 目录以及 `stream_count` / `tcp_streams` / `udp_streams`。

## 8. 工作目录和环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PROC_SNIFFER_WORKDIR` | `%USERPROFILE%\proc_sniffer_caps` | 抓包和导出目录 |
| `PROC_SNIFFER_L7_PORT` | `8080` | mitmproxy 监听端口 |
| `PROC_SNIFFER_ETL2PCAPNG` | `C:\tools\etl2pcapng.exe` | 可选转换器；文件不存在时使用 `pktmon etl2pcap` |

在当前终端临时修改工作目录：

```powershell
$env:PROC_SNIFFER_WORKDIR = "D:\proc-sniffer\captures"
```

这些变量必须在启动 `proc_sniffer.py` / `server.py` 之前设置。

## 9. 重要注意事项

### 9.1 系统代理会改变 PID 归因

如果目标程序使用了 Clash、系统代理或其他本地代理：

- 目标进程实际建立的连接是“目标 → 本地代理”，真实远端连接属于代理进程。
- L3/L4 的 `requests.json` 可能只看到本地代理，或者把流量归到代理进程。
- 需要看真实域名/路径时，用 L7 的 `http_traffic.jsonl`；或者临时关闭系统代理，让目标直连。
- 如果只关心代理进程本身，可以直接抓代理的进程名。

### 9.2 IPv4/IPv6 双栈

当前 L3/L4 过滤已支持 IPv4 和 IPv6，游戏战斗 UDP 无论走 IPv4 还是 IPv6 都能进入 `filtered.pcap` 和 `requests.json`。

- `requests.json` 的每条连接带 `ip_version: 4` 或 `ip_version: 6`。
- `index.md` 会分别统计 IPv4 连接数和 IPv6 连接数。
- ETW 中的 IPv6 zone id（如 `fe80::1%12`）会被归一化；IPv4-mapped 地址（`::ffff:a.b.c.d`）按 IPv4 匹配。
- 抓到的连接如果同时包含 IPv4 和 IPv6，会分别列出，不会混在一起。
- 如果 `filtered.pcap` 里没有 IPv6，而原始 `capture.pcapng` 里有，先检查目标进程是否真的在抓取窗口内发送了 IPv6 流量，以及 ETW 是否解析到了对应 PID。

### 9.3 VPN / NAT 的精度下降

ETW 和物理网卡看到的元组可能不同，工具保留端点/对端 IP 弱匹配，并单独标记；VPN/NAT 是可能原因之一，不能仅凭弱匹配数量断言使用了 VPN：

- 看 `index.md` 里的 `peer_only_packets`。
- 该数值非 0 时，结果可能混入其他进程发往同一服务器的流量。
- 需要精确归因时，尽量让目标直连物理网卡，或关闭 VPN/TUN。

### 9.4 磁盘占用

`pktmon` 先抓网卡流量再过滤，使用 `--pkt-size 0 --comp nics --type flow` 完整保存帧并减少协议栈副本。它包含网卡收到的广播/多播；多网卡仍可能重复采集，纯回环或协议栈内部流量可能看不到。既有 pktmon 筛选器不会自动清除。ETL 采用 512 MiB 循环日志，达到上限会覆盖最早记录；转换后的 pcapng/XML 可能更大。

建议：

- 抓取时间尽量短，先 10～30 秒。
- 不要把工作目录放在空间紧张的盘。
- 定期删除 `captures\` 下的旧 ETL/Pcapng/XML 和 `exports\`。
- `streams/` 会额外保存一份 payload 副本；UDP 的 `.jsonl` 又是 base64 副本，抓大流量时要预留空间。
- 不要把包含账号、Cookie、Token 的抓包文件提交到 Git 或公开位置。

### 9.5 L3 不负责解密 HTTPS

L3/L4 只能看到加密后的 TLS 字节，看不到 HTTPS 的请求体和响应体。需要明文时使用 L7，并接受第 6 节的代理和 CA 配置要求。

### 9.6 证书绑定

如果目标使用 SSL Pinning，mitmproxy 无法解密。这不是安装问题，属于工具能力边界，需要 Frida 等额外手段，已超出本项目范围。

### 9.7 合法使用

只抓取自己拥有或明确获授权的软件流量。抓包文件可能包含个人信息、登录凭据和业务数据，请限制访问范围并在分析结束后删除。

## 10. 故障排查

| 现象 | 处理 |
|---|---|
| `未找到匹配 ... 的进程` | 确认程序正在运行；用 `tasklist /FI "IMAGENAME eq chrome.exe"` 确认进程名；改用完整 exe 名；确认终端是管理员 |
| `pktmon` 启动失败 / 拒绝访问 | 用管理员终端；执行 `pktmon status` 查看状态；如有残留抓取，执行 `pktmon stop` |
| 抓取完成但连接数为 0 | 查看 `index.md` 的 IPv4/IPv6 连接数；检查目标是否经过系统代理；确认抓取窗口内目标确实发起请求；检查 ETW 是否解析到对应 PID |
| `streams/` 为空或 TCP 缺口很多 | 抓包是否从连接中途开始；TCP 最好在启动目标前开始抓；检查 `filtered.pcap` 是否包含 payload；看 `streams/index.json` 的 `gaps`/`gap_free` |
| `http_traffic.jsonl` 不存在 | 检查 8080 是否被占用；确认目标走了代理；确认 CA 已信任；检查目标是否使用 QUIC 或证书绑定 |
| L7 抓到的是 502/连接错误 | 代理本身启动成功，但上游连接失败；检查目标 URL、网络和上游代理设置 |
| MCP 启动即 `Connection closed` | 先在管理员终端直接运行 `server.py` 看报错；确认 `command` 指向本项目 `.venv` 下的 Python；确认依赖完整 |
| MCP 能列进程但不能抓包 | 通常是客户端/服务进程没有管理员权限，先检查权限 |
| 重新安装依赖非常慢 | `requirements.txt` 版本范围较宽，pip 可能反复回溯；当前环境已经装好，通常不需要重装。如必须重装，优先固定本文第 2 节的版本 |

## 11. 中断、清理和卸载

### 11.1 抓取被中断

如果终端被强制关闭，`pktmon` 可能仍在运行：

```powershell
pktmon status
pktmon stop
```

确认显示“数据包监视器没有运行”即可。

### 11.2 清理抓包文件

先确认路径，再删除：

```powershell
Test-Path "D:\proc-sniffer\captures"
Remove-Item "D:\proc-sniffer\captures" -Recurse -Force
```

如果使用默认目录，把路径换成 `"$env:USERPROFILE\proc_sniffer_caps"`。

### 11.3 卸载

1. 删除虚拟环境 `D:\proc-sniffer\.venv`。
2. 删除项目目录 `D:\proc-sniffer`。
3. 如果导入过 mitmproxy CA，在 `certmgr.msc` 的“受信任的根证书颁发机构”中删除对应证书。
4. 删除抓包工作目录。

不需要卸载系统 Python，也不影响其他项目。

## 12. 本机对源码做的兼容修改

当前源码有两处兼容修改，并新增了 `stream_export.py`、本文件 `USAGE.md` 和 `tests/` 下的双栈/流重组测试。升级或 `git pull` 前请先看 `git diff`：

| 文件 | 修改目的 |
|---|---|
| [proc_sniffer.py](proc_sniffer.py) | L3/L4 过滤、端口回退和导出支持 IPv4/IPv6；导出时调用流重组；为 Scapy 补充 Windows 环境变量默认值，避免 MCP 客户端精简环境导致启动失败 |
| [stream_export.py](stream_export.py) | TCP 按序号重组、重传去重、缺口标记；UDP 按数据报保存边界 |
| [l7_capture.py](l7_capture.py) | 修正 mitmdump 启动入口；把 L7 生命周期钩子暴露到模块级，确保 mitmproxy 能加载 |

查看修改：

```powershell
Set-Location D:\proc-sniffer
git diff
```

如果以后更新源码，请保留这些修复，或在更新后重新验证 L7 和 MCP 启动。

## 13. 快速自检

```powershell
Set-Location D:\proc-sniffer

# 依赖是否正常
.\.venv\Scripts\python.exe -m pip check

# Python 导入是否正常
.\.venv\Scripts\python.exe -c "import psutil, scapy, mitmproxy, fastmcp; print('imports OK')"

# pktmon 是否可用
pktmon status

# IPv4/IPv6 过滤、TCP/UDP 流重组的合成测试（不需要管理员）
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

以上是依赖和离线回归检查，不代替管理员权限下的实际采集验证。当前审查结论见 [AUDIT.md](D:/proc-sniffer/AUDIT.md)。

## 14. 校园网一键采集

```powershell
D:\proc-sniffer\campus_capture.cmd
# 可选：延长到 120 秒、不自动打开浏览器
D:\proc-sniffer\campus_capture.cmd -Seconds 120 -NoBrowser
```

默认抓取 60 秒，自动停止和转换，在 `captures/campus/` 下输出唯一命名的 pcapng 和命令日志。脚本先申请管理员权限，沿用并记录 pktmon 全局筛选器，不会为了启动而先停掉其他抓包。启动、停止或转换失败将返回非零退出码，不再只因文件存在就报告成功。

`--pkt-size 0` 表示保存完整帧。1500 是常见 IP MTU，不是所有以太网帧的总长度；旧脚本截短大包后生成的文件无法补回丢失字节。分析前检查 `frame.cap_len < frame.len`，不要把 pktmon 的“丢弃计数”直接解释为抓包漏包或广播拥塞。

可以按一次授权测试操作后等待自动结束。脚本无需安装 Npcap，不修改网络连接、代理、证书或持久环境变量。窗口强制关闭或进程被强制终止时，`finally` 无法保证执行，需另行检查 `pktmon status`。
