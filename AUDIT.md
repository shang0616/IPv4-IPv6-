# proc-sniffer 正确性审查与修复记录

审查日期：2026-11-08。范围包括核心采集/PID 归因、TCP/UDP/分片重组、L7/MCP、校园一键脚本及此前分析方法。使用本机已有抓包、合成报文、离线进程替身与真实 FastMCP 工具调度验证，没有启动新的实际抓包、代理、登录操作或更改系统网络设置。

## 结论

旧版本存在影响数据真实性和分析结论的缺陷，不能因原有 9 项测试通过就认为“全面正确”。本次修复了已复现的关键问题。完整采集链路仍需在以后授权测试时进行管理员实机验证；离线测试不能保证所有网卡、Windows 版本和代理行为一致。

校园登录 POST 明文传输的核心结论经原始字节和 Wireshark 复核仍成立；此前的响应错误文案、丢包原因、MAC 归属和部分 TLS 解密结论需要更正。

## 1. 主要缺陷与处理

| 优先级 | 缺陷 | 影响 | 修复/验证 |
|---|---|---|---|
| 高 | 校园脚本 `--pkt-size 1500`；核心固定 4096 | 长帧被截短，gzip/TLS 重组和解密失败 | 改为 `--pkt-size 0`。旧文件中实测 `cap_len=1500`、`wire_len=1514` |
| 高 | pktmon 默认 ALL 组件；过滤器按全时窗 payload/seq 简单去重 | 同一包多组件副本放大统计；相同 UDP 内容或同长不同内容 TCP 被误删 | 默认 NIC/flow 采集减少副本；完整 UDP 与 TCP 原始报文保留；TCP 重组单独处理重传和冲突 |
| 高 | TCP 仅看已捕获 payload，没有可靠 FIN 尾界；冲突/RST 仍可 complete | 缺尾、截短或冲突流被误称完整 | 声明长度、TCP dataofs、FIN 边界参与 gap；冲突、RST、无边界不再认证完整；序号回绕和观察到的新连接拆分有回归 |
| 高 | 过滤阶段丢失无端口的非首分片；IPv6 helper 缺片填 X | 无法重组完整数据，甚至生成假 UDP 端口/载荷 | 过滤保留首片关联的全组；重组验证连续覆盖、实际长度、末片、重叠；缺失/冲突组丢弃并计数 |
| 高 | 启动失败状态未回滚；stop 依赖 ETL 是否存在；过期 timer | 假运行、漏停或旧 timer 停掉新抓取 | 所有权与运行状态分开、同锁/代次控制、停止失败保留重试权、异常清理 |
| 高 | 核心将单个本地端点命中称为 exact；L7 只按源端口找 PID | 不同进程/不同远端可能误归因 | 核心 exact 需协议和双端元组；弱匹配单独计数；L7 需客户端到本地代理的完整 TCP 双端+PID |
| 中高 | 旧 XML/PCAP/导出副本复用，默认导出名允许路径穿越；stream 清空整个目标目录 | 旧数据冒充新结果或覆盖无关文件 | 清理本次生成的旧产物、失败/空输出报错、验证默认目录名、只清理生成文件模式、拒绝 stream 链接目录 |
| 中 | L7 提前退出/输出不可写未明确反馈、无 request 归因的 response 可写入 | 假启动成功、记录非目标数据或重复记录 | 私有 ready 状态握手、错误诊断、只清理拥有的子进程、无归因响应不写、记录只消费一次 |
| 中 | MCP 导出重新查询当前 PID；并发 stop/export | 程序退出后 PID 历史错误、转换与导出竞争 | 采集 PID 快照、MCP 调用串行与核心锁配合 |
| 中 | 校园脚本忽略停止/转换返回码、先无条件 stop、同名输出删除、UAC 路径引用错误 | 停掉其他会话、假成功、带空格且尾随反斜杠的路径失败 | 成功 start 后才拥有 stop 权、finally 清理、检查退出码和非空输出、唯一文件名、正确 Windows argv 引用 |

主要实现：[proc_sniffer.py](D:/proc-sniffer/proc_sniffer.py)、[stream_export.py](D:/proc-sniffer/stream_export.py)、[l7_capture.py](D:/proc-sniffer/l7_capture.py)、[server.py](D:/proc-sniffer/server.py)、[campus_capture.ps1](D:/proc-sniffer/campus_capture.ps1)、[campus_capture.cmd](D:/proc-sniffer/campus_capture.cmd)。

## 2. 校园抓包的独立证据复核

逐帧检查既有 pcapng 的原始长度、实际保存长度、IP/TCP 声明长度和序号，没有依赖此前生成的乱码 HTML。

| 文件时间标识 | 抓包记录数 | 截短记录数 | 合计少保存字节 |
|---|---:|---:|---:|
| 20261103_203728 | 208,602 | 12,420 | 285,828 |
| 20261103_220953 | 210,042 | 19,020 | 437,796 |

“记录数”含同一报文经过多个组件时的副本。第二份文件的登录请求 frame 152335：

- 原始帧长度和保存长度均为 1305 字节。
- HTTP 声明 `Content-Length: 429`，实际 body 也是 429 字节，共 23 个字段。
- 测试账号/密码与此前报告一致，直接位于 HTTP/TCP 80 POST；这一结论成立。
- 152336–152340 是同一 POST 的相同副本，不能当成额外登录尝试。
- GET、POST 两个响应各有 15 个不同序号的数据段，每个响应缺失 196 字节。
- 修复后的流导出独立得到：客户端 gap=0；服务器总 gap=392；两方向都因未观测到完整 FIN 边界而 `complete=false`。

修订后的本机报告：[完整认证报告](D:/proc-sniffer/captures/campus/campus_auth_full_report.md)、[简要报告](D:/proc-sniffer/captures/campus/campus_report.md)。详细无凭据统计：[audit_evidence.json](D:/proc-sniffer/captures/campus/audit_evidence.json)。

### 需要纠正的原分析

1. **将每段已保存的 TCP 字节直接拼接，忽略序号缺口，不能恢复正确 gzip。** 缺口后的部分解压文本可能已损坏；“密码错误”不能作为已经通过完整性校验的服务端证据。HTTP 200 也不能证明登录成功或失败。
2. **pktmon 转换的丢弃计数不等同于抓包漏包数。** 不能据此认定广播拥塞；本次有直接证据的是每帧截断。
3. **响应中的以太网源 MAC 是本链路观察值。** 它可能属于路由网关，不能直接标成远端认证服务器的网卡或设备品牌。
4. **本次 HTTP Host 使用 IP 字面量，不等于服务器没有任何域名。** 文件中未见该 IP 的 443 通信，也不能断言没有 HTTPS 服务。
5. **URL 查询参数和 POST body 应分开。** `wlanuserip/wlanacname/wlanusermac` 在 URL；`userId/passwd` 在表单 body。
6. 表单中的内部主机名/回环地址是客户端提交值，不能反推出实际后端连接拓扑。学校站点 DNS 查询是先前单独查询的结果，不是认证请求使用的域名证据。
7. 位于同一网段并不自动获得他人单播流量；风险成立需要实际能观察该通信的终端或链路位置。

## 3. 此前 TLS 分析脚本错误

此前临时 TLS 1.2 AES-GCM 脚本把 AAD 的长度字段设为整个加密 record body 长度，正确值应是解密后明文长度（该 AES-GCM suite 的 body 长度减 8 字节 explicit nonce 和 16 字节 tag）。另有循环中的版本切片写成 `data[off+1:3]`，应为 `data[off+1:off+3]`。

使用保存的 keylog 和已匹配的 flow-0047 做离线修正验证：

- cipher `0xc02c`；客户端 3 条记录通过 AES-GCM 认证，失败 0；服务器 1 条认证通过，失败 0。
- 恢复客户端应用数据 1365 字节，有 HTTP POST 特征；审计输出不打印密钥/应用正文。
- Wireshark/tshark 独立加载相同旧抓包和 keylog，识别到 TCP 443 上 2 条 HTTP POST（frame 532 / stream 34，以及 frame 642 / stream 45）。

因此，“对应 TLS 会话仍无法解密”的旧结论需要撤回。此前检查另一批 pcap 未出现 HTTP/2，也不能代表这份历史抓包无可解密会话。此验证没有得到战斗 UDP 密钥，也不代表所有 TLS 都已解密。

本机验证记录：[audit_tls_validation.json](D:/proc-sniffer/captures/sslkeylog/audit_tls_validation.json)。

## 4. 验证方式

```powershell
Set-Location D:\proc-sniffer
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

回归覆盖：合成 IPv4/IPv6 TCP/UDP、分片乱序/缺片/冲突/重复、序号回绕、四元组复用、重传补洞、截断头部/尾部、资源上限、归因降级、停止失败重试、旧 timer、路径保护、L7 启动异常/端点归因、MCP 并发和历史 PID。校园脚本在 PowerShell 5.1 与 7 下使用替身验证失败路径，UAC 参数用 Windows 原生 argv 解析器验证；没有实际提升或抓包。

真实证据复核包括历史 ETW 事件的协议映射、pcapng 字节检查、修复后 stream 导出及 tshark 的 TLS 独立解析。

最终由 Lead 运行：**99 项测试全部通过，耗时 3.575 秒**。分项为核心 37、双栈 5、流重组 30、L7 18、MCP 7、校园脚本 2（内含 PowerShell 5.1/7 的多个生命周期和参数引用场景）。`pip check` 无依赖冲突；`git diff --check` 通过；Python/PowerShell 语法检查通过。未做新的管理员实机抓包或真实代理连接测试。

## 5. 仍存在的限制

- **未做新的管理员实机采集或真实 MITM 启动测试。** NIC-only 采集可能遗漏回环/协议栈内部通信；多适配器仍可能重复。
- pktmon 具有全局会话和筛选器状态；已有筛选器会影响范围。校园脚本记录但不清除它们；不要同时由多个控制程序抢占会话。强制结束进程无法保证 finally 运行。
- `exact` 是采集时段的协议+双端元组证据，不是逐包 PID。时间窗口、PID 创建时间、端口复用和 scope/interface 关联仍有限；弱匹配和端口回退可能混入其他进程。
- 进程列表主要来自开始时的 PID 快照；新启动的子进程不会自动按应用树追踪。psutil 查询也可能漏掉结束过快的 L7 连接。
- TCP 没看到新 SYN 时的连接复用、迟到的旧连接段，以及跨度达到 2 GiB 的序号不能可靠消歧。没有完整 TCP 接收端状态机或校验和认证。首片之后的复杂 IPv6 扩展链、隧道封装和巨型报文未做全面覆盖测试。
- 分片按整个采集内的地址/协议/ID 分组；相同 ID 复用仍可能与副本或互补缺片混淆。冲突组保守丢弃；不能把 `discarded_fragment_packets=0` 当作全面完整性证明。
- `complete` 是观测数据的局部结构判断，不代表应用业务、登录结果或加密数据完整。UDP complete 仅覆盖实际观测到的数据报，不证明没漏其他数据报。
- 512 MiB 循环 ETL 可能覆盖最早事件。每方向 128 MiB 的 stream 输出上限不限制整个抓包、所有流的元数据或 JSONL 记录数量；大抓包导出仍可能耗用大量内存。
- 已截断的历史字节不能通过代码修复补回。不要把零填充后的 gzip/TLS 内容当作已恢复明文。

## 6. 本次工作区变更

保留原有安装、Git 未提交变更和原始抓包。修改后的采集脚本仍可通过原命令运行，默认 60 秒；可附加 `-Seconds 120 -NoBrowser`。未提交或推送任何修改；抓包、keylog 和含测试凭据的报告仍位于 Git 忽略的本机目录。
