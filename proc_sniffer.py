"""
proc_sniffer — 按进程名抓取本机网络报文（Windows 10 本机版，含 L3/L4 + L7）

链路:
  软件名 --psutil--> PID/端口
    L3/L4: pktmon(抓全量) + Kernel-Network(每条 socket 操作带 PID) --> ETL
           --etl2pcapng--> pcapng --按 4 元组 join ETW 的 PID--> filtered.pcap
    L7   : mitmproxy(代理, 按源端口->PID过滤) --> http_traffic.jsonl (HTTP 明文 req/resp)
    导出 : requests.json / index.md / filtered.pcap / streams/ / http_traffic.jsonl

说明:
  - pktmon 为 Win10 1809+ 内置。它记录的报文本身不带 PID, pktmon etl2pcap
    转出的 pcapng 里也没有进程元数据(Wireshark 的 _ws.process.id 字段并不存在)。
  - 真正带 PID 的是 Microsoft-Windows-Kernel-Network 这个 ETW provider: 每条
    TCP/UDP send/recv/connect 事件都有 PID + saddr/sport/daddr/dport。所以抓包时
    同时挂上它, 事后用 4 元组把 pcapng 报文 join 到 PID。
  - L3/L4 同时支持 IPv4 和 IPv6; ETW 的 IPv6 zone id 会在匹配前归一化。
  - ETW 拿不到时回退端口采样(精度低, 短连接可能漏)。
  - L7 明文需目标进程走代理(系统代理或单独设代理), 并信任 mitmproxy CA;
    证书绑定(SSL Pinning)需 Frida 绕过(超出本工具范围, 见 README)。
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import psutil
# Scapy on Windows reads these variables at import time. Some MCP clients
# launch servers with a minimal environment, so provide standard fallbacks.
for _var, _default in {
    "SystemRoot": r"C:\Windows",
    "WINDIR": r"C:\Windows",
    "ProgramFiles": r"C:\Program Files",
    "ProgramFiles(x86)": r"C:\Program Files (x86)",
    "ProgramW6432": r"C:\Program Files",
}.items():
    os.environ.setdefault(_var, _default)
from scapy.all import PcapReader, PcapWriter, conf, rdpcap, IP, IPv6, TCP, UDP
from scapy.layers.inet6 import IPv6ExtHdrFragment

PKTMON = "pktmon"                                  # Win10 1809+ 内置, 需管理员
ETL2PCAP = "etl2pcap"                               # pktmon 子命令: pktmon etl2pcap <etl> --out <pcapng>
# 可选, 下载: https://github.com/microsoft/etl2pcapng  (也可用 PROC_SNIFFER_ETL2PCAPNG 覆盖)
ETL2PCAPNG_FALLBACK = os.environ.get(
    "PROC_SNIFFER_ETL2PCAPNG", r"C:\tools\etl2pcapng.exe")
# 抓包工作目录 (也可用 PROC_SNIFFER_WORKDIR 覆盖)
WORK_DIR = Path(os.environ.get("PROC_SNIFFER_WORKDIR", str(Path.home() / "proc_sniffer_caps")))
L7_PROXY_PORT = int(os.environ.get("PROC_SNIFFER_L7_PORT", "8080"))
# 带 PID 的 ETW provider: 每条 TCP/UDP 收发事件都有 PID + 4 元组
ETW_PROVIDER = "Microsoft-Windows-Kernel-Network"


def _norm_ip(value: str | None) -> str | None:
    """统一 IPv4/IPv6 文本，便于 ETW 与 pcap 的地址比较。

    ETW 可能带 IPv6 zone id，Windows 双栈 socket 也可能给出 IPv4-mapped
    地址；这里去掉 zone，并把 ::ffff:a.b.c.d 还原成 IPv4。
    """
    if not value:
        return None
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _ip_layer(pkt):
    """返回报文的 IPv4/IPv6 层，非 IP 报文返回 None。"""
    if IP in pkt:
        return pkt[IP]
    if IPv6 in pkt:
        return pkt[IPv6]
    return None


def _l4_layer(pkt):
    """返回报文的 TCP/UDP 层，其他协议返回 None。"""
    if TCP in pkt:
        return pkt[TCP]
    if UDP in pkt:
        return pkt[UDP]
    return None


def _fragment_info(pkt):
    """分片关联键和偏移；保留原始分片，重组交给导出器。"""
    ip = _ip_layer(pkt)
    if isinstance(ip, IP) and (int(ip.frag) or ip.flags.MF):
        return (4, _norm_ip(ip.src), _norm_ip(ip.dst), int(ip.id), int(ip.proto)), int(ip.frag)
    if isinstance(ip, IPv6) and IPv6ExtHdrFragment in pkt:
        frag = pkt[IPv6ExtHdrFragment]
        return (6, _norm_ip(ip.src), _norm_ip(ip.dst), int(frag.id), int(frag.nh)), int(frag.offset)
    return None


def _packet_tuple(pkt):
    ip = _ip_layer(pkt)
    if ip is None:
        return None
    fragment = _fragment_info(pkt)
    if fragment is not None and fragment[1] != 0:
        return None
    src, dst = _norm_ip(ip.src), _norm_ip(ip.dst)
    if not src or not dst:
        return None
    l4 = _l4_layer(pkt)
    if l4 is not None:
        return ("TCP" if isinstance(l4, TCP) else "UDP", src, int(l4.sport), dst, int(l4.dport))
    # 很小的首片可能只有端口，没有完整 TCP 头，Scapy 此时保留为 Raw。
    if fragment is not None and fragment[0][-1] in (6, 17):
        payload = bytes(pkt[IPv6ExtHdrFragment].payload if isinstance(ip, IPv6) else ip.payload)
        if len(payload) >= 4:
            return ("TCP" if fragment[0][-1] == 6 else "UDP", src,
                    int.from_bytes(payload[:2], "big"), dst,
                    int.from_bytes(payload[2:4], "big"))
    return None


def _safe_export_name(name):
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    if (not name or name in (".", "..") or name[-1] in " ."
            or any(ord(c) < 32 or c in '/\\\\<>:"|?*' for c in name)
            or name.split(".", 1)[0].upper() in reserved):
        raise ValueError("app_name 必须是安全的单段目录名；自定义输出位置请使用 out_dir")
    return name


class ProcSniffer:
    def __init__(self, work_dir: str | None = None):
        self.work_dir = Path(work_dir) if work_dir else WORK_DIR
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._etl = self.work_dir / "capture.etl"
        self._pcapng = self.work_dir / "capture.pcapng"
        self._filtered = self.work_dir / "filtered.pcap"
        self._http = self.work_dir / "http_traffic.jsonl"
        self._pids_file = self.work_dir / "pids.txt"
        self._running = False
        self._target_pids: set[int] = set()
        self._ports_snapshot: set[int] = set()
        self._timer = None
        self._l7_proc = None
        self._layers = "l3"
        self._etw_xml: Path | None = None
        self._peer_only = 0
        self._attribution = "none"
        self._attribution_counts: dict[str, int] = {}
        self._capture_lock = threading.RLock()
        self._generation = 0
        self._pktmon_owned = False
        self._capture_error: str | None = None
        self._port_sampler_thread = None
        self._sampler_stop = threading.Event()

    @property
    def capture_pids(self) -> list[int]:
        """当前/最近一次采集的 PID 快照，不重新查询已退出的进程。"""
        with self._capture_lock:
            return sorted(self._target_pids)

    # ① 软件名 -> PID 列表(精确进程名优先, 否则模糊匹配 name/exe/cmdline)
    def resolve_pids(self, app_name: str) -> list[int]:
        if not app_name or not app_name.strip():
            raise ValueError("app_name 不得为空")
        app = app_name.strip().lower()
        exact: set[int] = set()
        fuzzy: set[int] = set()
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                info = p.info
                name = (info.get("name") or "").lower()
                exe = (info.get("exe") or "").lower()
                hay = " ".join(filter(None, [
                    name,
                    exe,
                    " ".join(info.get("cmdline") or []).lower(),
                ]))
                # 避免抓 dwrg 时把命令行里带 "dwrg" 的 shell/Python 也算进来。
                if (name == app or Path(name).stem == app
                        or exe == app or Path(exe).stem == app):
                    exact.add(info["pid"])
                elif app in hay:
                    fuzzy.add(info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sorted(exact or fuzzy)

    # ② 采样指定 PID 使用的本地端口
    def sample_ports(self, pids: set[int]) -> set[int]:
        ports: set[int] = set()
        for c in psutil.net_connections(kind="inet"):
            if c.pid in pids and c.laddr:
                ports.add(c.laddr.port)
        return ports

    def _port_sampler(self, stop_event, pids, ports):
        # 使用每代独立对象，旧线程不能污染下一次采集的端口快照。
        while not stop_event.is_set():
            try:
                ports.update(self.sample_ports(pids))
            except (psutil.Error, OSError):
                pass
            stop_event.wait(1)

    def _stop_l7(self):
        proc = self._l7_proc
        if proc is not None:
            # 失败时仍持有自己创建的子进程，允许再次 stop，而不是遗失所有权。
            proc.terminate()
            proc.wait(timeout=5)
            self._l7_proc = None

    def _stop_pktmon(self):
        if not self._pktmon_owned:
            return
        # 仅成功 start 才有 stop 权；停止失败保留所有权供显式重试。
        subprocess.run([PKTMON, "stop"], check=True, capture_output=True)
        self._pktmon_owned = False

    def _stop_generation(self, generation):
        with self._capture_lock:
            if generation == self._generation:
                self.stop_capture()

    # ③ 启动抓取
    def start_capture(self, pids: list[int], duration: int | None = None,
                      layers: str = "full"):
        """
        layers:
          "l3"  仅 L3/L4 报文(pktmon)
          "l7"  仅 HTTP 明文(mitmproxy, 需目标进程走代理)
          "full" 两者都开(默认)
        """
        with self._capture_lock:
            if self._running or self._pktmon_owned or self._l7_proc is not None:
                raise RuntimeError("已在抓取中或停止尚未成功, 请先 stop_capture")
            if not pids or any(type(pid) is not int or pid <= 0 for pid in pids):
                raise ValueError("pids 必须是非空的正整数列表")
            if layers not in ("l3", "l7", "full"):
                raise ValueError("layers 必须为 l3、l7 或 full")
            if duration is not None and (type(duration) not in (int, float)
                    or not math.isfinite(duration) or duration < 0):
                raise ValueError("duration 必须为有限非负数；0 表示手动停止")
            self._generation += 1
            self._target_pids = set(pids)
            self._ports_snapshot = set()
            self._layers = layers
            self._capture_error = None
            self._attribution = "none"
            self._attribution_counts = {}
            self._peer_only = 0
            self._sampler_stop = threading.Event()
            self._etw_xml = self.work_dir / "etw_network.xml"
            try:
                # 写 pids 文件供 L7 addon 读取；每次采集清除上一代产物。
                self._pids_file.write_text(" ".join(map(str, pids)), encoding="utf-8")
                for f in (self._etl, self._pcapng, self._filtered, self._http, self._etw_xml):
                    f.unlink(missing_ok=True)
                if layers in ("l3", "full"):
                    # 0 为完整包；网卡/flow 限制减少协议栈多组件的重复记录。
                    subprocess.run([PKTMON, "start", "--capture", "--trace",
                                    "--provider", ETW_PROVIDER,
                                    "--pkt-size", "0", "--comp", "nics", "--type", "flow",
                                    "--file-size", "512", "--file-name", str(self._etl)],
                                   check=True, capture_output=True)
                    self._pktmon_owned = True
                    self._port_sampler_thread = threading.Thread(
                        target=self._port_sampler,
                        args=(self._sampler_stop, set(pids), self._ports_snapshot),
                        daemon=True)
                    self._port_sampler_thread.start()
                if layers in ("l7", "full"):
                    self._start_l7()
                self._running = True
                if duration:
                    self._timer = threading.Timer(
                        duration, self._stop_generation, args=(self._generation,))
                    self._timer.daemon = True
                    self._timer.start()
            except BaseException as exc:
                self._capture_error = str(exc)
                self._running = False
                self._sampler_stop.set()
                if self._timer is not None:
                    self._timer.cancel()
                    self._timer = None
                for cleanup in (self._stop_l7, self._stop_pktmon):
                    try:
                        cleanup()
                    except (OSError, subprocess.SubprocessError) as exc:
                        print(f"[capture] 启动回滚停止失败: {exc}", file=sys.stderr)
                raise

    def _start_l7(self, port: int = L7_PROXY_PORT):
        from l7_capture import run_mitmproxy
        self._l7_proc = run_mitmproxy(
            port=port, pids_file=self._pids_file, out_file=self._http)

    # ④ 停止 + 转换 + 过滤
    def stop_capture(self):
        with self._capture_lock:
            if not self._running and not self._pktmon_owned and self._l7_proc is None:
                return None
            self._running = False
            self._sampler_stop.set()
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            try:
                self._stop_pktmon()
                if self._layers in ("l3", "full"):
                    # 即使 ETL 未出现也必须先停止本工具拥有的会话，再明确报告失败。
                    self.convert()
                    self.filter_by_pid(self._target_pids)
            except BaseException as exc:
                self._capture_error = str(exc)
                try:
                    self._stop_l7()
                except (OSError, subprocess.SubprocessError) as exc:
                    print(f"[l7] 停止失败，可重试 stop_capture: {exc}", file=sys.stderr)
                raise
            else:
                try:
                    self._stop_l7()
                except BaseException as exc:
                    self._capture_error = str(exc)
                    raise
            self._capture_error = None
            if self._layers in ("l3", "full") and self._pcapng.exists():
                return str(self._pcapng)
            return str(self._http) if self._http.exists() else None

    def convert(self) -> Path:
        self._pcapng.unlink(missing_ok=True)
        self._filtered.unlink(missing_ok=True)
        self._attribution = "none"
        self._attribution_counts = {}
        self._peer_only = 0
        if not self._etl.exists():
            raise RuntimeError("未找到 ETL, 请确认以管理员身份运行且 pktmon 可用")
        # ETL 同时含 PktMon 报文和 Kernel-Network 事件。
        self._export_etw()
        try:
            if Path(ETL2PCAPNG_FALLBACK).exists():
                subprocess.run([ETL2PCAPNG_FALLBACK, str(self._etl), str(self._pcapng)], check=True, capture_output=True)
            else:
                subprocess.run([PKTMON, ETL2PCAP, str(self._etl), "--out", str(self._pcapng)], check=True, capture_output=True)
            if not self._pcapng.exists() or self._pcapng.stat().st_size == 0:
                raise RuntimeError("ETL 转换未产出 pcapng")
        except BaseException:
            self._pcapng.unlink(missing_ok=True)
            raise
        return self._pcapng

    def _export_etw(self):
        """用 tracerpt 把 ETL 里的 ETW 事件导成 XML(报文由 pktmon etl2pcap 单独转)。"""
        if self._etw_xml is None:
            self._etw_xml = self.work_dir / "etw_network.xml"
        self._etw_xml.unlink(missing_ok=True)
        try:
            r = subprocess.run(["tracerpt", str(self._etl), "-of", "XML",
                                "-o", str(self._etw_xml), "-y"],
                               check=False, capture_output=True)
        except OSError as exc:
            self._etw_xml.unlink(missing_ok=True)
            print(f"[etw] tracerpt 不可用: {exc}", file=sys.stderr)
            return
        if (r.returncode != 0 or not self._etw_xml.exists()
                or self._etw_xml.stat().st_size == 0):
            self._etw_xml.unlink(missing_ok=True)
            print(f"[etw] tracerpt 未产出可用 XML rc={r.returncode}", file=sys.stderr)

    def _filter_packets(self, src: Path, classify, attribution: str) -> Path:
        """两遍流式过滤，后续分片沿用首片归因，不按内容消除真实报文。"""
        if src.resolve() == self._filtered.resolve():
            raise ValueError("过滤输入不能与 filtered.pcap 输出相同")
        self._filtered.unlink(missing_ok=True)
        self._attribution = "none"
        self._attribution_counts = {}
        self._peer_only = 0
        if not src.exists():
            raise FileNotFoundError(f"未找到抓包文件: {src}")
        # 同一分片 ID 若出现不同端口/归因，不能把无端口的尾片分给其中一条流。
        fragments = {}
        linktypes = set()
        with PcapReader(str(src)) as reader:
            for pkt in reader:
                linktypes.add(conf.l2types.layer2num.get(type(pkt)))
                frag = _fragment_info(pkt)
                if frag is None or frag[1] != 0:
                    continue
                signature = (_packet_tuple(pkt), classify(pkt))
                previous = fragments.get(frag[0], signature)
                fragments[frag[0]] = signature if previous == signature else (None, None)
        # PCAP 只支持一个链路类型。PCAPNG 的无以太头 IPv4/IPv6 可共同用 DLT_RAW。
        if len(linktypes) > 1 and linktypes <= {228, 229}:
            linktype = 101
        elif len(linktypes) > 1 or None in linktypes:
            raise ValueError("混合或未知链路类型无法无损导出为单一 PCAP")
        else:
            linktype = next(iter(linktypes), 1)
        counts = {key: 0 for key in ("exact", "tuple_only", "endpoint_only", "peer_only", "port_sample")}
        try:
            with PcapReader(str(src)) as reader, PcapWriter(str(self._filtered), linktype=linktype) as writer:
                # 即使无命中，也写有效空 PCAP，防止把旧数据冒充本次结果。
                writer.write_header(None)
                for pkt in reader:
                    frag = _fragment_info(pkt)
                    if frag is not None:
                        category = fragments.get(frag[0], (None, None))[1]
                    else:
                        category = classify(pkt)
                    if category is None:
                        continue
                    writer.write_packet(pkt)
                    counts[category] += 1
        except BaseException:
            self._filtered.unlink(missing_ok=True)
            raise
        self._attribution = attribution
        self._attribution_counts = counts
        self._peer_only = counts["peer_only"]
        return self._filtered

    # ⑤ 按端口集合过滤 pcapng -> pcap(回退方案)
    def filter_by_ports(self, ports: set[int], src: str | None = None) -> Path:
        def classify(pkt):
            key = _packet_tuple(pkt)
            if key is not None and (key[2] in ports or key[4] in ports):
                return "port_sample"
            return None
        return self._filter_packets(Path(src) if src else self._pcapng, classify, "port-sample")

    # ⑥ ETW 元组优先，缺少可解析事件时回退端口采样
    def filter_by_pid(self, pids: set[int]) -> Path:
        kept = self.filter_by_etw(pids)
        if kept is not None:
            return kept
        try:
            ports = self._ports_snapshot | self.sample_ports(set(pids))
        except (psutil.Error, OSError):
            ports = set(self._ports_snapshot)
        return self.filter_by_ports(ports)

    # ⑥a 解析 ETW: (protocol,saddr,sport,daddr,dport) -> {pid}
    def _local_ips(self) -> set[str]:
        ips: set[str] = set()
        try:
            for _, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        ip = _norm_ip(a.address)
                        if ip:
                            ips.add(ip)
        except Exception:
            pass
        return ips

    def _etw_tuples(self) -> dict[tuple, set[int]]:
        if self._etw_xml is None or not self._etw_xml.exists():
            return {}
        import xml.etree.ElementTree as ET
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        m: dict[tuple, set[int]] = {}

        def number(text):
            return int(text, 16 if text.lower().startswith("0x") else 10)

        try:
            with self._etw_xml.open("rb") as handle:
                for _, el in ET.iterparse(handle, events=("end",)):
                    if el.tag != ns + "Event":
                        continue
                    prov = el.find(ns + "System/" + ns + "Provider")
                    if prov is None or (prov.get("Name") or "").lower() != ETW_PROVIDER.lower():
                        el.clear()
                        continue
                    d = {(x.get("Name") or "").lower(): (x.text or "").strip()
                         for x in el.findall(ns + "EventData/" + ns + "Data")}
                    saddr, daddr = _norm_ip(d.get("saddr")), _norm_ip(d.get("daddr"))
                    try:
                        sport, dport, pid = number(d["sport"]), number(d["dport"]), number(d["pid"])
                        if not saddr or not daddr or not (0 <= sport <= 65535 and 0 <= dport <= 65535) or pid <= 0:
                            raise ValueError("invalid ETW endpoint")
                        event_id = number(el.findtext(ns + "System/" + ns + "EventID", "0"))
                        # Kernel-Network manifest: v4 TCP 10..18, v6 TCP 26..34;
                        # UDP send/recv 42/43 (v4), 58/59 (v6)。未知事件不能标 exact。
                        if event_id in (*range(10, 19), *range(26, 35)):
                            proto = "TCP"
                        elif event_id in (42, 43, 58, 59):
                            proto = "UDP"
                        else:
                            proto = None
                        key = (proto, saddr, sport, daddr, dport)
                        m.setdefault(key, set()).add(pid)
                    except (KeyError, ValueError):
                        pass
                    el.clear()
        except (ET.ParseError, OSError) as exc:
            print(f"[etw] 无法解析事件，回退端口采样: {exc}", file=sys.stderr)
            return {}
        return m

    # ⑥b 用 ETW 的 PID 过滤 pcapng。ETW 一条记录都没解析到 -> 返回 None(交给回退)
    def filter_by_etw(self, pids: set[int]) -> Path | None:
        m = self._etw_tuples()
        if not m:
            self._filtered.unlink(missing_ok=True)
            self._attribution = "none"
            self._attribution_counts = {}
            self._peer_only = 0
            return None
        pids = set(pids)
        endpoints: set[tuple] = set()
        peer: set[str] = set()
        local_ips = self._local_ips()
        for (proto, sa, sp, da, dp), owners in m.items():
            if not (owners & pids):
                continue
            if sa in local_ips:
                endpoints.add((proto, sa, sp))
            else:
                peer.add(sa)
            if da in local_ips:
                endpoints.add((proto, da, dp))
            else:
                peer.add(da)

        def classify(pkt):
            key = _packet_tuple(pkt)
            if key is None:
                return None
            proto, src, sport, dst, dport = key
            reverse = (proto, dst, dport, src, sport)
            owners = m.get(key, set()) | m.get(reverse, set())
            if owners:
                if not owners & pids:
                    return None  # 已知属于其他 PID，不能经 peer 回退重新混入。
                return "exact" if owners <= pids else "tuple_only"
            unknown = (m.get((None, src, sport, dst, dport), set())
                       | m.get((None, dst, dport, src, sport), set()))
            if unknown:
                return "tuple_only" if unknown & pids else None
            if any(endpoint in endpoints for endpoint in (
                    (proto, src, sport), (proto, dst, dport),
                    (None, src, sport), (None, dst, dport))):
                return "endpoint_only"
            if src in peer or dst in peer:
                return "peer_only"
            return None

        return self._filter_packets(self._pcapng, classify, "etw")

    # ⑦ 导出
    def export(self, app_name: str, pids: list[int], out_dir: str | None = None) -> dict:
        with self._capture_lock:
            if self._running or self._pktmon_owned or self._l7_proc is not None:
                raise RuntimeError("采集尚未停止成功，请先 stop_capture 再导出")
            if self._capture_error is not None:
                raise RuntimeError(f"上次采集失败，不能导出为成功结果: {self._capture_error}")
            return self._export(app_name, sorted(self._target_pids) if self._target_pids else pids, out_dir)

    def _export(self, app_name, pids, out_dir):
        out = Path(out_dir) if out_dir else (self.work_dir / "exports" / _safe_export_name(app_name))
        out.mkdir(parents=True, exist_ok=True)
        # 同目录复用导出时，缺失的本代源文件不能留下上一代副本。
        for source in (self._filtered, self._http):
            destination = out / source.name
            if not source.exists() and destination.exists():
                destination.unlink()
        # L3/L4 连接清单
        packets = rdpcap(str(self._filtered)) if self._filtered.exists() else []
        conns: dict = {}
        fragment_tuples = {}
        for pkt in packets:
            frag = _fragment_info(pkt)
            key = _packet_tuple(pkt)
            if frag is not None and frag[1] == 0 and key is not None:
                fragment_tuples[frag[0]] = key
        for pkt in packets:
            ip = _ip_layer(pkt)
            key = _packet_tuple(pkt)
            frag = _fragment_info(pkt)
            if key is None and frag is not None:
                key = fragment_tuples.get(frag[0])
            if ip is None or key is None:
                continue
            proto, src, sport, dst, dport = key
            version = 6 if isinstance(ip, IPv6) else 4
            key = (src, sport, dst, dport, proto, version)
            c = conns.setdefault(key, {"packets": 0, "bytes": 0,
                                       "ip_version": version})
            c["packets"] += 1
            c["bytes"] += len(pkt)
        ipv4_connections = sum(1 for v in conns.values() if v["ip_version"] == 4)
        ipv6_connections = sum(1 for v in conns.values() if v["ip_version"] == 6)
        try:
            from stream_export import export_streams
            stream_info = export_streams(packets, out / "streams")
        except Exception:
            import traceback
            stream_info = {"error": traceback.format_exc()}
        stats = {
            "app_name": app_name,
            "pids": pids,
            "captured_at": datetime.now().isoformat(timespec="seconds"),
            "attribution": self._attribution,
            "attribution_counts": dict(self._attribution_counts),
            "peer_only_packets": self._peer_only,
            "packet_count": len(packets),
            "limitations": [
                "exact 表示协议及完整双端元组命中，不是按事件时间证明的进程归属；端口/PID 重用仍可能误归因。",
                "tuple_only 缺协议或存在多 PID 归属；endpoint_only 和 peer_only 为弱匹配，可能混入其他进程流量。",
                "port_sample 按任一端口匹配，可能漏短连接或混入其他进程流量。",
                "保留原始重复报文；网卡采集仍可能在多个适配器记录同包，不按 payload 消除 UDP 数据报或 TCP 重传。",
                "pktmon 继承系统中已有的过滤规则；本工具不修改用户过滤器，已有规则可能导致漏包。",
                "分片依赖可归因首片；缺首片或相同分片标识有冲突时不保留该分片组。",
            ],
            "ipv4_connections": ipv4_connections,
            "ipv6_connections": ipv6_connections,
            "streams": stream_info,
            "connections": [
                {"src": s, "sport": sp, "dst": d, "dport": dp, "proto": pr,
                 "ip_version": v["ip_version"],
                 "packets": v["packets"], "bytes": v["bytes"]}
                for (s, sp, d, dp, pr, _), v in conns.items()
            ],
        }
        (out / "requests.json").write_text(
            json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
        # index.md
        lines = [
            f"# {app_name} 流量导出",
            f"- 时间: {stats['captured_at']}",
            f"- PID: {pids}",
            f"- 归因方式: {stats['attribution']}",
            f"- L3/L4 连接数: {len(stats['connections'])}",
            f"- IPv4 连接数: {ipv4_connections}",
            f"- IPv6 连接数: {ipv6_connections}",
        ]
        if "error" in stream_info:
            lines.append("- 数据流重组: 失败（见 requests.json）")
        else:
            lines += [
                f"- 重组数据流: {stream_info.get('flows', 0)} 条"
                f"（TCP {stream_info.get('tcp_flows', 0)} / UDP {stream_info.get('udp_flows', 0)}）",
                f"- 数据流目录: [streams/index.json](streams/index.json)"
                f"（共 {stream_info.get('payload_bytes', 0)} 字节）",
            ]
        lines += [
            f"- L7 HTTP 记录数: {self._count_http()}",
            "",
        ]
        lines += [f"- 归因分级包数: {stats['attribution_counts']}", ""]
        lines += [f"> {note}" for note in stats["limitations"]]
        lines.append("")
        lines += [
            "## L3/L4 连接清单", "",
            "| 源 | 源端口 | 目的 | 目的端口 | 协议 | IP版本 | 包数 | 字节 |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for c in stats["connections"]:
            lines.append(
                f"| {c['src']} | {c['sport']} | {c['dst']} | {c['dport']} | "
                f"{c['proto']} | IPv{c['ip_version']} | {c['packets']} | {c['bytes']} |")
        (out / "index.md").write_text("\n".join(lines), encoding="utf-8")
        # 复制产物
        if self._filtered.exists() and self._filtered.resolve() != (out / "filtered.pcap").resolve():
            shutil.copy(self._filtered, out / "filtered.pcap")
        if self._http.exists() and self._http.resolve() != (out / "http_traffic.jsonl").resolve():
            shutil.copy(self._http, out / "http_traffic.jsonl")
        return {
            "json": str(out / "requests.json"),
            "index": str(out / "index.md"),
            "pcap": str(out / "filtered.pcap") if self._filtered.exists() else None,
            "http": str(out / "http_traffic.jsonl") if self._http.exists() else None,
            "connections": len(stats["connections"]),
            "ipv4_connections": ipv4_connections,
            "ipv6_connections": ipv6_connections,
            "streams": stream_info.get("dir"),
            "stream_count": stream_info.get("flows", 0),
            "tcp_streams": stream_info.get("tcp_streams", 0),
            "udp_streams": stream_info.get("udp_streams", 0),
            "http_records": self._count_http(),
            "attribution": stats["attribution"],
            "attribution_counts": stats["attribution_counts"],
            "packet_count": stats["packet_count"],
            "limitations": stats["limitations"],
            "peer_only_packets": self._peer_only,
        }

    def _count_http(self) -> int:
        if not self._http.exists():
            return 0
        try:
            with self._http.open(encoding="utf-8") as handle:
                return sum(1 for _ in handle)
        except Exception:
            return 0


if __name__ == "__main__":
    # CLI: 参数校验在进程解析和采集之前；--help 不启动任何采集。
    import argparse
    parser = argparse.ArgumentParser(description="按进程名采集 Windows TCP/UDP 与可选 HTTP 明文")
    parser.add_argument("app", help="软件名或 exe 名")
    parser.add_argument("duration", nargs="?", type=int, default=30, help="采集秒数，必须大于 0（默认 30）")
    parser.add_argument("layers", nargs="?", choices=("l3", "l7", "full"), default="full")
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("采集秒数必须大于 0")
    if not args.app.strip():
        parser.error("软件名不得为空")
    app, dur, layers = args.app, args.duration, args.layers
    s = ProcSniffer()
    pids = s.resolve_pids(app)
    print("解析到 PID:", pids)
    if not pids:
        print("未找到进程, 退出")
        sys.exit(1)
    if layers in ("l7", "full"):
        print(f"[提示] L7 模式需让 '{app}' 走代理 127.0.0.1:{L7_PROXY_PORT} (系统代理或单独设)")
    print(f"[*] 开始抓取 {dur}s")
    s.start_capture(pids, duration=None, layers=layers)  # 不用 timer, 主线程同步等待
    print(f">>> 现在去操作 '{app}' 触发目标请求(窗口越长越容易漏, 建议开始后立即操作) <<<")
    try:
        time.sleep(dur)                                # 抓取窗口
    finally:
        s.stop_capture()                               # 同步 stop + convert + filter
    print("抓取完成, 导出中...")
    print(json.dumps(s.export(app, pids), ensure_ascii=False, indent=2))
