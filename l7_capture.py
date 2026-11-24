"""
l7_capture — mitmproxy addon: 按 TCP 连接->PID 过滤, 仅记录目标进程的 HTTP/HTTPS 明文

被两种方式使用:
  1) 主进程 import run_mitmproxy() 启动 mitmdump 子进程
  2) mitmdump -s l7_capture.py --set pids_file=... --set out_file=...
     加载本模块, 自动注册模块级 addon 实例

工作原理: 作为正向代理拦截流量; 对每个 flow 取客户端和代理的 IP/端口,
反查 psutil 的完整 TCP 连接得到 PID, 仅当属于目标 PID 集合时才记录明文。
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil
from mitmproxy import ctx


def run_mitmproxy(port: int = 8080, pids_file=None, out_file=None, *,
                  startup_timeout: float = 15.0) -> subprocess.Popen:
    """启动本机代理，确认监听和日志初始化成功后返回拥有的子进程。"""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("代理端口必须是 1..65535 的整数")
    if not math.isfinite(startup_timeout) or startup_timeout <= 0:
        raise ValueError("startup_timeout 必须是正数")
    if pids_file is None or out_file is None:
        raise ValueError("必须提供 pids_file 和 out_file")
    pids_path, out_path = Path(pids_file).resolve(), Path(out_file).resolve()
    if pids_path == out_path:
        raise ValueError("PID 文件与 HTTP 输出文件不能相同")
    _read_pids(pids_path)  # Fail before launching on missing or malformed input.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve()
    mitmdump = Path(sys.executable).with_name(
        "mitmdump.exe" if sys.platform == "win32" else "mitmdump")
    # Only our addon can publish this private status file. An unrelated listener
    # on the requested port must never make startup appear successful.
    with tempfile.TemporaryDirectory(prefix="proc-sniffer-l7-") as status_dir:
        ready_path = Path(status_dir) / "ready.json"
        cmd = [
            str(mitmdump), "--listen-host", "127.0.0.1", "-p", str(port),
            "-s", str(script),
            "--set", f"pids_file={pids_path}",
            "--set", f"out_file={out_path}",
            "--set", f"ready_file={ready_path}",
            "--set", "termlog_verbosity=warn",
            "--set", "flow_detail=0",
        ]
        with tempfile.TemporaryFile(mode="w+b") as diagnostics:
            proc = subprocess.Popen(cmd, stdout=diagnostics, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + startup_timeout
                while True:
                    returncode = proc.poll()
                    if returncode is not None:
                        diagnostics.seek(0)
                        detail = diagnostics.read(8192).decode("utf-8", errors="replace").strip()
                        raise RuntimeError(f"mitmdump 启动失败 (exit={returncode}): {detail}")
                    if ready_path.exists():
                        status = json.loads(ready_path.read_text(encoding="utf-8"))
                        if status.get("error"):
                            raise RuntimeError(f"L7 初始化失败: {status['error']}")
                        if status.get("ready"):
                            return proc
                    if time.monotonic() >= deadline:
                        raise TimeoutError("等待 mitmdump 初始化超时")
                    time.sleep(0.05)
            except BaseException:
                # Never find or terminate a process by port/name: only the child
                # returned by this Popen belongs to this startup attempt.
                if proc.poll() is None:
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
                raise


def _read_pids(path: Path) -> set[int]:
    pids = {int(value) for value in path.read_text(encoding="utf-8").split()}
    if any(pid <= 0 for pid in pids):
        raise ValueError("PID 必须是正整数")
    return pids


def _endpoint(value):
    """Normalize psutil/mitmproxy socket endpoints, including mapped IPv4."""
    try:
        host, port = value[:2]
        address = ipaddress.ip_address(host.split("%", 1)[0])
        scope = host.split("%", 1)[1] if "%" in host else None
        if len(value) > 3 and value[3]:
            scope = str(value[3])
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped is not None:
                address, scope = address.ipv4_mapped, None
            elif not address.is_link_local:
                scope = None
        return str(address), int(port), scope
    except (TypeError, ValueError, IndexError, AttributeError):
        return None


class ProcL7Addon:
    def __init__(self):
        self.pids: set[int] = set()
        self.out = None
        self._last_reload = 0.0

    def load(self, loader):
        loader.add_option("pids_file", str, "", "path to pids.txt")
        loader.add_option("out_file", str, "", "path to http_traffic.jsonl")
        loader.add_option("ready_file", str, "", "private startup status file")

    def _publish_status(self, status):
        path = getattr(ctx.options, "ready_file", "")
        if path and Path(path).parent.is_dir():
            # The launcher removes the status directory after startup. A later
            # mitmproxy script reload does not need to acknowledge startup again.
            pending = Path(path).with_suffix(".tmp")
            pending.write_text(json.dumps(status), encoding="utf-8")
            pending.replace(path)

    def running(self):
        self.done()
        try:
            self.pids = _read_pids(Path(ctx.options.pids_file))
            self._last_reload = time.monotonic()
            self.out = open(ctx.options.out_file, "a", encoding="utf-8")
            self._publish_status({"ready": True})
        except (OSError, ValueError) as exc:
            self.done()
            logging.getLogger(__name__).error("L7 初始化失败: %s", exc)
            try:
                self._publish_status({"error": str(exc)})
            finally:
                ctx.master.shutdown()

    def _reload(self):
        self._last_reload = time.monotonic()
        try:
            self.pids = _read_pids(Path(ctx.options.pids_file))
        except (OSError, ValueError):
            # Never keep authorizing stale targets after an unreadable update.
            self.pids.clear()

    def _belongs(self, flow) -> bool:
        if time.monotonic() - self._last_reload > 2:
            self._reload()
        if not self.pids:
            return False
        peer = _endpoint(getattr(flow.client_conn, "peername", None))
        local = _endpoint(getattr(flow.client_conn, "sockname", None))
        if peer is None or local is None:
            return False
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.Error, OSError):
            return False
        for c in connections:
            if (c.type == socket.SOCK_STREAM and c.pid in self.pids
                    and _endpoint(c.laddr) == peer and _endpoint(c.raddr) == local):
                return True
        return False

    def request(self, flow):
        flow.metadata.pop("rec", None)
        flow.metadata["skip"] = True
        if not self._belongs(flow):
            return
        req = flow.request
        flow.metadata["rec"] = {
            "ts": time.time(),
            "type": "request",
            "method": req.method,
            "url": req.pretty_url,
            "req_headers": dict(req.headers),
            "req_body": req.get_text(strict=False),
        }
        flow.metadata["skip"] = False

    def response(self, flow):
        if flow.metadata.get("skip", True):
            return
        rec = flow.metadata.pop("rec", None)
        if rec is None:
            return
        # Consume the request record so repeated hooks cannot duplicate output.
        resp = flow.response
        rec.update({
            "resp_status": resp.status_code if resp else None,
            "resp_headers": dict(resp.headers) if resp else {},
            "resp_body": resp.get_text(strict=False) if resp else None,
        })
        if self.out:
            self.out.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            self.out.flush()

    def done(self):
        out, self.out = self.out, None
        if out is not None:
            try:
                out.close()
            except OSError:
                pass


# mitmproxy treats a script module itself as the addon and does not pick up an
# "addon" object variable, so expose the lifecycle hooks at module level.
addon = ProcL7Addon()
load = addon.load
running = addon.running
request = addon.request
response = addon.response
done = addon.done
