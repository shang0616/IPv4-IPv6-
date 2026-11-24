"""Offline MCP tests: import with a mock sniffer, never start capture."""
from __future__ import annotations

import asyncio
import importlib.util
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_server(sniffer):
    spec = importlib.util.spec_from_file_location("_test_proc_sniffer_server", ROOT / "server.py")
    module = importlib.util.module_from_spec(spec)
    with patch("proc_sniffer.ProcSniffer", return_value=sniffer):
        with patch.dict(sys.modules, {spec.name: module}):
            spec.loader.exec_module(module)
    return module


def raw_tool(module, name):
    tool = getattr(module, name)
    return getattr(tool, "fn", tool)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.sniffer = Mock()
        self.sniffer.capture_pids = [123]
        self.sniffer.resolve_pids.return_value = [456]
        self.server = load_server(self.sniffer)

    def test_export_keeps_captured_pids_after_target_exit_or_replacement(self):
        raw_tool(self.server, "export_last")("report-name")
        self.sniffer.resolve_pids.assert_not_called()
        self.sniffer.export.assert_called_once_with("report-name", [123])

    def test_zero_duration_reports_manual_stop(self):
        result = raw_tool(self.server, "start_capture")("app.exe", duration=0, layers="l7")
        self.assertIn("手动停止", result)
        self.assertNotIn("0s 后自动停止", result)
        self.sniffer.start_capture.assert_called_once_with([456], duration=0, layers="l7")

    def test_start_reports_configured_proxy_port(self):
        with patch.object(self.server, "L7_PROXY_PORT", 9090):
            result = raw_tool(self.server, "start_capture")("app.exe", layers="l7")
        self.assertIn("127.0.0.1:9090", result)

    def test_missing_target_and_start_failure_are_not_reported_as_success(self):
        self.sniffer.resolve_pids.return_value = []
        self.assertIn("未找到", raw_tool(self.server, "start_capture")("missing"))
        self.sniffer.start_capture.assert_not_called()
        self.sniffer.resolve_pids.return_value = [123]
        self.sniffer.start_capture.side_effect = RuntimeError("startup failed")
        with self.assertRaisesRegex(RuntimeError, "startup failed"):
            raw_tool(self.server, "start_capture")("app.exe")

    def test_stop_returns_only_existing_core_output(self):
        self.sniffer.stop_capture.return_value = "capture/http_traffic.jsonl"
        self.assertIn("http_traffic.jsonl", raw_tool(self.server, "stop_capture")())
        self.sniffer.stop_capture.return_value = None
        self.assertIn("未生成输出", raw_tool(self.server, "stop_capture")())

    def test_export_failure_is_preserved(self):
        self.sniffer.export.side_effect = PermissionError("read-only export directory")
        with self.assertRaisesRegex(PermissionError, "read-only export directory"):
            raw_tool(self.server, "export_last")("app.exe")


class ServerDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_mcp_workers_serialize_export_and_stop_without_blocking_loop(self):
        sniffer = Mock()
        sniffer.capture_pids = [123]
        server = load_server(sniffer)
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        release = threading.Event()
        stopped = threading.Event()

        def export(*args):
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(3):
                raise RuntimeError("mock export release timed out")
            return {"pids": [123]}

        sniffer.export.side_effect = export
        sniffer.stop_capture.side_effect = lambda: stopped.set()
        export_tool = await server.mcp.get_tool("export_last")
        stop_tool = await server.mcp.get_tool("stop_capture")
        list_tool = await server.mcp.get_tool("list_monitorable_apps")
        pending = []
        with patch.object(server.psutil, "net_connections", return_value=[SimpleNamespace(pid=987)]), \
                patch.object(server.psutil, "Process") as process:
            process.return_value.name.return_value = "available.exe"
            try:
                pending.append(asyncio.create_task(export_tool.run({"app_name": "app.exe"})))
                await asyncio.wait_for(entered.wait(), timeout=2)
                pending.append(asyncio.create_task(stop_tool.run({})))
                # List remains callable while an export worker is busy.
                result = await asyncio.wait_for(list_tool.run({}), timeout=2)
                self.assertIn("available.exe", str(result))
                self.assertFalse(stopped.is_set(), "stop overlapped an in-flight export")
            finally:
                release.set()
                await asyncio.gather(*pending)
        self.assertTrue(stopped.is_set())


if __name__ == "__main__":
    unittest.main()
