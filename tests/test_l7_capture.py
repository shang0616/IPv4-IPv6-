"""Offline L7 attribution and subprocess lifecycle regression tests."""
from __future__ import annotations

import io
import json
import socket
import sys
import tempfile
import unittest
from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import l7_capture


def flow(peer=("127.0.0.1", 50000), local=("127.0.0.1", 8080)):
    return SimpleNamespace(
        client_conn=SimpleNamespace(peername=peer, sockname=local),
        metadata={},
        request=SimpleNamespace(method="GET", pretty_url="http://example.test/",
                                headers={}, get_text=lambda strict=False: ""),
        response=SimpleNamespace(status_code=200, headers={},
                                 get_text=lambda strict=False: "response"),
    )


Endpoint = namedtuple("Endpoint", "ip port")


def connection(local=("127.0.0.1", 50000), remote=("127.0.0.1", 8080), pid=123):
    return SimpleNamespace(laddr=Endpoint(*local) if local else (),
                           raddr=Endpoint(*remote) if remote else (),
                           pid=pid, type=socket.SOCK_STREAM)


class L7AttributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="psniff-l7-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.pids = self.work / "pids.txt"
        self.pids.write_text("123", encoding="utf-8")
        self.options = SimpleNamespace(pids_file=str(self.pids),
                                       out_file=str(self.work / "http.jsonl"), ready_file="")
        self.ctx = SimpleNamespace(options=self.options, master=Mock())
        self.addCleanup(patch.stopall)
        patch.object(l7_capture, "ctx", self.ctx).start()
        self.connections = patch.object(l7_capture.psutil, "net_connections", return_value=[]).start()
        self.addon = l7_capture.ProcL7Addon()
        self.addCleanup(self.addon.done)
        self.addon._reload()
        self.addon.out = io.StringIO()

    def test_full_connection_required_for_attribution(self):
        for unrelated in (
            connection(local=("127.0.0.2", 50000)),
            connection(remote=("198.51.100.1", 443)),
            connection(remote=()),
            connection(pid=456),
        ):
            with self.subTest(connection=unrelated):
                self.connections.return_value = [unrelated]
                self.assertFalse(self.addon._belongs(flow()))
        self.connections.return_value = [connection()]
        self.assertTrue(self.addon._belongs(flow()))
        self.connections.assert_called_with(kind="tcp")

    def test_ipv4_mapped_and_ipv6_endpoints(self):
        self.connections.return_value = [connection()]
        self.assertTrue(self.addon._belongs(flow(
            ("::ffff:127.0.0.1", 50000, 0, 0), ("::ffff:127.0.0.1", 8080, 0, 0))))
        self.connections.return_value = [connection(("::1", 50000), ("::1", 8080))]
        self.assertTrue(self.addon._belongs(flow(("::1", 50000, 0, 0), ("::1", 8080, 0, 0))))

    def test_missing_or_malformed_endpoint_rejects_flow(self):
        for peer in (None, (), ("invalid-address", 50000)):
            with self.subTest(peer=peer):
                self.assertFalse(self.addon._belongs(flow(peer=peer)))
        request = flow()
        del request.client_conn.sockname
        self.assertFalse(self.addon._belongs(request))

    def test_ipv6_link_local_scope_is_part_of_connection_identity(self):
        self.connections.return_value = [connection(("fe80::1%4", 50000), ("fe80::2%4", 8080))]
        self.assertTrue(self.addon._belongs(flow(("fe80::1", 50000, 0, 4), ("fe80::2", 8080, 0, 4))))
        self.assertFalse(self.addon._belongs(flow(("fe80::1", 50000, 0, 5), ("fe80::2", 8080, 0, 5))))

    def test_connection_lookup_failure_rejects_flow(self):
        self.connections.side_effect = l7_capture.psutil.AccessDenied()
        self.assertFalse(self.addon._belongs(flow()))

    def test_reload_failure_clears_previous_targets(self):
        self.pids.write_text("partial-write", encoding="utf-8")
        self.addon._reload()
        self.assertEqual(self.addon.pids, set())

    def test_response_without_attributed_request_is_not_logged(self):
        self.addon.response(flow())
        self.assertEqual(self.addon.out.getvalue(), "")

    def test_repeated_response_hook_writes_once(self):
        self.connections.return_value = [connection()]
        request = flow()
        self.addon.request(request)
        self.addon.response(request)
        self.addon.response(request)
        records = self.addon.out.getvalue().splitlines()
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(records[0])["url"], "http://example.test/")

    def test_running_closes_previous_output_and_done_is_idempotent(self):
        old = self.addon.out
        self.addon.running()
        self.assertTrue(old.closed)
        current = self.addon.out
        self.addon.done()
        self.addon.done()
        self.assertTrue(current.closed)
        self.assertIsNone(self.addon.out)

    def test_startup_output_error_is_reported(self):
        self.options.out_file = str(self.work)
        self.options.ready_file = str(self.work / "status.json")
        with self.assertLogs(l7_capture.__name__, level="ERROR"):
            self.addon.running()
        self.ctx.master.shutdown.assert_called_once()
        self.assertIn("error", json.loads(Path(self.options.ready_file).read_text(encoding="utf-8")))


class L7StartupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="psniff-launch-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.pids = self.work / "pids.txt"
        self.pids.write_text("123", encoding="utf-8")
        self.output = self.work / "logs" / "http.jsonl"
        self.proc = Mock()
        self.proc.poll.return_value = None
        self.proc.wait.return_value = 0
        self.popen_patch = patch.object(l7_capture.subprocess, "Popen")
        self.popen = self.popen_patch.start()
        self.addCleanup(self.popen_patch.stop)

    def publish(self, status, cmd, **kwargs):
        self.status_path = Path(next(x.split("=", 1)[1] for x in cmd if x.startswith("ready_file=")))
        self.status_path.write_text(json.dumps(status), encoding="utf-8")
        return self.proc

    def start(self, **kwargs):
        return l7_capture.run_mitmproxy(pids_file=self.pids, out_file=self.output, **kwargs)

    def test_success_requires_own_ready_status_and_binds_loopback(self):
        self.popen.side_effect = lambda cmd, **kw: self.publish({"ready": True}, cmd, **kw)
        self.assertIs(self.start(), self.proc)
        cmd = self.popen.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--listen-host") + 1], "127.0.0.1")
        self.assertTrue(self.output.parent.is_dir())
        self.assertFalse(self.status_path.exists())
        self.proc.terminate.assert_not_called()

    def test_launcher_and_addon_share_startup_protocol(self):
        addon = l7_capture.ProcL7Addon()
        self.addCleanup(addon.done)

        def launch(cmd, **kwargs):
            options = {}
            for index, arg in enumerate(cmd):
                if arg == "--set":
                    key, value = cmd[index + 1].split("=", 1)
                    options[key] = value
            ctx = SimpleNamespace(options=SimpleNamespace(**options), master=Mock())
            with patch.object(l7_capture, "ctx", ctx):
                addon.running()
            ctx.master.shutdown.assert_not_called()
            return self.proc

        self.popen.side_effect = launch
        self.assertIs(self.start(), self.proc)
        self.assertEqual(addon.pids, {123})
        self.assertFalse(addon.out.closed)

    def test_early_child_exit_is_reported(self):
        self.proc.poll.return_value = 1
        self.popen.return_value = self.proc
        with self.assertRaisesRegex(RuntimeError, "exit=1"):
            self.start()
        self.proc.terminate.assert_not_called()

    def test_initialization_error_stops_only_spawned_child(self):
        self.popen.side_effect = lambda cmd, **kw: self.publish({"error": "output denied"}, cmd, **kw)
        with self.assertRaisesRegex(RuntimeError, "output denied"):
            self.start()
        self.proc.terminate.assert_called_once()
        self.proc.wait.assert_called_once()

    def test_unacknowledged_startup_times_out_and_reaps_child(self):
        self.popen.return_value = self.proc
        with patch.object(l7_capture.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaises(TimeoutError):
                self.start(startup_timeout=1)
        self.proc.terminate.assert_called_once()
        self.proc.wait.assert_called_once()

    def test_cleanup_escalates_only_the_unresponsive_owned_child(self):
        self.popen.side_effect = lambda cmd, **kw: self.publish({"error": "startup failed"}, cmd, **kw)
        self.proc.wait.side_effect = [l7_capture.subprocess.TimeoutExpired("mitmdump", 3), 0]
        with self.assertRaisesRegex(RuntimeError, "startup failed"):
            self.start()
        self.proc.terminate.assert_called_once()
        self.proc.kill.assert_called_once()
        self.assertEqual(self.proc.wait.call_count, 2)

    def test_invalid_input_does_not_launch_child(self):
        for port in (0, 65536, True):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.start(port=port)
        self.pids.write_text("bad-pid", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.start()
        self.popen.assert_not_called()

    def test_module_registers_each_response_hook_once(self):
        from mitmproxy import addonmanager
        hooks = [getattr(addon, "response", None) for addon in addonmanager.traverse([l7_capture])]
        self.assertEqual(sum(callable(hook) for hook in hooks), 1)


if __name__ == "__main__":
    unittest.main()
