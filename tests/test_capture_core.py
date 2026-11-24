"""Offline capture lifecycle and filtering regressions; never invoke pktmon."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import IP, IPv6, PcapNgWriter, TCP, UDP, fragment, rdpcap, wrpcap
from scapy.layers.inet6 import IPv6ExtHdrFragment, fragment6

from proc_sniffer import ProcSniffer
from test_dualstack import write_etw


class CaptureCoreTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="psniff-core-test-"))
        self.addCleanup(shutil.rmtree, self.work, True)
        self.sniffer = ProcSniffer(str(self.work / "capture"))
        self.sniffer._etw_xml = self.sniffer.work_dir / "etw_network.xml"
        # Every test is offline, even if production startup or fallback changes.
        self.run = self.enterContext(patch("proc_sniffer.subprocess.run"))
        self.run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
        self.enterContext(patch.object(self.sniffer, "sample_ports", return_value=set()))
        self.enterContext(patch.object(self.sniffer, "_local_ips", return_value={"192.0.2.1", "2001:db8::1"}))
        self.enterContext(patch.object(self.sniffer, "_start_l7"))
        self.enterContext(patch("proc_sniffer.threading.Thread"))
        self.timer = self.enterContext(patch("proc_sniffer.threading.Timer"))

    def udp(self, payload=b"repeat", sport=50000, dst="198.51.100.2"):
        return IP(src="192.0.2.1", dst=dst) / UDP(sport=sport, dport=443) / payload

    def seed_etw(self, proto=42):
        write_etw(self.sniffer._etw_xml, 1234,
                  [("192.0.2.1", 50000, "198.51.100.2", 443)], event_id=proto)

    def seed_pcap(self, packets):
        wrpcap(str(self.sniffer._pcapng), packets)

    def test_capture_uses_full_packets_at_nics(self):
        self.sniffer.start_capture([1234], layers="l3")
        args = self.run.call_args.args[0]
        self.assertEqual(args[args.index("--pkt-size") + 1], "0")
        self.assertEqual(args[args.index("--comp") + 1], "nics")
        self.assertEqual(args[args.index("--type") + 1], "flow")

    def test_failed_start_cannot_stop_existing_session(self):
        def fail_start(args, **kwargs):
            # Simulate a residual/partial file despite a rejected global start.
            self.sniffer._etl.write_bytes(b"partial")
            raise subprocess.CalledProcessError(1, args)
        self.run.side_effect = fail_start
        with self.assertRaises(subprocess.CalledProcessError):
            self.sniffer.start_capture([1234], layers="l3")
        self.assertFalse(self.sniffer._running)
        self.sniffer.stop_capture()
        self.assertEqual([c.args[0][1] for c in self.run.call_args_list], ["start"])

    def test_owned_session_is_stopped_without_etl(self):
        self.sniffer.start_capture([1234], layers="l3")
        with self.assertRaisesRegex(RuntimeError, "ETL"):
            self.sniffer.stop_capture()
        self.assertEqual([c.args[0][1] for c in self.run.call_args_list], ["start", "stop"])
        with self.assertRaisesRegex(RuntimeError, "上次采集失败"):
            self.sniffer.export("example", [1234])

    def test_l7_start_failure_rolls_back_owned_pktmon(self):
        self.sniffer._start_l7.side_effect = RuntimeError("proxy failed")
        with self.assertRaisesRegex(RuntimeError, "proxy failed"):
            self.sniffer.start_capture([1234], layers="full")
        self.assertFalse(self.sniffer._running)
        self.assertEqual([c.args[0][1] for c in self.run.call_args_list], ["start", "stop"])
        self.sniffer.stop_capture()
        self.assertEqual(self.run.call_count, 2)

    def test_stop_failure_is_reported_without_converting(self):
        self.sniffer.start_capture([1234], layers="l3")
        self.sniffer._etl.write_bytes(b"trace")
        self.run.side_effect = subprocess.CalledProcessError(1, ["pktmon", "stop"])
        with patch.object(self.sniffer, "convert") as convert:
            with self.assertRaises(subprocess.CalledProcessError):
                self.sniffer.stop_capture()
            convert.assert_not_called()
        self.assertFalse(self.sniffer._running)

    def test_l7_stops_even_when_conversion_fails(self):
        self.sniffer.start_capture([1234], layers="full")
        self.sniffer._etl.write_bytes(b"trace")
        proc = self.sniffer._l7_proc = Mock()
        with patch.object(self.sniffer, "convert", side_effect=RuntimeError("bad ETL")):
            with self.assertRaisesRegex(RuntimeError, "bad ETL"):
                self.sniffer.stop_capture()
        proc.terminate.assert_called_once_with()
        self.assertIsNone(self.sniffer._l7_proc)

    def test_old_timer_cannot_stop_new_capture(self):
        self.sniffer.start_capture([1234], duration=10, layers="l7")
        timer_call = self.timer.call_args
        self.sniffer.stop_capture()
        self.timer.return_value.cancel.assert_called_once_with()
        self.sniffer.start_capture([5678], layers="l7")
        callback = timer_call.args[1]
        callback(*timer_call.kwargs.get("args", ()), **timer_call.kwargs.get("kwargs", {}))
        self.assertTrue(self.sniffer._running)
        self.assertEqual(self.sniffer.capture_pids, [5678])

    def test_invalid_layers_do_not_change_capture_state(self):
        with self.assertRaises(ValueError):
            self.sniffer.start_capture([1234], layers="typo")
        self.assertFalse(self.sniffer._running)
        self.run.assert_not_called()

    def test_capture_pids_is_an_independent_snapshot(self):
        self.sniffer.start_capture([8, 3], layers="l7")
        self.sniffer.stop_capture()
        snapshot = self.sniffer.capture_pids
        snapshot.append(99)
        self.assertEqual(self.sniffer.capture_pids, [3, 8])

    def test_missing_source_cannot_reuse_old_filtered_packets(self):
        wrpcap(str(self.sniffer._filtered), [self.udp()])
        with self.assertRaises(FileNotFoundError):
            self.sniffer.filter_by_ports({50000})
        self.assertFalse(self.sniffer._filtered.exists())

    def test_start_preparation_failure_cannot_export_old_data(self):
        wrpcap(str(self.sniffer._filtered), [self.udp()])
        with patch.object(Path, "write_text", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                self.sniffer.start_capture([1234], layers="l3")
        self.run.assert_not_called()
        self.assertFalse(self.sniffer._running)
        with self.assertRaisesRegex(RuntimeError, "上次采集失败"):
            self.sniffer.export("example", [1234])

    def test_failed_tracerpt_cannot_reuse_old_xml(self):
        self.seed_etw()
        self.sniffer._etl.write_bytes(b"trace")
        self.run.return_value = subprocess.CompletedProcess([], 1, b"", b"failed")
        self.sniffer._export_etw()
        self.assertFalse(self.sniffer._etw_xml.exists())

    def test_failed_conversion_cannot_reuse_old_pcap(self):
        self.seed_pcap([self.udp()])
        wrpcap(str(self.sniffer._filtered), [self.udp()])
        self.sniffer._etl.write_bytes(b"trace")
        self.run.side_effect = subprocess.CalledProcessError(1, ["pktmon", "etl2pcap"])
        with patch.object(self.sniffer, "_export_etw"):
            with self.assertRaises(subprocess.CalledProcessError):
                self.sniffer.convert()
        self.assertFalse(self.sniffer._pcapng.exists())
        self.assertFalse(self.sniffer._filtered.exists())

    def test_converter_success_without_output_is_an_error(self):
        self.sniffer._etl.write_bytes(b"trace")
        with patch.object(self.sniffer, "_export_etw"):
            with self.assertRaises(RuntimeError):
                self.sniffer.convert()

    def test_empty_etw_uses_port_attribution(self):
        self.sniffer._etw_xml.write_text("<Events />", encoding="utf-8")
        self.seed_pcap([self.udp()])
        self.sniffer._ports_snapshot = {50000}
        self.sniffer.filter_by_pid({1234})
        result = self.sniffer.export("example", [1234])
        self.assertEqual(result["attribution"], "port-sample")

    def test_same_udp_payload_is_not_deduplicated(self):
        self.seed_etw()
        self.seed_pcap([self.udp(), self.udp()])
        self.sniffer.filter_by_etw({1234})
        self.assertEqual(len(rdpcap(str(self.sniffer._filtered))), 2)

    def test_same_length_conflicting_tcp_payload_is_preserved(self):
        self.seed_etw(proto=10)
        base = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=50000, dport=443, seq=10)
        self.seed_pcap([base / b"first", base / b"other"])
        self.sniffer.filter_by_etw({1234})
        self.assertEqual(len(rdpcap(str(self.sniffer._filtered))), 2)

    def test_endpoint_only_match_is_not_exact(self):
        self.seed_etw()
        self.seed_pcap([self.udp(dst="203.0.113.3")])
        self.sniffer.filter_by_etw({1234})
        result = self.sniffer.export("example", [1234])
        self.assertEqual(result["attribution_counts"]["exact"], 0)
        self.assertEqual(result["attribution_counts"]["endpoint_only"], 1)

    def test_protocol_mismatch_is_not_exact(self):
        self.seed_etw(proto=10)
        self.seed_pcap([self.udp()])
        self.sniffer.filter_by_etw({1234})
        result = self.sniffer.export("example", [1234])
        self.assertEqual(result["attribution_counts"]["exact"], 0)

    def test_unknown_etw_protocol_is_not_exact(self):
        self.seed_etw(proto=None)
        self.seed_pcap([self.udp()])
        self.sniffer.filter_by_etw({1234})
        result = self.sniffer.export("example", [1234])
        self.assertEqual(result["attribution_counts"]["exact"], 0)
        self.assertEqual(result["attribution_counts"]["tuple_only"], 1)

    def test_known_other_pid_flow_does_not_enter_via_peer_fallback(self):
        self.seed_etw()
        from xml.etree import ElementTree as ET
        other = self.work / "other.xml"
        write_etw(other, 9999, [("192.0.2.1", 50001, "198.51.100.2", 443)], event_id=42)
        root = ET.parse(self.sniffer._etw_xml).getroot()
        root.extend(ET.parse(other).getroot())
        ET.ElementTree(root).write(self.sniffer._etw_xml, encoding="utf-8")
        self.seed_pcap([self.udp(sport=50001)])
        self.sniffer.filter_by_etw({1234})
        self.assertEqual(len(rdpcap(str(self.sniffer._filtered))), 0)

    def test_etw_filter_retains_out_of_order_ipv4_fragments(self):
        self.seed_etw()
        fragments = fragment(self.udp(b"fragmented-data" * 20), fragsize=64)
        self.seed_pcap(list(reversed(fragments)))
        self.sniffer.filter_by_etw({1234})
        kept = rdpcap(str(self.sniffer._filtered))
        self.assertEqual(len(kept), len(fragments))
        self.assertEqual([int(p[IP].frag) for p in kept], [int(p[IP].frag) for p in reversed(fragments)])

    def test_port_filter_retains_ipv6_fragments(self):
        packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrFragment(id=42) / UDP(sport=50000, dport=443) / (b"fragmented" * 40)
        fragments = fragment6(packet, 128)
        self.seed_pcap(list(reversed(fragments)))
        self.sniffer.filter_by_ports({50000})
        kept = rdpcap(str(self.sniffer._filtered))
        self.assertEqual(len(kept), len(fragments))

    def test_export_removes_stale_optional_copies(self):
        out = self.work / "export"
        out.mkdir()
        (out / "filtered.pcap").write_bytes(b"old")
        (out / "http_traffic.jsonl").write_bytes(b"old")
        result = self.sniffer.export("example", [1234], str(out))
        self.assertIsNone(result["pcap"])
        self.assertIsNone(result["http"])
        self.assertFalse((out / "filtered.pcap").exists())
        self.assertFalse((out / "http_traffic.jsonl").exists())

    def test_failed_stop_can_be_retried_without_new_start(self):
        self.sniffer.start_capture([1234], layers="l3")
        self.run.side_effect = subprocess.CalledProcessError(1, ["pktmon", "stop"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.sniffer.stop_capture()
        self.assertTrue(self.sniffer._pktmon_owned)
        with self.assertRaises(RuntimeError):
            self.sniffer.start_capture([5678], layers="l3")
        self.run.side_effect = None
        self.sniffer._etl.write_bytes(b"synthetic")
        with patch.object(self.sniffer, "convert", side_effect=lambda: self.seed_pcap([self.udp()])):
            self.sniffer.stop_capture()
        self.assertFalse(self.sniffer._pktmon_owned)
        self.assertIsNone(self.sniffer._capture_error)

    def test_l7_timeout_preserves_owned_process_for_retry(self):
        self.sniffer.start_capture([1234], layers="l7")
        proc = self.sniffer._l7_proc = Mock()
        proc.wait.side_effect = subprocess.TimeoutExpired("proxy", 5)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.sniffer.stop_capture()
        self.assertIs(self.sniffer._l7_proc, proc)
        proc.wait.side_effect = None
        self.sniffer.stop_capture()
        self.assertIsNone(self.sniffer._l7_proc)
        self.assertEqual(proc.terminate.call_count, 2)

    def test_export_rejects_active_capture(self):
        self.sniffer.start_capture([1234], layers="l7")
        with self.assertRaises(RuntimeError):
            self.sniffer.export("example", [1234])

    def test_export_uses_capture_pid_snapshot(self):
        self.sniffer.start_capture([1234], layers="l7")
        self.sniffer.stop_capture()
        result = self.sniffer.export("example", [9999])
        stats = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
        self.assertEqual(stats["pids"], [1234])

    def test_invalid_pid_duration_and_app_have_no_side_effects(self):
        for pids in ([], [0], [-1], [True], ["1234"]):
            with self.subTest(pids=pids), self.assertRaises(ValueError):
                self.sniffer.start_capture(pids, layers="l3")
        for duration in (-1, float("nan"), float("inf"), "30", True):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                self.sniffer.start_capture([1234], duration=duration, layers="l3")
        with patch("proc_sniffer.psutil.process_iter") as process_iter:
            with self.assertRaises(ValueError):
                self.sniffer.resolve_pids(" ")
            process_iter.assert_not_called()
        self.run.assert_not_called()

    def test_filter_preserves_raw_ip_pcapng_linktype(self):
        with PcapNgWriter(str(self.sniffer._pcapng)) as writer:
            writer.write(self.udp())
        self.sniffer.filter_by_ports({50000})
        kept = rdpcap(str(self.sniffer._filtered))
        self.assertEqual(len(kept), 1)
        self.assertTrue(IP in kept[0])
        self.assertEqual(kept[0][UDP].sport, 50000)

    def test_exact_etw_match_counts_both_directions(self):
        self.seed_etw()
        incoming = IP(src="198.51.100.2", dst="192.0.2.1") / UDP(sport=443, dport=50000) / b"reply"
        self.seed_pcap([self.udp(), incoming])
        self.sniffer.filter_by_etw({1234})
        result = self.sniffer.export("example", [1234])
        self.assertEqual(result["attribution_counts"]["exact"], 2)
        self.assertEqual(sum(result["attribution_counts"].values()), result["packet_count"])

    def test_fragment_export_counts_all_raw_fragments(self):
        fragments = fragment(self.udp(b"payload" * 50), fragsize=64)
        self.seed_pcap(list(reversed(fragments)))
        self.sniffer.filter_by_ports({50000})
        result = self.sniffer.export("example", [1234])
        stats = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
        self.assertEqual(stats["connections"][0]["packets"], len(fragments))
        self.assertEqual(stats["packet_count"], len(fragments))

    def test_filter_preserves_mixed_raw_ip_pcapng(self):
        packets = [self.udp(), IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=50000, dport=443) / b"v6"]
        with PcapNgWriter(str(self.sniffer._pcapng)) as writer:
            writer.write_header(packets[0])
            for index, packet in enumerate(packets):
                packet.sniffed_on = f"synthetic-{index}"
                writer.write_packet(packet)
        self.sniffer.filter_by_ports({50000})
        kept = rdpcap(str(self.sniffer._filtered))
        self.assertEqual(len(kept), 2)
        self.assertTrue(IP in kept[0])
        self.assertTrue(IPv6 in kept[1])

    def test_malformed_etw_falls_back_without_stale_precision(self):
        self.seed_etw()
        self.seed_pcap([self.udp()])
        self.sniffer.filter_by_etw({1234})
        self.sniffer._etw_xml.write_text("<Events><broken>", encoding="utf-8")
        self.sniffer._ports_snapshot = {50000}
        self.sniffer.filter_by_pid({1234})
        result = self.sniffer.export("example", [1234])
        self.assertEqual(result["attribution"], "port-sample")
        self.assertEqual(result["attribution_counts"]["exact"], 0)
        self.assertEqual(result["attribution_counts"]["port_sample"], 1)

    def test_fragment_id_conflict_does_not_mix_process_flows(self):
        first = fragment(self.udp(b"a" * 200), fragsize=64)
        second = fragment(self.udp(b"b" * 200, sport=50001), fragsize=64)
        self.seed_pcap(first + second)
        self.sniffer.filter_by_ports({50000})
        self.assertEqual(len(rdpcap(str(self.sniffer._filtered))), 0)

    def test_cli_help_and_invalid_arguments_never_start_capture(self):
        import contextlib
        import io
        import runpy
        for argv, expected in ((["--help"], 0), (["example", "-1", "l3"], 2), (["example", "30", "invalid"], 2)):
            with self.subTest(argv=argv), patch.object(sys, "argv", ["proc_sniffer.py", *argv]):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as stopped:
                        runpy.run_path(str(ROOT / "proc_sniffer.py"), run_name="__main__")
                self.assertEqual(stopped.exception.code, expected)
        self.run.assert_not_called()

    def test_export_rejects_unsafe_default_directory_names(self):
        # The absolute-path probe also points inside this test's temp directory.
        for name in ("..", "../escape", "sub/dir", "sub\\dir", str(self.work / "absolute"), "CON", "name."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.sniffer.export(name, [1234])


if __name__ == "__main__":
    unittest.main()
