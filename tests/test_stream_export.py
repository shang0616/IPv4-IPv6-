"""Synthetic tests for TCP/UDP stream reassembly."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import (  # noqa: E402
    Ether,
    IP,
    IPv6,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    TCP,
    UDP,
    Raw,
    fragment,
    fragment6,
    rdpcap,
    wrpcap,
)

from stream_export import _tcp_direction, export_streams  # noqa: E402


class StreamExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="psniff-stream-"))
        self.addCleanup(shutil.rmtree, self.work, True)

    def _export(self, packets: list):
        pcap = self.work / "in.pcap"
        wrpcap(str(pcap), packets)
        return export_streams(rdpcap(str(pcap)), self.work / "streams")

    def test_tcp_out_of_order_retransmission_and_fin(self) -> None:
        client, server = ("10.0.0.1", 12345), ("10.0.0.2", 443)
        packets = [
            IP(src=client[0], dst=server[0])
            / TCP(sport=client[1], dport=server[1], flags="S", seq=1000),
            # Out of order: second half arrives before first half.
            IP(src=client[0], dst=server[0])
            / TCP(sport=client[1], dport=server[1], flags="PA", seq=1006)
            / Raw(b"World"),
            IP(src=client[0], dst=server[0])
            / TCP(sport=client[1], dport=server[1], flags="PA", seq=1001)
            / Raw(b"Hello"),
            # Retransmission must not duplicate bytes.
            IP(src=client[0], dst=server[0])
            / TCP(sport=client[1], dport=server[1], flags="PA", seq=1001)
            / Raw(b"Hello"),
            IP(src=client[0], dst=server[0])
            / TCP(sport=client[1], dport=server[1], flags="FA", seq=1011),
            IP(src=server[0], dst=client[0])
            / TCP(sport=server[1], dport=client[1], flags="SA", seq=5000),
            IP(src=server[0], dst=client[0])
            / TCP(sport=server[1], dport=client[1], flags="PA", seq=5001)
            / Raw(b"OK"),
            IP(src=server[0], dst=client[0])
            / TCP(sport=server[1], dport=client[1], flags="FA", seq=5003),
        ]
        info = self._export(packets)
        self.assertEqual(info["flows"], 1)
        self.assertEqual(info["tcp_streams"], 2)
        index = json.loads((self.work / "streams" / "index.json").read_text())
        flow = index["flows"][0]
        self.assertEqual(flow["proto"], "TCP")
        dirs = {d["from"]["port"]: d for d in flow["directions"]}
        client_dir = dirs[12345]
        server_dir = dirs[443]
        self.assertEqual((self.work / "streams" / client_dir["file"]).read_bytes(), b"HelloWorld")
        self.assertEqual((self.work / "streams" / server_dir["file"]).read_bytes(), b"OK")
        self.assertEqual(client_dir["gaps"], [])
        self.assertEqual(server_dir["gaps"], [])
        self.assertTrue(client_dir["complete"])
        self.assertTrue(server_dir["complete"])
        self.assertGreaterEqual(client_dir["retransmissions"], 1)

    def test_tcp_gap_is_reported_and_zero_filled(self) -> None:
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1000, dport=2000, flags="S", seq=100),
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1000, dport=2000, flags="PA", seq=101)
            / Raw(b"AB"),
            # Leave a hole at offsets 2..4, then continue.
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1000, dport=2000, flags="PA", seq=105)
            / Raw(b"EF"),
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1000, dport=2000, flags="FA", seq=107),
        ]
        info = self._export(packets)
        index = json.loads((self.work / "streams" / "index.json").read_text())
        direction = index["flows"][0]["directions"][0]
        self.assertEqual(direction["gaps"], [[2, 2]])
        self.assertFalse(direction["gap_free"])
        self.assertFalse(direction["complete"])
        data = (self.work / "streams" / direction["file"]).read_bytes()
        self.assertEqual(data, b"AB\x00\x00EF")

    def test_ipv4_and_ipv6_fragmented_udp_are_reassembled(self) -> None:
        ipv4 = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(
            sport=1111, dport=2222
        ) / Raw(b"A" * 3000)
        ipv6 = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(
            sport=3333, dport=4444
        ) / Raw(b"B" * 3000)

        for packets, expected_port in (
            (fragment(ipv4, fragsize=1200), 1111),
            (fragment6(ipv6, 1200), 3333),
        ):
            info = self._export(packets)
            self.assertEqual(info["udp_flows"], 1)
            index = json.loads((self.work / "streams" / "index.json").read_text())
            flow = index["flows"][0]
            self.assertEqual(flow["directions"][0]["from"]["port"], expected_port)
            self.assertEqual(flow["datagrams"], 1)
            record = json.loads(
                (self.work / "streams" / flow["jsonl"]).read_text().splitlines()[0]
            )
            self.assertEqual(record["length"], 3000)

    def test_udp_datagrams_keep_boundaries(self) -> None:
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=3000, dport=4000)
            / Raw(b"one"),
            IP(src="10.0.0.2", dst="10.0.0.1")
            / UDP(sport=4000, dport=3000)
            / Raw(b"reply"),
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=3000, dport=4000)
            / Raw(b"two"),
        ]
        info = self._export(packets)
        self.assertEqual(info["udp_flows"], 1)
        self.assertEqual(info["udp_streams"], 2)
        index = json.loads((self.work / "streams" / "index.json").read_text())
        flow = index["flows"][0]
        self.assertEqual(flow["datagrams"], 3)
        lines = (self.work / "streams" / flow["jsonl"]).read_text().splitlines()
        self.assertEqual(len(lines), 3)
        records = [json.loads(line) for line in lines]
        self.assertEqual([r["length"] for r in records], [3, 5, 3])
        self.assertEqual(
            [r["payload_b64"] for r in records],
            ["b25l", "cmVwbHk=", "dHdv"],
        )
        self.assertEqual([r["offset"] for r in records], [0, 0, 3])
        self.assertEqual((self.work / "streams" / flow["directions"][0]["file"]).read_bytes(), b"onetwo")
        self.assertEqual((self.work / "streams" / flow["directions"][1]["file"]).read_bytes(), b"reply")

    def _tcp(self, seq, payload=b"", flags="PA"):
        return (IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=1000, dport=2000, seq=seq, flags=flags)
                / Raw(payload))

    def _direction(self, packets):
        self._export(packets)
        index = json.loads((self.work / "streams" / "index.json").read_text())
        direction = index["flows"][0]["directions"][0]
        data = ((self.work / "streams" / direction["file"]).read_bytes()
                if direction["file"] else b"")
        return direction, data

    def test_tcp_truncated_pcap_preserves_declared_missing_tail(self) -> None:
        # The captured bytes end early, while IP.len still advertises six bytes.
        truncated = IP(bytes(self._tcp(101, b"ABCDEF"))[:-3])
        truncated.wirelen = 46
        direction, data = self._direction([self._tcp(100, flags="S"), truncated])
        self.assertEqual(data, b"ABC\x00\x00\x00")
        self.assertEqual(direction["gaps"], [[3, 3]])
        self.assertFalse(direction["complete"])

    def test_tcp_truncated_options_are_not_counted_as_application_bytes(self) -> None:
        packet = self._tcp(101, b"ABCDEF")
        packet[TCP].options = [("Timestamp", (1, 2))]
        truncated = IP(bytes(packet)[:-9])  # six payload bytes and three option bytes
        direction, data = self._direction([
            self._tcp(100, flags="S"), truncated, self._tcp(107, flags="FA"),
        ])
        self.assertEqual(data, b"\0" * 6)
        self.assertEqual(direction["gaps"], [[0, 6]])
        self.assertFalse(direction["complete"])
        self.assertEqual(direction["invalid_length_packets"], 1)

    def test_tcp_fin_reveals_missing_tail_and_whole_payload(self) -> None:
        for packets, expected, gaps in (
            ([self._tcp(100, flags="S"), self._tcp(101, b"AB"),
              self._tcp(107, flags="FA")], b"AB" + b"\0" * 4, [[2, 4]]),
            ([self._tcp(100, flags="S"), self._tcp(105, flags="FA")],
             b"\0" * 4, [[0, 4]]),
        ):
            with self.subTest(gaps=gaps):
                direction, data = self._direction(packets)
                self.assertEqual(data, expected)
                self.assertEqual(direction["gaps"], gaps)
                self.assertFalse(direction["complete"])

    def test_tcp_retransmission_can_repair_capture_truncation(self) -> None:
        truncated = IP(bytes(self._tcp(101, b"ABCDEF"))[:-3])
        direction, data = self._direction([
            self._tcp(100, flags="S"), truncated, self._tcp(101, b"ABCDEF"),
            self._tcp(107, flags="FA"),
        ])
        self.assertEqual(data, b"ABCDEF")
        self.assertEqual(direction["gaps"], [])
        self.assertTrue(direction["complete"])

    def test_tcp_overlap_prefers_capture_order_and_counts_segments(self) -> None:
        packets = [self._tcp(100, flags="S"), self._tcp(103, b"CD"),
                   self._tcp(101, b"abxyEF"), self._tcp(107, flags="FA")]
        # Timestamps may go backwards; pcap record order defines first-seen.
        packets[1].time = 20
        packets[2].time = 10
        direction, data = self._direction(packets)
        self.assertEqual(data, b"abCDEF")
        self.assertEqual(direction["conflicting_segments"], 1)
        self.assertFalse(direction["complete"])

    def test_tcp_midstream_wraparound_preserves_both_sides(self) -> None:
        for packets in (
            [self._tcp(0xFFFFFFFC, b"ABCD"), self._tcp(0, b"EFGH")],
            [self._tcp(0, b"EFGH"), self._tcp(0xFFFFFFFC, b"ABCD")],
        ):
            with self.subTest(first_seq=packets[0][TCP].seq):
                direction, data = self._direction(packets)
                self.assertEqual(data, b"ABCDEFGH")
                self.assertEqual(direction["gaps"], [])
                self.assertFalse(direction["complete"])

    def test_tcp_syn_wrap_and_fin_with_payload(self) -> None:
        direction, data = self._direction([
            self._tcp(0xFFFFFFFE, flags="S"), self._tcp(0xFFFFFFFF, b"AB"),
            self._tcp(1, b"CD", flags="FA"),
        ])
        self.assertEqual(data, b"ABCD")
        self.assertTrue(direction["complete"])

    def test_tcp_rst_does_not_certify_complete_delivery(self) -> None:
        direction, data = self._direction([
            self._tcp(100, flags="S"), self._tcp(101, b"AB"),
            self._tcp(999, flags="R"),
        ])
        self.assertEqual(data, b"AB")
        self.assertFalse(direction["complete"])

    def test_tcp_tuple_reuse_creates_separate_connections(self) -> None:
        self._export([
            self._tcp(100, flags="S"), self._tcp(100, flags="S"),
            self._tcp(101, b"old"), self._tcp(104, flags="FA"),
            self._tcp(500, flags="S"), self._tcp(501, b"new"),
            self._tcp(504, flags="FA"),
        ])
        index = json.loads((self.work / "streams" / "index.json").read_text())
        self.assertEqual(len(index["flows"]), 2)
        self.assertEqual([
            (self.work / "streams" / f["directions"][0]["file"]).read_bytes()
            for f in index["flows"]
        ], [b"old", b"new"])

    def test_tcp_same_isn_reuse_after_close_is_separate(self) -> None:
        self._export([
            self._tcp(100, flags="S"), self._tcp(101, b"old"),
            self._tcp(104, flags="FA"), self._tcp(100, flags="S"),
            self._tcp(101, b"new"), self._tcp(104, flags="FA"),
        ])
        index = json.loads((self.work / "streams" / "index.json").read_text())
        self.assertEqual(len(index["flows"]), 2)

    def test_tcp_limit_applies_to_export_and_tail_gap(self) -> None:
        with patch("stream_export.MAX_STREAM_BYTES", 4):
            direction, data = self._direction([
                self._tcp(100, flags="S"), self._tcp(101, b"AB"),
                self._tcp(110, flags="FA"),
            ])
        self.assertEqual(data, b"AB\0\0")
        self.assertEqual(direction["gaps"], [[2, 2]])
        self.assertTrue(direction["truncated"])
        self.assertFalse(direction["complete"])

    def test_tcp_limit_exact_and_zero(self) -> None:
        segments = [
            {"seq": 100, "payload": b"", "syn": True, "fin": False, "rst": False,
             "index": 0, "ts": 0},
            {"seq": 101, "payload": b"ABCD", "syn": False, "fin": True,
             "rst": False, "index": 1, "ts": 1},
        ]
        exact = _tcp_direction(segments, max_bytes=4)
        self.assertEqual(exact["data"], b"ABCD")
        self.assertTrue(exact["complete"])
        limited = _tcp_direction(segments, max_bytes=0)
        self.assertEqual(limited["data"], b"")
        self.assertTrue(limited["truncated"])
        self.assertFalse(limited["complete"])

    def test_incomplete_fragment_sets_do_not_invent_datagrams(self) -> None:
        for family in (IP(src="10.0.0.1", dst="10.0.0.2"),
                       IPv6(src="2001:db8::1", dst="2001:db8::2")):
            packet = family / UDP(sport=1111, dport=2222) / Raw(b"A" * 3000)
            fragments = (fragment(packet, fragsize=1200) if IP in packet
                         else fragment6(packet, 1200))
            for selected in (fragments[1:], fragments[:-1],
                             [fragments[0], fragments[-1]]):
                with self.subTest(family=family.name, offsets=len(selected)):
                    self._export(selected)
                    index = json.loads((self.work / "streams" / "index.json").read_text())
                    self.assertEqual(index["flows"], [])
                    self.assertEqual(index["discarded_fragment_packets"], len(selected))

    def test_fragments_reassemble_out_of_order(self) -> None:
        for family in (IP(src="10.0.0.1", dst="10.0.0.2"),
                       IPv6(src="2001:db8::1", dst="2001:db8::2"),
                       IPv6(src="2001:db8::1", dst="2001:db8::2")
                       / IPv6ExtHdrHopByHop()):
            packet = family / UDP(sport=1111, dport=2222) / Raw(b"A" * 3000)
            fragments = (fragment(packet, fragsize=1200) if IP in packet
                         else fragment6(packet, 1200))
            with self.subTest(family=family.summary()):
                direction, data = self._direction(list(reversed(fragments)))
                self.assertEqual(data, b"A" * 3000)

    def test_truncated_fragment_is_not_concatenated_over_missing_bytes(self) -> None:
        for family in (IP(src="10.0.0.1", dst="10.0.0.2"),
                       IPv6(src="2001:db8::1", dst="2001:db8::2")):
            packet = family / UDP(sport=1111, dport=2222) / Raw(b"A" * 3000)
            fragments = (fragment(packet, fragsize=1200) if IP in packet
                         else fragment6(packet, 1200))
            fragments[0] = family.__class__(bytes(fragments[0])[:-20])
            with self.subTest(family=family.name):
                info = self._export(fragments)
                self.assertEqual(info["udp_flows"], 0)

    def test_overlapping_fragments_are_not_emitted(self) -> None:
        for family in (IP(src="10.0.0.1", dst="10.0.0.2"),
                       IPv6(src="2001:db8::1", dst="2001:db8::2")):
            packet = family / UDP(sport=1111, dport=2222) / Raw(b"A" * 3000)
            fragments = (fragment(packet, fragsize=1200) if IP in packet
                         else fragment6(packet, 1200))
            conflict_bytes = bytes(fragments[0])[:-1] + b"B"
            conflicting = family.__class__(conflict_bytes)
            with self.subTest(family=family.name):
                info = self._export([fragments[0], conflicting] + fragments[1:])
                self.assertEqual(info["udp_flows"], 0)

    def test_identical_fragment_copies_reassemble_once(self) -> None:
        for family in (IP(src="10.0.0.1", dst="10.0.0.2"),
                       IPv6(src="2001:db8::1", dst="2001:db8::2")):
            packet = family / UDP(sport=1111, dport=2222) / Raw(b"A" * 3000)
            fragments = (fragment(packet, fragsize=1200) if IP in packet
                         else fragment6(packet, 1200))
            with self.subTest(family=family.name):
                direction, data = self._direction([p for p in fragments for _ in range(6)])
                self.assertEqual(direction["datagrams"], 1)
                self.assertEqual(data, b"A" * 3000)

    def test_udp_duplicate_datagrams_preserve_capture_order(self) -> None:
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1111, dport=2222)
        packets = [packet / Raw(b"same"), packet / Raw(b"same"), packet / Raw(b"tail")]
        for time, pkt in zip((30, 20, 10), packets):
            pkt.time = time
        direction, data = self._direction(packets)
        self.assertEqual(direction["datagrams"], 3)
        self.assertEqual(data, b"samesametail")
        self.assertTrue(direction["complete"])

    def test_udp_truncation_is_explicit_without_fake_bytes(self) -> None:
        for family in (IP(src="10.0.0.1", dst="10.0.0.2"),
                       IPv6(src="2001:db8::1", dst="2001:db8::2")):
            packet = family / UDP(sport=1111, dport=2222) / Raw(b"ABCDEF")
            truncated = family.__class__(bytes(packet)[:-3])
            with self.subTest(family=family.name):
                direction, data = self._direction([truncated])
                self.assertEqual(data, b"ABC")
                self.assertFalse(direction["complete"])
                self.assertTrue(direction["truncated"])
                index = json.loads((self.work / "streams" / "index.json").read_text())
                record = json.loads((self.work / "streams" / index["flows"][0]["jsonl"]).read_text())
                self.assertEqual(record["declared_length"], 6)
                self.assertEqual(record["missing_bytes"], 3)
                self.assertFalse(record["complete"])

    def test_link_padding_does_not_fill_truncated_ipv6_tcp_tail(self) -> None:
        packet = (Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2")
                  / IPv6ExtHdrHopByHop()
                  / TCP(sport=1111, dport=2222, seq=101, flags="PA")
                  / Raw(b"ABCDEF"))
        padded = Ether(bytes(packet) + b"\0" * 20)
        direction, data = self._direction([padded])
        self.assertEqual(data, b"ABCDEF")
        self.assertEqual(direction["gaps"], [])
        truncated = Ether(bytes(packet)[:-3])
        direction, data = self._direction([truncated])
        self.assertEqual(data, b"ABC\0\0\0")
        self.assertEqual(direction["gaps"], [[3, 3]])

    def test_ipv6_atomic_fragments_keep_duplicate_datagrams(self) -> None:
        packet = (IPv6(src="2001:db8::1", dst="2001:db8::2")
                  / IPv6ExtHdrFragment(id=123, offset=0, m=0)
                  / UDP(sport=1111, dport=2222) / Raw(b"same"))
        direction, data = self._direction([packet, packet])
        self.assertEqual(data, b"samesame")
        self.assertEqual(direction["datagrams"], 2)

    def test_tcp_contradictory_fin_boundary_prevents_complete(self) -> None:
        direction, data = self._direction([
            self._tcp(100, flags="S"), self._tcp(101, b"ABCDEF"),
            self._tcp(104, flags="FA"),
        ])
        self.assertEqual(data, b"ABCDEF")
        self.assertFalse(direction["complete"])

    def test_udp_limit_bounds_binary_and_jsonl_payloads(self) -> None:
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1111, dport=2222)
        with patch("stream_export.MAX_STREAM_BYTES", 4):
            direction, data = self._direction([packet / Raw(b"ABC"), packet / Raw(b"DEF")])
        self.assertEqual(data, b"ABCD")
        self.assertTrue(direction["truncated"])
        self.assertFalse(direction["complete"])
        index = json.loads((self.work / "streams" / "index.json").read_text())
        records = [json.loads(line) for line in
                   (self.work / "streams" / index["flows"][0]["jsonl"]).read_text().splitlines()]
        self.assertEqual([r["length"] for r in records], [3, 1])
        self.assertEqual(records[1]["captured_length"], 3)
        self.assertTrue(records[1]["truncated"])

    def test_output_cleanup_preserves_unrelated_files_and_directories(self) -> None:
        out = self.work / "streams"
        out.mkdir()
        (out / "notes.txt").write_text("keep me")
        (out / "capture.pcap").write_bytes(b"evidence")
        (out / "archive").mkdir()
        (out / "archive" / "flow-0001-a.tcp.bin").write_bytes(b"archived")
        (out / "flow-9999-a.tcp.bin").write_bytes(b"stale generated bytes")
        export_streams([], out)
        self.assertEqual((out / "notes.txt").read_text(), "keep me")
        self.assertEqual((out / "capture.pcap").read_bytes(), b"evidence")
        self.assertTrue((out / "archive" / "flow-0001-a.tcp.bin").exists())
        self.assertFalse((out / "flow-9999-a.tcp.bin").exists())

    def test_output_rejects_regular_file_without_deleting_it(self) -> None:
        out = self.work / "user-data"
        out.write_bytes(b"important")
        with self.assertRaises(ValueError):
            export_streams([], out)
        self.assertEqual(out.read_bytes(), b"important")

    def test_output_rejects_link_directory(self) -> None:
        # Windows symlink creation may require privilege; mock only link detection.
        out = self.work / "streams"
        out.mkdir()
        (out / "notes.txt").write_text("keep me")
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaises(ValueError):
                export_streams([], out)
        self.assertEqual((out / "notes.txt").read_text(), "keep me")


if __name__ == "__main__":
    unittest.main()
