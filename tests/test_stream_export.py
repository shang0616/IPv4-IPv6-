"""Synthetic tests for TCP/UDP stream reassembly."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import (  # noqa: E402
    IP,
    IPv6,
    TCP,
    UDP,
    Raw,
    fragment,
    fragment6,
    rdpcap,
    wrpcap,
)

from stream_export import export_streams  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
