"""Synthetic IPv4/IPv6 filtering tests; no packet capture or admin required."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, IP, IPv6, TCP, UDP, rdpcap, wrpcap  # noqa: E402

from proc_sniffer import ProcSniffer, _norm_ip  # noqa: E402

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
PROVIDER = "Microsoft-Windows-Kernel-Network"


def write_etw(path: Path, pid: int, tuples: list[tuple[str, int, str, int]],
              event_id: int | None = 10) -> None:
    root = ET.Element("Events")
    for saddr, sport, daddr, dport in tuples:
        event = ET.SubElement(root, f"{{{EVENT_NS}}}Event")
        system = ET.SubElement(event, f"{{{EVENT_NS}}}System")
        ET.SubElement(system, f"{{{EVENT_NS}}}Provider", {"Name": PROVIDER})
        if event_id is not None:
            ET.SubElement(system, f"{{{EVENT_NS}}}EventID").text = str(event_id)
        data = ET.SubElement(event, f"{{{EVENT_NS}}}EventData")
        for name, value in (
            ("PID", str(pid)),
            ("saddr", saddr),
            ("sport", str(sport)),
            ("daddr", daddr),
            ("dport", str(dport)),
        ):
            ET.SubElement(data, f"{{{EVENT_NS}}}Data", {"Name": name}).text = value
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


class DualStackFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="psniff-test-"))
        self.addCleanup(shutil.rmtree, self.work, True)

    def make_sniffer(self, name: str) -> ProcSniffer:
        sniffer = ProcSniffer(work_dir=str(self.work / name))
        sniffer._pcapng = self.work / name / "capture.pcapng"
        sniffer._filtered = self.work / name / "filtered.pcap"
        sniffer._etw_xml = self.work / name / "etw_network.xml"
        return sniffer

    def test_normalize_address_forms(self) -> None:
        self.assertEqual(_norm_ip("fe80::1%12"), "fe80::1")
        self.assertEqual(_norm_ip("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(_norm_ip("::ffff:192.0.2.5"), "192.0.2.5")
        self.assertEqual(_norm_ip("2001:0db8:0:0::1"), "2001:db8::1")
        self.assertIsNone(_norm_ip("not-an-ip"))

    def test_ipv6_udp_port_fallback(self) -> None:
        sniffer = self.make_sniffer("udp")
        wrpcap(
            str(sniffer._pcapng),
            [IPv6(src="::1", dst="2001:db8::3") / UDP(sport=7777, dport=9999) / b"x"],
        )
        sniffer.filter_by_ports({9999})
        packets = rdpcap(str(sniffer._filtered))
        self.assertEqual(len(packets), 1)
        self.assertIsNotNone(packets[0].getlayer(IPv6))

    def test_ipv6_etw_join_and_export(self) -> None:
        sniffer = self.make_sniffer("v6")
        write_etw(
            sniffer._etw_xml,
            1234,
            [("::1", 5555, "2001:db8::2", 443)],
        )
        wrpcap(
            str(sniffer._pcapng),
            [
                IPv6(src="::1", dst="2001:db8::2")
                / TCP(sport=5555, dport=443, flags="S", seq=1),
                IPv6(src="2001:db8::2", dst="::1")
                / TCP(sport=443, dport=5555, flags="SA", seq=10, ack=2),
                IPv6(src="2001:db8::9", dst="::1")
                / UDP(sport=443, dport=6666)
                / b"unrelated",
            ],
        )
        sniffer.filter_by_etw({1234})
        packets = rdpcap(str(sniffer._filtered))
        self.assertEqual(len(packets), 2)
        self.assertTrue(all(pkt.getlayer(IPv6) is not None for pkt in packets))

        result = sniffer.export("v6", [1234], out_dir=str(self.work / "v6-out"))
        self.assertEqual(result["ipv6_connections"], 2)
        self.assertEqual(result["ipv4_connections"], 0)
        stats = json.loads(
            (self.work / "v6-out" / "requests.json").read_text(encoding="utf-8")
        )
        self.assertTrue(stats["connections"])
        self.assertTrue(all(c["ip_version"] == 6 for c in stats["connections"]))
        self.assertIn("IPv6", (self.work / "v6-out" / "index.md").read_text(encoding="utf-8"))

    def test_mixed_family_export(self) -> None:
        sniffer = self.make_sniffer("mixed")
        write_etw(
            sniffer._etw_xml,
            9999,
            [
                ("127.0.0.1", 5555, "198.51.100.10", 80),
                ("::1", 6666, "2001:db8::2", 443),
            ],
        )
        wrpcap(
            str(sniffer._pcapng),
            [
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                / IP(src="127.0.0.1", dst="198.51.100.10")
                / TCP(sport=5555, dport=80, flags="S", seq=1),
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                / IPv6(src="::1", dst="2001:db8::2")
                / TCP(sport=6666, dport=443, flags="S", seq=1),
            ],
        )
        sniffer.filter_by_etw({9999})
        result = sniffer.export("mixed", [9999], out_dir=str(self.work / "mixed-out"))
        self.assertEqual(result["ipv4_connections"], 1)
        self.assertEqual(result["ipv6_connections"], 1)
        stats = json.loads(
            (self.work / "mixed-out" / "requests.json").read_text(encoding="utf-8")
        )
        self.assertEqual({c["ip_version"] for c in stats["connections"]}, {4, 6})

    def test_ipv4_regression(self) -> None:
        sniffer = self.make_sniffer("v4")
        write_etw(
            sniffer._etw_xml,
            4321,
            [("127.0.0.1", 5555, "198.51.100.10", 80)],
        )
        wrpcap(
            str(sniffer._pcapng),
            [
                IP(src="127.0.0.1", dst="198.51.100.10")
                / TCP(sport=5555, dport=80, flags="S", seq=1),
                IP(src="198.51.100.10", dst="127.0.0.1")
                / TCP(sport=80, dport=5555, flags="SA", seq=10, ack=2),
            ],
        )
        sniffer.filter_by_etw({4321})
        result = sniffer.export("v4", [4321], out_dir=str(self.work / "v4-out"))
        self.assertEqual(result["ipv4_connections"], 2)
        self.assertEqual(result["ipv6_connections"], 0)
        stats = json.loads(
            (self.work / "v4-out" / "requests.json").read_text(encoding="utf-8")
        )
        self.assertTrue(all(c["ip_version"] == 4 for c in stats["connections"]))


if __name__ == "__main__":
    unittest.main()
