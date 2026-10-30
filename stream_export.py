"""Reassemble TCP byte streams and UDP datagram flows from filtered packets.

Output layout (under exports/<app>/streams/):

  index.json                 flow metadata, gaps and file names
  flow-0001-a.tcp.bin        one direction of a TCP byte stream
  flow-0002-a.udp.bin        one direction of a UDP payload concatenation
  flow-0002.udp.jsonl        every UDP datagram, preserving boundaries

TCP data is ordered by sequence number and retransmissions are removed. If
bytes are missing, the .bin file is zero-filled and the gap is listed in
index.json. UDP has no sequence numbers; capture order is preserved.
"""
from __future__ import annotations

import base64
import json
import shutil
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP, UDP, defragment
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, defragment6
from scapy.packet import Padding

MAX_STREAM_BYTES = 128 * 1024 * 1024
SEQ_MOD = 1 << 32
SEQ_HALF = 1 << 31


def _ip_layer(pkt):
    if IP in pkt:
        return pkt[IP]
    if IPv6 in pkt:
        return pkt[IPv6]
    return None


def _l4_layer(pkt):
    if TCP in pkt:
        return pkt[TCP]
    if UDP in pkt:
        return pkt[UDP]
    return None


def _payload(l4) -> bytes:
    """Return the L4 payload without Ethernet padding."""
    if l4.payload is None:
        return b""
    data = bytes(l4.payload)
    pad = l4.payload.getlayer(Padding)
    if pad is not None:
        pad_len = len(bytes(pad))
        if pad_len:
            data = data[:-pad_len]
    return data


def _reassemble_fragments(packets: list) -> list:
    """Best-effort IPv4/IPv6 fragment reassembly before flow grouping."""
    packets = list(packets)
    if any(IP in p and (p[IP].flags.MF or int(p[IP].frag) > 0) for p in packets):
        try:
            packets = list(defragment(packets))
        except Exception:
            pass

    groups: dict[tuple, list[tuple[int, Any]]] = defaultdict(list)
    rest: list[tuple[int, Any]] = []
    for i, pkt in enumerate(packets):
        if IPv6 in pkt and IPv6ExtHdrFragment in pkt:
            frag = pkt[IPv6ExtHdrFragment]
            key = (pkt[IPv6].src, pkt[IPv6].dst, int(frag.id))
            groups[key].append((i, pkt))
        else:
            rest.append((i, pkt))

    if groups:
        for items in groups.values():
            try:
                whole = defragment6([p for _, p in items])
            except Exception:
                rest.extend(items)
                continue
            if whole is None:
                rest.extend(items)
            else:
                rest.append((min(i for i, _ in items), whole))
        rest.sort(key=lambda item: item[0])

    return [pkt for _, pkt in rest]


def _signed_delta(value: int, base: int) -> int:
    delta = (value - base) & (SEQ_MOD - 1)
    return delta - SEQ_MOD if delta & SEQ_HALF else delta


def _tcp_direction(segments: list[dict], max_bytes: int = MAX_STREAM_BYTES) -> dict:
    """Reassemble one direction of a TCP connection."""
    payload_segments = [s for s in segments if s["payload"]]
    syn_segments = [s for s in segments if s["syn"]]
    saw_syn = bool(syn_segments)
    saw_fin = any(s["fin"] for s in segments)
    saw_rst = any(s["rst"] for s in segments)

    if syn_segments:
        # The first SYN in capture order defines the initial sequence number.
        syn = min(syn_segments, key=lambda s: (s["ts"], s["index"]))
        base = (syn["seq"] + 1) & (SEQ_MOD - 1)
    elif payload_segments:
        base = min(s["seq"] for s in payload_segments)
    else:
        return {
            "data": b"",
            "segments": 0,
            "packets": len(segments),
            "gaps": [],
            "gap_free": True,
            "complete": False,
            "truncated": False,
            "retransmissions": 0,
            "conflicting_segments": 0,
            "saw_syn": saw_syn,
            "saw_fin": saw_fin,
            "saw_rst": saw_rst,
        }

    normalized = []
    for seg in payload_segments:
        seq = seg["seq"] + 1 if seg["syn"] else seg["seq"]
        rel = _signed_delta(seq & (SEQ_MOD - 1), base)
        if rel < 0:
            # Data before the chosen SYN/base cannot be part of this stream.
            continue
        normalized.append((rel, seg))
    normalized.sort(key=lambda item: (item[0], item[1]["ts"], item[1]["index"]))

    end_max = max((rel + len(seg["payload"]) for rel, seg in normalized), default=0)
    truncated = end_max > max_bytes
    if truncated:
        end_max = max_bytes

    buf = bytearray(end_max)
    covered = bytearray(end_max)
    retransmissions = 0
    conflicts = 0

    for rel, seg in normalized:
        data = seg["payload"]
        if rel >= end_max:
            continue
        end = min(rel + len(data), end_max)
        data = data[:end - rel]
        if not data:
            continue
        missing = covered.count(0, rel, end)
        if missing == end - rel:
            buf[rel:end] = data
            covered[rel:end] = b"\x01" * (end - rel)
        elif missing == 0:
            retransmissions += 1
            if bytes(buf[rel:end]) != data:
                conflicts += 1
        else:
            # Partially overlapping/retransmitted segment.
            for offset, value in enumerate(data):
                pos = rel + offset
                if covered[pos]:
                    if buf[pos] != value:
                        conflicts += 1
                else:
                    buf[pos] = value
                    covered[pos] = 1

    gaps = []
    pos = 0
    while pos < end_max:
        if covered[pos]:
            pos += 1
            continue
        start = pos
        while pos < end_max and not covered[pos]:
            pos += 1
        gaps.append([start, pos - start])

    gap_free = not gaps
    complete = bool(saw_syn and (saw_fin or saw_rst) and gap_free and not truncated)
    return {
        "data": bytes(buf),
        "segments": len(normalized),
        "packets": len(segments),
        "gaps": gaps,
        "gap_free": gap_free,
        "complete": complete,
        "truncated": truncated,
        "retransmissions": retransmissions,
        "conflicting_segments": conflicts,
        "saw_syn": saw_syn,
        "saw_fin": saw_fin,
        "saw_rst": saw_rst,
    }


def _endpoint(ip: str, port: int) -> dict:
    return {"ip": ip, "port": port}


def _flow_key(src: tuple[str, int], dst: tuple[str, int], version: int, proto: str):
    a, b = (src, dst) if src <= dst else (dst, src)
    return (version, a, b, proto)


def export_streams(packets: list, out_dir: str | Path) -> dict:
    """Write reassembled streams and their metadata to *out_dir*."""
    out = Path(out_dir)
    if out.is_dir():
        shutil.rmtree(out)
    elif out.exists():
        out.unlink()
    out.mkdir(parents=True, exist_ok=True)

    packets = _reassemble_fragments(packets)
    flows: dict[tuple, dict] = {}

    for index, pkt in enumerate(packets):
        ip = _ip_layer(pkt)
        l4 = _l4_layer(pkt)
        if ip is None or l4 is None:
            continue
        version = 6 if isinstance(ip, IPv6) else 4
        proto = "TCP" if TCP in pkt else "UDP"
        src = (str(ip.src), int(l4.sport))
        dst = (str(ip.dst), int(l4.dport))
        key = _flow_key(src, dst, version, proto)
        flow = flows.setdefault(key, {
            "proto": proto,
            "ip_version": version,
            "endpoints": [src, dst],
            "packets": 0,
            "payload_bytes": 0,
            "first_ts": float(pkt.time),
            "last_ts": float(pkt.time),
            "directions": [
                {
                    "from": src,
                    "to": dst,
                    "packets": 0,
                    "bytes": 0,
                    "segments": [],
                    "datagrams": [],
                    "saw_syn": False,
                    "saw_fin": False,
                    "saw_rst": False,
                },
                {
                    "from": dst,
                    "to": src,
                    "packets": 0,
                    "bytes": 0,
                    "segments": [],
                    "datagrams": [],
                    "saw_syn": False,
                    "saw_fin": False,
                    "saw_rst": False,
                },
            ],
        })
        flow["packets"] += 1
        ts = float(pkt.time)
        flow["first_ts"] = min(flow["first_ts"], ts)
        flow["last_ts"] = max(flow["last_ts"], ts)
        direction = flow["directions"][0 if src == flow["endpoints"][0] else 1]
        direction["packets"] += 1
        payload = _payload(l4)
        direction["bytes"] += len(payload)
        flow["payload_bytes"] += len(payload)

        if proto == "TCP":
            flags = l4.flags
            seg = {
                "seq": int(l4.seq),
                "ts": ts,
                "index": index,
                "payload": payload,
                "syn": bool(flags.S),
                "fin": bool(flags.F),
                "rst": bool(flags.R),
            }
            direction["segments"].append(seg)
            direction["saw_syn"] |= seg["syn"]
            direction["saw_fin"] |= seg["fin"]
            direction["saw_rst"] |= seg["rst"]
        else:
            direction["datagrams"].append({
                "ts": ts,
                "index": index,
                "payload": payload,
            })

    index_data = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_packets": len(packets),
        "note": (
            "TCP .bin streams are reassembled by sequence number per direction; "
            "gaps are zero-filled and listed in gaps. UDP .bin files concatenate "
            "payloads; use .udp.jsonl for datagram boundaries."
        ),
        "flows": [],
    }
    tcp_flows = 0
    udp_flows = 0
    tcp_streams = 0
    udp_streams = 0
    total_payload = 0

    for number, flow in enumerate(flows.values(), 1):
        flow_id = f"flow-{number:04d}"
        item = {
            "id": flow_id,
            "proto": flow["proto"],
            "ip_version": flow["ip_version"],
            "endpoints": [
                _endpoint(ip, port) for ip, port in flow["endpoints"]
            ],
            "packets": flow["packets"],
            "payload_bytes": flow["payload_bytes"],
            "first_ts": flow["first_ts"],
            "last_ts": flow["last_ts"],
            "directions": [],
        }
        total_payload += flow["payload_bytes"]

        if flow["proto"] == "TCP":
            tcp_flows += 1
            for dir_index, direction in enumerate(flow["directions"]):
                built = _tcp_direction(direction["segments"])
                suffix = "a" if dir_index == 0 else "b"
                direction_item = {
                    "from": _endpoint(*flow["endpoints"][dir_index]),
                    "to": _endpoint(*flow["endpoints"][1 - dir_index]),
                    "packets": direction["packets"],
                    "segments": built["segments"],
                    "bytes": len(built["data"]),
                    "file": None,
                    "gaps": built["gaps"],
                    "gap_free": built["gap_free"],
                    "complete": built["complete"],
                    "truncated": built["truncated"],
                    "retransmissions": built["retransmissions"],
                    "conflicting_segments": built["conflicting_segments"],
                    "saw_syn": built["saw_syn"],
                    "saw_fin": built["saw_fin"],
                    "saw_rst": built["saw_rst"],
                }
                if built["data"]:
                    filename = f"{flow_id}-{suffix}.tcp.bin"
                    (out / filename).write_bytes(built["data"])
                    direction_item["file"] = filename
                    tcp_streams += 1
                item["directions"].append(direction_item)
        else:
            udp_flows += 1
            events = []
            for dir_index, direction in enumerate(flow["directions"]):
                suffix = "a" if dir_index == 0 else "b"
                direction_item = {
                    "from": _endpoint(*flow["endpoints"][dir_index]),
                    "to": _endpoint(*flow["endpoints"][1 - dir_index]),
                    "packets": direction["packets"],
                    "datagrams": len(direction["datagrams"]),
                    "bytes": direction["bytes"],
                    "file": None,
                }
                datagrams = sorted(
                    direction["datagrams"],
                    key=lambda d: (d["ts"], d["index"]),
                )
                if datagrams:
                    data = b"".join(d["payload"] for d in datagrams)
                    filename = f"{flow_id}-{suffix}.udp.bin"
                    (out / filename).write_bytes(data)
                    direction_item["file"] = filename
                    udp_streams += 1
                offset = 0
                for datagram in datagrams:
                    events.append({
                        "ts": datagram["ts"],
                        "direction": "a->b" if dir_index == 0 else "b->a",
                        "from": direction_item["from"],
                        "to": direction_item["to"],
                        "offset": offset,
                        "length": len(datagram["payload"]),
                        "payload_b64": base64.b64encode(
                            datagram["payload"]).decode("ascii"),
                    })
                    offset += len(datagram["payload"])
                item["directions"].append(direction_item)

            events.sort(key=lambda event: event["ts"])
            jsonl_name = f"{flow_id}.udp.jsonl"
            with (out / jsonl_name).open("w", encoding="utf-8") as handle:
                for event in events:
                    handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            item["datagrams"] = len(events)
            item["jsonl"] = jsonl_name

        index_data["flows"].append(item)

    (out / "index.json").write_text(
        json.dumps(index_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        "dir": str(out),
        "index": str(out / "index.json"),
        "flows": len(index_data["flows"]),
        "tcp_flows": tcp_flows,
        "udp_flows": udp_flows,
        "tcp_streams": tcp_streams,
        "udp_streams": udp_streams,
        "payload_bytes": total_payload,
    }
