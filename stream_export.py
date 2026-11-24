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
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.packet import Padding, Raw

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


def _declared_after(ip, layer) -> int:
    """IP-declared bytes after a header, including missing captured bytes."""
    header_bytes = len(bytes(ip)) - len(bytes(layer.payload))
    if isinstance(ip, IP):
        total = int(ip.len) if ip.len is not None else len(bytes(ip))
    else:
        total = 40 + int(ip.plen) if ip.plen is not None else len(bytes(ip))
    return total - header_bytes


def _transport_payload(ip, l4) -> tuple[bytes, int, bool]:
    """Keep captured payload distinct from its advertised length."""
    data = _payload(l4)
    declared = _declared_after(ip, l4)
    invalid = declared < 0
    if isinstance(l4, UDP):
        udp_length = int(l4.len) if l4.len is not None else 8 + len(data)
        udp_payload = udp_length - 8
        invalid |= udp_length < 8 or udp_payload > declared
        declared = max(0, udp_payload)
        # Do not turn IP/UDP padding into application data.
        data = data[:max(0, min(declared, _declared_after(ip, l4)))]
    else:
        captured_header = len(bytes(l4)) - len(bytes(l4.payload))
        header_length = int(l4.dataofs) * 4 if l4.dataofs is not None else captured_header
        invalid |= header_length < 20 or captured_header < header_length
        # A snaplen can end inside TCP options. Missing header bytes are not
        # missing application bytes and must not extend the stream length.
        declared -= header_length - captured_header
        invalid |= declared < 0
        declared = max(0, declared)
        data = data[:declared]
    return data, declared, invalid


def _reassemble_fragments(packets: list, stats: dict | None = None) -> list:
    """Only emit datagrams proven complete, without overlap or capture loss.

    Scapy's IPv6 helper fills holes with 'X'; IPv4 uses declared fragment
    lengths even when caplen is shorter. Neither is safe for evidence export.
    Exact fragment copies collapse within a group; conflicting/reused IDs are
    discarded. Identical datagrams reusing an ID cannot be distinguished from
    duplicate captures. Whole UDP datagrams are never deduplicated.
    """
    groups: dict[tuple, list[tuple[int, Any]]] = defaultdict(list)
    rest: list[tuple[int, Any]] = []
    for i, pkt in enumerate(packets):
        ip = _ip_layer(pkt)
        if isinstance(ip, IP) and (ip.flags.MF or int(ip.frag) > 0):
            key = (4, ip.src, ip.dst, int(ip.id), int(ip.proto))
        elif isinstance(ip, IPv6) and IPv6ExtHdrFragment in pkt:
            frag = pkt[IPv6ExtHdrFragment]
            key = (6, ip.src, ip.dst, int(frag.id), int(frag.nh))
            if not frag.offset and not frag.m:
                # Atomic fragments are independent datagrams, even with ID reuse.
                key += (i,)
        else:
            rest.append((i, pkt))
            continue
        groups[key].append((i, pkt))

    discarded = 0
    for key, items in groups.items():
        pieces = []
        seen = set()
        valid = True
        for _, pkt in items:
            ip = _ip_layer(pkt)
            frag = ip if key[0] == 4 else pkt[IPv6ExtHdrFragment]
            offset = 8 * int(frag.frag if key[0] == 4 else frag.offset)
            more = bool(frag.flags.MF if key[0] == 4 else frag.m)
            declared = _declared_after(ip, frag)
            data = _payload(frag)
            if (declared < 0 or len(data) < declared
                    or (more and (declared == 0 or declared % 8))):
                valid = False
            data = data[:max(0, declared)]
            signature = (offset, more, data)
            if signature in seen:
                continue
            seen.add(signature)
            pieces.append((offset, more, data, pkt))
        pieces.sort(key=lambda piece: piece[0])
        end = 0
        for n, (offset, more, data, _) in enumerate(pieces):
            if offset != end or more != (n < len(pieces) - 1):
                valid = False
            end = offset + len(data)
        first_ip = _ip_layer(pieces[0][3])
        if key[0] == 4:
            header_size = len(bytes(first_ip)) - len(bytes(first_ip.payload))
        else:
            first_frag = pieces[0][3][IPv6ExtHdrFragment]
            header_size = len(bytes(first_ip)) - len(bytes(first_frag)) - 40
        if end + header_size > 65535:
            valid = False
        if not valid:
            discarded += len(items)
            continue

        first = pieces[0][3]
        whole = _ip_layer(first).copy()
        data = b"".join(piece[2] for piece in pieces)
        if key[0] == 4:
            whole.flags.MF = False
            whole.frag = 0
            whole.len = None
            whole.chksum = None
            whole.remove_payload()
            whole.add_payload(Raw(data))
            whole = IP(bytes(whole))
        else:
            frag = whole[IPv6ExtHdrFragment]
            parent = frag.underlayer
            parent.nh = frag.nh
            parent.remove_payload()
            parent.add_payload(Raw(data))
            whole.plen = None
            whole = IPv6(bytes(whole))
        first_index, first_captured = min(items, key=lambda item: item[0])
        whole.time = first_captured.time
        rest.append((first_index, whole))
    if stats is not None:
        stats["discarded_fragment_packets"] = discarded
    rest.sort(key=lambda item: item[0])
    return [pkt for _, pkt in rest]


def _signed_delta(value: int, base: int) -> int:
    delta = (value - base) & (SEQ_MOD - 1)
    return delta - SEQ_MOD if delta & SEQ_HALF else delta


def _tcp_direction(segments: list[dict], max_bytes: int | None = None) -> dict:
    """Reassemble one direction, keeping the first captured byte on overlap.

    Sequence positions use RFC-style signed distances (less than 2 GiB).
    MAX_STREAM_BYTES limits the output window, not total capture memory.
    """
    if max_bytes is None:
        max_bytes = MAX_STREAM_BYTES
    if max_bytes < 0:
        raise ValueError("max_bytes must be nonnegative")
    ordered = sorted(segments, key=lambda seg: seg["index"])
    payload_segments = [s for s in ordered if s.get("declared_length", len(s["payload"]))]
    syn_segments = [s for s in ordered if s["syn"]]
    saw_syn = bool(syn_segments)
    saw_fin = any(s["fin"] for s in ordered)
    saw_rst = any(s["rst"] for s in ordered)
    if syn_segments:
        base = (syn_segments[0]["seq"] + 1) & (SEQ_MOD - 1)
    elif payload_segments:
        # Numeric min(seq) is wrong when a midstream capture crosses 2**32.
        anchor = payload_segments[0]["seq"]
        earliest = min(_signed_delta(s["seq"], anchor) for s in payload_segments)
        base = (anchor + earliest) & (SEQ_MOD - 1)
    else:
        base = ordered[0]["seq"] if ordered else 0

    normalized = []
    fin_ends = set()
    ambiguous = False
    invalid = any(s.get("invalid_length", False) for s in ordered)
    expected_end = 0
    for seg in ordered:
        declared = seg.get("declared_length", len(seg["payload"]))
        rel = _signed_delta(seg["seq"] + int(seg["syn"]), base)
        if rel < 0 and (declared or seg["fin"]):
            ambiguous = True
            continue
        if declared:
            normalized.append((rel, seg))
            expected_end = max(expected_end, rel + declared)
        if seg["fin"]:
            fin_ends.add(rel + declared)
            expected_end = max(expected_end, rel + declared)

    truncated = expected_end > max_bytes
    end_max = min(expected_end, max_bytes)
    buf = bytearray(end_max)
    covered = bytearray(end_max)
    retransmissions = 0
    conflicts = 0

    for rel, seg in normalized:
        if rel >= end_max:
            continue
        end = min(rel + len(seg["payload"]), end_max)
        data = seg["payload"][:end - rel]
        if not data:
            continue
        missing = covered.count(0, rel, end)
        if missing == end - rel:
            buf[rel:end] = data
            covered[rel:end] = b"\x01" * (end - rel)
        elif missing == 0:
            retransmissions += 1
            conflicts += bytes(buf[rel:end]) != data
        else:
            conflict = False
            for offset, value in enumerate(data):
                pos = rel + offset
                if covered[pos]:
                    conflict |= buf[pos] != value
                else:
                    buf[pos] = value
                    covered[pos] = 1
            conflicts += conflict

    gaps = []
    pos = 0
    while pos < end_max:
        start = covered.find(b"\x00", pos)
        if start < 0:
            break
        end = covered.find(b"\x01", start)
        pos = end if end >= 0 else end_max
        gaps.append([start, pos - start])

    gap_free = not gaps
    # RST supplies no reliable final byte boundary. A conflicting retransmit
    # also prevents certifying which byte sequence the receiver accepted.
    complete = bool(saw_syn and fin_ends == {expected_end} and not saw_rst
                    and gap_free and not truncated and not conflicts
                    and not ambiguous and not invalid)
    return {
        "data": bytes(buf),
        "segments": len(normalized),
        "packets": len(segments),
        "gaps": gaps,
        "gap_free": gap_free,
        "complete": complete,
        "truncated": truncated,
        "capture_truncated_packets": sum(
            s.get("declared_length", len(s["payload"])) > len(s["payload"])
            for s in ordered),
        "invalid_length_packets": sum(s.get("invalid_length", False) for s in ordered),
        "sequence_ambiguous": ambiguous,
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


def _new_tcp_connection(flow: dict, src: tuple, tcp) -> bool:
    """Recognize a new observed handshake on an existing four-tuple."""
    if not tcp.flags.S:
        return False
    direction = flow["directions"][0 if src == flow["endpoints"][0] else 1]
    prior_syn = next((s for s in direction["segments"] if s["syn"]), None)
    if not tcp.flags.A and any(d["saw_fin"] or d["saw_rst"] for d in flow["directions"]):
        return True
    if prior_syn is not None:
        return prior_syn["seq"] != int(tcp.seq)
    # The peer's first SYN/SYN-ACK belongs to the same handshake. A SYN
    # after a capture that began midstream starts a separately observed flow.
    return not any(d["saw_syn"] for d in flow["directions"])


def export_streams(packets: list, out_dir: str | Path) -> dict:
    """Write reassembled streams and their metadata to *out_dir*."""
    out = Path(out_dir)
    if out.is_symlink() or (hasattr(out, "is_junction") and out.is_junction()):
        raise ValueError("stream output directory must not be a link")
    if out.exists() and not out.is_dir():
        raise ValueError("stream output path must be a directory")
    out.mkdir(parents=True, exist_ok=True)
    generated = re.compile(r"(?:index\.json|flow-\d{4,}(?:-[ab]\.(?:tcp|udp)\.bin|\.udp\.jsonl))")
    old_files = [path for path in out.iterdir() if generated.fullmatch(path.name)]
    if any(path.is_dir() for path in old_files):
        raise ValueError("a stream output filename is occupied by a directory")
    for path in old_files:
        path.unlink()

    source_packets = len(packets)
    fragment_stats = {}
    packets = _reassemble_fragments(packets, fragment_stats)
    flows: dict[tuple, dict] = {}
    generations: dict[tuple, int] = {}

    for index, pkt in enumerate(packets):
        ip = _ip_layer(pkt)
        l4 = _l4_layer(pkt)
        if ip is None or l4 is None:
            continue
        version = 6 if isinstance(ip, IPv6) else 4
        proto = "TCP" if TCP in pkt else "UDP"
        src = (str(ip.src), int(l4.sport))
        dst = (str(ip.dst), int(l4.dport))
        tuple_key = _flow_key(src, dst, version, proto)
        generation = generations.get(tuple_key, 0)
        key = (*tuple_key, generation)
        if proto == "TCP" and key in flows and _new_tcp_connection(flows[key], src, l4):
            generation += 1
            generations[tuple_key] = generation
            key = (*tuple_key, generation)
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
        payload, declared_length, invalid_length = _transport_payload(ip, l4)
        direction["bytes"] += len(payload)
        flow["payload_bytes"] += len(payload)

        if proto == "TCP":
            flags = l4.flags
            seg = {
                "seq": int(l4.seq),
                "ts": ts,
                "index": index,
                "payload": payload,
                "declared_length": declared_length,
                "invalid_length": invalid_length,
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
                "declared_length": declared_length,
                "invalid_length": invalid_length,
            })

    index_data = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_packets": source_packets,
        "reassembled_packets": len(packets),
        **fragment_stats,
        "note": (
            "TCP .bin streams use sequence numbers per direction and keep the first "
            "captured byte on overlap; gaps are zero-filled and listed in gaps. "
            "TCP complete requires observed SYN/FIN boundaries without gaps, conflicts "
            "or truncation. New observed handshakes split reused four-tuples; reuse "
            "without a SYN and sequence spans of 2 GiB or more remain ambiguous. "
            "Incomplete or conflicting fragment groups are discarded; identical fragment "
            "copies collapse, and fragment-ID reuse without a conflict is indistinguishable. "
            "UDP .bin files concatenate captured payloads; .udp.jsonl records boundaries, "
            "missing bytes and truncation. UDP complete describes observed datagrams, "
            "not whether every sent datagram was captured. MAX_STREAM_BYTES caps exported bytes; "
            "it does not bound total capture or metadata memory."
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
                    "capture_truncated_packets": built["capture_truncated_packets"],
                    "invalid_length_packets": built["invalid_length_packets"],
                    "sequence_ambiguous": built["sequence_ambiguous"],
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
                    "bytes": 0,
                    "captured_bytes": direction["bytes"],
                    "complete": bool(direction["datagrams"]),
                    "truncated": False,
                    "file": None,
                }
                datagrams = sorted(direction["datagrams"], key=lambda d: d["index"])
                if datagrams:
                    filename = f"{flow_id}-{suffix}.udp.bin"
                    direction_item["file"] = filename
                    udp_streams += 1
                    offset = 0
                    with (out / filename).open("wb") as handle:
                        for datagram in datagrams:
                            captured = len(datagram["payload"])
                            data = datagram["payload"][:max(0, MAX_STREAM_BYTES - offset)]
                            missing = max(0, datagram["declared_length"] - captured)
                            limited = len(data) < captured
                            complete = not (missing or limited or datagram["invalid_length"])
                            event = {
                                "ts": datagram["ts"],
                                "direction": "a->b" if dir_index == 0 else "b->a",
                                "from": direction_item["from"],
                                "to": direction_item["to"],
                                "offset": offset,
                                "length": len(data),
                                "declared_length": datagram["declared_length"],
                                "captured_length": captured,
                                "missing_bytes": missing,
                                "complete": complete,
                                "truncated": bool(missing or limited),
                                "export_truncated": limited,
                                "invalid_length": datagram["invalid_length"],
                                "payload_b64": base64.b64encode(data).decode("ascii"),
                            }
                            events.append((datagram["index"], event))
                            handle.write(data)
                            offset += len(data)
                            direction_item["complete"] &= complete
                            direction_item["truncated"] |= event["truncated"]
                    direction_item["bytes"] = offset
                item["directions"].append(direction_item)

            events.sort(key=lambda event: event[0])
            jsonl_name = f"{flow_id}.udp.jsonl"
            with (out / jsonl_name).open("w", encoding="utf-8") as handle:
                for _, event in events:
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
