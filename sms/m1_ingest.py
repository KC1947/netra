"""Offline dpkt ingest with bounded TCP flows and exact packet-byte provenance.

Conversations share a generation across both directions; only retained
payload bytes can enter the reassembly and evidence path.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from struct import error as StructError
from struct import unpack as struct_unpack
import time
import tracemalloc
from typing import Iterable, Mapping

import dpkt

from .contracts import ByteSlice, ByteStream, PacketObservation, Session, StreamGap


MAIL_SERVER_PORTS = frozenset({25, 110, 143, 465, 993, 995})
MAIL_PAYLOAD_PREFIXES = (b"220 ", b"* OK", b"+OK", b"\x16\x03")
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LT_NULL, LT_ETHERNET, LT_RAW, LT_LOOP = 0, 1, 101, 108
LT_SLL, LT_SLL2, LT_IPV4, LT_IPV6 = 113, 276, 228, 229
_DECODE_ERRORS = (dpkt.UnpackError, ValueError, IndexError, StructError)


def open_reader(fh):
    """Sniff the magic number instead of trusting the file extension."""
    magic = fh.read(4)
    fh.seek(0)
    return dpkt.pcapng.Reader(fh) if magic == PCAPNG_MAGIC else dpkt.pcap.Reader(fh)


def _network_with_offset(linktype: int, buf: bytes):
    if linktype == LT_ETHERNET:
        link = dpkt.ethernet.Ethernet(buf)
        # dpkt unwraps 802.1Q/QinQ; derive offsets from headers, never from
        # serialized packet length (which can include padding or omit trailers).
        offset = link.__hdr_len__ + sum(tag.__hdr_len__ for tag in getattr(link, "vlan_tags", ()))
        offset += sum(label.__hdr_len__ for label in getattr(link, "mpls_labels", ()))
        return link.data, offset
    if linktype in (LT_NULL, LT_LOOP):
        if len(buf) < 4:
            raise dpkt.NeedData("truncated loopback header")
        # AF values belong to the capturing OS, not the reader's host.
        # NULL uses capture-host byte order; LOOP uses network byte order.
        # dpkt's loopback decoder omits Linux's AF_INET6 (10).
        family = int.from_bytes(buf[:4], "big")
        if linktype == LT_NULL and family not in (2, 10, 24, 28, 30):
            family = int.from_bytes(buf[:4], "little")
        payload = buf[4:]
        return (dpkt.ip.IP(payload) if family == 2 else
                dpkt.ip6.IP6(payload) if family in (10, 24, 28, 30) else None), 4
    if linktype in (LT_SLL, LT_SLL2):
        cls = {LT_SLL: dpkt.sll.SLL, LT_SLL2: dpkt.sll2.SLL2}[linktype]
        link = cls(buf)
        return link.data, link.__hdr_len__
    # DLT_RAW is 12 on some platforms; savefiles normally use LINKTYPE_RAW=101.
    if linktype in (12, LT_RAW, LT_IPV4, LT_IPV6):
        version = buf[0] >> 4 if buf else 0
        return (dpkt.ip.IP(buf) if version == 4 else
                dpkt.ip6.IP6(buf) if version == 6 else None), 0
    raise ValueError(f"unsupported linktype {linktype}")


def network_layer(linktype: int, buf: bytes):
    """Return the decoded IP/IP6 layer (or non-IP data) for a capture link type."""
    return _network_with_offset(linktype, buf)[0]


def addr(ip) -> tuple[str, str]:
    """Convert IPv4/IPv6 separately, without sockets or name resolution."""
    address = IPv6Address if isinstance(ip, dpkt.ip6.IP6) else IPv4Address
    return str(address(ip.src)), str(address(ip.dst))


@dataclass
class Budget:
    total_bytes: int = 512 * 1024 * 1024
    bytes_per_flow: int = 1 * 1024 * 1024
    segments_per_flow: int = 20_000
    max_flows: int = 50_000

    def __post_init__(self):
        if self.total_bytes < 0 or self.bytes_per_flow < 0:
            raise ValueError("byte budgets must be non-negative")
        if self.segments_per_flow < 1 or self.max_flows < 1:
            raise ValueError("flow and segment limits must be positive")


@dataclass
class IngestStats:
    file_format: str = "unknown"
    snaplen: int | None = None
    truncated: bool = False
    frames: int = 0
    tcp_segments: int = 0
    skipped: Counter = field(default_factory=Counter)
    linktypes: Counter = field(default_factory=Counter)
    ipv4: int = 0
    ipv6: int = 0
    fragments: int = 0
    flows_evicted: int = 0
    flows_truncated: int = 0
    trimmed_padding: int = 0
    sessions_with_holes: int = 0
    sessions_with_conflicting_overlaps: int = 0
    sessions_incomplete: int = 0
    total_flows: int = 0
    candidate_flows: int = 0
    confirmed_mail_sessions: int = 0
    midstream_sessions: dict[str, bool] = field(default_factory=dict)
    unsupported_packets: Counter = field(default_factory=Counter)
    # Runtime measurements stay outside the canonical report: they describe
    # this run, not the capture. The same capture must produce byte-identical
    # reports regardless of wall-clock timing or machine load. Callers can
    # read these measurements from IngestStats; docs/BENCHMARKS.json records
    # benchmark measurements.
    elapsed_time_ms: float = 0.0
    peak_memory_bytes: int = 0

    def as_dict(self):
        unsupported = sum(self.unsupported_packets.values())
        decoded_pct = round(100 * self.tcp_segments / self.frames, 2) if self.frames else 0
        if (self.frames and self.unsupported_packets.get("link_type", 0) == self.frames):
            analysis_status = "unsupported"
        elif self.frames == 0 and any(
                reason.startswith(("capture_header:", "capture_record:", "capture_io"))
                for reason in self.skipped):
            analysis_status = "unreadable"
        elif unsupported or self.truncated:
            analysis_status = "partial"
        else:
            analysis_status = "complete"
        return {"file_format": self.file_format,
                "snaplen": self.snaplen,
                "truncated": self.truncated,
                "frames_decoded_pct": decoded_pct,
                "analysis_status": analysis_status,
                "frames": self.frames, "tcp_segments": self.tcp_segments,
                "ipv4": self.ipv4, "ipv6": self.ipv6, "ipv4_fragments": self.fragments,
                "linktypes": {str(linktype): count
                              for linktype, count in sorted(self.linktypes.items())},
                "skipped": dict(self.skipped),
                "flows_evicted": self.flows_evicted, "flows_truncated": self.flows_truncated,
                "padding_bytes_trimmed": self.trimmed_padding,
                "sessions_with_holes": self.sessions_with_holes,
                "sessions_with_conflicting_overlaps": self.sessions_with_conflicting_overlaps,
                "sessions_incomplete": self.sessions_incomplete,
                "total_flows": self.total_flows,
                "candidate_flows": self.candidate_flows,
                "confirmed_mail_sessions": self.confirmed_mail_sessions,
                "midstream_sessions": dict(sorted(self.midstream_sessions.items())),
                "unsupported_packets": {
                    "count": unsupported,
                    "breakdown": {
                        reason: self.unsupported_packets.get(reason, 0)
                        for reason in ("link_type", "malformed", "non_tcp", "truncated_header")
                    },
                }}


class FlowTable:
    """Byte/segment/flow-bounded LRU table with bidirectional ISN generations.

    ``segs`` retains the reference (sequence, frame, payload) API. Observations
    share those same payload objects and retain direction, time and wire offset.
    Generation state is discarded with the last retained flow for its endpoints.
    """
    def __init__(self, budget: Budget | None = None, stats: IngestStats | None = None):
        self.b = budget if budget is not None else Budget()
        self.st = stats if stats is not None else IngestStats()
        self.flows = OrderedDict()
        self.isn, self.gen = {}, {}
        self.reset, self.next_seq = set(), {}
        self.total = 0

    def key_for(self, tup, syn, rst, seq, *, length=0, synack=False):
        left, right = _endpoint_key((tup[0], tup[1]), (tup[2], tup[3]))
        side = (tup[0], tup[1]) == right
        tup = (*left, *right)
        if syn and self.isn.get(tup) != seq:
            self._new_generation(tup)
            self.isn[tup] = seq
        elif rst:
            self.isn.pop(tup, None)
            self.reset.add(tup)
        elif tup in self.reset and (synack or (
                length and self.next_seq.get(tup, (None, None))[side] != seq)):
            # A RST ends the conversation. A later SYN-ACK, or data that does
            # not continue its sender's byte stream, is a new conversation whose
            # SYN was not captured. Data continuing exactly where its sender
            # stopped is the old conversation's (in flight, or an ignored RST).
            self._new_generation(tup)
        if length or syn or synack:
            # Next sequence number per side, indexed by sender == right.
            ends = self.next_seq.setdefault(tup, [None, None])
            ends[side] = seq + length + bool(syn or synack)
        return (*tup, self.gen.get(tup, 0))

    def _new_generation(self, tup):
        self.gen[tup] = self.gen.get(tup, 0) + 1
        self.reset.discard(tup)
        self.next_seq.pop(tup, None)

    def add(self, key, frame, ts, seq, payload, *, source=None, packet_offset=0,
            first_packet_syn: bool | None = None):
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = {"segs": [], "observations": [], "bytes": 0,
                                   "incomplete": False, "first_ts": ts,
                                   "first_frame": frame, "last_frame": frame,
                                   "midstream": first_packet_syn is False}
        self.flows.move_to_end(key)
        # Insert before evicting: removing an older generation of this same
        # tuple must not erase the new generation's ISN.
        while len(self.flows) > self.b.max_flows:
            self._evict()
        f["last_frame"] = frame
        if f["incomplete"]:
            return
        if (f["bytes"] + len(payload) > min(self.b.bytes_per_flow, self.b.total_bytes)
                or len(f["segs"]) >= self.b.segments_per_flow):
            f["incomplete"] = True
            self.st.flows_truncated += 1
            return
        while self.total + len(payload) > self.b.total_bytes:
            self._evict()
        f["segs"].append((seq, frame, payload))
        if source is not None:
            _, client = _server_and_client(((key[0], key[1]), (key[2], key[3])))
            direction = "client_to_server" if source == client else "server_to_client"
            f["observations"].append(PacketObservation(
                frame, direction, float(ts), seq, payload, packet_offset,
            ))
        f["bytes"] += len(payload)
        self.total += len(payload)

    def _evict(self):
        key, f = self.flows.popitem(last=False)
        self.total -= f["bytes"]
        self.st.flows_evicted += 1
        tup = key[:4]
        if not any(k[:4] == tup for k in self.flows):
            self.isn.pop(tup, None)
            self.gen.pop(tup, None)
            self.reset.discard(tup)
            self.next_seq.pop(tup, None)


def _endpoint_key(left: tuple[str, int], right: tuple[str, int]) -> tuple[tuple[str, int], tuple[str, int]]:
    return tuple(sorted((left, right)))  # type: ignore[return-value]


def _server_and_client(endpoints: tuple[tuple[str, int], tuple[str, int]]) -> tuple[tuple[str, int], tuple[str, int]]:
    candidates = [endpoint for endpoint in endpoints if endpoint[1] in MAIL_SERVER_PORTS]
    if len(candidates) == 1:
        return candidates[0], endpoints[0] if endpoints[1] == candidates[0] else endpoints[1]
    # A non-mail capture remains deterministic and usable; later protocol grammar
    # detection decides whether it represents an email protocol.
    return endpoints[0], endpoints[1]


class _ReassembledChunk(dict):
    """Reference chunk shape plus its private byte-to-frame provenance map."""

    def __init__(self, start: int, end: int, data: bytes, frames: list[int],
                 sources: list[ByteSlice]):
        super().__init__(start=start, end=end, data=data, frames=frames)
        self.sources = tuple(sources)


class _ReassemblyResult(dict):
    """Reference mapping with compatibility helpers for ingest unit tests."""

    def __init__(self, chunks: list[_ReassembledChunk], conflicts: list[dict]):
        super().__init__(
            chunks=chunks,
            holes=max(0, len(chunks) - 1),
            conflicts=conflicts,
            complete=len(chunks) <= 1 and not conflicts,
        )

    @property
    def chunks(self):
        return self["chunks"]

    @property
    def conflicts(self):
        return self["conflicts"]

    @property
    def complete(self) -> bool:
        return self["complete"]

    @property
    def has_gaps(self) -> bool:
        return bool(self["holes"])

    @property
    def gaps(self) -> list[StreamGap]:
        if len(self.chunks) < 2:
            return []
        origin = self.chunks[0]["start"]
        return [
            StreamGap(
                left["end"] - origin,
                right["start"] - left["end"],
                left["end"],
                right["start"],
            )
            for left, right in zip(self.chunks, self.chunks[1:])
        ]

    def iter_spans(self):
        for chunk in self.chunks:
            yield chunk["data"], chunk.sources

    def contiguous_bytes(self) -> bytes:
        if self.has_gaps:
            raise ValueError("TCP stream has gaps; inspect chunks separately")
        return self.chunks[0]["data"] if self.chunks else b""

    def provenance_for(self, start: int, length: int) -> list[ByteSlice]:
        if start < 0 or length < 0:
            raise ValueError("stream range must be non-negative")
        end = start + length
        result: list[ByteSlice] = []
        for chunk in self.chunks:
            for source in chunk.sources:
                source_end = source.stream_offset + source.byte_length
                left, right = max(start, source.stream_offset), min(end, source_end)
                if left < right:
                    result.append(ByteSlice(
                        left, right - left, source.frame,
                        source.packet_byte_offset + (left - source.stream_offset),
                    ))
        if sum(item.byte_length for item in result) != length:
            raise ValueError("requested range contains uncaptured TCP bytes")
        return result

    def first_stream(self) -> ByteStream:
        """Return only the first contiguous chunk for downstream parsing."""
        if not self.chunks:
            return ByteStream()
        chunk = self.chunks[0]
        pieces, sources = [], []
        for source in chunk.sources:
            start = source.stream_offset
            pieces.append(chunk["data"][start:start + source.byte_length])
            sources.append(source)
        disputed = sorted({
            conflict["offset"] - chunk["start"] for conflict in self.conflicts
            if chunk["start"] <= conflict["offset"] < chunk["end"]
        })
        return ByteStream(pieces, sources, disputed=tuple(disputed))


def _chunk(entries: list[tuple[int, int, int, int]], origin: int) -> _ReassembledChunk:
    """Build one contiguous chunk and coalesce adjacent provenance slices."""
    start, end = entries[0][0], entries[-1][0] + 1
    sources: list[ByteSlice] = []
    run_position, _, run_frame, run_packet_offset = entries[0]
    run_length = 1
    previous_position, previous_packet_offset = run_position, run_packet_offset
    for position, _byte, frame, packet_offset in entries[1:]:
        if (position == previous_position + 1 and frame == run_frame
                and packet_offset == previous_packet_offset + 1):
            run_length += 1
        else:
            sources.append(ByteSlice(
                run_position - origin, run_length, run_frame, run_packet_offset,
            ))
            run_position, run_frame, run_packet_offset, run_length = position, frame, packet_offset, 1
        previous_position, previous_packet_offset = position, packet_offset
    sources.append(ByteSlice(
        run_position - origin, run_length, run_frame, run_packet_offset,
    ))
    return _ReassembledChunk(
        start, end, bytes(item[1] for item in entries),
        sorted({item[2] for item in entries}), sources,
    )


def _reassemble(observations: Iterable[PacketObservation]) -> _ReassemblyResult:
    """Return contiguous TCP chunks, preserving holes and comparing all overlaps.

    This ports ``verify.fixed.reassemble`` while retaining packet offsets for
    exact downstream evidence. The first sequence/frame occurrence owns a byte;
    every later overlapping byte is still compared and any mismatch reported.
    """
    captured: dict[int, tuple[int, int, int]] = {}
    conflicts: list[dict] = []
    ordered = sorted(
        (item for item in observations if item.payload),
        key=lambda item: (item.sequence, item.frame_no),
    )
    for item in ordered:
        for index, byte in enumerate(item.payload):
            position = item.sequence + index
            previous = captured.get(position)
            if previous is not None:
                if previous[0] != byte:
                    conflicts.append({
                        "offset": position,
                        "frames": [previous[1], item.frame_no],
                    })
                continue
            captured[position] = (
                byte, item.frame_no, item.payload_packet_offset + index,
            )

    if not captured:
        return _ReassemblyResult([], conflicts)

    positions = sorted(captured)
    origin = positions[0]
    chunks: list[_ReassembledChunk] = []
    entries: list[tuple[int, int, int, int]] = []
    previous_position: int | None = None
    for position in positions:
        if previous_position is not None and position != previous_position + 1:
            chunks.append(_chunk(entries, origin))
            entries = []
        byte, frame, packet_offset = captured[position]
        entries.append((position, byte, frame, packet_offset))
        previous_position = position
    chunks.append(_chunk(entries, origin))
    return _ReassemblyResult(chunks, conflicts)


def _tcp_payload(linktype, buf, stats):
    """Decode one frame, returning TCP bytes and their exact captured offset."""
    try:
        ip, network_offset = _network_with_offset(linktype, buf)
    except _DECODE_ERRORS as exc:
        stats.skipped[f"link_decode:{type(exc).__name__}"] += 1
        category = ("link_type" if isinstance(exc, ValueError)
                    and str(exc).startswith("unsupported linktype ") else "malformed")
        stats.unsupported_packets[category] += 1
        return None
    if isinstance(ip, dpkt.ip.IP):
        stats.ipv4 += 1
        if ip.mf or ip.offset:
            stats.fragments += 1
            stats.skipped["ipv4_fragment"] += 1
            stats.unsupported_packets["malformed"] += 1
            return None
        network_length = ip.hl * 4
        packet_length = ip.len or len(buf) - network_offset
        protocol = ip.p
        version = 4
    elif isinstance(ip, dpkt.ip6.IP6):
        stats.ipv6 += 1
        extensions = getattr(ip, "all_extension_headers", ())
        if any(isinstance(ext, dpkt.ip6.IP6FragmentHeader) for ext in extensions):
            stats.skipped["ipv6_fragment"] += 1
            stats.unsupported_packets["malformed"] += 1
            return None
        network_length = 40 + sum(ext.length for ext in extensions)
        packet_length = 40 + ip.plen if ip.plen else len(buf) - network_offset
        protocol = getattr(ip, "p", ip.nxt)
        version = 6
    else:
        stats.skipped["not_ip"] += 1
        stats.unsupported_packets["non_tcp"] += 1
        return None
    if (ip.v != version or packet_length < network_length
            or network_offset >= len(buf) or buf[network_offset] >> 4 != version):
        stats.skipped["invalid_ip_header"] += 1
        stats.unsupported_packets["truncated_header"] += 1
        return None
    if network_offset + packet_length > len(buf):
        stats.skipped["truncated_ip"] += 1
        stats.unsupported_packets["truncated_header"] += 1
        return None
    tcp = ip.data
    if not isinstance(tcp, dpkt.tcp.TCP):
        stats.skipped["tcp_decode" if protocol == dpkt.ip.IP_PROTO_TCP else "not_tcp"] += 1
        stats.unsupported_packets[
            "malformed" if protocol == dpkt.ip.IP_PROTO_TCP else "non_tcp"
        ] += 1
        return None
    tcp_length = tcp.off * 4
    if tcp_length < 20 or packet_length < network_length + tcp_length:
        stats.skipped["invalid_tcp_header"] += 1
        stats.unsupported_packets["truncated_header"] += 1
        return None
    packet_offset = network_offset + network_length + tcp_length
    packet_end = network_offset + packet_length
    stats.trimmed_padding += len(buf) - packet_end
    # Slice the original frame, not a reserialized dpkt object. This also keeps
    # IP/TCP options, IPv6 extensions and Ethernet padding out of the payload.
    return ip, tcp, buf[packet_offset:packet_end], packet_offset


def _pcap_records(reader):
    """Yield pcap records including captured/original lengths hidden by dpkt."""
    capture = reader._Reader__f
    packet_header = reader._Reader__ph
    while True:
        raw_header = capture.read(packet_header.__hdr_len__)
        if not raw_header:
            return
        header = packet_header(raw_header)
        buf = capture.read(header.caplen)
        if len(buf) != header.caplen:
            raise dpkt.NeedData("short pcap packet data")
        timestamp = header.tv_sec + (header.tv_usec / reader._divisor)
        yield timestamp, buf, reader.datalink(), header.len


def _pcapng_interface(idb, little_endian: bool) -> tuple[int, float, int]:
    divisor, offset = 1e6, 0
    endian = "<" if little_endian else ">"
    for option in idb.opts:
        if option.code == dpkt.pcapng.PCAPNG_OPT_IF_TSRESOL:
            value = struct_unpack("b", option.data)[0]
            divisor = float((2 if value & 0x80 else 10) ** (value & 0x7f))
        elif option.code == dpkt.pcapng.PCAPNG_OPT_IF_TSOFFSET:
            offset = struct_unpack(f"{endian}q", option.data)[0]
    return idb.linktype, divisor, offset


def _pcapng_records(reader):
    """Yield pcapng packet blocks with their interface and original length."""
    capture = reader._Reader__f
    little_endian = reader._Reader__le
    endian = "<" if little_endian else ">"
    idb_class = (dpkt.pcapng.InterfaceDescriptionBlockLE if little_endian
                 else dpkt.pcapng.InterfaceDescriptionBlock)
    epb_class = (dpkt.pcapng.EnhancedPacketBlockLE if little_endian
                 else dpkt.pcapng.EnhancedPacketBlock)
    pb_class = (dpkt.pcapng.PacketBlockLE if little_endian
                else dpkt.pcapng.PacketBlock)
    interfaces = [_pcapng_interface(reader.idb, little_endian)]
    while True:
        prefix = capture.read(8)
        if not prefix:
            return
        if len(prefix) != 8:
            raise dpkt.NeedData("short pcapng block header")
        block_type, block_length = struct_unpack(f"{endian}II", prefix)
        if block_length < 12:
            raise dpkt.UnpackError("invalid pcapng block length")
        raw_block = prefix + capture.read(block_length - 8)
        if len(raw_block) != block_length:
            raise dpkt.NeedData("short pcapng block")
        if block_type == dpkt.pcapng.PCAPNG_BT_IDB:
            interfaces.append(_pcapng_interface(idb_class(raw_block), little_endian))
            continue
        if block_type not in (dpkt.pcapng.PCAPNG_BT_EPB, dpkt.pcapng.PCAPNG_BT_PB):
            continue
        block = epb_class(raw_block) if block_type == dpkt.pcapng.PCAPNG_BT_EPB else pb_class(raw_block)
        if block.iface_id >= len(interfaces):
            raise dpkt.UnpackError("pcapng packet names an unknown interface")
        linktype, divisor, offset = interfaces[block.iface_id]
        timestamp = offset + (((block.ts_high << 32) | block.ts_low) / divisor)
        yield timestamp, block.pkt_data, linktype, block.pkt_len


def _tcp_records(path: str | Path, stats: IngestStats):
    """Yield decoded TCP records while updating one pass's wire counters."""
    try:
        with Path(path).open("rb") as capture:
            stats.file_format = "pcapng" if capture.read(4) == PCAPNG_MAGIC else "pcap"
            capture.seek(0)
            try:
                reader = open_reader(capture)
            except _DECODE_ERRORS as exc:
                stats.skipped[f"capture_header:{type(exc).__name__}"] += 1
                return
            stats.snaplen = int(reader.snaplen)
            records = (_pcapng_records(reader) if isinstance(reader, dpkt.pcapng.Reader)
                       else _pcap_records(reader))
            try:
                for frame_no, (ts, buf, linktype, original_length) in enumerate(records, start=1):
                    stats.frames += 1
                    stats.linktypes[linktype] += 1
                    stats.truncated |= len(buf) < original_length
                    decoded = _tcp_payload(linktype, buf, stats)
                    if decoded is not None:
                        yield frame_no, ts, *decoded
            except _DECODE_ERRORS as exc:
                stats.skipped[f"capture_record:{type(exc).__name__}"] += 1
    except OSError:
        stats.skipped["capture_io"] += 1


def ingest(path: str | Path, budget: Budget | None = None, port_filter=None):
    """Stream a capture into bounded flows; return (FlowTable, IngestStats).

    Bad frames are counted and processing continues at the next capture record.
    An unreadable container/header/tail is counted without inventing a frame.
    No captured contents are printed or persisted by ingest.
    """
    stats = IngestStats()
    table = FlowTable(budget, stats)
    seen = set()
    for frame_no, ts, ip, tcp, payload, packet_offset in _tcp_records(path, stats):
        if port_filter and tcp.sport not in port_filter and tcp.dport not in port_filter:
            stats.skipped["port_filtered"] += 1
            continue
        src, dst = addr(ip)
        syn = bool(tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)
        rst = bool(tcp.flags & dpkt.tcp.TH_RST)
        synack = bool(tcp.flags & dpkt.tcp.TH_SYN) and bool(tcp.flags & dpkt.tcp.TH_ACK)
        key = table.key_for((src, tcp.sport, dst, tcp.dport), syn, rst, tcp.seq,
                            length=len(payload), synack=synack)
        seen.add(key)
        stats.tcp_segments += 1
        # SYN occupies one sequence number before any Fast Open data.
        sequence = tcp.seq + bool(tcp.flags & dpkt.tcp.TH_SYN) if payload else tcp.seq
        table.add(key, frame_no, ts, sequence, payload,
                  source=(src, tcp.sport), packet_offset=packet_offset,
                  first_packet_syn=syn)
    stats.total_flows = len(seen)
    return table, stats


def _triage_candidates(path: str | Path) -> tuple[set[tuple], dict[tuple, int], IngestStats]:
    """Find mail candidates without retaining or reassembling their streams.

    A flow is admitted by either endpoint's conventional mail port or by the
    first contiguous payload bytes in either direction. Only four byte
    positions per direction are retained, including across split TCP segments.

    This pass assigns each flow its Wireshark ``tcp.stream`` index over all
    TCP flows, including flows excluded from mail analysis. Counting only
    retained flows would produce incorrect indices whenever triage filters
    out a non-mail flow.
    """
    stats = IngestStats()
    generations = FlowTable(stats=stats)
    seen: set[tuple] = set()
    candidates: set[tuple] = set()
    # Insertion-ordered: Wireshark numbers a stream on the frame it first
    # appears, and so does this, including a new generation after port reuse.
    stream_index: dict[tuple, int] = {}
    streams = 0
    prefix_bytes: dict[tuple[tuple, tuple[str, int]], dict[int, int]] = {}

    for _frame, _ts, ip, tcp, payload, _offset in _tcp_records(path, stats):
        src, dst = addr(ip)
        syn = bool(tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)
        rst = bool(tcp.flags & dpkt.tcp.TH_RST)
        synack = bool(tcp.flags & dpkt.tcp.TH_SYN) and bool(tcp.flags & dpkt.tcp.TH_ACK)
        key = generations.key_for((src, tcp.sport, dst, tcp.dport), syn, rst, tcp.seq,
                                  length=len(payload), synack=synack)
        seen.add(key)
        if key not in stream_index:
            previous = (*key[:4], key[4] - 1)
            if not tcp.flags & dpkt.tcp.TH_SYN and previous in stream_index:
                # Wireshark opens a tcp.stream only on SYN or SYN-ACK; data
                # after a RST stays in the reset flow's stream even though
                # it is a separate conversation here.
                stream_index[key] = stream_index[previous]
            else:
                stream_index[key] = streams
                streams += 1
        stats.tcp_segments += 1
        if tcp.sport in MAIL_SERVER_PORTS or tcp.dport in MAIL_SERVER_PORTS:
            candidates.add(key)
        if not payload or key in candidates:
            continue

        sequence = tcp.seq + bool(tcp.flags & dpkt.tcp.TH_SYN)
        prefix_key = (key, (src, tcp.sport))
        positions = prefix_bytes.setdefault(prefix_key, {})
        for index, byte in enumerate(payload[:4]):
            positions.setdefault(sequence + index, byte)
        first = min(positions)
        positions = {position: byte for position, byte in positions.items()
                     if position < first + 4}
        prefix_bytes[prefix_key] = positions
        prefix = bytearray()
        position = first
        while position in positions and len(prefix) < 4:
            prefix.append(positions[position])
            position += 1
        if any(bytes(prefix).startswith(signature) for signature in MAIL_PAYLOAD_PREFIXES):
            candidates.add(key)

    stats.total_flows = len(seen)
    stats.candidate_flows = len(candidates)
    return candidates, stream_index, stats


def _ingest_candidates(path: str | Path, candidates: set[tuple],
                       budget: Budget | None = None) -> tuple[FlowTable, IngestStats]:
    """Second pass: retain payload and provenance for candidate flows only."""
    deep_stats = IngestStats()
    table = FlowTable(budget, deep_stats)
    if not candidates:
        return table, deep_stats
    for frame_no, ts, ip, tcp, payload, packet_offset in _tcp_records(path, deep_stats):
        src, dst = addr(ip)
        syn = bool(tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)
        rst = bool(tcp.flags & dpkt.tcp.TH_RST)
        synack = bool(tcp.flags & dpkt.tcp.TH_SYN) and bool(tcp.flags & dpkt.tcp.TH_ACK)
        key = table.key_for((src, tcp.sport, dst, tcp.dport), syn, rst, tcp.seq,
                            length=len(payload), synack=synack)
        if key not in candidates:
            continue
        sequence = tcp.seq + bool(tcp.flags & dpkt.tcp.TH_SYN) if payload else tcp.seq
        table.add(key, frame_no, ts, sequence, payload,
                  source=(src, tcp.sport), packet_offset=packet_offset,
                  first_packet_syn=syn)
    return table, deep_stats


def _sessions_from_table(table: FlowTable, stats: IngestStats,
                         stream_index: Mapping[tuple, int] | None = None) -> list[Session]:
    """Build sessions and attach V2b reassembly health to the ingest passport."""
    stream_index = stream_index or {}
    sessions: list[Session] = []
    ordered = sorted(table.flows.items(), key=lambda item: item[1]["first_frame"])
    for index, (key, flow) in enumerate(ordered, start=1):
        server, client = _server_and_client(((key[0], key[1]), (key[2], key[3])))
        observations = flow["observations"]
        client_reassembly = _reassemble(
            item for item in observations if item.direction == "client_to_server"
        )
        server_reassembly = _reassemble(
            item for item in observations if item.direction == "server_to_client"
        )
        conflicts = [
            {"direction": direction, **conflict}
            for direction, result in (
                ("client_to_server", client_reassembly),
                ("server_to_client", server_reassembly),
            )
            for conflict in result["conflicts"]
        ]
        holes = client_reassembly["holes"] + server_reassembly["holes"]
        incomplete = bool(flow["incomplete"] or holes or conflicts)
        stats.sessions_with_holes += int(bool(holes))
        stats.sessions_with_conflicting_overlaps += int(bool(conflicts))
        stats.sessions_incomplete += int(incomplete)
        midstream = bool(flow["midstream"])
        session_id = f"s{index}"
        stats.midstream_sessions[session_id] = midstream
        sessions.append(Session(
            id=session_id,
            five_tuple={"client_ip": client[0], "client_port": client[1],
                        "server_ip": server[0], "server_port": server[1], "transport": "tcp"},
            tcp_stream=stream_index.get(key),
            packets={"first": flow["first_frame"], "last": flow["last_frame"]},
            client_to_server=client_reassembly.first_stream(),
            server_to_client=server_reassembly.first_stream(),
            packet_observations=observations,
            incomplete=incomplete,
            holes=holes,
            conflicts=conflicts,
            midstream=midstream,
        ))
    return sessions


def ingest_pcap_with_stats(path: str | Path) -> tuple[list[Session], IngestStats]:
    """Triage, then reassemble only candidate mail flows and return health data.

    Elapsed time and traced Python allocation measurements remain diagnostic
    fields on IngestStats, outside the deterministic canonical report. The
    benchmark harness records elapsed samples and process peak RSS.
    """
    started = time.perf_counter()
    owns_trace = not tracemalloc.is_tracing()
    trace_start = 0
    if owns_trace:
        tracemalloc.start()
    else:
        trace_start = tracemalloc.get_traced_memory()[0]

    candidates, stream_index, stats = _triage_candidates(path)
    table, deep_stats = _ingest_candidates(path, candidates)
    stats.flows_evicted = deep_stats.flows_evicted
    stats.flows_truncated = deep_stats.flows_truncated
    sessions = _sessions_from_table(table, stats, stream_index)

    # Measured precisely and left off the canonical report. Bucketing cannot fix
    # this: every bucket has a boundary that machine load can cross, which is
    # what the 100 ms cliff did. Report consumers get reproducible capture
    # facts; performance belongs in docs/BENCHMARKS.json.
    stats.elapsed_time_ms = (time.perf_counter() - started) * 1000
    current, peak = tracemalloc.get_traced_memory()
    stats.peak_memory_bytes = peak if owns_trace else max(0, current - trace_start)
    if owns_trace:
        tracemalloc.stop()
    return sessions, stats


def ingest_pcap(path: str | Path) -> list[Session]:
    """Triage a PCAP and return deterministic candidate sessions.

    Frame numbers are one-based PCAP indices. ``payload_packet_offset`` and all
    derived evidence offsets are zero-based from the start of that captured frame.
    Use ``ingest`` when a caller explicitly needs every TCP flow rather than the
    report pipeline's mail-candidate boundary.
    """
    sessions, _ = ingest_pcap_with_stats(path)
    return sessions
