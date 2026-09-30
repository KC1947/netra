#!/usr/bin/env python3
"""Build deterministic non-mail background traffic and independent needle truth."""

from __future__ import annotations

import argparse
import hashlib
from ipaddress import IPv4Address
import json
from pathlib import Path

import dpkt


ROOT = Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _ethernet_ipv4(src: str, dst: str, transport, protocol: int, *, reverse: bool = False) -> bytes:
    ip = dpkt.ip.IP(
        src=IPv4Address(src).packed,
        dst=IPv4Address(dst).packed,
        p=protocol,
        ttl=64,
        data=transport,
    )
    ip.len = len(ip)
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\x02\x00\x00\x00\x00\x02" if reverse else b"\x02\x00\x00\x00\x00\x01",
        dst=b"\x02\x00\x00\x00\x00\x01" if reverse else b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(ethernet)


def build_background(path: Path, *, tcp_flows: int = 5_000, udp_packets: int = 40_000) -> dict:
    """Write a sizeable capture whose generated grammar contains no mail flows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    packet_no = 0
    base_ts = 1_600_000_000.0
    with path.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        for flow in range(tcp_flows):
            third = (flow // 250) % 250
            fourth = flow % 250 + 1
            client = f"198.18.{third}.{fourth}"
            server = f"198.19.{third}.{fourth}"
            source_port = 10_000 + flow
            destination_port = (80, 443, 8080, 8443)[flow % 4]
            request = f"GET /object/{flow} HTTP/1.1\r\nHost: background.invalid\r\n\r\n".encode()
            response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
            packets = (
                _ethernet_ipv4(
                    client, server,
                    dpkt.tcp.TCP(sport=source_port, dport=destination_port,
                                 seq=1_000, flags=dpkt.tcp.TH_SYN),
                    dpkt.ip.IP_PROTO_TCP,
                ),
                _ethernet_ipv4(
                    server, client,
                    dpkt.tcp.TCP(sport=destination_port, dport=source_port,
                                 seq=7_000, ack=1_001,
                                 flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK),
                    dpkt.ip.IP_PROTO_TCP, reverse=True,
                ),
                _ethernet_ipv4(
                    client, server,
                    dpkt.tcp.TCP(sport=source_port, dport=destination_port,
                                 seq=1_001, ack=7_001,
                                 flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                                 data=request),
                    dpkt.ip.IP_PROTO_TCP,
                ),
                _ethernet_ipv4(
                    server, client,
                    dpkt.tcp.TCP(sport=destination_port, dport=source_port,
                                 seq=7_001, ack=1_001 + len(request),
                                 flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                                 data=response),
                    dpkt.ip.IP_PROTO_TCP, reverse=True,
                ),
            )
            for packet in packets:
                writer.writepkt(packet, ts=base_ts + packet_no / 100_000)
                packet_no += 1

        for index in range(udp_packets):
            third = (index // 250) % 250
            fourth = index % 250 + 1
            payload = b"synthetic-non-mail-background:" + index.to_bytes(4, "big")
            udp = dpkt.udp.UDP(
                sport=20_000 + index % 40_000,
                dport=(53, 123, 5353)[index % 3],
                data=payload,
            )
            udp.ulen = len(udp)
            packet = _ethernet_ipv4(
                f"203.0.{third}.{fourth}", f"203.1.{third}.{fourth}",
                udp, dpkt.ip.IP_PROTO_UDP,
            )
            writer.writepkt(packet, ts=base_ts + packet_no / 100_000)
            packet_no += 1

    return {
        "kind": "synthetic_non_mail",
        "path": _display_path(path),
        "packets": packet_no,
        "tcp_flows": tcp_flows,
        "known_mail_sessions": 0,
        "size_bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def _flow_key(left: tuple[str, int], right: tuple[str, int]) -> str:
    endpoints = sorted((left, right))
    return "|".join(f"{ip}:{port}" for ip, port in endpoints)


def _capture_flows(path: Path) -> tuple[list[str], int]:
    """Extract lab TCP five-tuples without calling the analyzer under test."""
    flows: dict[str, int] = {}
    packets = 0
    with path.open("rb") as capture:
        magic = capture.read(4)
        capture.seek(0)
        reader = (dpkt.pcapng.Reader(capture) if magic == b"\x0a\x0d\x0d\x0a"
                  else dpkt.pcap.Reader(capture))
        for frame_no, (_ts, raw) in enumerate(reader, start=1):
            packets = frame_no
            try:
                network = dpkt.ethernet.Ethernet(raw).data
            except dpkt.UnpackError:
                continue
            if not isinstance(network, dpkt.ip.IP) or not isinstance(network.data, dpkt.tcp.TCP):
                continue
            tcp = network.data
            key = _flow_key(
                (str(IPv4Address(network.src)), tcp.sport),
                (str(IPv4Address(network.dst)), tcp.dport),
            )
            flows.setdefault(key, frame_no)
    return [key for key, _frame in sorted(flows.items(), key=lambda item: item[1])], packets


def write_truth(output: Path, haystack: Path, background: Path,
                needles: list[Path], *, background_kind: str) -> dict:
    injected: list[dict] = []
    sources: list[dict] = []
    keys: set[str] = set()
    for needle in needles:
        flows, packets = _capture_flows(needle)
        duplicate = keys.intersection(flows)
        if duplicate:
            raise ValueError(f"needle captures reuse flow keys: {sorted(duplicate)}")
        keys.update(flows)
        source_name = _display_path(needle)
        sources.append({
            "path": source_name,
            "mail_sessions": len(flows),
            "packets": packets,
            "sha256": _sha256(needle),
        })
        injected.extend({"source_capture": source_name, "flow_key": key} for key in flows)

    _background_flows, background_packets = _capture_flows(background)
    _haystack_flows, haystack_packets = _capture_flows(haystack)
    truth = {
        "schema_version": 1,
        "measurement_basis": "exact canonical TCP endpoint-pair intersection",
        "background": {
            "kind": background_kind,
            "path": _display_path(background),
            "known_mail_sessions": 0,
            "packets": background_packets,
            "size_bytes": background.stat().st_size,
            "sha256": _sha256(background),
        },
        "needle_sources": sources,
        "injected_mail_sessions": len(injected),
        "injected_flows": injected,
        "haystack": {
            "path": _display_path(haystack),
            "packets": haystack_packets,
            "size_bytes": haystack.stat().st_size,
            "sha256": _sha256(haystack),
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(truth, indent=2, sort_keys=True) + "\n")
    return truth


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    background = subparsers.add_parser("background")
    background.add_argument("--output", type=Path, required=True)
    truth = subparsers.add_parser("truth")
    truth.add_argument("--output", type=Path, required=True)
    truth.add_argument("--haystack", type=Path, required=True)
    truth.add_argument("--background", type=Path, required=True)
    truth.add_argument("--background-kind", required=True)
    truth.add_argument("needles", type=Path, nargs="+")
    args = parser.parse_args()

    if args.command == "background":
        metadata = build_background(args.output.resolve())
        print(json.dumps(metadata, sort_keys=True))
        return 0
    result = write_truth(
        args.output.resolve(), args.haystack.resolve(), args.background.resolve(),
        [path.resolve() for path in args.needles],
        background_kind=args.background_kind,
    )
    print(json.dumps({
        "truth_file": str(args.output),
        "injected_mail_sessions": result["injected_mail_sessions"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
