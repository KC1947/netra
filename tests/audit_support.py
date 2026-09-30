"""Deterministic, offline PCAP constructors shared only by new audit tests."""
from pathlib import Path
import ipaddress
import dpkt
import json
import subprocess
import sys

from lab import tls_wire as wire

FIXTURES = Path(__file__).parent / "fixtures"
STAMP = 1590969600.0  # 2020-06-01 UTC


def zeros(n):
    return b"\x42" * n


def client_hello(**kwargs):
    return wire.client_hello(random_bytes=zeros, **kwargs)


def server_hello(version=wire.V_TLS13, cipher=0x1301, group=29, **kwargs):
    return wire.server_hello(version, cipher, group, random_bytes=kwargs.pop("random_bytes", zeros), **kwargs)


def with_extensions(record, extensions):
    """Replace a minimal Hello's extension vector, preserving outer lengths."""
    body = record[9:]
    cursor = 35 + body[34]
    if record[5] == 1:
        cursor += 2 + int.from_bytes(body[cursor:cursor+2], "big")
        cursor += 1 + body[cursor]
    else:
        cursor += 3  # cipher and compression
    body = body[:cursor] + wire._u16(len(extensions)) + extensions
    return wire._record(22, 0x303, wire._handshake(record[5], body))


def bounded_report(path):
    """No network: isolate each parser probe with CPU and wall-time bounds."""
    code = '''
import json, resource, sys, time
resource.setrlimit(resource.RLIMIT_CPU, (12, 12))
from sms.pipeline import run_pipeline
started = time.monotonic()
report = run_pipeline(sys.argv[1], ml=False)
print(json.dumps({"report": report, "elapsed": round(time.monotonic()-started, 4),
                  "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
'''
    result = subprocess.run([sys.executable, "-c", code, str(path)],
                            capture_output=True, text=True, timeout=20, check=True)
    data = json.loads(result.stdout)
    print(f"bounded {Path(path).name}: elapsed={data['elapsed']}s peak_rss_bytes={data['peak_rss_bytes']}")
    return data["report"]


def session_summary(report):
    return {"health": report["capture_health"]["analysis_status"],
            "coverage": report["evidence_coverage"], "risk": report["observed_risk"],
            "hndl": report["hndl"],
            "sessions": [{"id": s["id"], "stream": s["tcp_stream"], "packets": s["packets"],
                          "version": s["tls"]["negotiated_version"],
                          "group": s["tls"]["group"], "cipher": s["tls"]["cipher"],
                          "version_tier": s["fact_tiers"]["tls.negotiated_version"],
                          "coverage": s["evidence_coverage"], "risk": s["observed_risk"],
                          "findings": [(f["rule_id"], f["tier"]) for f in s["findings"]],
                          "incomplete": s.get("incomplete", False),
                          "conflicts": len(s.get("conflicts", []))} for s in report["sessions"]]}


class Capture:
    def __init__(self, timestamp=STAMP):
        self.frames = []
        self.timestamp = timestamp
        self.sequences = {}

    def add(self, direction, payload=b"", *, port=40000, server_port=465,
            seq=None, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH):
        client = ("192.0.2.1", port)
        server = ("192.0.2.2", server_port)
        src, dst = (client, server) if direction == "c" else (server, client)
        key = (port, server_port, direction)
        if seq is None:
            seq = self.sequences.get(key, 1000 if direction == "c" else 8000)
        tcp = dpkt.tcp.TCP(sport=src[1], dport=dst[1], seq=seq, ack=1,
                          flags=flags, win=65535, data=payload)
        tcp.off = 5
        ip = dpkt.ip.IP(src=ipaddress.ip_address(src[0]).packed,
                        dst=ipaddress.ip_address(dst[0]).packed,
                        p=6, ttl=64, data=tcp)
        ip.len = len(ip)
        eth = dpkt.ethernet.Ethernet(src=b"\x02\0\0\0\0\x01",
                                   dst=b"\x02\0\0\0\0\x02", type=0x0800, data=ip)
        self.frames.append((self.timestamp + len(self.frames) * .01, bytes(eth)))
        self.sequences[key] = seq + len(payload) + bool(flags & dpkt.tcp.TH_SYN) + bool(flags & dpkt.tcp.TH_FIN)
        return self

    def hello(self, *, port=40000, group=29, version=wire.V_TLS13, cipher=0x1301):
        self.add("c", client_hello(groups=(group,) if group else ()), port=port)
        self.add("s", server_hello(version, cipher, group), port=port)
        return self

    def starttls(self, *, port=40000):
        for direction, data in (("s", b"220 mail.example ESMTP\r\n"),
                                ("c", b"EHLO audit.example\r\n"),
                                ("s", b"250-mail.example\r\n250 STARTTLS\r\n"),
                                ("c", b"STARTTLS\r\n"),
                                ("s", b"220 Ready for TLS\r\n")):
            self.add(direction, data, port=port, server_port=25)
        return self

    def write(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            writer = dpkt.pcap.Writer(handle)
            for ts, data in self.frames:
                writer.writepkt(data, ts)
        return path
