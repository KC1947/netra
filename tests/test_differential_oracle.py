"""Offline differential oracle between SecureMailScope and TShark TLS fields."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

from sms.m1_ingest import ingest_pcap
from sms.m2_protocol import classify_protocols
from sms.m4_tls import analyse_tls, is_grease


ROOT = Path(__file__).resolve().parents[1]
CAPTURES = (
    ROOT / "out" / "sample.pcap",
    ROOT / "out" / "multiclient.pcap",
    ROOT / "tests" / "fixtures" / "real_mail.pcap",
)
MINIMUM_AGREEMENT = 0.99
TSHARK = shutil.which("tshark")

_VERSION_CODES = {
    "SSL3.0": 0x0300,
    "TLS1.0": 0x0301,
    "TLS1.1": 0x0302,
    "TLS1.2": 0x0303,
    "TLS1.3": 0x0304,
}
_HEX_VALUE = re.compile(r"0x[0-9a-fA-F]+")


FlowKey = tuple[tuple[str, int], tuple[str, int]]


@dataclass
class HelloFields:
    client_hello: bool = False
    server_hello: bool = False
    offered_versions: tuple[int, ...] | None = None
    sni: str | None = None
    negotiated_version: int | None = None
    selected_cipher: int | None = None


def _values(layers: dict, field: str) -> list[str]:
    value = layers.get(field, [])
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _first(layers: dict, *fields: str) -> str | None:
    for field in fields:
        values = _values(layers, field)
        if values:
            return values[0]
    return None


def _code(value: str) -> int:
    match = _HEX_VALUE.search(value)
    if match is None:
        raise ValueError(f"TShark returned a non-hex TLS code point: {value!r}")
    return int(match.group(0), 16)


def _flow_key(src: str, src_port: int, dst: str, dst_port: int) -> FlowKey:
    first, second = sorted(((src, src_port), (dst, dst_port)))
    return first, second


def _layers_flow_key(layers: dict) -> FlowKey:
    src = _first(layers, "ip.src", "ipv6.src")
    dst = _first(layers, "ip.dst", "ipv6.dst")
    src_port = _first(layers, "tcp.srcport")
    dst_port = _first(layers, "tcp.dstport")
    if None in (src, dst, src_port, dst_port):
        raise ValueError(f"TShark TLS packet lacks a TCP endpoint: {layers!r}")
    return _flow_key(src, int(src_port), dst, int(dst_port))


def _tshark_rows(tshark: str, capture: Path, hello_type: int) -> list[dict]:
    fields = (
        "frame.number",
        "ip.src",
        "ipv6.src",
        "tcp.srcport",
        "ip.dst",
        "ipv6.dst",
        "tcp.dstport",
        "tls.handshake.version",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.ciphersuite",
        "tls.handshake.extensions_server_name",
    )
    command = [
        tshark,
        "-n",
        "-r",
        str(capture),
        "-Y",
        f"tls.handshake.type == {hello_type}",
        "-T",
        "json",
    ]
    for field in fields:
        command.extend(("-e", field))
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [packet["_source"]["layers"] for packet in json.loads(completed.stdout)]


def _tshark_fields(tshark: str, capture: Path) -> dict[FlowKey, HelloFields]:
    result: dict[FlowKey, HelloFields] = {}
    for layers in _tshark_rows(tshark, capture, 1):
        fields = result.setdefault(_layers_flow_key(layers), HelloFields())
        if fields.client_hello:
            continue
        supported = tuple(
            code for code in (
                _code(value)
                for value in _values(layers, "tls.handshake.extensions.supported_version")
            )
            if not is_grease(code)
        )
        legacy = _first(layers, "tls.handshake.version")
        fields.offered_versions = supported or ((_code(legacy),) if legacy is not None else ())
        sni = _first(layers, "tls.handshake.extensions_server_name")
        fields.sni = sni.rstrip(".").lower() if sni else None
        fields.client_hello = True

    for layers in _tshark_rows(tshark, capture, 2):
        fields = result.setdefault(_layers_flow_key(layers), HelloFields())
        if fields.server_hello:
            continue
        selected = _first(layers, "tls.handshake.extensions.supported_version")
        legacy = _first(layers, "tls.handshake.version")
        cipher = _first(layers, "tls.handshake.ciphersuite")
        fields.negotiated_version = _code(selected or legacy) if selected or legacy else None
        fields.selected_cipher = _code(cipher) if cipher is not None else None
        fields.server_hello = True
    return result


def _securemailscope_fields(capture: Path) -> dict[FlowKey, HelloFields]:
    sessions = classify_protocols(ingest_pcap(capture))
    result: dict[FlowKey, HelloFields] = {}
    for session in sessions:
        analyse_tls(session)
        flow = session.five_tuple
        key = _flow_key(
            flow["client_ip"],
            int(flow["client_port"]),
            flow["server_ip"],
            int(flow["server_port"]),
        )
        fields = result.setdefault(key, HelloFields())
        fields.client_hello = session.tls.client_hello_frame is not None
        fields.server_hello = session.tls.server_hello_frame is not None
        if fields.client_hello:
            offered = tuple(session.tls.offered_versions)
            fallback = _VERSION_CODES.get(session.tls.offered_version or "")
            fields.offered_versions = offered or ((fallback,) if fallback is not None else ())
            sni = getattr(session, "_sni_hostname", None)
            fields.sni = sni.rstrip(".").lower() if sni else None
        if fields.server_hello:
            correlation = getattr(session, "_correlation_tls", {})
            fields.negotiated_version = correlation.get("selected_version")
            fields.selected_cipher = correlation.get("selected_cipher")
    return result


def compare_capture(tshark: str, capture: Path) -> dict:
    expected = _tshark_fields(tshark, capture)
    actual = _securemailscope_fields(capture)
    comparisons = 0
    matches = 0
    mismatches: list[str] = []

    for key in sorted(set(expected) | set(actual)):
        reference = expected.get(key, HelloFields())
        observed = actual.get(key, HelloFields())
        if reference.client_hello or observed.client_hello:
            for field in ("offered_versions", "sni"):
                comparisons += 1
                if getattr(reference, field) == getattr(observed, field):
                    matches += 1
                else:
                    mismatches.append(
                        f"{key} {field}: tshark={getattr(reference, field)!r} "
                        f"sms={getattr(observed, field)!r}"
                    )
        if reference.server_hello or observed.server_hello:
            for field in ("negotiated_version", "selected_cipher"):
                comparisons += 1
                if getattr(reference, field) == getattr(observed, field):
                    matches += 1
                else:
                    mismatches.append(
                        f"{key} {field}: tshark={getattr(reference, field)!r} "
                        f"sms={getattr(observed, field)!r}"
                    )

    return {
        "capture": str(capture.relative_to(ROOT)),
        "comparisons": comparisons,
        "matches": matches,
        "mismatches": mismatches,
        "agreement_rate": matches / comparisons if comparisons else 0.0,
    }


def run_differential_oracle(tshark: str = TSHARK or "tshark") -> dict:
    captures = [compare_capture(tshark, capture) for capture in CAPTURES]
    comparisons = sum(item["comparisons"] for item in captures)
    matches = sum(item["matches"] for item in captures)
    return {
        "captures": captures,
        "captures_compared": [item["capture"] for item in captures],
        "comparisons": comparisons,
        "matches": matches,
        "mismatches": [
            f"{item['capture']}: {mismatch}"
            for item in captures
            for mismatch in item["mismatches"]
        ],
        "agreement_rate": matches / comparisons if comparisons else 0.0,
    }


class DifferentialOracleTests(unittest.TestCase):
    @unittest.skipUnless(
        TSHARK,
        "tshark is absent; install TShark to run the offline TLS differential oracle",
    )
    def test_tls_fields_agree_with_tshark(self):
        result = run_differential_oracle(TSHARK)
        print(
            "TShark differential agreement: "
            f"{result['agreement_rate']:.3%} "
            f"({result['matches']}/{result['comparisons']} fields) across "
            f"{', '.join(result['captures_compared'])}"
        )
        self.assertGreater(result["comparisons"], 0)
        self.assertGreaterEqual(
            result["agreement_rate"],
            MINIMUM_AGREEMENT,
            "\n".join(result["mismatches"]),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
