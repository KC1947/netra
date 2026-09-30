"""Hostile-capture regressions from docs/LOGIC_SECURITY_REVIEW.md (H02, H04).

Every fixture is synthetic and built in memory; nothing here is real mail.
"""

from datetime import datetime, timezone
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import dpkt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from lab.tls_wire import V_TLS12, certificate, client_hello, server_hello
from server.app import app
from sms import m5_x509
from sms.delivery.cbom import build_cbom
from sms.delivery.pdf import render_pdf
from sms.m9_report import build_report, render_html
from sms.packet_view import packet_view
from sms.pipeline import run_pipeline

CANARY = b"CANARYpw7Q2xZ"


def _frame(payload, *, server, port, seq):
    client_ip, server_ip, client_port = b"\x0a\x00\x00\x0a", b"\x0a\x00\x00\x14", 42000
    src, dst, sport, dport = client_ip, server_ip, client_port, port
    if server:
        src, dst, sport, dport = dst, src, dport, sport
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, flags=0x18, data=payload)
    tcp.off = 5
    ip = dpkt.ip.IP(src=src, dst=dst, p=6, ttl=64, data=tcp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x02" + b"\x00" * 5, dst=b"\x02" + b"\x01" * 5,
                                        type=0x800, data=ip))


def _pcap_bytes(events, port=25, ts=1780000000):
    """``events`` is [(from_server, payload)]; returns classic-pcap bytes."""
    out = io.BytesIO()
    out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    seq = {False: 1, True: 1}
    for index, (server, data) in enumerate(events):
        frame = _frame(data, server=server, port=port, seq=seq[server])
        seq[server] += len(data)
        out.write(struct.pack("<IIII", ts, index * 1000, len(frame), len(frame)))
        out.write(frame)
    return out.getvalue()


def _pdf_text(pdf: bytes) -> str:
    from pypdf import PdfReader
    return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages)


class EvidenceWindowCanaryTests(unittest.TestCase):
    """H02: a secret next to (or inside) an evidence span reaches no output."""

    # Each conversation puts the canary in server response bytes that share a
    # TCP packet with the span STARTTLS-NOT-OFFERED cites.
    CASES = {
        "error-after-span": [
            (True, b"220 mail.example ESMTP\r\n"), (False, b"EHLO x\r\n"),
            (True, b"250 AUTH PLAIN\r\n535 5.7.8 " + CANARY + b"\r\n"),
            (False, b"AUTH PLAIN OTHERSECRET\r\n"),
        ],
        "error-before-span": [
            (True, b"220 mail.example ESMTP\r\n"), (False, b"EHLO x\r\n"),
            (True, b"421 4.7.0 " + CANARY + b"\r\n250 AUTH PLAIN\r\n"),
            (False, b"AUTH PLAIN OTHERSECRET\r\n"),
        ],
        "canary-inside-span": [
            (True, b"220 mail.example ESMTP\r\n"), (False, b"EHLO x\r\n"),
            (True, b"250-" + CANARY + b"\r\n250 AUTH PLAIN\r\n"),
            (False, b"AUTH PLAIN OTHERSECRET\r\n"),
        ],
    }

    @staticmethod
    def _leaks(text: str) -> list[str]:
        needles = {
            "ascii": CANARY.decode(),
            "hex": CANARY.hex(" "),
            "hex-compact": CANARY.hex(),
            "secret": "OTHERSECRET",
        }
        return [name for name, needle in needles.items() if needle.lower() in text.lower()]

    def _assert_windows_hold_no_canary(self, view):
        for window in view["evidence"]:
            shown = bytes.fromhex(window["hex_window"].replace(" ", ""))
            self.assertNotIn(CANARY, shown, window)
            self.assertNotIn(b"OTHERSECRET", shown, window)

    def test_canary_absent_from_every_output_path(self):
        for label, events in self.CASES.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / f"{label}.pcap"
                path.write_bytes(_pcap_bytes(events))
                report = run_pipeline(path, ml=False)
                rules = {finding["rule_id"] for finding in report["findings"]}
                # The fixture must actually produce a non-AUTH window, or this
                # test would pass vacuously.
                self.assertIn("STARTTLS-NOT-OFFERED", rules)
                views = [packet_view(path, report, session["id"]) for session in report["sessions"]]
                for view in views:
                    self._assert_windows_hold_no_canary(view)
                outputs = {
                    "json": json.dumps(report, sort_keys=True),
                    "html": render_html(report),
                    "cbom": json.dumps(build_cbom(report), sort_keys=True),
                    "pdf_text": _pdf_text(render_pdf(report)),
                    "packet_view": json.dumps(views, sort_keys=True),
                }
                for name, text in outputs.items():
                    self.assertEqual(self._leaks(text), [], f"{label}: {name}")

    def test_canary_absent_from_packet_endpoint(self):
        client = TestClient(app)
        for label, events in self.CASES.items():
            with self.subTest(case=label):
                upload = client.post("/api/captures/upload",
                                     files={"file": (f"{label}.pcap", _pcap_bytes(events))})
                self.assertEqual(upload.status_code, 200)
                started = client.post("/api/analyses",
                                      json={"capture_id": upload.json()["id"], "ml": False})
                analysis_id = started.json()["analysis_id"]
                client.get(f"/api/analyses/{analysis_id}/events")
                report = client.get(f"/api/analyses/{analysis_id}/report").json()
                bodies = [client.get(f"/api/analyses/{analysis_id}/report").text]
                for session in report["sessions"]:
                    response = client.get(
                        f"/api/analyses/{analysis_id}/sessions/{session['id']}/packets")
                    self.assertEqual(response.status_code, 200)
                    self._assert_windows_hold_no_canary(response.json())
                    bodies.append(response.text)
                for fmt in ("json", "html", "cbom"):
                    bodies.append(client.get(f"/api/analyses/{analysis_id}/export?format={fmt}").text)
                self.assertEqual(self._leaks("\n".join(bodies)), [], label)

    def test_cited_protocol_line_shows_only_its_status_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inside.pcap"
            path.write_bytes(_pcap_bytes(self.CASES["canary-inside-span"]))
            report = run_pipeline(path, ml=False)
            view = packet_view(path, report, "s1")
        window = next(item for item in view["evidence"] if item["rule_id"] == "STARTTLS-NOT-OFFERED")
        self.assertEqual(window["ascii_window"], "250")
        self.assertEqual(window["highlight"], [0, 3])
        self.assertTrue(window["redacted"])
        self.assertEqual(window["withheld_bytes"], window["byte_length"] - 3)

    def test_allowlisted_spans_are_shown_exactly_without_neighbours(self):
        report = build_report("out/sample.pcap", ml=False).to_dict()
        s4 = packet_view("out/sample.pcap", report, "s4")
        capability = next(item for item in s4["evidence"] if item["field"] == "smtp.capability")
        self.assertEqual((capability["ascii_window"], capability["redacted"]), ("XSNVVQRW", False))
        s = next(session for session in report["sessions"]
                 if any(f["rule_id"] == "CIPHER-CBC" for f in session["findings"]))
        view = packet_view("out/sample.pcap", report, s["id"])
        cipher = next(item for item in view["evidence"] if item["field"] == "tls.server_hello.cipher_suite")
        self.assertEqual((cipher["hex_window"], cipher["highlight"], cipher["redacted"]),
                         ("00 2f", [0, 2], False))


class NetworkStringEscapingTests(unittest.TestCase):
    """Banner and SNI bytes carrying markup never reach any output raw."""

    MARKUP = '"\'><img src=x onerror=alert(1)>'

    def test_hostile_banner_and_sni(self):
        markup = self.MARKUP.encode()
        captures = {
            "banner": (_pcap_bytes([
                (True, b"220 " + markup + b" ESMTP\r\n"), (False, b"EHLO x\r\n"),
                (True, b"250-" + markup + b"\r\n250 AUTH PLAIN\r\n"),
                (False, b"AUTH PLAIN OTHERSECRET\r\n"),
            ])),
            "sni": _pcap_bytes([
                (False, client_hello(server_name=self.MARKUP, random_bytes=lambda n: b"R" * n)),
                (True, server_hello(V_TLS12, 0xC02F, random_bytes=lambda n: b"S" * n)),
            ], port=993),
        }
        for label, capture in captures.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / f"{label}.pcap"
                path.write_bytes(capture)
                report = run_pipeline(path, ml=False)
                views = [packet_view(path, report, s["id"]) for s in report["sessions"]]
                for text in (json.dumps(report), render_html(report), json.dumps(views)):
                    self.assertNotIn("<img", text)
                    self.assertNotIn("onerror", text)


class WiresharkFilterTests(unittest.TestCase):
    def test_non_integer_stream_cannot_extend_the_filter(self):
        report = build_report("out/sample.pcap", ml=False).to_dict()
        expected = packet_view("out/sample.pcap", report, "s4")["wireshark_filter"]
        self.assertRegex(expected, r"^tcp\.stream eq \d+ && frame\.number == \d+$")
        for hostile in ('0 || frame.number > 0', '0" or 1', True, -1, 1.5):
            with self.subTest(value=hostile):
                tampered = json.loads(json.dumps(report))
                next(s for s in tampered["sessions"] if s["id"] == "s4")["tcp_stream"] = hostile
                emitted = packet_view("out/sample.pcap", tampered, "s4")["wireshark_filter"]
                self.assertRegex(emitted, r"^frame\.number == \d+$")


def _certificate_der(subject="SUBJECTNAME", issuer="ISSUERNAME") -> bytes:
    key = ec.derive_private_key(7, ec.SECP256R1())
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256()).public_bytes(Encoding.DER))


def _tls_capture(der: bytes) -> bytes:
    return _pcap_bytes([
        (False, client_hello(random_bytes=lambda n: b"R" * n)),
        (True, server_hello(V_TLS12, 0xC02F, random_bytes=lambda n: b"S" * n)),
        (True, certificate(der)),
    ], port=993)


class MalformedCertificateTests(unittest.TestCase):
    """H04: lazily parsed certificate properties yield INDETERMINATE, not a crash."""

    def _assert_malformed(self, certificate_dict, reason_codes, rendered: str, marker: str):
        self.assertEqual(certificate_dict["status"], "INDETERMINATE")
        self.assertEqual(certificate_dict["reason"], "certificate DER could not be parsed")
        self.assertEqual(reason_codes["certificate.status"], "malformed_certificate")
        self.assertEqual(reason_codes["certificate.key_strength"], "malformed_certificate")
        # Neither the offending bytes nor the parser's message reach output.
        for leaked in (marker, "ParseError", "InvalidValue", "\\xff", "�"):
            self.assertNotIn(leaked, rendered)

    def test_invalid_utf8_in_real_der_through_the_whole_pipeline(self):
        valid = _certificate_der()
        cases = {
            "subject": valid.replace(b"SUBJECTNAME", b"\xffUBJECTNAME"),
            "issuer": valid.replace(b"ISSUERNAME", b"\xffSSUERNAME"),
            "notBefore": valid.replace(b"260101000000Z", b"2601010000QQZ"),
            "notAfter": valid.replace(b"270101000000Z", b"2701010000QQZ"),
        }
        for label, der in cases.items():
            with self.subTest(field=label), tempfile.TemporaryDirectory() as directory:
                self.assertNotEqual(der, valid)
                path = Path(directory) / f"{label}.pcap"
                path.write_bytes(_tls_capture(der))
                with self.assertNoLogs(level="DEBUG"):
                    report = run_pipeline(path, ml=False)
                session = report["sessions"][0]
                rendered = json.dumps(report) + render_html(report)
                self._assert_malformed(session["certificate"], session["fact_reason_codes"],
                                       rendered, "UBJECTNAME" if label == "subject" else "SSUERNAME")

    def test_each_lazy_property_access_path(self):
        from sms.m1_ingest import ingest_pcap
        from sms.m2_protocol import classify_protocols
        from sms.m4_tls import analyse_tls

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "valid.pcap"
            path.write_bytes(_tls_capture(_certificate_der()))
            sessions = classify_protocols(ingest_pcap(path))
        for session in sessions:
            analyse_tls(session)
        session = next(item for item in sessions if getattr(item, "_cert_der", None))
        real = x509.load_der_x509_certificate(session._cert_der)
        secret = "BADBYTES\xff"

        for prop in ("subject", "issuer", "not_valid_before_utc", "not_valid_after_utc",
                     "signature_hash_algorithm"):
            with self.subTest(property=prop):
                def raising(_self, _prop=prop):
                    raise ValueError(f"error parsing asn1 value: {secret} at {_prop}")

                stub_type = type("StubCertificate", (), {
                    name: property(lambda _self, _n=name: getattr(real, _n))
                    for name in ("subject", "issuer", "not_valid_before_utc",
                                 "not_valid_after_utc", "signature_hash_algorithm")
                } | {prop: property(raising), "public_key": lambda _self: real.public_key()})
                session.fact_reason_codes.pop("certificate.status", None)
                with mock.patch.object(m5_x509.x509, "load_der_x509_certificate",
                                       return_value=stub_type()), \
                        self.assertNoLogs(level="DEBUG"):
                    m5_x509.analyse_certificate(session)
                self._assert_malformed(session.certificate.to_dict(), session.fact_reason_codes,
                                       json.dumps(session.to_dict()), secret)

    def test_valid_control_still_judged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "valid.pcap"
            path.write_bytes(_tls_capture(_certificate_der()))
            report = run_pipeline(path, ml=False)
        certificate_dict = report["sessions"][0]["certificate"]
        self.assertIn(certificate_dict["status"], {"VALID", "INVALID"})
        self.assertEqual(certificate_dict["sig_alg"], "sha256")


if __name__ == "__main__":
    unittest.main()
