import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

from sms.contracts import Evidence, PacketObservation, Session
from sms.m5_x509 import analyse_certificate
from sms.m6_rules import apply_rules
from sms.m8_score import score_session
from sms.m9_report import build_report


CAPTURE_TIME = datetime.datetime(2026, 9, 26, tzinfo=datetime.timezone.utc)


def _certificate_der(private_key, common_name: str) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    # A different issuer name keeps this focused on key strength rather than
    # the separate self-signed-certificate policy.
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture CA")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
    )
    algorithm = None if isinstance(
        private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)
    ) else hashes.SHA256()
    return builder.sign(private_key, algorithm).public_bytes(serialization.Encoding.DER)


def _analyse(der: bytes) -> Session:
    session = Session(
        id="cert-fixture",
        five_tuple={"server_port": 993},
        packets={"first": 1, "last": 1},
        packet_observations=[PacketObservation(1, "s2c", CAPTURE_TIME.timestamp(), 0, b"", 0)],
    )
    session._cert_der = der
    session._cert_evidence = [Evidence(1, "tls.certificate", 0, len(der), "certificate DER")]
    analyse_certificate(session)
    apply_rules(session)
    return session


class CertificateKeyTypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sessions = {
            "rsa_2048": _analyse(_certificate_der(
                rsa.generate_private_key(65537, 2048), "RSA 2048",
            )),
            "rsa_1024": _analyse(_certificate_der(
                rsa.generate_private_key(65537, 1024), "RSA 1024",
            )),
            "ec_p256": _analyse(_certificate_der(
                ec.generate_private_key(ec.SECP256R1()), "EC P-256",
            )),
            "ec_p192": _analyse(_certificate_der(
                ec.generate_private_key(ec.SECP192R1()), "EC P-192",
            )),
            "ed25519": _analyse(_certificate_der(
                ed25519.Ed25519PrivateKey.generate(), "Ed25519",
            )),
            "ed448": _analyse(_certificate_der(
                ed448.Ed448PrivateKey.generate(), "Ed448",
            )),
            "unsupported": _analyse(_certificate_der(dsa.generate_private_key(1024), "DSA")),
        }

    def test_spki_key_types_and_curve_names_are_extracted(self):
        self.assertEqual(self.sessions["rsa_2048"].certificate.key_type, "RSA")
        self.assertIsNone(self.sessions["rsa_2048"].certificate.curve)
        self.assertEqual(self.sessions["ec_p256"].certificate.key_type, "EC")
        self.assertEqual(self.sessions["ec_p256"].certificate.curve, "secp256r1")
        self.assertEqual(self.sessions["ec_p192"].certificate.curve, "secp192r1")
        self.assertEqual(self.sessions["ed25519"].certificate.key_type, "Ed25519")
        self.assertEqual(self.sessions["ed448"].certificate.key_type, "Ed448")

    def test_only_rsa_1024_and_ec_p192_are_weak(self):
        weak = {
            name
            for name, session in self.sessions.items()
            if any(finding.rule_id == "CERT-WEAK-KEY" for finding in session.findings)
        }
        self.assertEqual(weak, {"rsa_1024", "ec_p192"})

        for name in {"rsa_2048", "ec_p256", "ed25519", "ed448"}:
            with self.subTest(name=name):
                self.assertEqual(self.sessions[name].certificate.status, "VALID")
                self.assertEqual(self.sessions[name].certificate.key_strength, "VALID")

        for name in {"rsa_1024", "ec_p192"}:
            with self.subTest(name=name):
                certificate = self.sessions[name].certificate
                self.assertEqual(certificate.status, "INVALID")
                self.assertEqual(certificate.key_strength, "INVALID")
                self.assertIn(f"weak key ({certificate.key_type},", certificate.reason)

    def test_unknown_key_type_is_not_observable_and_never_guessed(self):
        session = self.sessions["unsupported"]
        self.assertIsNone(session.certificate.key_type)
        self.assertEqual(session.certificate.key_strength, "NOT_OBSERVABLE")
        self.assertEqual(session.certificate.status, "INDETERMINATE")
        self.assertIn("key-strength check NOT_OBSERVABLE", session.certificate.reason)
        self.assertFalse(any(f.rule_id == "CERT-WEAK-KEY" for f in session.findings))

        session.protocol_confidence = "certain"
        session.transition.confidence_band = "certain"
        session.tls.negotiated_version = "TLS1.2"
        score_session(session)
        self.assertLess(session.evidence_coverage, 100)

    def test_real_mail_p256_certificates_are_valid_and_not_weak(self):
        report = build_report("tests/fixtures/real_mail.pcap", ml=False)
        observable = [
            session for session in report.sessions
            if session.certificate.status != "NOT_OBSERVABLE"
        ]
        self.assertEqual(len(report.sessions), 37)
        self.assertTrue(observable)
        self.assertTrue(all(s.certificate.status == "VALID" for s in observable))
        self.assertTrue(all(s.certificate.key_type == "EC" for s in observable))
        self.assertTrue(all(s.certificate.curve == "secp256r1" for s in observable))
        self.assertFalse(any(
            finding.rule_id == "CERT-WEAK-KEY"
            for session in report.sessions
            for finding in session.findings
        ))


if __name__ == "__main__":
    unittest.main()
