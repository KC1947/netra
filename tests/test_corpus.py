import hashlib
from pathlib import Path
import tempfile
import unittest
from cryptography import x509
from lab.generate_corpus import generate, CERTS
from sms.m9_report import build_report


class CorpusTests(unittest.TestCase):
    def test_certificates_and_captures(self):
        certs = [x509.load_der_x509_certificate((CERTS / f'cert_{name}.der').read_bytes()) for name in ('A', 'B')]
        self.assertNotEqual(certs[0].issuer, certs[1].issuer)
        self.assertNotEqual(certs[0].public_key().public_numbers(), certs[1].public_key().public_numbers())
        self.assertTrue(all(c.public_key().key_size == 2048 for c in certs))
        baseline = build_report('out/baseline.pcap')
        self.assertEqual(len(baseline.sessions), 240)
        self.assertEqual(sum(s.protocol == 'imap' for s in baseline.sessions), 72)
        self.assertEqual(sum(s.tls.hybrid_pq_flag for s in baseline.sessions), 24)
        anomaly = build_report('out/anomaly_demo.pcap')
        self.assertEqual(len(anomaly.sessions), 41)
        self.assertTrue(all(s.certificate.status == 'VALID' for s in anomaly.sessions))
        self.assertTrue(all(f.severity not in {'medium', 'high', 'critical'} for s in anomaly.sessions for f in s.findings))
        self.assertEqual(anomaly.sessions[24]._cert_der, (CERTS / 'cert_B.der').read_bytes())

    def test_deterministic_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kind, seed, original in [('baseline', 7, 'baseline'), ('certswap', 11, 'anomaly_demo')]:
                dest = Path(tmp) / 'copy.pcap'
                generate(kind, seed=seed, out=dest)
                self.assertEqual(hashlib.sha256(dest.read_bytes()).digest(),
                                 hashlib.sha256(Path(f'out/{original}.pcap').read_bytes()).digest())
