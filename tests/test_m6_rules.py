import unittest

from sms.m1_ingest import ingest_pcap
from sms.m2_protocol import classify_protocols
from sms.m3_transition import analyse_transition
from sms.m4_tls import analyse_tls
from sms.m5_x509 import analyse_certificate
from sms.m6_rules import apply_rules


def analysed_sessions():
    sessions = classify_protocols(ingest_pcap("out/sample.pcap"))
    for session in sessions:
        analyse_transition(session)
        analyse_tls(session)
        analyse_certificate(session)
        apply_rules(session)
    return sessions


EXPECTED_RULE_IDS = [
    [],
    ["TLS-VER-DEPRECATED", "DOWNGRADE-DELTA", "CIPHER-CBC", "KEX-NO-FS", "CERT-SELF-SIGNED", "CERT-WEAK-KEY"],
    ["STARTTLS-NOT-OFFERED", "CLEARTEXT-AUTH"],
    ["STARTTLS-STRIP-SUSPECTED", "CLEARTEXT-AUTH"],
    ["CERT-EXPIRED"],
    ["PQ-HYBRID-OBSERVED"],
]


class RulesTests(unittest.TestCase):
    def test_fixture_rule_ids_match_ground_truth(self):
        sessions = analysed_sessions()
        for session, expected in zip(sessions, EXPECTED_RULE_IDS):
            self.assertEqual({item.rule_id for item in session.findings}, set(expected), session.id)

    def test_downgrade_escalates_tls_ver_deprecated_severity(self):
        s2 = analysed_sessions()[1]
        deprecated = next(item for item in s2.findings if item.rule_id == "TLS-VER-DEPRECATED")
        self.assertEqual(deprecated.severity, "critical")  # escalated: delta=3 >= 2

    def test_rules_are_idempotent_and_have_frame_evidence(self):
        sessions = analysed_sessions()
        s2 = sessions[1]
        before = len(s2.findings)
        apply_rules(s2)
        self.assertEqual(len(s2.findings), before)
        for finding in s2.findings:
            self.assertTrue(finding.evidence, finding.rule_id)


if __name__ == "__main__":
    unittest.main()
