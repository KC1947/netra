"""A risk-bearing finding must carry frame evidence, enforced in one place.

``admit_finding`` is the only path by which a finding reaches a session. Before
it existed, the ``if evidence:`` check guarded the v1.5 conditional rules only,
so the eight legacy rules and m3's cleartext-AUTH finding could each emit an
OBSERVED, risk-contributing claim with an empty evidence list -- a confident
assertion about bytes nobody could look at.
"""

from __future__ import annotations

from pathlib import Path
import unittest

from sms.contracts import Evidence, Finding, Session, TlsInfo
from sms.judgement.epistemic import AFFECTS_RISK_VALUES, Tier, admit_finding
from sms.m6_rules import apply_rules
from sms.m8_score import score_session
from sms.m9_report import build_report

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = (
    "out/sample.pcap", "out/anomaly_demo.pcap", "out/multiclient.pcap",
    "out/baseline.pcap", "out/haystack.pcap",
    "tests/fixtures/real_mail.pcap", "tests/fixtures/mixed_enterprise.pcap",
    "tests/fixtures/recorded_mail_ethernet.pcapng",
)


def session(**tls) -> Session:
    item = Session("s1", {"server_ip": "10.0.0.2", "server_port": 25,
                          "client_ip": "10.0.0.1", "client_port": 1})
    item.protocol, item.protocol_confidence = "smtp", "high"
    item.transition.verdict, item.transition.confidence_band = "upgraded", "certain"
    item.fact_tiers["protocol"] = Tier.OBSERVED.value
    item.fact_tiers["transition.verdict"] = Tier.OBSERVED.value
    if tls:
        item.tls = TlsInfo(**tls)
    return item


def finding(rule_id: str, tier: str, evidence=()) -> Finding:
    return Finding(rule_id=rule_id, tier=tier, confidence_band="certain",
                   severity="critical", confidence=1.0, what="w", why="y", fix="f",
                   remediation_id="r", remediation_effort="one_line_reload",
                   evidence=list(evidence))


class EvidenceGuardTests(unittest.TestCase):
    def test_observed_finding_without_evidence_is_demoted(self):
        item = session()
        admit_finding(item, finding("PROBE", Tier.OBSERVED.value))
        self.assertEqual(item.findings[0].tier, Tier.NOT_OBSERVABLE.value)
        self.assertEqual(item.fact_tiers["finding.PROBE"], Tier.NOT_OBSERVABLE.value)
        self.assertEqual(item.fact_reason_codes["finding.PROBE"],
                         "not_present_in_capture")

    def test_deduced_finding_without_evidence_is_demoted(self):
        """DEDUCED also reaches observed_risk, so it needs the same guard."""
        item = session()
        admit_finding(item, finding("PROBE", Tier.DEDUCED.value))
        self.assertEqual(item.findings[0].tier, Tier.NOT_OBSERVABLE.value)

    def test_evidence_bearing_finding_keeps_its_tier(self):
        item = session()
        ev = Evidence(7, "tls.server_hello.legacy_version", 2, 2, "TLS1.0")
        admit_finding(item, finding("PROBE", Tier.OBSERVED.value, [ev]))
        self.assertEqual(item.findings[0].tier, Tier.OBSERVED.value)
        self.assertNotIn("finding.PROBE", item.fact_reason_codes)

    def test_already_unobservable_finding_is_left_alone(self):
        """TLS-ECH-IN-USE is declared NOT_OBSERVABLE in the rule pack."""
        item = session()
        admit_finding(item, finding("PROBE", Tier.NOT_OBSERVABLE.value))
        self.assertEqual(item.findings[0].tier, Tier.NOT_OBSERVABLE.value)
        self.assertNotIn("finding.PROBE", item.fact_reason_codes)

    def test_demoted_finding_contributes_no_risk(self):
        """The point of the guard: an unprovable claim must not raise risk."""
        with_evidence = session(negotiated_version="TLS1.0",
                                cipher="TLS_RSA_WITH_AES_128_CBC_SHA",
                                forward_secrecy_status="NO")
        ev = [Evidence(7, "tls.server_hello.legacy_version", 2, 2, "TLS1.0")]
        with_evidence._tls_evidence = {"negotiated_version": ev, "cipher": ev}
        for key in ("tls.negotiated_version", "tls.forward_secrecy"):
            with_evidence.fact_tiers[key] = Tier.OBSERVED.value
        apply_rules(with_evidence)
        score_session(with_evidence)

        without = session(negotiated_version="TLS1.0",
                          cipher="TLS_RSA_WITH_AES_128_CBC_SHA",
                          forward_secrecy_status="NO")
        without._tls_evidence = {}
        apply_rules(without)
        score_session(without)

        self.assertGreaterEqual(with_evidence.observed_risk, 80)
        self.assertEqual(without.observed_risk, 0)
        self.assertEqual({f.rule_id for f in with_evidence.findings},
                         {f.rule_id for f in without.findings})
        for item in without.findings:
            self.assertEqual(item.tier, Tier.NOT_OBSERVABLE.value)

    def test_cleartext_auth_from_m3_passes_the_same_gate(self):
        """m3 kept its own appender with no guard, and CLEARTEXT-AUTH floors
        risk at 90 -- the most consequential claim in the engine."""
        import sms.m3_transition as m3
        self.assertFalse(hasattr(m3, "_append_once"),
                         "m3 has its own appender again; the gate is bypassable")
        item = session()
        admit_finding(item, finding("CLEARTEXT-AUTH", Tier.OBSERVED.value))
        score_session(item)
        self.assertEqual(item.findings[0].tier, Tier.NOT_OBSERVABLE.value)
        self.assertEqual(item.observed_risk, 0,
                         "an unprovable cleartext-AUTH claim still floored risk at 90")

    def test_the_gate_is_the_only_appender(self):
        """Grep the engine: a second appender is how this invariant was lost."""
        appenders = [
            f"{path.relative_to(ROOT)}:{number}"
            for path in (ROOT / "sms").rglob("*.py")
            for number, line in enumerate(path.read_text().splitlines(), 1)
            if "findings.append" in line
        ]
        self.assertEqual(appenders, ["sms/judgement/epistemic.py:61"],
                         f"findings are appended outside admit_finding: {appenders}")

    def test_no_shipped_capture_emits_an_evidence_free_risk_bearing_finding(self):
        for capture in CAPTURES:
            path = ROOT / capture
            if not path.exists():
                continue
            report = build_report(path, ml=False).to_dict()
            for item in report["sessions"]:
                for found in item["findings"]:
                    with self.subTest(capture=capture, session=item["id"],
                                      rule=found["rule_id"]):
                        if found["tier"] in AFFECTS_RISK_VALUES:
                            self.assertTrue(
                                found["evidence"],
                                "risk-bearing finding with no frame evidence",
                            )


if __name__ == "__main__":
    unittest.main()
