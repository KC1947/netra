import unittest

from sms.contracts import Finding, Session
from sms.judgement.epistemic import UntieredFactError, partition
from sms.m8_score import score_session


class EpistemicTests(unittest.TestCase):
    @staticmethod
    def finding(tier):
        return Finding(
            rule_id="TIERED",
            confidence_band="certain",
            severity="high",
            confidence=1.0,
            what="test",
            why="test",
            fix="test",
            remediation_id="test",
            remediation_effort="one_line_reload",
            tier=tier,
        )

    def test_partition_rejects_missing_and_unknown_tiers(self):
        for fact in ({"key": "missing"}, {"key": "unknown", "tier": "PROBABLY"}):
            with self.subTest(fact=fact), self.assertRaises(UntieredFactError):
                partition([fact])

    def test_untiered_finding_cannot_reach_scoring(self):
        session = Session("s1", {"server_port": 25})
        session.findings.append(self.finding(None))
        with self.assertRaises(UntieredFactError):
            score_session(session)

    def test_tiers_control_risk_and_separate_coverage(self):
        observed = Session("observed", {"server_port": 25})
        observed.findings.append(self.finding("OBSERVED"))
        deduced = Session("deduced", {"server_port": 25})
        deduced.findings.append(self.finding("DEDUCED"))
        inferred = Session("inferred", {"server_port": 25})
        inferred.findings.append(self.finding("INFERRED"))

        for session in (observed, deduced, inferred):
            score_session(session)

        self.assertGreater(observed.observed_risk, 0)
        self.assertGreater(deduced.observed_risk, 0)
        self.assertEqual(inferred.observed_risk, 0)
        self.assertGreater(deduced.deduced_coverage, 0)
        self.assertGreater(inferred.inferred_coverage, 0)

    def test_not_observable_reason_codes_are_closed_and_required(self):
        session = Session("s1", {"server_port": 25})
        session.fact_reason_codes["protocol"] = "generic_unknown"
        with self.assertRaisesRegex(ValueError, "outside the closed vocabulary"):
            session.to_dict()


if __name__ == "__main__":
    unittest.main()
