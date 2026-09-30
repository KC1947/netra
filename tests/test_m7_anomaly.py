import copy
import json
from pathlib import Path
import unittest
import numpy as np
from sms.m9_report import build_report, render_html
from sms.m7_anomaly import FEATURES, _percentile, _train, apply_anomalies, extract_features

ORACLE = json.loads(Path('tests/ml_expectations.json').read_text())


def without_ml(report):
    report = copy.deepcopy(report)
    report.pop('ml_summary')
    for s in report['sessions']:
        s.pop('ml')
    return report


class AnomalyTests(unittest.TestCase):
    def test_certswap_oracle(self):
        expected = ORACLE['anomaly_demo.pcap']
        report = build_report('out/anomaly_demo.pcap', ml=True)
        ranked = sorted(report.sessions, key=lambda s: -s.ml['anomaly_score'])
        target = next(s for s in report.sessions if s.id == expected['session_id'])
        self.assertEqual(ranked.index(target) + 1, expected['rank'])
        self.assertEqual(target.ml['is_anomaly'], expected['is_anomaly'])
        self.assertEqual(target.ml['disagrees_with_rules'], expected['disagrees_with_rules'])
        normals = [s for s in report.sessions if s is not target]
        self.assertEqual(len(normals), expected['normal_sessions'])
        self.assertLessEqual(sum(s.ml['is_anomaly'] for s in normals), expected['max_normal_anomalies'])

        # Regression: a high-ranked ML-only session remains visible in the AI
        # review queue even though the rules have no medium-or-higher finding.
        self.assertFalse(any(f.severity in {'medium', 'high', 'critical'} for f in target.findings))
        rendered = render_html(report)
        self.assertIn('s25 - percentile', rendered)
        self.assertIn('rules/AI disagreement', rendered)

    def test_sample_oracle(self):
        report = build_report('out/sample.pcap', ml=True)
        self.assertEqual(report.sessions[0].ml['is_anomaly'], ORACLE['sample.pcap']['s1']['is_anomaly'])

    def test_honesty_determinism_and_privacy(self):
        for path in ('out/sample.pcap', 'out/anomaly_demo.pcap'):
            off = build_report(path, ml=False).to_dict()
            on = build_report(path, ml=True)
            self.assertEqual(without_ml(off), without_ml(on.to_dict()))
            self.assertEqual(on.to_dict(), build_report(path, ml=True).to_dict())
            self.assertTrue(all(s['ml'] is None for s in off['sessions']))
            rendered = json.dumps(on.to_dict()) + render_html(on)
            for secret in ('supersecret', 'AGxvZ2lu', 'login'):
                self.assertNotIn(secret, rendered)
            self.assertIn('AI review queue (unusual ≠ malicious)', rendered)

    def test_ensemble_scores_are_model_outputs_and_cached(self):
        report = build_report('out/sample.pcap', ml=True)
        trained = _train()
        self.assertIs(trained, _train())
        # ccfc472 changed the M7 spec to a 215-session mixed baseline with
        # capture-level GroupKFold: this unseen fixture uses 157/58, not the
        # old 192/48 row split of the 240-session synthetic-only baseline.
        self.assertEqual(len(trained.training), 157)
        self.assertEqual(len(trained.calibration), 58)
        self.assertFalse(np.shares_memory(trained.training, trained.calibration))
        training_captures = {c['sha256'] for c in trained.provenance['training']}
        calibration_captures = {c['sha256'] for c in trained.provenance['calibration']}
        self.assertTrue(training_captures.isdisjoint(calibration_captures))
        rows = extract_features(report.sessions)
        if_scores = trained.ensemble.score_if(rows)
        hbos_scores = trained.ensemble.score_hbos(rows)
        for session, if_score, hbos_score in zip(report.sessions, if_scores, hbos_scores):
            robust_z = max(if_score, hbos_score)
            self.assertEqual(session.ml['anomaly_score'], robust_z)
            self.assertEqual(
                session.ml['anomaly_percentile'],
                _percentile(robust_z, trained.calibration_scores),
            )
            self.assertEqual(session.ml['model'], 'IsolationForest+HBOS')
        # ccfc472 also forbids padding explanations to three: only factors
        # with observed baseline share <= 5% qualify, so zero to three is valid.
        for s in report.sessions:
            factors = s.ml['top_factors']
            self.assertLessEqual(len(factors), 3)
            for factor in factors:
                self.assertGreaterEqual(factor['baseline_share_pct'], 0.0)
                self.assertLessEqual(factor['baseline_share_pct'], 5.0)
            if not factors:
                self.assertIn('No single factor', s.ml['explanation'])
        self.assertEqual(apply_anomalies([], True)['anomalies'], 0)

    def test_unobservable_features_are_nan_not_numeric_sentinels(self):
        report = build_report('out/sample.pcap', ml=False)
        rows = extract_features(report.sessions)
        cleartext = rows[2]
        for feature in (
            'negotiated_version_ord', 'offered_version_ord', 'downgrade_delta',
            'forward_secrecy', 'hybrid_pq_flag', 'aead_flag', 'cbc_flag',
            'cert_key_bits', 'cert_days_to_expiry_at_capture', 'cert_self_signed',
            'cert_fp_share_for_server',
        ):
            self.assertTrue(np.isnan(cleartext[FEATURES.index(feature)]), feature)
