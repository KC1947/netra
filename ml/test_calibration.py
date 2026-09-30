"""M7 anomaly calibration regression tests.

Run: python -m unittest ml.test_calibration -v
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np

from ml.validate_anomaly import Ensemble, HBOS, false_alert_rate, planted_recall
from sms.m7_anomaly import (
    BASELINE, FEATURES, RARITY_SHARE_PCT, _explain, _split_baseline,
    _train, apply_anomalies, extract_features,
)
from sms.m9_report import analyse_sessions, build_report, render_html


class CalibrationTests(unittest.TestCase):
    def test_constant_feature_contributes_exactly_zero_even_outside_range(self):
        reference = np.ones((20, 2))
        evaluation = np.array([[1, 1], [-1e12, 1e12], [np.nan, np.nan]])
        hbos = HBOS().fit(reference)
        np.testing.assert_array_equal(hbos.contributions(evaluation), np.zeros((3, 2)))
        model = Ensemble().fit(reference, reference)
        np.testing.assert_array_equal(model.score(evaluation), np.zeros(3))
        np.testing.assert_array_equal(model.abstentions(evaluation), np.ones(3, dtype=bool))

    def test_constant_calibration_feature_cannot_contribute(self):
        train = np.arange(40, dtype=float).reshape(20, 2)
        model = Ensemble().fit(train, np.ones((10, 2)))
        evaluation = np.array([[1e12, -1e12]])
        np.testing.assert_array_equal(model.hbos.contributions(evaluation), [[0, 0]])
        np.testing.assert_array_equal(model.score(evaluation), [0])
        self.assertEqual(model.active_components, {"isolation_forest": False, "hbos": False})

    def test_zero_mad_with_a_tail_is_disabled_not_epsilon_scaled(self):
        calibration = np.array([1., 1., 1., 2.])
        location_scale = Ensemble._robust(calibration)
        self.assertEqual(location_scale, (1., 0.))
        np.testing.assert_array_equal(
            Ensemble._standardise(np.array([0., 2., 1e12]), location_scale), [0, 0, 0]
        )

    def test_validation_does_not_treat_abstentions_as_alerts_or_first_ranks(self):
        reference = np.ones((20, 2))
        model = Ensemble().fit(reference, reference)
        self.assertEqual(false_alert_rate(model, reference, threshold=0), 0)
        ranks = planted_recall(model.score, reference, {"outside": np.array([1e12, -1e12])})
        self.assertEqual(ranks["outside"]["rank"], 21)
        self.assertFalse(ranks["outside"]["in_top_10"])

    def test_sparse_binary_and_extreme_numeric_bins_are_bounded(self):
        matrix = np.column_stack([np.arange(100.), np.zeros(100)])
        matrix[-1] = [1e100, 1]
        hbos = HBOS().fit(matrix)
        self.assertTrue(all(1 < len(edges) <= 11 for edges in hbos.edges))
        self.assertAlmostEqual(hbos.shares[1][-1], 0.01)

    def test_inactive_component_does_not_floor_active_negative_scores(self):
        model = Ensemble()
        model._if_calibration = (0, 1)
        model._hbos_calibration = (0, 0)
        with patch.object(model, "score_if", return_value=np.array([-2.])), \
             patch.object(model, "score_hbos", side_effect=AssertionError("inactive")):
            np.testing.assert_array_equal(model.score(np.ones((1, 1))), [-2])

    def test_constant_column_changes_neither_estimator(self):
        train = np.column_stack([np.arange(20), np.ones(20)])
        calibration = np.column_stack([np.arange(0, 20, 2), np.ones(10)])
        model = Ensemble().fit(train, calibration)
        evaluation = np.array([[5, 1], [5, 1e12]], dtype=float)
        for score in (model.score_if, model.score_hbos):
            self.assertEqual(*score(evaluation))
        self.assertTrue(model.abstentions(np.full((1, 2), np.nan))[0])

    def test_explanations_never_pad_common_or_constant_features(self):
        baseline = np.zeros((100, len(FEATURES)))
        baseline[50:, 0] = 1  # Each value is common: 50%.
        baseline[-1, 1] = 1  # One genuinely rare value: 1%.
        hbos = HBOS().fit(baseline)
        self.assertEqual(_explain(baseline[0], baseline, hbos), [])
        factors = _explain(baseline[-1], baseline, hbos)
        self.assertEqual(len(factors), 1)
        self.assertEqual(factors[0]["feature"], FEATURES[1])
        self.assertEqual(factors[0]["baseline_share_pct"], 1.0)
        self.assertLessEqual(factors[0]["baseline_share_pct"], RARITY_SHARE_PCT)

    def test_capture_groups_are_disjoint_and_targets_excluded(self):
        artifact = json.loads(BASELINE.read_text())
        self.assertEqual(sum(len(c["features"]) for c in artifact["captures"]), 215)
        for filename in ("real_mail", "mixed_enterprise"):
            path = Path(f"tests/fixtures/{filename}.pcap")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            trained = _train(digest)
            self.assertIs(trained, _train(digest))
            train = {c["sha256"] for c in trained.provenance["training"]}
            cal = {c["sha256"] for c in trained.provenance["calibration"]}
            self.assertFalse(train & cal)
            self.assertNotIn(digest, train | cal)
            self.assertTrue(trained.provenance["scoring_capture_excluded"])
            self.assertTrue(all(trained.ensemble.active_components.values()))
            self.assertTrue(any(c["path"].startswith("tests/fixtures/")
                                for c in trained.provenance["calibration"]))
        groups = np.array(["a"] * 7 + ["b"] * 3 + ["c"] * 2)
        train, cal = _split_baseline(np.zeros((12, 1)), groups)
        self.assertFalse(set(groups[train]) & set(groups[cal]))

    def test_missing_capture_identity_abstains_without_leaking_or_flagging(self):
        sessions = analyse_sessions("out/sample.pcap")
        summary = apply_anomalies(sessions)
        self.assertEqual(summary["abstentions"], len(sessions))
        for session in sessions:
            self.assertFalse(session.ml["is_anomaly"])
            self.assertIsNone(session.ml["anomaly_score"])
            self.assertIsNone(session.ml["anomaly_percentile"])
            self.assertEqual(session.ml["top_factors"], [])

    def test_zero_scale_abstention_is_visible_in_json_and_html(self):
        model = copy.deepcopy(_train())
        model.ensemble._if_calibration = (0, 0)
        model.ensemble._hbos_calibration = (0, 0)
        with patch("sms.m7_anomaly._train", return_value=model):
            report = build_report("out/sample.pcap", ml=True)
        self.assertEqual(report.ml_summary["abstentions"], 6)
        for session in report.sessions:
            self.assertEqual(session.ml["abstention_reason"], "degenerate_calibration")
            self.assertIsNone(session.ml["anomaly_percentile"])
        self.assertIn("detector abstained", render_html(report))
        json.dumps(report.to_dict(), allow_nan=False)

    def test_target_reports_are_deterministic_and_isolated(self):
        for filename in ("real_mail", "mixed_enterprise"):
            path = f"tests/fixtures/{filename}.pcap"
            off = build_report(path, ml=False).to_dict()
            on = build_report(path, ml=True).to_dict()
            self.assertEqual(on, build_report(path, ml=True).to_dict())
            percentiles = [s["ml"]["anomaly_percentile"] for s in on["sessions"]]
            self.assertLess(min(percentiles), max(percentiles))
            for s in on["sessions"]:
                self.assertLessEqual(len(s["ml"]["top_factors"]), 3)
                self.assertTrue(all(f["baseline_share_pct"] <= RARITY_SHARE_PCT
                                    for f in s["ml"]["top_factors"]))
            for report in (off, on):
                report.pop("ml_summary")
                for session in report["sessions"]:
                    session.pop("ml")
            self.assertEqual(off, on)


if __name__ == "__main__":
    unittest.main()
