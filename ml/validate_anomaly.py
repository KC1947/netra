"""Validate the unsupervised anomaly detector against captured sessions.

The harness deliberately needs no labelled attack corpus.  It measures planted
anomaly rank, held-out false alerts, model ablation, and top-10 stability.  Its
train, calibration, and test units are whole capture files so a session from a
capture can never leak across those sets.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Callable, Iterable

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import GroupKFold


class HBOS:
    """Histogram-based outlier score: sum ``-log(bin density)`` by feature."""

    def __init__(self, bins: int = 10, alpha: float = 1e-3):
        self.bins = bins
        self.alpha = alpha

    def fit(self, matrix: np.ndarray, active: np.ndarray | None = None) -> "HBOS":
        # Unobservable values are NaN, never a sentinel like -1. A sentinel
        # would share a histogram bin with real low values and make them normal.
        self.edges: list[np.ndarray] = []
        self.densities: list[np.ndarray] = []
        self.shares: list[np.ndarray] = []
        self.outside_densities: list[float] = []
        self.active = np.zeros(matrix.shape[1], dtype=bool)
        for index in range(matrix.shape[1]):
            column = matrix[:, index]
            observed = column[~np.isnan(column)]
            if len(observed) == 0 or observed.min() == observed.max():
                low = observed.min() if len(observed) else 0.0
                edges = np.array([low - 0.5, low + 0.5])
                counts = np.array([len(observed)])
            else:
                # Small/discrete columns often cannot support ten bins.
                # Cap resolution with the data's Freedman-Diaconis width so
                # ordinary values between observations do not land in a forest
                # of empty bins and inflate the held-out decision boundary.
                q25, q75 = np.percentile(observed, [25, 75])
                width = 2 * (q75 - q25) / np.cbrt(len(observed))
                # Cap BEFORE allocating edges, including extreme outliers.
                supported_bins = (
                    max(2, int(min(self.bins, np.ceil(np.ptp(observed) / width))))
                    if width > 0 else 2
                )
                counts, edges = np.histogram(observed, bins=min(self.bins, supported_bins))
                self.active[index] = True
            self.edges.append(edges)
            # Reserve one smoothed bucket for unseen values. Its denominator
            # must use the same observed population as the in-range buckets.
            denominator = counts.sum() + self.alpha * (len(counts) + 1)
            self.densities.append(
                (counts + self.alpha) / denominator
            )
            self.outside_densities.append(self.alpha / denominator)
            self.shares.append(counts / max(1, counts.sum()))
        if active is not None:
            self.active &= active
        return self

    def contributions(self, matrix: np.ndarray) -> np.ndarray:
        """Return per-feature scores; missing values contribute exactly zero."""
        result = np.zeros_like(matrix, dtype=float)
        for index in range(matrix.shape[1]):
            if not self.active[index]:
                continue
            values = matrix[:, index]
            observed = ~np.isnan(values)
            edges = self.edges[index]
            densities = self.densities[index]
            positions = np.clip(
                np.searchsorted(edges, np.nan_to_num(values), side="right") - 1,
                0,
                len(densities) - 1,
            )
            outside = (values < edges[0]) | (values > edges[-1])
            outside_density = self.outside_densities[index]
            selected = np.where(outside, outside_density, densities[positions])
            result[:, index] = np.where(observed, -np.log(selected), 0.0)
        return result

    def score(self, matrix: np.ndarray) -> np.ndarray:
        return self.contributions(matrix).sum(axis=1)


class Ensemble:
    """Maximum of robust z-scores calibrated on held-out normal sessions.

    Training percentiles are intentionally not used.  They cap every score
    beyond the training range at the same value and destroy tail resolution.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed

    def fit(self, train: np.ndarray, calibration: np.ndarray) -> "Ensemble":
        if not len(train):
            raise ValueError("anomaly training matrix is empty")
        if not len(calibration):
            raise ValueError("anomaly calibration matrix is empty")
        # Isolation Forest requires finite numbers.  The canonical feature
        # matrix remains NaN-bearing and HBOS sees those NaNs; this conversion
        # is a private estimator adapter, not an observable-value encoding.
        # A constant/unobserved feature in either reference set has no usable
        # spread. Ignore it in BOTH estimators, including out-of-range inputs.
        def varying(matrix):
            return np.array([
                len(values := column[np.isfinite(column)]) > 1
                and np.ptp(values) > 0
                for column in matrix.T
            ])

        self.active_features = varying(train) & varying(calibration)
        finite_train = self._finite(train)
        self.iforest = IsolationForest(
            n_estimators=200,
            random_state=self.seed,
            contamination="auto",
        ).fit(finite_train) if self.active_features.any() else None
        self.hbos = HBOS().fit(train, active=self.active_features)
        self._if_calibration = self._robust(
            self._raw_if(calibration)
        )
        self._hbos_calibration = self._robust(self.hbos.score(calibration))
        return self

    @staticmethod
    def _robust(scores: np.ndarray) -> tuple[float, float]:
        median = float(np.median(scores))
        mad = float(np.median(np.abs(scores - median)) * 1.4826)
        return median, mad

    def _finite(self, matrix: np.ndarray) -> np.ndarray:
        return np.nan_to_num(matrix[:, self.active_features], nan=-1.0)

    def _raw_if(self, matrix: np.ndarray) -> np.ndarray:
        if self.iforest is None or not len(matrix):
            return np.zeros(len(matrix))
        return -self.iforest.score_samples(self._finite(matrix))

    @staticmethod
    def _standardise(raw: np.ndarray, location_scale: tuple[float, float]) -> np.ndarray:
        median, mad = location_scale
        # No epsilon, substitute spread, or manufactured evidence.
        if not np.isfinite(mad) or mad <= 0:
            return np.zeros_like(raw, dtype=float)
        return (raw - median) / mad

    @property
    def active_components(self) -> dict[str, bool]:
        return {
            "isolation_forest": self._if_calibration[1] > 0,
            "hbos": self._hbos_calibration[1] > 0,
        }

    def abstentions(self, matrix: np.ndarray) -> np.ndarray:
        if not any(self.active_components.values()):
            return np.ones(len(matrix), dtype=bool)
        return ~np.isfinite(matrix[:, self.active_features]).any(axis=1)

    def score_if(self, matrix: np.ndarray) -> np.ndarray:
        return self._standardise(self._raw_if(matrix), self._if_calibration)

    def score_hbos(self, matrix: np.ndarray) -> np.ndarray:
        return self._standardise(self.hbos.score(matrix), self._hbos_calibration)

    def score(self, matrix: np.ndarray) -> np.ndarray:
        components = [
            score(matrix) for name, score in (
                ("isolation_forest", self.score_if), ("hbos", self.score_hbos)
            ) if self.active_components[name]
        ]
        return np.maximum.reduce(components) if components else np.zeros(len(matrix))


def planted_recall(
    model_score: Callable[[np.ndarray], np.ndarray],
    normal_test: np.ndarray,
    plants: dict[str, np.ndarray],
    k: int = 10,
) -> dict[str, dict[str, int | bool]]:
    """Return each plant's rank among held-out normals plus that plant."""
    result: dict[str, dict[str, int | bool]] = {}
    for name, planted in plants.items():
        pool = np.vstack([normal_test, planted[None, :]])
        scores = model_score(pool)
        # Conservative tied rank: a disabled detector returning all zeros
        # must not claim that every injected anomaly ranked first.
        rank = int((scores >= scores[-1]).sum())
        result[name] = {"rank": rank, "total": len(pool), "in_top_10": rank <= k}
    return result


def false_alert_rate(model: Ensemble, normal_test: np.ndarray, threshold: float) -> float:
    """Return false alerts per 1,000 held-out normal sessions."""
    return float(1000 * np.mean(
        ~model.abstentions(normal_test) & (model.score(normal_test) >= threshold)
    ))


def stability(
    fit_fn: Callable[[int], Ensemble],
    train: np.ndarray,
    calibration: np.ndarray,
    evaluation: np.ndarray,
    seeds: Iterable[int] = (1, 2, 3, 4, 5),
    k: int = 10,
) -> float:
    """Mean pairwise Jaccard similarity of top-k sets across random seeds."""
    top_sets = []
    for seed in seeds:
        model = fit_fn(seed).fit(train, calibration)
        top_sets.append(set(np.argsort(-model.score(evaluation))[:k]))
    pairs = [
        (left, right)
        for index, left in enumerate(top_sets)
        for right in top_sets[index + 1 :]
    ]
    if not pairs:
        return 1.0
    return float(np.mean([len(left & right) / len(left | right) for left, right in pairs]))


@dataclass(frozen=True)
class _CaptureMatrix:
    path: Path
    matrix: np.ndarray


def _discover(directory: str | Path) -> list[Path]:
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"capture directory does not exist: {root}")
    candidates = sorted(
        path for path in root.iterdir()
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng", ".cap"}
    )
    # Exact duplicate files are one capture for leakage purposes.
    unique: dict[str, Path] = {}
    for path in candidates:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        unique.setdefault(digest, path)
    paths = sorted(unique.values(), key=lambda path: path.name)
    if len(paths) < 3:
        raise ValueError("validate-anomaly requires at least three distinct capture files")
    return paths


def _normal_matrix(path: Path) -> np.ndarray:
    from sms.m7_anomaly import extract_features
    from sms.m9_report import analyse_sessions

    sessions = analyse_sessions(path)
    normal = [
        session for session in sessions
        if not any(
            finding.severity in {"medium", "high", "critical"}
            for finding in session.findings
        )
    ]
    return extract_features(normal)


def _partition(captures: list[_CaptureMatrix]) -> tuple[list[_CaptureMatrix], ...]:
    """Balance whole captures across train/calibration/test without overlap."""
    groups = np.array([i for i, capture in enumerate(captures) for _ in capture.matrix])
    splits = GroupKFold(n_splits=3).split(np.zeros((len(groups), 1)), groups=groups)
    return tuple([
        captures[index] for index in sorted(set(groups[held_out]))
    ] for _, held_out in splits)


def _stack(group: list[_CaptureMatrix]) -> np.ndarray:
    matrices = [item.matrix for item in group if len(item.matrix)]
    if not matrices:
        raise ValueError("a capture split contains no rule-clean sessions")
    return np.vstack(matrices)


def _plants(matrix: np.ndarray) -> dict[str, np.ndarray]:
    from sms.m7_anomaly import FEATURES

    positions = {name: index for index, name in enumerate(FEATURES)}
    base = matrix[int(np.argmax(np.sum(~np.isnan(matrix), axis=1)))].copy()

    cert_swap = base.copy()
    cert_swap[positions["cert_visible"]] = 1
    cert_swap[positions["cert_key_bits"]] = 2048
    cert_swap[positions["cert_days_to_expiry_at_capture"]] = 180
    cert_swap[positions["cert_self_signed"]] = 0
    cert_swap[positions["cert_fp_share_for_server"]] = 0.001

    downgrade = base.copy()
    downgrade[positions["negotiated_version_ord"]] = 1
    downgrade[positions["offered_version_ord"]] = 4
    downgrade[positions["downgrade_delta"]] = 3
    downgrade[positions["forward_secrecy"]] = 0
    downgrade[positions["aead_flag"]] = 0
    downgrade[positions["cbc_flag"]] = 1

    cleartext_auth = base.copy()
    cleartext_auth[positions["cleartext_auth_seen"]] = 1
    cleartext_auth[positions["implicit_tls"]] = 0
    for verdict in ("upgraded", "failed", "rejected", "not_used", "suspected"):
        cleartext_auth[positions[f"verdict_{verdict}"]] = int(verdict == "not_used")

    weak_expired_cert = cert_swap.copy()
    weak_expired_cert[positions["cert_key_bits"]] = 512
    weak_expired_cert[positions["cert_days_to_expiry_at_capture"]] = -365
    weak_expired_cert[positions["cert_self_signed"]] = 1

    packet_burst = base.copy()
    observed_counts = matrix[:, positions["packet_count"]]
    packet_burst[positions["packet_count"]] = float(np.nanmax(observed_counts) * 16)

    return {
        "certificate_swap": cert_swap,
        "legacy_downgrade": downgrade,
        "cleartext_auth": cleartext_auth,
        "weak_expired_certificate": weak_expired_cert,
        "packet_burst": packet_burst,
    }


def validate_capture_directory(directory: str | Path) -> dict:
    """Run all four validation measurements and return JSON-safe metrics."""
    captures = [
        _CaptureMatrix(path, matrix)
        for path in _discover(directory)
        if len(matrix := _normal_matrix(path))
    ]
    if len(captures) < 3:
        raise ValueError("fewer than three captures contain rule-clean mail sessions")
    train_group, calibration_group, test_group = _partition(captures)
    train, calibration, test = map(_stack, (train_group, calibration_group, test_group))

    split_paths = {
        "training": [item.path.name for item in train_group],
        "calibration": [item.path.name for item in calibration_group],
        "test": [item.path.name for item in test_group],
    }
    split_sets = [set(paths) for paths in split_paths.values()]
    disjoint = not any(
        split_sets[left] & split_sets[right]
        for left in range(3)
        for right in range(left + 1, 3)
    )
    if not disjoint:
        raise AssertionError("training, calibration, and test captures overlap")

    model = Ensemble(42).fit(train, calibration)
    calibration_scores = model.score(calibration)
    # HBOS is discrete, so the calibration quantile can contain a wide tie.
    # Place the boundary immediately above that tied score rather than turning
    # the whole tie into false alerts through the inclusive comparison below.
    threshold = float(np.nextafter(
        np.quantile(calibration_scores, 0.99, method="higher"), np.inf
    ))
    plants = _plants(test)
    planted = planted_recall(model.score, test, plants)
    ablation = {
        "isolation_forest": planted_recall(model.score_if, test, plants),
        "hbos": planted_recall(model.score_hbos, test, plants),
        "ensemble": planted,
    }
    evaluation = np.vstack([test, *plants.values()])
    seeds = (1, 2, 3, 4, 5)

    return {
        "capture_split": {
            **split_paths,
            "sessions": {
                "training": len(train),
                "calibration": len(calibration),
                "test": len(test),
            },
            "disjoint": disjoint,
        },
        "planted_anomaly_ranks": planted,
        "held_out_false_alerts_per_1000": false_alert_rate(model, test, threshold),
        "held_out_abstention_rate": float(np.mean(model.abstentions(test))),
        "active_components": model.active_components,
        "ablation": ablation,
        "top_10_stability": {
            "seeds": list(seeds),
            "mean_jaccard": stability(Ensemble, train, calibration, evaluation, seeds),
        },
    }
