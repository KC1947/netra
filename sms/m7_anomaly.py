"""Offline deterministic anomaly review. It never changes rules, scores, or HNDL."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import threading

import numpy as np
from sklearn.model_selection import GroupKFold

from ml.validate_anomaly import Ensemble, HBOS
from .registry import load as load_registry

BASELINE = Path(__file__).resolve().parent.parent / "ml" / "baseline.json"
RARITY_SHARE_PCT = 5.0
VERSION_ORD = {"SSL3.0": 0, "TLS1.0": 1, "TLS1.1": 2, "TLS1.2": 3, "TLS1.3": 4}
VERDICTS = ("upgraded", "failed", "rejected", "not_used", "suspected")
FEATURES = (
    "negotiated_version_ord", "offered_version_ord", "downgrade_delta",
    "forward_secrecy", "hybrid_pq_flag", "aead_flag", "cbc_flag",
    "cert_visible", "cert_key_bits", "cert_days_to_expiry_at_capture",
    "cert_self_signed", "cleartext_auth_seen",
    *(f"verdict_{verdict}" for verdict in VERDICTS), "implicit_tls", "packet_count",
    "cert_fp_share_for_server",
)

_TRAIN_LOCK = threading.Lock()


def _registry_flag(cipher_name: str | None, prop: str) -> float:
    """Return 1.0/0.0 for a registered suite, NaN when the registry cannot say."""
    value = load_registry().cipher_has_by_name(cipher_name, prop)
    return math.nan if value is None else float(value)


def _observed_version(value: str | None) -> float:
    return float(VERSION_ORD[value]) if value in VERSION_ORD else math.nan


def extract_features(sessions) -> np.ndarray:
    """Return the numeric, non-sensitive ML matrix in the documented order.

    An unavailable fact is always ``NaN``.  In particular it is never encoded
    as -1, which is a real low numeric value and would share an HBOS bin with
    weak-but-observed versions, key sizes, or certificate lifetimes.
    """
    counts: Counter[tuple[object, object]] = Counter()
    fingerprints: Counter[tuple[object, object, bytes]] = Counter()
    for session in sessions:
        server = (session.five_tuple["server_ip"], session.five_tuple["server_port"])
        counts[server] += 1
        der = getattr(session, "_cert_der", None)
        if der:
            fingerprints[server + (hashlib.sha256(der).digest(),)] += 1

    rows = []
    for session in sessions:
        tls, cert = session.tls, session.certificate
        der = getattr(session, "_cert_der", None)
        server = (session.five_tuple["server_ip"], session.five_tuple["server_port"])
        days = math.nan
        if cert.notAfter and session.packet_observations:
            capture = datetime.fromtimestamp(session.packet_observations[0].ts, timezone.utc)
            days = float(math.floor(
                (datetime.fromisoformat(cert.notAfter) - capture).total_seconds() / 86400
            ))

        facts = getattr(session, "_transition_facts", {})
        cipher = tls.cipher
        verdict = session.transition.verdict
        negotiated = _observed_version(tls.negotiated_version)
        offered = _observed_version(tls.offered_version)
        downgrade = (
            float(tls.downgrade_delta)
            if not math.isnan(negotiated) and not math.isnan(offered)
            and tls.downgrade_delta is not None
            else math.nan
        )
        forward_secrecy = (
            float(tls.forward_secrecy)
            if tls.forward_secrecy_status in {"YES", "NO"}
            else math.nan
        )
        hybrid_pq = (
            float(tls.hybrid_pq_flag)
            if session.fact_tiers.get("tls.hybrid_pq_flag") != "NOT_OBSERVABLE"
            else math.nan
        )
        # Registry lookup, not a substring of the suite name: an unregistered
        # code point must arrive as NaN (unknown), never as 0.0 (not AEAD, not
        # CBC), which is wrong input rather than missing input.
        aead = _registry_flag(cipher, "aead")
        cbc = _registry_flag(cipher, "cbc")
        verdict_features = (
            [float(verdict == candidate) for candidate in VERDICTS]
            if verdict is not None else [math.nan] * len(VERDICTS)
        )
        fingerprint_share = (
            fingerprints[server + (hashlib.sha256(der).digest(),)] / counts[server]
            if der else math.nan
        )
        rows.append([
            negotiated,
            offered,
            downgrade,
            forward_secrecy,
            hybrid_pq,
            aead,
            cbc,
            float(bool(der)),
            float(cert.key_bits) if cert.key_bits is not None else math.nan,
            days,
            float(cert.self_signed) if cert.self_signed is not None else math.nan,
            float(facts["auth_cleartext"]) if "auth_cleartext" in facts else math.nan,
            *verdict_features,
            float(facts["implicit_tls"]) if "implicit_tls" in facts else math.nan,
            float(len(session.packet_observations)),
            float(fingerprint_share),
        ])
    return np.array(rows, dtype=float).reshape((-1, len(FEATURES)))


def _percentile(score: float, calibration_scores: np.ndarray) -> float:
    """Display-only empirical midrank against held-out calibration scores."""
    return float(
        100
        * (
            np.sum(calibration_scores < score)
            + 0.5 * np.sum(calibration_scores == score)
        )
        / len(calibration_scores)
    )


def _hbos_scores(matrix: np.ndarray, hbos: HBOS) -> np.ndarray:
    """Compatibility helper used by focused model tests."""
    return hbos.score(matrix)


@dataclass(frozen=True)
class _TrainedModel:
    ensemble: Ensemble
    training: np.ndarray
    calibration: np.ndarray
    calibration_scores: np.ndarray
    threshold: float
    provenance: dict


def _split_baseline(matrix: np.ndarray, groups: np.ndarray,
                    reference_groups: dict[str, int] | None = None) -> tuple[np.ndarray, np.ndarray]:
    """Hold out whole captures, never sessions from a training capture."""
    count = len(np.unique(groups))
    if count < 3:
        raise ValueError("ML baseline needs three distinct captures after scoring exclusion")
    splits = list(GroupKFold(n_splits=3).split(matrix, groups=groups))
    # Prefer curated normal enterprise traffic, then assumed-benign recorded
    # traffic, over an entirely generated calibration set. Source priorities
    # never depend on evaluation scores; ties keep GroupKFold's fixed order.
    priorities = reference_groups or {}
    return max(splits, key=lambda split: sum(
        priorities.get(group, 0) for group in set(groups[split[1]])
    ))


@lru_cache(maxsize=16)
def _train(scoring_sha256: str | None = None) -> _TrainedModel:
    artifact = json.loads(BASELINE.read_text())
    if artifact["schema_version"] != "m7-baseline-v2" or artifact["features"] != list(FEATURES):
        raise ValueError("ML baseline feature schema mismatch")
    # Exact copies/uploads share a group, regardless of filename. Excluding
    # the scoring capture happens BEFORE any fitting, calibration or threshold.
    unique = {c["sha256"]: c for c in artifact["captures"] if c["sha256"] != scoring_sha256}
    captures = {c["path"]: c for c in unique.values()}
    matrix = np.vstack([np.asarray(c["features"], dtype=float) for c in captures.values()])
    groups = np.array([path for path, c in captures.items() for _ in c["features"]])
    reference_groups = {path: 2 if c["excluded_session_ids"] else 1
                        for path, c in captures.items()
                        if c["kind"] != "synthetic benign variation"}
    train_indices, calibration_indices = _split_baseline(matrix, groups, reference_groups)
    training, calibration = matrix[train_indices], matrix[calibration_indices]
    ensemble = Ensemble(seed=42).fit(training, calibration)
    calibration_scores = ensemble.score(calibration)
    # Put the decision boundary just above the selected calibration score so a
    # large tie at the 99th percentile does not turn every tied normal into an
    # alert. Values beyond the held-out tail retain full z-score resolution.
    threshold = float(np.nextafter(
        np.quantile(calibration_scores, 0.99, method="higher"), np.inf
    ))
    def sources(indices):
        return [{"path": path, "sha256": captures[path]["sha256"],
                 "sessions": len(captures[path]["features"])}
                for path in sorted(set(groups[indices]))]

    provenance = {
        "schema_version": artifact["schema_version"],
        "split": "GroupKFold(3), reference-containing calibration fold; scoring capture excluded by SHA-256",
        "corpus_sessions": sum(len(c["features"]) for c in artifact["captures"]),
        "training": sources(train_indices), "calibration": sources(calibration_indices),
        "scoring_capture_excluded": scoring_sha256 in {c["sha256"] for c in artifact["captures"]},
        "active_components": ensemble.active_components,
    }
    return _TrainedModel(ensemble, training, calibration, calibration_scores, threshold, provenance)


def _hbos_position(hbos: HBOS, feature_index: int, value: float) -> tuple[int, bool]:
    edges = hbos.edges[feature_index]
    densities = hbos.densities[feature_index]
    position = int(np.clip(
        np.searchsorted(edges, value, side="right") - 1,
        0,
        len(densities) - 1,
    ))
    return position, bool(value < edges[0] or value > edges[-1])


def _explain(row: np.ndarray, baseline: np.ndarray, hbos: HBOS) -> list[dict]:
    contributions = hbos.contributions(row[None, :])[0]
    factors = []
    for index, feature in enumerate(FEATURES):
        value = float(row[index])
        if math.isnan(value) or not hbos.active[index]:
            continue
        position, outside = _hbos_position(hbos, index, value)
        share = 0.0 if outside else float(hbos.shares[index][position])
        if share * 100 > RARITY_SHARE_PCT:
            continue
        column = baseline[:, index]
        observed = column[~np.isnan(column)]
        typical = None
        if len(observed):
            modal = int(np.argmax(hbos.densities[index]))
            for candidate in observed:
                candidate_position, candidate_outside = _hbos_position(
                    hbos, index, float(candidate)
                )
                if not candidate_outside and candidate_position == modal:
                    typical = float(candidate)
                    break
        factors.append({
            "feature": feature,
            "value": value,
            "baseline_typical": typical,
            "baseline_share_pct": share * 100,
            "_contribution": float(contributions[index]),
        })
    return [
        {key: value for key, value in factor.items() if key != "_contribution"}
        for factor in sorted(
            factors,
            key=lambda factor: (-factor["_contribution"], factor["feature"]),
        )[:3]
    ]


def apply_anomalies(sessions, enabled: bool = True, capture_path: str | Path | None = None) -> dict:
    """Add ML review fields only; callers retain sole ownership of risk and rules."""
    if not enabled or not BASELINE.exists():
        for session in sessions:
            session.ml = None
        return {"enabled": False}

    with _TRAIN_LOCK:
        digest = hashlib.sha256(Path(capture_path).read_bytes()).hexdigest() if capture_path else None
        trained = _train(digest)
    matrix = extract_features(sessions)
    scores = trained.ensemble.score(matrix) if len(matrix) else np.array([])
    abstentions = trained.ensemble.abstentions(matrix)
    if capture_path is None:
        # Without capture identity it is impossible to guarantee no leakage.
        abstentions[:] = True
    for session, row, score, abstained in zip(sessions, matrix, scores, abstentions):
        score = float(score)
        abstained = bool(abstained)
        anomalous = not abstained and score >= trained.threshold
        factors = (
            _explain(row, trained.training, trained.ensemble.hbos)
            if not abstained and trained.ensemble.active_components["hbos"] else []
        )
        session.ml = {
            "model": "IsolationForest+HBOS",
            "schema_version": "ml-v1",
            "baseline_sessions": len(trained.training),
            # The score is the max robust z-score, not a percentile. Tail
            # values remain ordered above every calibration example.
            "anomaly_score": None if abstained else score,
            # Binding UI compatibility only: display midrank from held-out
            # calibration, never the training data. It does not drive ranking.
            "anomaly_percentile": None if abstained else _percentile(score, trained.calibration_scores),
            "is_anomaly": anomalous,
            "abstained": abstained,
            "abstention_reason": (
                "capture_identity_unavailable" if capture_path is None else
                "degenerate_calibration" if not any(trained.ensemble.active_components.values()) else
                "no_observed_varying_features"
            ) if abstained else None,
            "top_factors": factors,
            "explanation": (
                "Detector abstained." if abstained else
                "Rare baseline values; unusual does not imply malicious." if factors else
                "No single factor clears the 5% rarity cutoff; ranking reflects the feature combination."
            ),
            "disagrees_with_rules": anomalous and not any(
                finding.severity in {"medium", "high", "critical"}
                for finding in session.findings
            ),
        }
    return {
        "enabled": True,
        "model": "IsolationForest+HBOS",
        "baseline_sessions": len(trained.training),
        "calibration_sessions": len(trained.calibration),
        "calibration": trained.provenance,
        "anomalies": sum(session.ml["is_anomaly"] for session in sessions),
        "abstentions": int(abstentions.sum()),
        "rarity_share_pct": RARITY_SHARE_PCT,
        "threshold_percentile": 99,
    }
