# ML feature schema ml-v1

Features are numeric, in the order declared by `sms.m7_anomaly.FEATURES`.
No addresses, credentials, message text, or key material enter the model.

| Features | Encoding |
|---|---|
| negotiated_version_ord, offered_version_ord | SSL3.0=0, TLS1.0=1 through TLS1.3=4; unobservable=NaN |
| downgrade_delta | Engine's observed version gap; unobservable=NaN |
| forward_secrecy, hybrid_pq_flag | Observed engine booleans, 0/1; unobservable=NaN |
| aead_flag, cbc_flag | Known cipher name contains GCM/CHACHA20/CCM or CBC, respectively; unknown cipher=NaN |
| cert_visible | Captured certificate DER exists: 0/1 |
| cert_key_bits | Observed public key size; unobservable=NaN |
| cert_days_to_expiry_at_capture | Whole signed days from session's first capture timestamp to notAfter; unobservable=NaN |
| cert_self_signed | Certificate fact 0/1; unobservable=NaN |
| cleartext_auth_seen | Transition parser observed authentication before TLS: 0/1 |
| verdict_upgraded, verdict_failed, verdict_rejected, verdict_not_used, verdict_suspected | One-hot transition verdict |
| implicit_tls | Transition parser's implicit TLS fact: 0/1 |
| packet_count | Captured packets in this session, including retransmissions |
| cert_fp_share_for_server | Sessions presenting the same SHA-256 certificate fingerprint divided by all sessions at the same server IP and port in this capture; unobservable=NaN |

The ensemble uses `IsolationForest(n_estimators=200, random_state=42,
contamination="auto")` and HBOS, cached per excluded capture under a lock.
`ml/baseline.json` stores 215 numeric feature rows from six whole captures:
37 recorded real-mail sessions, 18 enterprise sessions after excluding seven
planted risk cases, and four deterministic benign captures of 40 sessions each.
Rebuild with `python -m lab.build_m7_baseline`. The artifact contains source
hashes and session IDs but no addresses, credentials, message text or DER.
The old `out/baseline.pcap` (240 homogeneous synthetic sessions) remains a lab
fixture and is no longer the production model's baseline.

Before fitting, exclude the scoring capture by SHA-256, including renamed exact
copies. Partition remaining rows with `GroupKFold(3)` by original capture file.
Choose the calibration fold by source priority: curated enterprise normals
have priority 2, assumed-benign recorded traffic priority 1, generated traffic
priority 0; sum priorities per fold and break ties in GroupKFold order. This
keeps reference traffic in calibration without selecting folds by evaluation
scores. The other two folds train the estimators. No capture crosses training,
calibration or scoring. For a new capture the split is 157 training / 58
calibration; holding out real mail gives 120 / 58, and holding out enterprise
gives 120 / 77. All source hashes and split counts are emitted in `ml_summary`.

Features constant or entirely unavailable in either training or calibration
are disabled in both estimators. Even a wildly different scoring value cannot
make such a feature contribute. Missing HBOS cells also contribute exactly zero.
HBOS uses up to ten equal-width bins, capped by the Freedman–Diaconis width to
avoid sparse empty-bin artifacts. A varying column retains at least two bins,
including a rare binary value when the interquartile range is zero. The cap is
applied before allocating edges. Smoothing uses alpha=0.001 and reserves one
unseen-value bucket with the same population denominator as the observed bins.

Each component's raw score is standardised as `(score - median) / (1.4826 * MAD)`
using held-out calibration only. A zero MAD disables that component: there is
no epsilon or substitute scale. `anomaly_score` is the maximum of the active
components; an inactive zero never floors an active negative score. If neither
component is available, no varying feature is observed, or capture identity is
missing, the detector abstains: `abstained:true`, an explicit reason, null score
and percentile, `is_anomaly:false`, and no factors. Partial component abstention
appears in `ml_summary.calibration.active_components`; session abstention means
neither component can provide a usable decision.

The alert boundary remains immediately above the calibration 99th percentile.
`anomaly_percentile` is a display midrank against calibration and never drives
ranking or alerts. For rarity explanations, `baseline_share_pct` is now the
**unsmoothed observed bin frequency** among available training values (0 for
out-of-range values), not a smoothing prior presented as an observed frequency.
Only active features with share **at most 5%** can be cited. This is an explicit
one-in-twenty reference-bin cutoff, not a maliciousness probability. Return up
to three qualifying factors, never pad; if none qualify, say the ranking reflects
the combination and no single factor clears the cutoff. When HBOS is disabled,
no HBOS rarity factors are claimed. Disagreement still requires an anomaly with
no medium/high/critical rule finding.

Run `python -m ml.measure_calibration` for the two capture-held-out evaluations,
AI on/off reports and diffs, and fixed precision@5/precision@10. See
`docs/M7_CALIBRATION.md` for labels, measured results and limitations.

ML changes only session.ml and report.ml_summary. It does not claim malicious
activity, invent findings, modify scores, or change HNDL.
