/** Display formatting only; never changes report facts, model scores or ranking. */
export function anomalyPresentation(ml) {
  const percentile = ml?.anomalyPercentile;
  const valid = Number.isFinite(percentile) && percentile >= 0 && percentile <= 100;
  return {
    label: valid ? `Baseline percentile ${percentile.toFixed(1)} / 100` : 'Baseline percentile unavailable',
    tooltip: Number.isFinite(ml?.anomalyScore) ? `Raw anomaly score: ${ml.anomalyScore}` : 'Raw anomaly score unavailable'
  };
}

export function baselineShareLabel(value) {
  if (!Number.isFinite(value)) return 'baseline share not provided';
  return `baseline share ${value > 0 && value < 0.1 ? 'below 0.1' : value.toFixed(1)}%`;
}

export function sentinelLabel(tls) {
  if (!tls?.downgradeSentinel) return '';
  const context = tls.downgradeAnomaly
    ? 'TLS 1.3 offered; engine-reported anomaly'
    : tls.downgradeLegacyClient
      ? 'informational; expected legacy-client negotiation, not a finding'
      : 'informational; no downgrade anomaly reported';
  return `RFC 8446 §4.1.3 sentinel: ${tls.downgradeSentinel} (${context})`;
}
