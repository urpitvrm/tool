// Wazuh rule.level bands (0-15), matching the Wazuh dashboard convention.
export const SEVERITY_LEVELS = {
  critical: { gte: 15 },
  high: { gte: 12, lte: 14 },
  medium: { gte: 7, lte: 11 },
  low: { gte: 0, lte: 6 },
};

export const SEVERITY_NAMES = Object.keys(SEVERITY_LEVELS);

export function severityOf(level) {
  const value = Number(level);
  if (!Number.isFinite(value)) return 'unknown';
  if (value >= 15) return 'critical';
  if (value >= 12) return 'high';
  if (value >= 7) return 'medium';
  return 'low';
}
