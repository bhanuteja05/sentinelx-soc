export function severityClassForLevel(level: number | null): string {
  if (level === null) return 'sev-unknown'
  if (level >= 12) return 'sev-critical'
  if (level >= 8) return 'sev-high'
  if (level >= 5) return 'sev-medium'
  return 'sev-low'
}

export function severityClassForString(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical': return 'sev-critical'
    case 'high': return 'sev-high'
    case 'medium': return 'sev-medium'
    case 'low': return 'sev-low'
    default: return 'sev-unknown'
  }
}
