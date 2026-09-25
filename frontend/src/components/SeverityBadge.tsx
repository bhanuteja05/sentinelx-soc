import {
  severityClassForLevel,
  severityClassForString,
} from '../utils/severity'

export function SeverityBadge({ level }: { level: number | null }) {
  return (
    <span className={`sev ${severityClassForLevel(level)}`}>
      {level ?? '—'}
    </span>
  )
}

export function SeverityLabel({ severity }: { severity: string }) {
  return (
    <span className={`sev ${severityClassForString(severity)}`}>
      {severity}
    </span>
  )
}

