import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import {
  associateAlertToCase,
  createCase,
  fetchAlertById,
  type AlertDetailOut,
} from '../api/client'
import Spinner from '../components/Spinner'
import ErrorBanner from '../components/ErrorBanner'

function levelToSeverity(level: number | null): string {
  if (level === null) return 'low'
  if (level >= 12) return 'critical'
  if (level >= 8) return 'high'
  if (level >= 5) return 'medium'
  return 'low'
}

export default function CreateCase() {
  const [searchParams] = useSearchParams()
  const alertIdParam = searchParams.get('alert_id')
  const navigate = useNavigate()

  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [status, setStatus] = useState('open')

  const [alert, setAlert] = useState<AlertDetailOut | null>(null)
  const [loadingAlert, setLoadingAlert] = useState(() => Boolean(alertIdParam && !isNaN(Number(alertIdParam))))
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!alertIdParam) return
    const aid = Number(alertIdParam)
    if (isNaN(aid)) return

    let cancelled = false

    async function loadAlert() {
      try {
        const a = await fetchAlertById(aid)
        if (cancelled) return
        setAlert(a)
        setTitle(`Investigation: ${a.description ?? `Rule ${a.rule_id}`}`)
        setSeverity(levelToSeverity(a.rule_level))
        const tactics = a.mitre_tactics.length > 0 ? a.mitre_tactics.join(', ') : 'None'
        const techniques = a.mitre_techniques.length > 0 ? a.mitre_techniques.join(', ') : 'None'
        setDescription(
          `Alert #${a.id} Investigation\n` +
          `Rule: ${a.rule_id} (Level ${a.rule_level})\n` +
          `Agent: ${a.agent_name ?? a.agent_id ?? 'Unknown'}\n` +
          `MITRE Tactics: ${tactics}\n` +
          `MITRE Techniques: ${techniques}\n` +
          `Timestamp: ${a.timestamp}\n\n` +
          `Notes:\n`
        )
      } catch {
        // Non-fatal: if alert can't be fetched, analyst can still create a blank case
      } finally {
        if (!cancelled) setLoadingAlert(false)
      }
    }

    void loadAlert()
    return () => { cancelled = true }
  }, [alertIdParam])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)

    try {
      // 1. Create case
      const created = await createCase({
        title,
        description: description || undefined,
        severity,
        status,
      })

      // 2. If alert_id param was provided, associate it
      if (alertIdParam) {
        const aid = Number(alertIdParam)
        if (!isNaN(aid)) {
          await associateAlertToCase(created.id, aid)
        }
      }

      // 3. Navigate to case detail
      navigate(`/cases/${created.id}`)
    } catch (e) {
      setError(String(e))
      setSubmitting(false)
    }
  }

  if (loadingAlert) return <Spinner label="Pre-filling from alert…" />

  return (
    <div className="page">
      <div className="page-header">
        <div className="breadcrumb">
          <Link to="/cases">Cases</Link> / <span>New</span>
        </div>
        <h1 className="page-title">
          {alert ? `Create Case from Alert #${alert.id}` : 'Create New Case'}
        </h1>
        <p className="page-subtitle">
          {alert
            ? `Pre-filled with metadata from rule ${alert.rule_id}`
            : 'Open a new incident investigation'}
        </p>
      </div>

      {error && <ErrorBanner message={error} />}

      <form className="create-case-form" onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="c-title">Case Title *</label>
          <input
            id="c-title"
            type="text"
            required
            placeholder="e.g. Suspicious PowerShell Execution on Host 001"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
        </div>

        <div className="form-row">
          <div className="form-group">
            <label htmlFor="c-sev">Initial Severity</label>
            <select
              id="c-sev"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="c-status">Initial Status</label>
            <select
              id="c-status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="escalated">Escalated</option>
            </select>
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="c-desc">Investigation Description / Initial Notes</label>
          <textarea
            id="c-desc"
            rows={8}
            placeholder="Describe the incident, context, and immediate findings…"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Creating Case…' : 'Create Case'}
          </button>
          <Link
            to={alertIdParam ? `/alerts/${alertIdParam}` : '/cases'}
            className="btn btn-secondary"
          >
            Cancel
          </Link>
        </div>
      </form>
    </div>
  )
}
