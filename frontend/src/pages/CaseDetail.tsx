import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  closeCase,
  deleteCase,
  detachAlertFromCase,
  fetchCaseById,
  updateCase,
  type CaseDetailOut,
  NotFoundError,
} from '../api/client'
import { SeverityBadge, SeverityLabel } from '../components/SeverityBadge'
import Spinner from '../components/Spinner'
import ErrorBanner from '../components/ErrorBanner'

function formatTs(value: string | null | undefined): string {
  if (!value) return '—'
  const d = new Date(value)
  return isNaN(d.getTime()) ? value : d.toLocaleString()
}

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [c, setCase] = useState<CaseDetailOut | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionMsg, setActionMsg] = useState<string | null>(null)

  // Edit form state
  const [isEditing, setIsEditing] = useState(false)
  const [editTitle, setEditTitle] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editStatus, setEditStatus] = useState('')
  const [editSeverity, setEditSeverity] = useState('')
  const [saving, setSaving] = useState(false)

  async function reload() {
    if (!id) return
    try {
      const data = await fetchCaseById(Number(id))
      setCase(data)
      setEditTitle(data.title)
      setEditDesc(data.description ?? '')
      setEditStatus(data.status)
      setEditSeverity(data.severity)
    } catch (e) {
      if (e instanceof NotFoundError) {
        setError(`Case #${id} not found.`)
      } else {
        setError(String(e))
      }
    }
  }

  useEffect(() => {
    let cancelled = false
    async function load() {
      if (!id) return
      setLoading(true)
      try {
        const data = await fetchCaseById(Number(id))
        if (!cancelled) {
          setCase(data)
          setEditTitle(data.title)
          setEditDesc(data.description ?? '')
          setEditStatus(data.status)
          setEditSeverity(data.severity)
        }
      } catch (e) {
        if (!cancelled) {
          if (e instanceof NotFoundError) {
            setError(`Case #${id} not found.`)
          } else {
            setError(String(e))
          }
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    void load()
    return () => { cancelled = true }
  }, [id])

  async function handleSaveEdit(e: React.FormEvent) {
    e.preventDefault()
    if (!id || !c) return
    setSaving(true)
    setError(null)
    try {
      const updated = await updateCase(c.id, {
        title: editTitle,
        description: editDesc || undefined,
        status: editStatus,
        severity: editSeverity,
      })
      setCase({ ...c, ...updated })
      setIsEditing(false)
      setActionMsg('Case updated successfully.')
      setTimeout(() => setActionMsg(null), 3000)
    } catch (e) {
      setError(String(e))
    } finally {
      setSaving(false)
    }
  }

  async function handleCloseCase() {
    if (!c) return
    if (!confirm(`Are you sure you want to close Case #${c.id}?`)) return
    try {
      const updated = await closeCase(c.id)
      setCase({ ...c, ...updated })
      setActionMsg('Case closed.')
      setTimeout(() => setActionMsg(null), 3000)
    } catch (e) {
      setError(String(e))
    }
  }

  async function handleDeleteCase() {
    if (!c) return
    if (!confirm(`Are you sure you want to DELETE Case #${c.id}? Alerts will not be deleted.`)) return
    try {
      await deleteCase(c.id)
      navigate('/cases')
    } catch (e) {
      setError(String(e))
    }
  }

  async function handleDetachAlert(alertId: number) {
    if (!c) return
    if (!confirm(`Remove alert #${alertId} from this case?`)) return
    try {
      await detachAlertFromCase(c.id, alertId)
      await reload()
      setActionMsg(`Alert #${alertId} removed from case.`)
      setTimeout(() => setActionMsg(null), 3000)
    } catch (e) {
      setError(String(e))
    }
  }

  if (loading) return <Spinner label="Loading case detail…" />
  if (error) return (
    <div className="page">
      <ErrorBanner message={error} />
      <button className="btn btn-secondary" onClick={() => navigate('/cases')}>
        ← Back to Cases
      </button>
    </div>
  )
  if (!c) return null

  return (
    <div className="page">
      <div className="page-header page-header--split">
        <div>
          <div className="breadcrumb">
            <Link to="/cases">Cases</Link> / <span>#{c.id}</span>
          </div>
          <h1 className="page-title">{c.title}</h1>
        </div>
        <div className="header-actions">
          {c.status !== 'closed' && (
            <button className="btn btn-secondary" onClick={handleCloseCase}>
              Close Case
            </button>
          )}
          <button
            className="btn btn-secondary"
            onClick={() => setIsEditing(!isEditing)}
          >
            {isEditing ? 'Cancel Edit' : 'Edit Case'}
          </button>
          <button className="btn btn-danger" onClick={handleDeleteCase}>
            Delete Case
          </button>
        </div>
      </div>

      {actionMsg && <div className="success-banner">{actionMsg}</div>}

      {/* Edit Form */}
      {isEditing && (
        <form className="edit-case-form" onSubmit={handleSaveEdit}>
          <div className="form-group">
            <label htmlFor="e-title">Title</label>
            <input
              id="e-title"
              type="text"
              required
              value={editTitle}
              onChange={(e) => setEditTitle(e.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="e-desc">Description</label>
            <textarea
              id="e-desc"
              rows={4}
              value={editDesc}
              onChange={(e) => setEditDesc(e.target.value)}
            />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="e-status">Status</label>
              <select
                id="e-status"
                value={editStatus}
                onChange={(e) => setEditStatus(e.target.value)}
              >
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="escalated">Escalated</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="e-sev">Severity</label>
              <select
                id="e-sev"
                value={editSeverity}
                onChange={(e) => setEditSeverity(e.target.value)}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>
          <div className="form-actions">
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : 'Save Changes'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setIsEditing(false)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Case Info Cards */}
      <div className="meta-grid">
        <div className="meta-card">
          <h3>Case Overview</h3>
          <dl className="meta-list">
            <div><dt>Case ID</dt><dd>#{c.id}</dd></div>
            <div><dt>Status</dt><dd><span className={`status-badge status-${c.status}`}>{c.status}</span></dd></div>
            <div><dt>Severity</dt><dd><SeverityLabel severity={c.severity} /></dd></div>
            <div><dt>Associated Alerts</dt><dd>{c.alert_count}</dd></div>
            <div><dt>Created</dt><dd>{formatTs(c.created_at)}</dd></div>
            <div><dt>Last Updated</dt><dd>{formatTs(c.updated_at)}</dd></div>
          </dl>
        </div>

        <div className="meta-card meta-card--wide">
          <h3>Investigation Description / Notes</h3>
          <p className="case-desc-text">
            {c.description ?? <span className="text-muted">No description provided.</span>}
          </p>
        </div>
      </div>

      {/* Associated Alerts */}
      <section className="dash-section">
        <div className="section-header">
          <h2>Associated Alerts ({c.alerts.length})</h2>
        </div>
        {c.alerts.length === 0 ? (
          <p className="empty-text">No alerts currently associated with this case.</p>
        ) : (
          <div className="alerts-table-wrap">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Lvl</th>
                  <th>Rule</th>
                  <th>Description</th>
                  <th>Agent</th>
                  <th>Time</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {c.alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td><SeverityBadge level={alert.rule_level} /></td>
                    <td>{alert.rule_id ?? '—'}</td>
                    <td>
                      <Link to={`/alerts/${alert.id}`} className="table-link">
                        {alert.description ?? '—'}
                      </Link>
                    </td>
                    <td>{alert.agent_name ?? alert.agent_id ?? '—'}</td>
                    <td>{formatTs(alert.timestamp)}</td>
                    <td className="cell-actions">
                      <Link to={`/alerts/${alert.id}`} className="btn btn-xs">
                        Investigate
                      </Link>
                      <button
                        className="btn btn-xs btn-danger"
                        onClick={() => handleDetachAlert(alert.id)}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
