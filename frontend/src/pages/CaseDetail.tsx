import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  closeCase,
  createCaseNote,
  deleteCase,
  deleteCaseNote,
  detachAlertFromCase,
  fetchCaseById,
  fetchCaseNotes,
  updateCase,
  updateCaseNote,
  type CaseDetailOut,
  type CaseNote,
  NotFoundError,
} from '../api/client'
import { SeverityBadge, SeverityLabel } from '../components/SeverityBadge'
import Spinner from '../components/Spinner'
import ErrorBanner from '../components/ErrorBanner'
import { useAuth } from '../context/AuthContext'

function formatTs(value: string | null | undefined): string {
  if (!value) return '—'
  const d = new Date(value)
  return isNaN(d.getTime()) ? value : d.toLocaleString()
}

export default function CaseDetail() {
  const { user } = useAuth()
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

  // Case notes state
  const [notes, setNotes] = useState<CaseNote[]>([])
  const [loadingNotes, setLoadingNotes] = useState(true)
  const [notesError, setNotesError] = useState<string | null>(null)

  // Add note form state
  const [newNoteContent, setNewNoteContent] = useState('')
  const [addingNote, setAddingNote] = useState(false)
  const [addNoteError, setAddNoteError] = useState<string | null>(null)

  // Edit note state
  const [editingNoteId, setEditingNoteId] = useState<number | null>(null)
  const [editingContent, setEditingContent] = useState('')
  const [savingNoteEdit, setSavingNoteEdit] = useState(false)
  const [editNoteError, setEditNoteError] = useState<string | null>(null)

  async function reload() {
    if (!id) return
    try {
      const [caseData, notesData] = await Promise.all([
        fetchCaseById(Number(id)),
        fetchCaseNotes(Number(id)),
      ])
      setCase(caseData)
      setEditTitle(caseData.title)
      setEditDesc(caseData.description ?? '')
      setEditStatus(caseData.status)
      setEditSeverity(caseData.severity)
      setNotes(notesData)
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
      setLoadingNotes(true)
      try {
        const [caseData, notesData] = await Promise.all([
          fetchCaseById(Number(id)),
          fetchCaseNotes(Number(id)),
        ])
        if (!cancelled) {
          setCase(caseData)
          setEditTitle(caseData.title)
          setEditDesc(caseData.description ?? '')
          setEditStatus(caseData.status)
          setEditSeverity(caseData.severity)
          setNotes(notesData)
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
        if (!cancelled) {
          setLoading(false)
          setLoadingNotes(false)
        }
      }
    }
    void load()
    return () => {
      cancelled = true
    }
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

  async function handleAddNote(e: React.FormEvent) {
    e.preventDefault()
    if (!id || !c) return
    const content = newNoteContent.trim()
    if (!content) {
      setAddNoteError('Note content cannot be empty.')
      return
    }
    setAddingNote(true)
    setAddNoteError(null)
    try {
      const created = await createCaseNote(c.id, content)
      setNotes((prev) => [...prev, created])
      setNewNoteContent('')
      setActionMsg('Investigation note added.')
      setTimeout(() => setActionMsg(null), 3000)
    } catch (e) {
      setAddNoteError(String(e))
    } finally {
      setAddingNote(false)
    }
  }

  function handleStartEditNote(note: CaseNote) {
    setEditingNoteId(note.id)
    setEditingContent(note.content)
    setEditNoteError(null)
  }

  function handleCancelEditNote() {
    setEditingNoteId(null)
    setEditingContent('')
    setEditNoteError(null)
  }

  async function handleSaveEditNote(noteId: number) {
    if (!id || !c) return
    const content = editingContent.trim()
    if (!content) {
      setEditNoteError('Note content cannot be empty.')
      return
    }
    setSavingNoteEdit(true)
    setEditNoteError(null)
    try {
      const updated = await updateCaseNote(c.id, noteId, content)
      setNotes((prev) => prev.map((n) => (n.id === noteId ? updated : n)))
      setEditingNoteId(null)
      setEditingContent('')
      setActionMsg('Note updated.')
      setTimeout(() => setActionMsg(null), 3000)
    } catch (e) {
      setEditNoteError(String(e))
    } finally {
      setSavingNoteEdit(false)
    }
  }

  async function handleDeleteNote(noteId: number) {
    if (!c) return
    if (!confirm('Are you sure you want to delete this investigation note?')) return
    try {
      await deleteCaseNote(c.id, noteId)
      setNotes((prev) => prev.filter((n) => n.id !== noteId))
      setActionMsg('Note deleted.')
      setTimeout(() => setActionMsg(null), 3000)
    } catch (e) {
      setNotesError(String(e))
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
          {user?.role === 'admin' && (
            <button className="btn btn-danger" onClick={handleDeleteCase}>
              Delete Case
            </button>
          )}
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
          <h3>Investigation Description / Summary</h3>
          <p className="case-desc-text">
            {c.description ?? <span className="text-muted">No description provided.</span>}
          </p>
        </div>
      </div>

      {/* Investigation Notes & Timeline */}
      <section className="dash-section">
        <div className="section-header">
          <h2>Investigation Notes ({notes.length})</h2>
        </div>

        {/* Add Note Card */}
        <div className="new-note-card">
          <h4>Add Investigation Note</h4>
          {addNoteError && <div className="error-banner">{addNoteError}</div>}
          <form onSubmit={handleAddNote}>
            <div className="form-group">
              <textarea
                className="note-textarea"
                rows={3}
                placeholder="Document findings, forensic artifacts, hypotheses, containment steps..."
                value={newNoteContent}
                onChange={(e) => setNewNoteContent(e.target.value)}
                maxLength={10000}
              />
              <div className="char-count">
                {newNoteContent.length} / 10000 characters
              </div>
            </div>
            <div className="form-actions">
              <button
                type="submit"
                className="btn btn-primary"
                disabled={addingNote || !newNoteContent.trim()}
              >
                {addingNote ? 'Adding…' : 'Add Note'}
              </button>
            </div>
          </form>
        </div>

        {/* Notes Timeline */}
        {loadingNotes ? (
          <Spinner label="Loading investigation notes…" />
        ) : notesError ? (
          <ErrorBanner message={notesError} />
        ) : notes.length === 0 ? (
          <p className="empty-text">No investigation notes recorded for this case yet.</p>
        ) : (
          <div className="notes-timeline">
            {notes.map((note) => {
              const isAuthor = user?.id === note.author_id
              const canDelete = isAuthor || user?.role === 'admin'
              const isEditingThisNote = editingNoteId === note.id

              return (
                <div key={note.id} className="timeline-item">
                  <div className="timeline-marker" />
                  <div className="timeline-card">
                    <div className="timeline-header">
                      <div className="timeline-meta">
                        <span className="timeline-author">{note.author_username}</span>
                        {note.author?.role && (
                          <span className={`role-badge role-${note.author.role}`}>
                            {note.author.role}
                          </span>
                        )}
                        <span className="timeline-time">{formatTs(note.created_at)}</span>
                        {note.updated_at !== note.created_at && (
                          <span className="timeline-edited" title={`Edited ${formatTs(note.updated_at)}`}>
                            (edited)
                          </span>
                        )}
                      </div>
                      <div className="timeline-actions">
                        {isAuthor && !isEditingThisNote && (
                          <button
                            type="button"
                            className="btn btn-xs btn-secondary"
                            onClick={() => handleStartEditNote(note)}
                          >
                            Edit
                          </button>
                        )}
                        {canDelete && !isEditingThisNote && (
                          <button
                            type="button"
                            className="btn btn-xs btn-danger"
                            onClick={() => handleDeleteNote(note.id)}
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </div>

                    {isEditingThisNote ? (
                      <div className="note-edit-form">
                        {editNoteError && <div className="error-banner">{editNoteError}</div>}
                        <textarea
                          className="note-textarea"
                          rows={3}
                          value={editingContent}
                          onChange={(e) => setEditingContent(e.target.value)}
                          maxLength={10000}
                        />
                        <div className="form-actions">
                          <button
                            type="button"
                            className="btn btn-xs btn-primary"
                            disabled={savingNoteEdit || !editingContent.trim()}
                            onClick={() => handleSaveEditNote(note.id)}
                          >
                            {savingNoteEdit ? 'Saving…' : 'Save'}
                          </button>
                          <button
                            type="button"
                            className="btn btn-xs btn-secondary"
                            onClick={handleCancelEditNote}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="timeline-body">{note.content}</div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </section>

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
