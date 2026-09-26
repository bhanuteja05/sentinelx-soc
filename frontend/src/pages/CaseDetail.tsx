import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  addCaseEvidence,
  assignCase,
  closeCase,
  createCaseNote,
  deleteCase,
  deleteCaseEvidence,
  deleteCaseNote,
  detachAlertFromCase,
  fetchCaseById,
  fetchCaseEvidence,
  fetchCaseNotes,
  fetchResponseActions,
  fetchApprovedCommands,
  executeActiveResponse,
  reopenCase,
  resolveCase,
  updateCase,
  updateCaseEvidence,
  updateCaseNote,
  type ApprovedCommand,
  type CaseDetailOut,
  type CaseEvidence,
  type CaseNote,
  type ResponseAction,
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

const DISPOSITION_LABELS: Record<string, string> = {
  true_positive_incident: 'True Positive — Incident Confirmed',
  false_positive_benign: 'False Positive — Benign Alert',
  benign_authorized_activity: 'Benign — Authorized Activity',
}

const ROOT_CAUSE_LABELS: Record<string, string> = {
  malware_execution: 'Malware Execution',
  credential_compromise: 'Credential Compromise',
  privilege_escalation: 'Privilege Escalation',
  unauthorized_access: 'Unauthorized Access',
  misconfiguration: 'System Misconfiguration',
  policy_violation: 'Policy Violation',
  security_testing: 'Authorized Security Testing',
}

const EVIDENCE_TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address',
  domain: 'Domain Name',
  url: 'URL',
  hash_sha256: 'SHA-256 Hash',
  hash_md5: 'MD5 Hash',
  file_path: 'File Path',
  user_account: 'User Account',
  host: 'Host / Endpoint',
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

  // Evidence state
  const [evidence, setEvidence] = useState<CaseEvidence[]>([])
  const [loadingEvidence, setLoadingEvidence] = useState(true)
  const [evidenceError, setEvidenceError] = useState<string | null>(null)
  const [verdictFilter, setVerdictFilter] = useState<string>('all')

  // Add evidence modal state
  const [showAddEvidenceModal, setShowAddEvidenceModal] = useState(false)
  const [newEvType, setNewEvType] = useState('ip')
  const [newEvValue, setNewEvValue] = useState('')
  const [newEvVerdict, setNewEvVerdict] = useState<'malicious' | 'suspicious' | 'benign' | 'informational'>('suspicious')
  const [newEvNotes, setNewEvNotes] = useState('')
  const [addingEvidence, setAddingEvidence] = useState(false)
  const [addEvidenceError, setAddEvidenceError] = useState<string | null>(null)

  // Assignment modal / state
  const [showAssignModal, setShowAssignModal] = useState(false)
  const [assignTargetId, setAssignTargetId] = useState('')
  const [assigning, setAssigning] = useState(false)
  const [assignError, setAssignError] = useState<string | null>(null)

  // Incident Resolution modal / state
  const [showResolveModal, setShowResolveModal] = useState(false)
  const [resDisposition, setResDisposition] = useState('true_positive_incident')
  const [resRootCause, setResRootCause] = useState('unauthorized_access')
  const [resSummary, setResSummary] = useState('')
  const [resolving, setResolving] = useState(false)
  const [resolveError, setResolveError] = useState<string | null>(null)

  // Incident Reopen modal / state
  const [showReopenModal, setShowReopenModal] = useState(false)
  const [reopenReason, setReopenReason] = useState('')
  const [reopening, setReopening] = useState(false)
  const [reopenError, setReopenError] = useState<string | null>(null)

  // Active Response & Defensive Containment state
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([])
  const [loadingResponseActions, setLoadingResponseActions] = useState(true)
  const [responseActionError, setResponseActionError] = useState<string | null>(null)
  const [approvedCommands, setApprovedCommands] = useState<ApprovedCommand[]>([])
  const [showContainmentModal, setShowContainmentModal] = useState(false)
  const [containmentCommand, setContainmentCommand] = useState<string>('firewall-drop')
  const [containmentTargetType, setContainmentTargetType] = useState<'ip' | 'agent'>('ip')
  const [containmentTargetValue, setContainmentTargetValue] = useState<string>('')
  const [containmentAgentId, setContainmentAgentId] = useState<string>('')
  const [containmentConfirmed, setContainmentConfirmed] = useState(false)
  const [executingContainment, setExecutingContainment] = useState(false)
  const [containmentModalError, setContainmentModalError] = useState<string | null>(null)
  const [selectedActionDetail, setSelectedActionDetail] = useState<ResponseAction | null>(null)

  async function reload() {
    if (!id) return
    try {
      const [caseData, notesData, evidenceData, actionsData] = await Promise.all([
        fetchCaseById(Number(id)),
        fetchCaseNotes(Number(id)),
        fetchCaseEvidence(Number(id)),
        fetchResponseActions({ case_id: Number(id) }).catch(() => ({ items: [], total: 0, page: 1, page_size: 25, pages: 1 })),
      ])
      setCase(caseData)
      setEditTitle(caseData.title)
      setEditDesc(caseData.description ?? '')
      setEditStatus(caseData.status)
      setEditSeverity(caseData.severity)
      setNotes(notesData)
      setEvidence(evidenceData)
      setResponseActions(actionsData.items)
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
      setLoadingEvidence(true)
      setLoadingResponseActions(true)
      try {
        const [caseData, notesData, evidenceData, actionsData, cmdsData] = await Promise.all([
          fetchCaseById(Number(id)),
          fetchCaseNotes(Number(id)),
          fetchCaseEvidence(Number(id)),
          fetchResponseActions({ case_id: Number(id) }).catch((err) => {
            setResponseActionError(String(err))
            return { items: [], total: 0, page: 1, page_size: 25, pages: 1 }
          }),
          fetchApprovedCommands().catch(() => []),
        ])
        if (!cancelled) {
          setCase(caseData)
          setEditTitle(caseData.title)
          setEditDesc(caseData.description ?? '')
          setEditStatus(caseData.status)
          setEditSeverity(caseData.severity)
          setNotes(notesData)
          setEvidence(evidenceData)
          setResponseActions(actionsData.items)
          setApprovedCommands(cmdsData)
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
          setLoadingEvidence(false)
          setLoadingResponseActions(false)
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
      await reload()
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

  // --- Assignment Handlers ---

  async function handleClaimIncident() {
    if (!c) return
    setAssigning(true)
    setAssignError(null)
    try {
      const updated = await assignCase(c.id, {})
      setCase({ ...c, ...updated })
      setActionMsg('Incident claimed and assigned to you.')
      setTimeout(() => setActionMsg(null), 3000)
      const updatedNotes = await fetchCaseNotes(c.id)
      setNotes(updatedNotes)
    } catch (e) {
      setError(String(e))
    } finally {
      setAssigning(false)
    }
  }

  async function handleUnassignIncident() {
    if (!c) return
    if (!confirm(`Unassign Case #${c.id}? It will be returned to the unassigned backlog.`)) return
    setAssigning(true)
    setAssignError(null)
    try {
      const updated = await assignCase(c.id, { unassign: true })
      setCase({ ...c, ...updated })
      setActionMsg('Case returned to unassigned backlog.')
      setTimeout(() => setActionMsg(null), 3000)
      const updatedNotes = await fetchCaseNotes(c.id)
      setNotes(updatedNotes)
    } catch (e) {
      setError(String(e))
    } finally {
      setAssigning(false)
    }
  }

  async function handleAssignSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!c) return
    const target = parseInt(assignTargetId, 10)
    if (isNaN(target)) {
      setAssignError('Please enter a valid numeric User ID.')
      return
    }
    setAssigning(true)
    setAssignError(null)
    try {
      const updated = await assignCase(c.id, { assignee_id: target })
      setCase({ ...c, ...updated })
      setShowAssignModal(false)
      setAssignTargetId('')
      setActionMsg('Analyst assignment updated.')
      setTimeout(() => setActionMsg(null), 3000)
      const updatedNotes = await fetchCaseNotes(c.id)
      setNotes(updatedNotes)
    } catch (e) {
      setAssignError(String(e))
    } finally {
      setAssigning(false)
    }
  }

  // --- Resolution Handlers ---

  async function handleResolveSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!c) return
    const summary = resSummary.trim()
    if (summary.length < 10) {
      setResolveError('Resolution summary must be at least 10 characters.')
      return
    }
    setResolving(true)
    setResolveError(null)
    try {
      const updated = await resolveCase(c.id, {
        disposition: resDisposition,
        root_cause: resRootCause,
        resolution_summary: summary,
      })
      setCase({ ...c, ...updated })
      setShowResolveModal(false)
      setResSummary('')
      setActionMsg('Incident resolved successfully.')
      setTimeout(() => setActionMsg(null), 3000)
      const updatedNotes = await fetchCaseNotes(c.id)
      setNotes(updatedNotes)
    } catch (e) {
      setResolveError(String(e))
    } finally {
      setResolving(false)
    }
  }

  async function handleReopenSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!c) return
    const reason = reopenReason.trim()
    if (!reason) {
      setReopenError('Reopening reason is required.')
      return
    }
    setReopening(true)
    setReopenError(null)
    try {
      const updated = await reopenCase(c.id, { reason })
      setCase({ ...c, ...updated })
      setShowReopenModal(false)
      setReopenReason('')
      setActionMsg('Incident reopened.')
      setTimeout(() => setActionMsg(null), 3000)
      const updatedNotes = await fetchCaseNotes(c.id)
      setNotes(updatedNotes)
    } catch (e) {
      setReopenError(String(e))
    } finally {
      setReopening(false)
    }
  }

  // --- Evidence Handlers ---

  async function handleAddEvidenceSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!c) return
    const val = newEvValue.trim()
    if (!val) {
      setAddEvidenceError('Evidence indicator value is required.')
      return
    }
    setAddingEvidence(true)
    setAddEvidenceError(null)
    try {
      const created = await addCaseEvidence(c.id, {
        evidence_type: newEvType,
        value: val,
        verdict: newEvVerdict,
        notes: newEvNotes.trim() || undefined,
      })
      setEvidence((prev) => [created, ...prev])
      setShowAddEvidenceModal(false)
      setNewEvValue('')
      setNewEvNotes('')
      setActionMsg(`Evidence "${created.value}" added to case.`)
      setTimeout(() => setActionMsg(null), 3000)
      const updatedNotes = await fetchCaseNotes(c.id)
      setNotes(updatedNotes)
    } catch (e) {
      setAddEvidenceError(String(e))
    } finally {
      setAddingEvidence(false)
    }
  }

  async function handleVerdictChange(evId: number, newVerdict: 'malicious' | 'suspicious' | 'benign' | 'informational') {
    if (!c) return
    try {
      const updated = await updateCaseEvidence(c.id, evId, { verdict: newVerdict })
      setEvidence((prev) => prev.map((item) => (item.id === evId ? updated : item)))
      setActionMsg(`Evidence verdict updated to ${newVerdict}.`)
      setTimeout(() => setActionMsg(null), 3000)
      const updatedNotes = await fetchCaseNotes(c.id)
      setNotes(updatedNotes)
    } catch (e) {
      setEvidenceError(String(e))
    }
  }

  async function handleDeleteEvidence(evId: number, val: string) {
    if (!c) return
    if (!confirm(`Delete evidence artifact "${val}" from this case?`)) return
    try {
      await deleteCaseEvidence(c.id, evId)
      setEvidence((prev) => prev.filter((item) => item.id !== evId))
      setActionMsg(`Evidence "${val}" removed.`)
      setTimeout(() => setActionMsg(null), 3000)
      const updatedNotes = await fetchCaseNotes(c.id)
      setNotes(updatedNotes)
    } catch (e) {
      setEvidenceError(String(e))
    }
  }

  // --- Note Handlers ---

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

  function handleOpenContainmentModal(defaults?: {
    command?: string
    targetType?: 'ip' | 'agent'
    targetValue?: string
    agentId?: string
  }) {
    const cmd = defaults?.command ?? 'firewall-drop'
    setContainmentCommand(cmd)
    const matchingCmd = approvedCommands.find((c) => c.command === cmd)
    setContainmentTargetType(defaults?.targetType ?? (matchingCmd?.target_type ?? 'ip'))
    setContainmentTargetValue(defaults?.targetValue ?? '')
    setContainmentAgentId(defaults?.agentId ?? '')
    setContainmentConfirmed(false)
    setContainmentModalError(null)
    setShowContainmentModal(true)
  }

  function handleCommandChange(cmd: string) {
    setContainmentCommand(cmd)
    const matchingCmd = approvedCommands.find((c) => c.command === cmd)
    if (matchingCmd) {
      setContainmentTargetType(matchingCmd.target_type)
    }
  }

  async function handleExecuteContainment(e: React.FormEvent) {
    e.preventDefault()
    if (!c) return
    if (!containmentConfirmed) {
      setContainmentModalError('Please explicitly confirm the containment action before executing.')
      return
    }
    setExecutingContainment(true)
    setContainmentModalError(null)
    try {
      const action = await executeActiveResponse({
        command: containmentCommand,
        target_type: containmentTargetType,
        target_value: containmentTargetValue.trim(),
        agent_id: containmentTargetType === 'ip' && containmentAgentId.trim() ? containmentAgentId.trim() : undefined,
        case_id: c.id,
      })
      setResponseActions((prev) => [action, ...prev])
      setShowContainmentModal(false)
      setActionMsg(`Active response ${action.status}: ${action.command} on ${action.target_value}`)
      setTimeout(() => setActionMsg(null), 5000)

      // Refresh case notes to reflect audit note
      const notesRes = await fetchCaseNotes(c.id)
      setNotes(notesRes)
    } catch (err) {
      setContainmentModalError(String(err))
    } finally {
      setExecutingContainment(false)
    }
  }

  // Filter evidence
  const filteredEvidence = verdictFilter === 'all'
    ? evidence
    : evidence.filter((ev) => ev.verdict === verdictFilter)

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

  const isResolvedOrClosed = c.status === 'resolved' || c.status === 'closed'
  const isAssignedToCurrentUser = c.assignee_id === user?.id

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
          {!isResolvedOrClosed ? (
            <>
              <button
                type="button"
                className="btn btn-success"
                onClick={() => setShowResolveModal(true)}
              >
                ✓ Resolve Incident
              </button>
              {!isAssignedToCurrentUser && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleClaimIncident}
                  disabled={assigning}
                >
                  👤 Claim Incident
                </button>
              )}
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleCloseCase}
              >
                Close Case
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setShowReopenModal(true)}
            >
              🔄 Reopen Incident
            </button>
          )}

          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setIsEditing(!isEditing)}
          >
            {isEditing ? 'Cancel Edit' : 'Edit Case'}
          </button>
          {user?.role === 'admin' && (
            <button type="button" className="btn btn-danger" onClick={handleDeleteCase}>
              Delete Case
            </button>
          )}
        </div>
      </div>

      {actionMsg && <div className="success-banner">{actionMsg}</div>}

      {/* Incident Ownership Bar */}
      <div className="ownership-bar">
        <div className="ownership-left">
          <span className="ownership-label">Assigned Analyst:</span>
          {c.assignee ? (
            <div className="assignee-active">
              <span className="assignee-avatar">👤</span>
              <span className="assignee-name">{c.assignee.username}</span>
              <span className={`role-badge role-${c.assignee.role}`}>{c.assignee.role}</span>
              {isAssignedToCurrentUser && (
                <span className="assignee-you-tag">(You)</span>
              )}
            </div>
          ) : (
            <span className="unassigned-badge">⏳ Unassigned Backlog</span>
          )}
        </div>
        <div className="ownership-actions">
          {!isAssignedToCurrentUser && (
            <button
              type="button"
              className="btn btn-xs btn-primary"
              onClick={handleClaimIncident}
              disabled={assigning}
            >
              Claim (Assign to Me)
            </button>
          )}
          <button
            type="button"
            className="btn btn-xs btn-secondary"
            onClick={() => setShowAssignModal(true)}
          >
            Reassign
          </button>
          {c.assignee && (
            <button
              type="button"
              className="btn btn-xs btn-secondary"
              onClick={handleUnassignIncident}
              disabled={assigning}
            >
              Unassign
            </button>
          )}
        </div>
      </div>

      {/* Resolution Banner */}
      {isResolvedOrClosed && (
        <div className="resolution-banner">
          <div className="resolution-header">
            <div className="resolution-title">
              <span className="resolution-icon">✓</span>
              <span>Incident Resolution Details</span>
              <span className={`status-badge status-${c.status}`}>{c.status}</span>
            </div>
            <button
              type="button"
              className="btn btn-xs btn-secondary"
              onClick={() => setShowReopenModal(true)}
            >
              🔄 Reopen Incident
            </button>
          </div>
          <div className="resolution-grid">
            <div>
              <span className="res-field-label">Disposition</span>
              <span className="res-field-value res-highlight">
                {c.disposition ? (DISPOSITION_LABELS[c.disposition] ?? c.disposition) : '—'}
              </span>
            </div>
            <div>
              <span className="res-field-label">Root Cause</span>
              <span className="res-field-value">
                {c.root_cause ? (ROOT_CAUSE_LABELS[c.root_cause] ?? c.root_cause) : '—'}
              </span>
            </div>
            <div>
              <span className="res-field-label">Resolved By</span>
              <span className="res-field-value">
                {c.resolved_by ? c.resolved_by.username : '—'}
              </span>
            </div>
            <div>
              <span className="res-field-label">Resolved At</span>
              <span className="res-field-value">{formatTs(c.resolved_at)}</span>
            </div>
          </div>
          {c.resolution_summary && (
            <div className="resolution-summary-box">
              <span className="res-field-label">Resolution Summary:</span>
              <p className="resolution-summary-text">{c.resolution_summary}</p>
            </div>
          )}
        </div>
      )}

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
            <div><dt>Assignee</dt><dd>{c.assignee ? c.assignee.username : <span className="text-muted">Unassigned</span>}</dd></div>
            <div><dt>Evidence Items</dt><dd>{evidence.length}</dd></div>
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

      {/* Evidence / Artifact Locker Section */}
      <section className="dash-section">
        <div className="section-header">
          <div className="section-header-left">
            <h2>Evidence Locker ({evidence.length})</h2>
            <div className="verdict-filter-group">
              <button
                type="button"
                className={`filter-chip ${verdictFilter === 'all' ? 'active' : ''}`}
                onClick={() => setVerdictFilter('all')}
              >
                All ({evidence.length})
              </button>
              <button
                type="button"
                className={`filter-chip verdict-chip-malicious ${verdictFilter === 'malicious' ? 'active' : ''}`}
                onClick={() => setVerdictFilter('malicious')}
              >
                Malicious ({evidence.filter((e) => e.verdict === 'malicious').length})
              </button>
              <button
                type="button"
                className={`filter-chip verdict-chip-suspicious ${verdictFilter === 'suspicious' ? 'active' : ''}`}
                onClick={() => setVerdictFilter('suspicious')}
              >
                Suspicious ({evidence.filter((e) => e.verdict === 'suspicious').length})
              </button>
              <button
                type="button"
                className={`filter-chip verdict-chip-benign ${verdictFilter === 'benign' ? 'active' : ''}`}
                onClick={() => setVerdictFilter('benign')}
              >
                Benign ({evidence.filter((e) => e.verdict === 'benign').length})
              </button>
              <button
                type="button"
                className={`filter-chip verdict-chip-informational ${verdictFilter === 'informational' ? 'active' : ''}`}
                onClick={() => setVerdictFilter('informational')}
              >
                Info ({evidence.filter((e) => e.verdict === 'informational').length})
              </button>
            </div>
          </div>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => setShowAddEvidenceModal(true)}
          >
            + Catalog Evidence
          </button>
        </div>

        {evidenceError && <ErrorBanner message={evidenceError} />}

        {loadingEvidence ? (
          <Spinner label="Loading evidence locker…" />
        ) : filteredEvidence.length === 0 ? (
          <div className="empty-evidence-box">
            <span className="empty-icon">📁</span>
            <p>
              {verdictFilter === 'all'
                ? 'No evidence artifacts cataloged in this incident locker yet.'
                : `No evidence items with verdict "${verdictFilter}".`}
            </p>
            {verdictFilter === 'all' && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setShowAddEvidenceModal(true)}
              >
                Catalog First Evidence
              </button>
            )}
          </div>
        ) : (
          <div className="table-responsive">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Indicator / Artifact Value</th>
                  <th>Verdict</th>
                  <th>Analyst Notes</th>
                  <th>Source / Added By</th>
                  <th>Recorded At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvidence.map((ev) => (
                  <tr key={ev.id}>
                    <td>
                      <span className="evidence-type-badge">
                        {EVIDENCE_TYPE_LABELS[ev.evidence_type] ?? ev.evidence_type}
                      </span>
                    </td>
                    <td className="mono mono-strong">{ev.value}</td>
                    <td>
                      <select
                        className={`verdict-select verdict-${ev.verdict}`}
                        value={ev.verdict}
                        onChange={(e) =>
                          void handleVerdictChange(
                            ev.id,
                            e.target.value as 'malicious' | 'suspicious' | 'benign' | 'informational',
                          )
                        }
                      >
                        <option value="malicious">Malicious</option>
                        <option value="suspicious">Suspicious</option>
                        <option value="benign">Benign</option>
                        <option value="informational">Informational</option>
                      </select>
                    </td>
                    <td>
                      <span className="evidence-notes-text">
                        {ev.notes ?? <span className="text-muted">—</span>}
                      </span>
                    </td>
                    <td>
                      {ev.alert_id ? (
                        <Link to={`/alerts/${ev.alert_id}`} className="table-link">
                          Alert #{ev.alert_id}
                        </Link>
                      ) : ev.added_by ? (
                        <span>{ev.added_by.username}</span>
                      ) : (
                        <span className="text-muted">Manual</span>
                      )}
                    </td>
                    <td>{formatTs(ev.created_at)}</td>
                    <td className="cell-actions">
                      {ev.evidence_type === 'ip' && (
                        <button
                          type="button"
                          className="btn btn-xs btn-warning"
                          title="Block IP via Active Response"
                          onClick={() => handleOpenContainmentModal({ command: 'firewall-drop', targetType: 'ip', targetValue: ev.value })}
                        >
                          🛡️ Block IP
                        </button>
                      )}
                      {ev.evidence_type === 'host' && (
                        <button
                          type="button"
                          className="btn btn-xs btn-danger"
                          title="Isolate Host via Active Response"
                          onClick={() => handleOpenContainmentModal({ command: 'isolate-host', targetType: 'agent', targetValue: ev.value })}
                        >
                          🔒 Isolate Host
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn btn-xs btn-danger"
                        title="Delete evidence artifact"
                        onClick={() => void handleDeleteEvidence(ev.id, ev.value)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Defensive Containment & Active Response */}
      <section className="dash-section">
        <div className="section-header">
          <div>
            <h2>Defensive Containment & Active Response ({responseActions.length})</h2>
            <p className="section-subtitle">
              Auditable execution of verified Wazuh active response commands and host containment actions.
            </p>
          </div>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => handleOpenContainmentModal()}
          >
            + Execute Response
          </button>
        </div>

        {responseActionError && <ErrorBanner message={responseActionError} />}

        {loadingResponseActions ? (
          <Spinner label="Loading containment actions…" />
        ) : responseActions.length === 0 ? (
          <div className="empty-evidence-box">
            <span className="empty-icon">🛡️</span>
            <p>No active response containment actions executed for this incident yet.</p>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => handleOpenContainmentModal()}
            >
              Execute Defensive Action
            </button>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Action ID</th>
                  <th>Command</th>
                  <th>Target Type</th>
                  <th>Target Value</th>
                  <th>Status</th>
                  <th>Executed At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {responseActions.map((action) => (
                  <tr key={action.id}>
                    <td className="mono">#{action.id}</td>
                    <td>
                      <span className="mono mono-strong">{action.command}</span>
                    </td>
                    <td>
                      <span className="evidence-type-badge">{action.target_type.toUpperCase()}</span>
                    </td>
                    <td className="mono">{action.target_value}</td>
                    <td>
                      <span className={`status-badge status-${action.status}`}>
                        {action.status}
                      </span>
                    </td>
                    <td>{formatTs(action.created_at)}</td>
                    <td className="cell-actions">
                      <button
                        type="button"
                        className="btn btn-xs btn-secondary"
                        onClick={() => setSelectedActionDetail(action)}
                      >
                        View Output
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Investigation Notes & Timeline */}
      <section className="dash-section">
        <div className="section-header">
          <h2>Investigation Notes & Audit Timeline ({notes.length})</h2>
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

              // Determine audit tag
              let auditBadge = null
              if (note.content.startsWith('[Active Response]')) {
                auditBadge = <span className="role-badge note-tag-response">🛡️ Active Response</span>
              } else if (note.content.startsWith('[Case Assignment]')) {
                auditBadge = <span className="role-badge note-tag-assignment">👤 Assignment</span>
              } else if (note.content.startsWith('[Evidence')) {
                auditBadge = <span className="role-badge note-tag-evidence">📌 Evidence Locker</span>
              } else if (note.content.startsWith('[Incident Resolved]')) {
                auditBadge = <span className="role-badge note-tag-resolved">✓ Resolved</span>
              } else if (note.content.startsWith('[Incident Reopened]')) {
                auditBadge = <span className="role-badge note-tag-reopened">🔄 Reopened</span>
              } else if (note.content.startsWith('[Automated Triage]')) {
                auditBadge = <span className="role-badge triage-badge">⚡ Automated Triage</span>
              } else if (note.content.startsWith('[Alert Attached]') || note.content.startsWith('[Alert Detached]')) {
                auditBadge = <span className="role-badge note-tag-correlation">🔗 Correlation</span>
              } else if (note.author_username === 'system') {
                auditBadge = <span className="role-badge note-tag-system">⚙ System</span>
              }

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
                        {auditBadge}
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
                        type="button"
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

      {/* --- MODALS --- */}

      {/* Add Evidence Modal */}
      {showAddEvidenceModal && (
        <div className="modal-backdrop">
          <div className="modal-box">
            <div className="modal-header">
              <h3>Catalog Evidence Artifact</h3>
              <button
                type="button"
                className="btn-icon"
                onClick={() => setShowAddEvidenceModal(false)}
              >
                ✕
              </button>
            </div>
            {addEvidenceError && <ErrorBanner message={addEvidenceError} />}
            <form onSubmit={handleAddEvidenceSubmit}>
              <div className="form-group">
                <label htmlFor="ev-type">Evidence Type</label>
                <select
                  id="ev-type"
                  value={newEvType}
                  onChange={(e) => setNewEvType(e.target.value)}
                >
                  <option value="ip">IP Address</option>
                  <option value="domain">Domain Name</option>
                  <option value="url">URL</option>
                  <option value="hash_sha256">SHA-256 Hash</option>
                  <option value="hash_md5">MD5 Hash</option>
                  <option value="file_path">File Path</option>
                  <option value="user_account">User Account</option>
                  <option value="host">Host / Computer</option>
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="ev-value">Indicator / Value</label>
                <input
                  id="ev-value"
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.23, malware.exe, admin_test"
                  value={newEvValue}
                  onChange={(e) => setNewEvValue(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label htmlFor="ev-verdict">Analyst Verdict</label>
                <select
                  id="ev-verdict"
                  value={newEvVerdict}
                  onChange={(e) =>
                    setNewEvVerdict(
                      e.target.value as 'malicious' | 'suspicious' | 'benign' | 'informational',
                    )
                  }
                >
                  <option value="malicious">Malicious (Confirmed threat)</option>
                  <option value="suspicious">Suspicious (Requires validation)</option>
                  <option value="benign">Benign (Legitimate activity)</option>
                  <option value="informational">Informational (Context / telemetry)</option>
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="ev-notes">Forensic Context / Notes</label>
                <textarea
                  id="ev-notes"
                  rows={2}
                  placeholder="Optional analyst commentary or correlation note"
                  value={newEvNotes}
                  onChange={(e) => setNewEvNotes(e.target.value)}
                />
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowAddEvidenceModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={addingEvidence || !newEvValue.trim()}
                >
                  {addingEvidence ? 'Cataloging…' : 'Catalog Evidence'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Assign Incident Modal */}
      {showAssignModal && (
        <div className="modal-backdrop">
          <div className="modal-box">
            <div className="modal-header">
              <h3>Reassign Incident #{c.id}</h3>
              <button
                type="button"
                className="btn-icon"
                onClick={() => setShowAssignModal(false)}
              >
                ✕
              </button>
            </div>
            {assignError && <ErrorBanner message={assignError} />}
            <form onSubmit={handleAssignSubmit}>
              <p className="modal-desc">
                Assign this incident to another SOC analyst by entering their user ID, or claim it for yourself.
              </p>
              <div className="form-group">
                <label htmlFor="assign-id">Target Analyst User ID</label>
                <input
                  id="assign-id"
                  type="number"
                  required
                  placeholder="e.g. 1"
                  value={assignTargetId}
                  onChange={(e) => setAssignTargetId(e.target.value)}
                />
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowAssignModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleClaimIncident}
                  disabled={assigning}
                >
                  Assign to Me
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={assigning || !assignTargetId.trim()}
                >
                  {assigning ? 'Assigning…' : 'Reassign Incident'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Resolve Incident Modal */}
      {showResolveModal && (
        <div className="modal-backdrop">
          <div className="modal-box modal-box--large">
            <div className="modal-header">
              <h3>Resolve Incident #{c.id}</h3>
              <button
                type="button"
                className="btn-icon"
                onClick={() => setShowResolveModal(false)}
              >
                ✕
              </button>
            </div>
            {resolveError && <ErrorBanner message={resolveError} />}
            <form onSubmit={handleResolveSubmit}>
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="res-disp">Incident Disposition</label>
                  <select
                    id="res-disp"
                    value={resDisposition}
                    onChange={(e) => setResDisposition(e.target.value)}
                  >
                    <option value="true_positive_incident">
                      True Positive — Incident Confirmed
                    </option>
                    <option value="false_positive_benign">
                      False Positive — Benign Alert
                    </option>
                    <option value="benign_authorized_activity">
                      Benign — Authorized Activity
                    </option>
                  </select>
                </div>

                <div className="form-group">
                  <label htmlFor="res-cause">Root Cause Analysis</label>
                  <select
                    id="res-cause"
                    value={resRootCause}
                    onChange={(e) => setResRootCause(e.target.value)}
                  >
                    <option value="unauthorized_access">Unauthorized Access</option>
                    <option value="malware_execution">Malware Execution</option>
                    <option value="credential_compromise">Credential Compromise</option>
                    <option value="privilege_escalation">Privilege Escalation</option>
                    <option value="misconfiguration">System Misconfiguration</option>
                    <option value="policy_violation">Policy Violation</option>
                    <option value="security_testing">Authorized Security Testing</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="res-summary">Resolution Summary & Remediation Notes (min 10 characters)</label>
                <textarea
                  id="res-summary"
                  rows={4}
                  required
                  minLength={10}
                  placeholder="Detail containment actions taken, remediation steps, root cause confirmation, or false-positive rationale..."
                  value={resSummary}
                  onChange={(e) => setResSummary(e.target.value)}
                />
                <div className="char-count">
                  {resSummary.length} characters (minimum 10)
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowResolveModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-success"
                  disabled={resolving || resSummary.trim().length < 10}
                >
                  {resolving ? 'Resolving…' : '✓ Confirm Resolution'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reopen Incident Modal */}
      {showReopenModal && (
        <div className="modal-backdrop">
          <div className="modal-box">
            <div className="modal-header">
              <h3>Reopen Incident #{c.id}</h3>
              <button
                type="button"
                className="btn-icon"
                onClick={() => setShowReopenModal(false)}
              >
                ✕
              </button>
            </div>
            {reopenError && <ErrorBanner message={reopenError} />}
            <form onSubmit={handleReopenSubmit}>
              <p className="modal-desc">
                Reopening this incident will transition status back to <strong>in_progress</strong> and record an audit log with your justification.
              </p>
              <div className="form-group">
                <label htmlFor="reopen-reason">Reopening Justification / Reason</label>
                <textarea
                  id="reopen-reason"
                  rows={3}
                  required
                  placeholder="State why this incident is being reopened (e.g. recurrence of alerts, new forensic evidence, post-incident findings)..."
                  value={reopenReason}
                  onChange={(e) => setReopenReason(e.target.value)}
                />
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowReopenModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={reopening || !reopenReason.trim()}
                >
                  {reopening ? 'Reopening…' : '🔄 Confirm Reopen'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Active Response Containment Modal */}
      {showContainmentModal && (
        <div className="modal-backdrop">
          <div className="modal-box modal-box--large">
            <div className="modal-header">
              <h3>🛡️ Execute Defensive Active Response</h3>
              <button
                type="button"
                className="btn-icon"
                onClick={() => setShowContainmentModal(false)}
              >
                ✕
              </button>
            </div>
            {containmentModalError && <ErrorBanner message={containmentModalError} />}
            <form onSubmit={handleExecuteContainment}>
              <div className="form-group">
                <label htmlFor="response-cmd">Defensive Command</label>
                <select
                  id="response-cmd"
                  value={containmentCommand}
                  onChange={(e) => handleCommandChange(e.target.value)}
                >
                  {approvedCommands.length > 0 ? (
                    approvedCommands.map((cmd) => (
                      <option key={cmd.command} value={cmd.command}>
                        {cmd.name} ({cmd.risk_level.toUpperCase()})
                      </option>
                    ))
                  ) : (
                    <>
                      <option value="firewall-drop">Block IP (Firewall Drop)</option>
                      <option value="host-deny">Deny Host (TCP Wrappers)</option>
                      <option value="isolate-host">Isolate Endpoint (Network Quarantine)</option>
                      <option value="restart-wazuh">Restart Wazuh Agent</option>
                    </>
                  )}
                </select>
              </div>

              {/* Command Details & Warning Banner */}
              {(() => {
                const currentCmd = approvedCommands.find((c) => c.command === containmentCommand)
                return (
                  <div className="containment-warning-box">
                    <strong>⚠️ Caution: </strong>
                    {currentCmd?.warning || 'Defensive host response commands may impact network connectivity or daemon execution on the target.'}
                  </div>
                )
              })()}

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="target-type">Target Type</label>
                  <select
                    id="target-type"
                    value={containmentTargetType}
                    onChange={(e) => setContainmentTargetType(e.target.value as 'ip' | 'agent')}
                  >
                    <option value="ip">IP Address</option>
                    <option value="agent">Wazuh Agent ID</option>
                  </select>
                </div>
                <div className="form-group">
                  <label htmlFor="target-value">
                    {containmentTargetType === 'ip' ? 'Target IP Address' : 'Target Agent Identifier'}
                  </label>
                  <input
                    id="target-value"
                    type="text"
                    required
                    placeholder={containmentTargetType === 'ip' ? 'e.g. 198.51.100.77' : 'e.g. 001'}
                    value={containmentTargetValue}
                    onChange={(e) => setContainmentTargetValue(e.target.value)}
                  />
                </div>
              </div>

              {containmentTargetType === 'ip' && (
                <div className="form-group">
                  <label htmlFor="agent-id">Host Agent ID (Optional, leave blank for all active hosts)</label>
                  <input
                    id="agent-id"
                    type="text"
                    placeholder="e.g. 000, 001 (or leave blank)"
                    value={containmentAgentId}
                    onChange={(e) => setContainmentAgentId(e.target.value)}
                  />
                </div>
              )}

              {/* Human-in-the-loop confirmation */}
              <label className="containment-confirm-check">
                <input
                  type="checkbox"
                  checked={containmentConfirmed}
                  onChange={(e) => setContainmentConfirmed(e.target.checked)}
                />
                <span>
                  I confirm execution of defensive command <strong>{containmentCommand}</strong> against target{' '}
                  <code className="mono">{containmentTargetValue || '[specify target]'}</code>.
                </span>
              </label>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowContainmentModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-danger"
                  disabled={executingContainment || !containmentConfirmed || !containmentTargetValue.trim()}
                >
                  {executingContainment ? 'Executing Containment…' : 'Execute Containment'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Action Output Detail Modal */}
      {selectedActionDetail && (
        <div className="modal-backdrop">
          <div className="modal-box modal-box--large">
            <div className="modal-header">
              <h3>Response Action #{selectedActionDetail.id} Output</h3>
              <button
                type="button"
                className="btn-icon"
                onClick={() => setSelectedActionDetail(null)}
              >
                ✕
              </button>
            </div>
            <div className="meta-list" style={{ marginBottom: '1rem' }}>
              <div><dt>Command</dt><dd className="mono">{selectedActionDetail.command}</dd></div>
              <div><dt>Target</dt><dd className="mono">{selectedActionDetail.target_type.toUpperCase()}: {selectedActionDetail.target_value}</dd></div>
              <div><dt>Status</dt><dd><span className={`status-badge status-${selectedActionDetail.status}`}>{selectedActionDetail.status}</span></dd></div>
              <div><dt>Timestamp</dt><dd>{formatTs(selectedActionDetail.created_at)}</dd></div>
            </div>

            {selectedActionDetail.error_message && (
              <div className="error-banner" style={{ marginBottom: '1rem' }}>
                {selectedActionDetail.error_message}
              </div>
            )}

            <div className="form-group">
              <label>Raw Execution Output</label>
              <pre className="response-output-pre">
                {JSON.stringify(selectedActionDetail.execution_output, null, 2) || 'No output payload recorded.'}
              </pre>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setSelectedActionDetail(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
