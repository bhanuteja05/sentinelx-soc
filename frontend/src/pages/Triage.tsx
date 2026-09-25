import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  fetchTriageRules,
  updateTriageRule,
  evaluateTriageBacklog,
  type TriageRule,
  type TriageEvaluationResult,
} from '../api/client'
import { useAuth } from '../context/AuthContext'
import { SeverityLabel } from '../components/SeverityBadge'
import Spinner from '../components/Spinner'
import ErrorBanner from '../components/ErrorBanner'

export default function Triage() {
  const { user } = useAuth()
  const [rules, setRules] = useState<TriageRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const [evalResult, setEvalResult] = useState<TriageEvaluationResult | null>(null)
  const [evalError, setEvalError] = useState<string | null>(null)
  const [togglingRuleId, setTogglingRuleId] = useState<number | null>(null)

  const isAdmin = user?.role === 'admin'

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const data = await fetchTriageRules()
        if (!cancelled) {
          setRules(data)
          setError(null)
        }
      } catch (e) {
        if (!cancelled) setError(String(e))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [])

  async function handleToggleRule(rule: TriageRule) {
    if (!isAdmin) return
    setTogglingRuleId(rule.id)
    try {
      const updated = await updateTriageRule(rule.id, { is_active: !rule.is_active })
      setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)))
    } catch (e) {
      setError(String(e))
    } finally {
      setTogglingRuleId(null)
    }
  }

  async function handleRunEvaluation() {
    setEvaluating(true)
    setEvalError(null)
    setEvalResult(null)
    try {
      const res = await evaluateTriageBacklog(100)
      setEvalResult(res)
    } catch (e) {
      setEvalError(String(e))
    } finally {
      setEvaluating(false)
    }
  }

  const activeCount = rules.filter((r) => r.is_active).length

  return (
    <div className="page">
      <div className="page-header page-header--split">
        <div>
          <h1 className="page-title">Automated Alert Triage</h1>
          <p className="page-subtitle">
            Rule-based alert evaluation, automated case escalation, and campaign correlation
          </p>
        </div>
        <div className="header-actions">
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleRunEvaluation}
            disabled={evaluating}
          >
            {evaluating ? 'Evaluating Backlog…' : '⚡ Run Triage Evaluation'}
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}
      {evalError && <ErrorBanner message={evalError} />}

      {/* Evaluation Results Banner */}
      {evalResult && (
        <div className="triage-result-banner">
          <div className="result-summary">
            <h3>Triage Backlog Evaluation Completed</h3>
            <p>
              Evaluated <strong>{evalResult.evaluated_alerts}</strong> alerts:{' '}
              <span className="res-highlight res-create">{evalResult.cases_created} cases created</span>,{' '}
              <span className="res-highlight res-corr">{evalResult.alerts_correlated} alerts correlated</span>,{' '}
              <span className="res-highlight res-unmatch">{evalResult.unmatched_alerts} unmatched</span>.
            </p>
          </div>
          {evalResult.details.length > 0 && (
            <div className="result-actions-list">
              {evalResult.details.map((d, i) => (
                <div key={i} className="result-action-item">
                  <span className={`action-badge action-${d.action}`}>
                    {d.action.toUpperCase()}
                  </span>
                  <span>
                    Alert #{d.alert_id} →{' '}
                    <Link to={`/cases/${d.case_id}`} className="table-link">
                      Case #{d.case_id}: {d.case_title}
                    </Link>{' '}
                    (via {d.rule_name})
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* KPI Cards */}
      <section className="stat-grid">
        <div className="stat-card stat-card--neutral">
          <div className="stat-value">{rules.length}</div>
          <div className="stat-label">Configured Rules</div>
        </div>
        <div className="stat-card stat-card--low">
          <div className="stat-value">{activeCount}</div>
          <div className="stat-label">Active Rules</div>
        </div>
        <div className="stat-card stat-card--high">
          <div className="stat-value">24h</div>
          <div className="stat-label">Correlation Window</div>
        </div>
        <div className="stat-card stat-card--neutral">
          <div className="stat-value">Auto</div>
          <div className="stat-label">Execution Mode</div>
        </div>
      </section>

      {/* Triage Rules Table */}
      <section className="dash-section">
        <div className="section-header">
          <h2>Triage Escalation Policies</h2>
          <span className="section-sub">Evaluated in order during alert ingestion</span>
        </div>

        {loading ? (
          <Spinner label="Loading triage policies…" />
        ) : rules.length === 0 ? (
          <p className="empty-text">No triage rules configured.</p>
        ) : (
          <div className="alerts-table-wrap">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Rule Name</th>
                  <th>Match Criteria</th>
                  <th>Action Mode</th>
                  <th>Case Severity</th>
                  <th>Title Template</th>
                  {isAdmin && <th>Action</th>}
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => {
                  const criteria = []
                  if (rule.min_rule_level !== null) {
                    criteria.push(`Level ≥ ${rule.min_rule_level}`)
                  }
                  if (rule.rule_ids.length > 0) {
                    criteria.push(`IDs: ${rule.rule_ids.join(', ')}`)
                  }
                  if (rule.mitre_tactics.length > 0) {
                    criteria.push(`Tactics: ${rule.mitre_tactics.join(', ')}`)
                  }
                  if (rule.mitre_techniques.length > 0) {
                    criteria.push(`Techs: ${rule.mitre_techniques.join(', ')}`)
                  }

                  return (
                    <tr key={rule.id} className={rule.is_active ? '' : 'row-disabled'}>
                      <td>
                        <span className={`status-badge status-${rule.is_active ? 'active' : 'inactive'}`}>
                          {rule.is_active ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                      <td>
                        <strong>{rule.name}</strong>
                        {rule.description && (
                          <div className="rule-desc">{rule.description}</div>
                        )}
                      </td>
                      <td>
                        <div className="criteria-list">
                          {criteria.map((c, idx) => (
                            <span key={idx} className="criteria-chip">
                              {c}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <code className="action-code">{rule.action_type}</code>
                      </td>
                      <td>
                        <SeverityLabel severity={rule.case_severity} />
                      </td>
                      <td>
                        <span className="template-preview" title={rule.case_title_template}>
                          {rule.case_title_template}
                        </span>
                      </td>
                      {isAdmin && (
                        <td>
                          <button
                            type="button"
                            className={`btn btn-xs ${rule.is_active ? 'btn-secondary' : 'btn-primary'}`}
                            disabled={togglingRuleId === rule.id}
                            onClick={() => handleToggleRule(rule)}
                          >
                            {togglingRuleId === rule.id
                              ? 'Saving…'
                              : rule.is_active
                              ? 'Disable'
                              : 'Enable'}
                          </button>
                        </td>
                      )}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
