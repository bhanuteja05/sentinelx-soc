import { useEffect, useState } from 'react'

import { Link } from 'react-router-dom'
import {
  fetchAlerts,
  type AlertOut,
  type AlertsQuery,
  type PaginatedAlertsResponse,
} from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'
import Pagination from '../components/Pagination'
import Spinner from '../components/Spinner'
import ErrorBanner from '../components/ErrorBanner'

function formatTs(value: string | null | undefined): string {
  if (!value) return '—'
  const d = new Date(value)
  return isNaN(d.getTime()) ? value : d.toLocaleString()
}

function formatMitre(alert: AlertOut): string {
  const parts: string[] = []
  if (alert.mitre_tactics.length > 0) parts.push(alert.mitre_tactics.join(', '))
  if (alert.mitre_techniques.length > 0) parts.push(alert.mitre_techniques.join(', '))
  return parts.length > 0 ? parts.join(' | ') : '—'
}

type SortField = 'timestamp' | 'rule_level' | 'rule_id'

export default function Alerts() {
  const [data, setData] = useState<PaginatedAlertsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filter state
  const [ruleLevel, setRuleLevel] = useState<string>('')
  const [agentName, setAgentName] = useState<string>('')
  const [ruleId, setRuleId] = useState<string>('')
  const [mitreTactic, setMitreTactic] = useState<string>('')
  const [mitreTechnique, setMitreTechnique] = useState<string>('')
  const [sortBy, setSortBy] = useState<SortField>('timestamp')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const [page, setPage] = useState(1)
  const pageSize = 20

  useEffect(() => {
    let cancelled = false
    const query: AlertsQuery = {
      page,
      page_size: pageSize,
      sort_by: sortBy,
      sort_order: sortOrder,
    }
    if (ruleLevel !== '') query.rule_level = Number(ruleLevel)
    if (agentName.trim()) query.agent_name = agentName.trim()
    if (ruleId.trim()) query.rule_id = ruleId.trim()
    if (mitreTactic.trim()) query.mitre_tactic = mitreTactic.trim()
    if (mitreTechnique.trim()) query.mitre_technique = mitreTechnique.trim()

    async function execute() {
      try {
        const resp = await fetchAlerts(query)
        if (!cancelled) {
          setData(resp)
          setError(null)
        }
      } catch (e) {
        if (!cancelled) setError(String(e))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void execute()
    return () => {
      cancelled = true
    }
  }, [ruleLevel, agentName, ruleId, mitreTactic, mitreTechnique, sortBy, sortOrder, page])

  function handleFilterSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setPage(1)
  }


  function handleClearFilters() {
    setRuleLevel('')
    setAgentName('')
    setRuleId('')
    setMitreTactic('')
    setMitreTechnique('')
    setPage(1)
  }

  function toggleSort(field: SortField) {
    if (sortBy === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortBy(field)
      setSortOrder('desc')
    }
    setPage(1)
  }

  function sortIndicator(field: SortField) {
    if (sortBy !== field) return ' ⇅'
    return sortOrder === 'asc' ? ' ▲' : ' ▼'
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Alerts</h1>
        <p className="page-subtitle">Persisted Wazuh alert archive</p>
      </div>

      {error && <ErrorBanner message={error} />}

      {/* Filter bar */}
      <form className="filter-bar" onSubmit={handleFilterSubmit}>
        <div className="filter-group">
          <label htmlFor="f-level">Level</label>
          <input
            id="f-level"
            type="number"
            min="0"
            max="16"
            placeholder="e.g. 10"
            value={ruleLevel}
            onChange={(e) => setRuleLevel(e.target.value)}
          />
        </div>
        <div className="filter-group">
          <label htmlFor="f-agent">Agent</label>
          <input
            id="f-agent"
            type="text"
            placeholder="Agent name"
            value={agentName}
            onChange={(e) => setAgentName(e.target.value)}
          />
        </div>
        <div className="filter-group">
          <label htmlFor="f-rule">Rule ID</label>
          <input
            id="f-rule"
            type="text"
            placeholder="e.g. 60100"
            value={ruleId}
            onChange={(e) => setRuleId(e.target.value)}
          />
        </div>
        <div className="filter-group">
          <label htmlFor="f-tactic">MITRE Tactic</label>
          <input
            id="f-tactic"
            type="text"
            placeholder="e.g. Persistence"
            value={mitreTactic}
            onChange={(e) => setMitreTactic(e.target.value)}
          />
        </div>
        <div className="filter-group">
          <label htmlFor="f-technique">MITRE Technique</label>
          <input
            id="f-technique"
            type="text"
            placeholder="e.g. T1059"
            value={mitreTechnique}
            onChange={(e) => setMitreTechnique(e.target.value)}
          />
        </div>
        <div className="filter-actions">
          <button type="submit" className="btn btn-primary">Filter</button>
          <button type="button" className="btn btn-secondary" onClick={handleClearFilters}>
            Clear
          </button>
        </div>
      </form>

      {/* Table */}
      {loading ? (
        <Spinner label="Loading alerts…" />
      ) : !data || data.items.length === 0 ? (
        <div className="empty-state">No alerts match the current query.</div>
      ) : (
        <>
          <div className="alerts-table-wrap">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th onClick={() => toggleSort('rule_level')} className="sortable-th">
                    Level{sortIndicator('rule_level')}
                  </th>
                  <th onClick={() => toggleSort('rule_id')} className="sortable-th">
                    Rule{sortIndicator('rule_id')}
                  </th>
                  <th>Description</th>
                  <th>Agent</th>
                  <th onClick={() => toggleSort('timestamp')} className="sortable-th">

                    Timestamp{sortIndicator('timestamp')}
                  </th>
                  <th>MITRE</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((alert) => (
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
                    <td className="cell-mitre">{formatMitre(alert)}</td>
                    <td>
                      <Link to={`/alerts/${alert.id}`} className="btn btn-xs">
                        Investigate
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <Pagination
            page={data.page}
            pages={data.pages}
            total={data.total}
            pageSize={data.page_size}
            onPage={(p) => setPage(p)}
          />
        </>
      )}
    </div>
  )
}
