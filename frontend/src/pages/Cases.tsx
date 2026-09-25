import { useEffect, useState } from 'react'

import { Link } from 'react-router-dom'
import {
  fetchCases,
  type CaseOut,
  type CasesQuery,
  type PaginatedCasesResponse,
} from '../api/client'
import { SeverityLabel } from '../components/SeverityBadge'
import Pagination from '../components/Pagination'
import Spinner from '../components/Spinner'
import ErrorBanner from '../components/ErrorBanner'

function formatTs(value: string | null | undefined): string {
  if (!value) return '—'
  const d = new Date(value)
  return isNaN(d.getTime()) ? value : d.toLocaleString()
}

type SortField = 'created_at' | 'updated_at' | 'severity' | 'status' | 'title'

export default function Cases() {
  const [data, setData] = useState<PaginatedCasesResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [status, setStatus] = useState<string>('')
  const [severity, setSeverity] = useState<string>('')
  const [sortBy, setSortBy] = useState<SortField>('created_at')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const [page, setPage] = useState(1)
  const pageSize = 20

  useEffect(() => {
    let cancelled = false
    const query: CasesQuery = {
      page,
      page_size: pageSize,
      sort_by: sortBy,
      sort_order: sortOrder,
    }
    if (status) query.status = status
    if (severity) query.severity = severity

    async function execute() {
      try {
        const resp = await fetchCases(query)
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
  }, [status, severity, sortBy, sortOrder, page])

  function handleFilterSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setPage(1)
  }

  function handleClearFilters() {
    setStatus('')
    setSeverity('')
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
      <div className="page-header page-header--split">
        <div>
          <h1 className="page-title">Cases</h1>
          <p className="page-subtitle">Security incident investigations</p>
        </div>
        <div className="header-actions">
          <Link to="/cases/new" className="btn btn-primary">
            + New Case
          </Link>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {/* Filter bar */}
      <form className="filter-bar" onSubmit={handleFilterSubmit}>
        <div className="filter-group">
          <label htmlFor="f-status">Status</label>
          <select
            id="f-status"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="escalated">Escalated</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="f-sev">Severity</label>
          <select
            id="f-sev"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            <option value="">All severities</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
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
        <Spinner label="Loading cases…" />
      ) : !data || data.items.length === 0 ? (
        <div className="empty-state">No cases match the current query.</div>
      ) : (
        <>
          <div className="alerts-table-wrap">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th onClick={() => toggleSort('title')} className="sortable-th">
                    Title{sortIndicator('title')}
                  </th>
                  <th onClick={() => toggleSort('severity')} className="sortable-th">
                    Severity{sortIndicator('severity')}
                  </th>
                  <th onClick={() => toggleSort('status')} className="sortable-th">
                    Status{sortIndicator('status')}
                  </th>
                  <th>Alerts</th>
                  <th onClick={() => toggleSort('created_at')} className="sortable-th">
                    Created{sortIndicator('created_at')}
                  </th>
                  <th onClick={() => toggleSort('updated_at')} className="sortable-th">
                    Updated{sortIndicator('updated_at')}
                  </th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((c: CaseOut) => (
                  <tr key={c.id}>
                    <td>#{c.id}</td>
                    <td>
                      <Link to={`/cases/${c.id}`} className="table-link">
                        {c.title}
                      </Link>
                    </td>
                    <td><SeverityLabel severity={c.severity} /></td>
                    <td>
                      <span className={`status-badge status-${c.status}`}>
                        {c.status}
                      </span>
                    </td>
                    <td>{c.alert_count}</td>
                    <td>{formatTs(c.created_at)}</td>
                    <td>{formatTs(c.updated_at)}</td>
                    <td>
                      <Link to={`/cases/${c.id}`} className="btn btn-xs">
                        View
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
