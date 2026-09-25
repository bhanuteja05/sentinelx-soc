import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  fetchAlertCount,
  fetchAlerts,
  fetchCases,
  fetchDatabaseHealth,
  fetchWazuhAgents,
  fetchWazuhHealth,
  type AlertOut,
  type CaseOut,
  BackendUnavailableError,
  DatabaseUnavailableError,
} from '../api/client'
import { SeverityBadge, SeverityLabel } from '../components/SeverityBadge'
import Spinner from '../components/Spinner'
import ErrorBanner from '../components/ErrorBanner'

type ConnectionState = 'loading' | 'connected' | 'unavailable'

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


function StatusDot({ state }: { state: ConnectionState }) {
  const label =
    state === 'loading' ? 'Checking…' : state === 'connected' ? 'Connected' : 'Unavailable'
  return <span className={`status-dot status-dot--${state}`}>{label}</span>
}

type Stats = {
  totalAlerts: number
  criticalAlerts: number
  highAlerts: number
  mediumAlerts: number
  lowAlerts: number
  totalCases: number
  openCases: number
  agentCount: number
  activeAgents: number
}

export default function Dashboard() {
  const [backend, setBackend] = useState<ConnectionState>('loading')
  const [db, setDb] = useState<ConnectionState>('loading')
  const [wazuh, setWazuh] = useState<ConnectionState>('loading')
  const [stats, setStats] = useState<Stats | null>(null)
  const [recentAlerts, setRecentAlerts] = useState<AlertOut[]>([])
  const [recentCases, setRecentCases] = useState<CaseOut[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      // 1. DB health
      try {
        await fetchDatabaseHealth()
        if (cancelled) return
        setBackend('connected')
        setDb('connected')
      } catch (e) {
        if (cancelled) return
        if (e instanceof BackendUnavailableError) {
          setBackend('unavailable')
          setDb('unavailable')
          setWazuh('unavailable')
          return
        }
        if (e instanceof DatabaseUnavailableError) {
          setBackend('connected')
          setDb('unavailable')
          setWazuh('unavailable')
          return
        }
        setBackend('unavailable')
        setDb('unavailable')
        setWazuh('unavailable')
        return
      }

      // 2. Wazuh health + agents (best effort)
      let agentCount = 0
      let activeAgents = 0
      try {
        await fetchWazuhHealth()
        const ar = await fetchWazuhAgents()
        if (!cancelled) {
          setWazuh('connected')
          agentCount = ar.data.total_affected_items ?? ar.data.affected_items.length
          activeAgents = ar.data.affected_items.filter((a) => a.status === 'active').length
        }
      } catch {
        if (!cancelled) setWazuh('unavailable')
      }

      // 3. Alert counts via parallel requests
      try {
        const [total, critical, high, medium, low, casesResp, alertsResp] = await Promise.all([
          fetchAlertCount(),
          fetchAlerts({ min_rule_level: 12, page_size: 1 }),
          fetchAlerts({ min_rule_level: 8, max_rule_level: 11, page_size: 1 }),
          fetchAlerts({ min_rule_level: 5, max_rule_level: 7, page_size: 1 }),
          fetchAlerts({ max_rule_level: 4, page_size: 1 }),
          fetchCases({ page_size: 5, sort_by: 'created_at', sort_order: 'desc' }),
          fetchAlerts({ page_size: 5, sort_by: 'timestamp', sort_order: 'desc' }),
        ])
        if (cancelled) return
        setStats({
          totalAlerts: total.count,
          criticalAlerts: critical.total,
          highAlerts: high.total,
          mediumAlerts: medium.total,
          lowAlerts: low.total,
          totalCases: casesResp.total,
          openCases: casesResp.items.filter((c) => c.status === 'open').length,
          agentCount,
          activeAgents,
        })
        setRecentAlerts(alertsResp.items)
        setRecentCases(casesResp.items)
      } catch (e) {
        if (!cancelled) setError(String(e))
      }
    }

    void load()
    return () => { cancelled = true }
  }, [])

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-subtitle">Security Operations Center — SentinelX v1.0</p>
      </div>

      {error && <ErrorBanner message={error} />}

      {/* Health strip */}
      <section className="health-strip">
        <div className="health-item">
          <span className="health-label">Backend</span>
          <StatusDot state={backend} />
        </div>
        <div className="health-item">
          <span className="health-label">Database</span>
          <StatusDot state={db} />
        </div>
        <div className="health-item">
          <span className="health-label">Wazuh SIEM</span>
          <StatusDot state={wazuh} />
        </div>
        <div className="health-item">
          <span className="health-label">Agents</span>
          <span className="health-val">
            {wazuh === 'loading' ? '…' : wazuh === 'unavailable' ? '—' : `${activeStr(stats)}`}
          </span>
        </div>
      </section>

      {/* Stat cards */}
      {stats === null ? (
        <Spinner label="Loading statistics…" />
      ) : (
        <>
          <section className="stat-grid">
            <StatCard label="Total Alerts" value={stats.totalAlerts} accent="neutral" />
            <StatCard label="Critical" value={stats.criticalAlerts} accent="critical" />
            <StatCard label="High" value={stats.highAlerts} accent="high" />
            <StatCard label="Medium" value={stats.mediumAlerts} accent="medium" />
            <StatCard label="Low" value={stats.lowAlerts} accent="low" />
            <StatCard label="Cases" value={stats.totalCases} accent="neutral" />
          </section>

          {/* Quick Actions */}
          <div className="quick-actions-bar">
            <span className="quick-actions-label">Quick Actions:</span>
            <Link to="/alerts" className="btn btn-secondary btn-xs">Search Alerts</Link>
            <Link to="/cases/new" className="btn btn-primary btn-xs">+ New Case</Link>
            <Link to="/cases" className="btn btn-secondary btn-xs">Review Cases</Link>
            <Link to="/status" className="btn btn-secondary btn-xs">System Status</Link>
          </div>

          {/* Recent Alerts */}
          <section className="dash-section">
            <div className="section-header">
              <h2>Recent Alerts</h2>
              <Link to="/alerts" className="section-link">View all →</Link>
            </div>
            {recentAlerts.length === 0 ? (
              <p className="empty-text">No alerts found.</p>
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
                      <th>MITRE</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAlerts.map((a) => (
                      <tr key={a.id}>
                        <td><SeverityBadge level={a.rule_level} /></td>
                        <td>{a.rule_id ?? '—'}</td>
                        <td>
                          <Link to={`/alerts/${a.id}`} className="table-link">
                            {a.description ?? '—'}
                          </Link>
                        </td>
                        <td>{a.agent_name ?? a.agent_id ?? '—'}</td>
                        <td>{formatTs(a.timestamp)}</td>
                        <td className="cell-mitre">{formatMitre(a)}</td>
                        <td>
                          <Link to={`/alerts/${a.id}`} className="btn btn-xs">
                            Investigate
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>


          {/* Recent Cases */}
          <section className="dash-section">
            <div className="section-header">
              <h2>Recent Cases</h2>
              <Link to="/cases" className="section-link">View all →</Link>
            </div>
            {recentCases.length === 0 ? (
              <p className="empty-text">No cases found.</p>
            ) : (
              <div className="alerts-table-wrap">
                <table className="alerts-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Title</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Alerts</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentCases.map((c) => (
                      <tr key={c.id}>
                        <td>#{c.id}</td>
                        <td>
                          <Link to={`/cases/${c.id}`} className="table-link">{c.title}</Link>
                        </td>
                        <td><SeverityLabel severity={c.severity} /></td>
                        <td><span className={`status-badge status-${c.status}`}>{c.status}</span></td>
                        <td>{c.alert_count}</td>
                        <td>{formatTs(c.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  )
}

function activeStr(stats: Stats | null): string {
  if (!stats) return '…'
  return `${stats.activeAgents} / ${stats.agentCount} active`
}

function StatCard({
  label,
  value,
  accent,
}: {
  label: string
  value: number
  accent: 'critical' | 'high' | 'medium' | 'low' | 'neutral'
}) {
  return (
    <div className={`stat-card stat-card--${accent}`}>
      <div className="stat-value">{value.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
