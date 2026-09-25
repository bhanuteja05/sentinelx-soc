import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  fetchDashboardSummary,
  fetchDatabaseHealth,
  fetchWazuhAgents,
  fetchWazuhHealth,
  type DashboardSummary,
  type TimeSeriesBucket,
  type DaySeriesBucket,
  type MITREAnalytics,
  type IOCSummary,
  type RecentActivitySummary,
  type RecentAlertSummary,
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

function formatMitre(alert: RecentAlertSummary): string {
  const parts: string[] = []
  if (alert.mitre_tactics && alert.mitre_tactics.length > 0) {
    parts.push(alert.mitre_tactics.join(', '))
  }
  if (alert.mitre_techniques && alert.mitre_techniques.length > 0) {
    parts.push(alert.mitre_techniques.join(', '))
  }
  return parts.length > 0 ? parts.join(' | ') : '—'
}

function StatusDot({ state }: { state: ConnectionState }) {
  const label =
    state === 'loading' ? 'Checking…' : state === 'connected' ? 'Connected' : 'Unavailable'
  return <span className={`status-dot status-dot--${state}`}>{label}</span>
}

function StatCard({
  label,
  value,
  sublabel,
  accent,
}: {
  label: string
  value: number
  sublabel?: string
  accent: 'critical' | 'high' | 'medium' | 'low' | 'neutral'
}) {
  return (
    <div className={`stat-card stat-card--${accent}`}>
      <div className="stat-value">{value.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
      {sublabel && <div className="stat-sublabel">{sublabel}</div>}
    </div>
  )
}

// ── Pure SVG Time-Series Volume Chart ────────────────────────────────────────

function VolumeChart({
  series24h,
  series7d,
}: {
  series24h: TimeSeriesBucket[]
  series7d: DaySeriesBucket[]
}) {
  const [view, setView] = useState<'24h' | '7d'>('24h')

  const data =
    view === '24h'
      ? series24h.map((b) => ({ label: b.label, count: b.count, sub: b.timestamp }))
      : series7d.map((b) => ({ label: b.label, count: b.count, sub: b.date }))

  const maxVal = Math.max(1, ...data.map((d) => d.count))
  const chartHeight = 130
  const totalWidth = 650
  const barPadding = view === '24h' ? 4 : 18
  const barWidth = Math.max(8, (totalWidth - (data.length + 1) * barPadding) / data.length)

  return (
    <div className="soc-chart-card">
      <div className="chart-header">
        <div>
          <h3 className="chart-title">Alert Ingestion Volume</h3>
          <span className="chart-sub">
            {view === '24h' ? 'Last 24 Hours (hourly distribution)' : 'Last 7 Days (daily distribution)'}
          </span>
        </div>
        <div className="chart-toggle-group">
          <button
            type="button"
            className={`btn btn-xs ${view === '24h' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setView('24h')}
          >
            Last 24h
          </button>
          <button
            type="button"
            className={`btn btn-xs ${view === '7d' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setView('7d')}
          >
            Last 7d
          </button>
        </div>
      </div>

      <div className="chart-body">
        <svg
          viewBox={`0 0 ${totalWidth} ${chartHeight + 36}`}
          className="soc-svg-chart"
          preserveAspectRatio="none"
          role="img"
          aria-label="Alert Volume Chart"
        >
          {/* Baseline grid */}
          <line
            x1="0"
            y1={chartHeight}
            x2={totalWidth}
            y2={chartHeight}
            stroke="#2d3a4d"
            strokeWidth="1"
          />

          {data.map((item, idx) => {
            const x = barPadding + idx * (barWidth + barPadding)
            const h = item.count > 0 ? Math.max(4, (item.count / maxVal) * (chartHeight - 24)) : 0
            const y = chartHeight - h
            const showLabel = view === '7d' || idx % 3 === 0 || idx === data.length - 1

            return (
              <g key={idx} className="chart-bar-group">
                <title>{`${item.label}: ${item.count} alert${item.count === 1 ? '' : 's'}`}</title>
                {/* Invisible hover touch area */}
                <rect
                  x={x - barPadding / 2}
                  y="0"
                  width={barWidth + barPadding}
                  height={chartHeight + 32}
                  fill="transparent"
                  className="chart-hit-area"
                />
                {/* Value on top of bar */}
                {item.count > 0 && (
                  <text
                    x={x + barWidth / 2}
                    y={y - 4}
                    textAnchor="middle"
                    className="chart-bar-value"
                  >
                    {item.count}
                  </text>
                )}
                {/* Bar rect */}
                <rect
                  x={x}
                  y={y}
                  width={barWidth}
                  height={h}
                  rx="3"
                  className={`chart-bar ${item.count > 0 ? 'chart-bar--active' : 'chart-bar--empty'}`}
                />
                {/* X-axis label */}
                {showLabel && (
                  <text
                    x={x + barWidth / 2}
                    y={chartHeight + 20}
                    textAnchor="middle"
                    className="chart-axis-label"
                  >
                    {item.label}
                  </text>
                )}
              </g>
            )
          })}
        </svg>
      </div>
    </div>
  )
}

// ── Severity & Triage Breakdown ─────────────────────────────────────────────

function SeverityDistribution({
  bySeverity,
  total,
}: {
  bySeverity: Record<string, number>
  total: number
}) {
  const crit = bySeverity['critical'] || 0
  const high = bySeverity['high'] || 0
  const med = bySeverity['medium'] || 0
  const low = bySeverity['low'] || 0

  const critPct = total > 0 ? ((crit / total) * 100).toFixed(1) : '0'
  const highPct = total > 0 ? ((high / total) * 100).toFixed(1) : '0'
  const medPct = total > 0 ? ((med / total) * 100).toFixed(1) : '0'
  const lowPct = total > 0 ? ((low / total) * 100).toFixed(1) : '0'

  return (
    <div className="soc-breakdown-card">
      <h3 className="breakdown-title">Alert Severity Distribution</h3>
      {total === 0 ? (
        <p className="empty-subtext">No alerts recorded yet.</p>
      ) : (
        <>
          <div className="segmented-progress-bar">
            {crit > 0 && (
              <div
                className="seg-bar seg-crit"
                style={{ width: `${critPct}%` }}
                title={`Critical: ${crit} (${critPct}%)`}
              />
            )}
            {high > 0 && (
              <div
                className="seg-bar seg-high"
                style={{ width: `${highPct}%` }}
                title={`High: ${high} (${highPct}%)`}
              />
            )}
            {med > 0 && (
              <div
                className="seg-bar seg-med"
                style={{ width: `${medPct}%` }}
                title={`Medium: ${med} (${medPct}%)`}
              />
            )}
            {low > 0 && (
              <div
                className="seg-bar seg-low"
                style={{ width: `${lowPct}%` }}
                title={`Low: ${low} (${lowPct}%)`}
              />
            )}
          </div>
          <div className="breakdown-legend">
            <div className="legend-item">
              <span className="legend-dot dot-crit" /> Critical: <strong>{crit}</strong> ({critPct}%)
            </div>
            <div className="legend-item">
              <span className="legend-dot dot-high" /> High: <strong>{high}</strong> ({highPct}%)
            </div>
            <div className="legend-item">
              <span className="legend-dot dot-med" /> Medium: <strong>{med}</strong> ({medPct}%)
            </div>
            <div className="legend-item">
              <span className="legend-dot dot-low" /> Low: <strong>{low}</strong> ({lowPct}%)
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function StatusDistribution({
  byStatus,
  total,
  cases,
}: {
  byStatus: Record<string, number>
  total: number
  cases: DashboardSummary['cases']
}) {
  const associated = byStatus['associated'] || 0
  const unassociated = byStatus['unassociated'] || 0
  const assocPct = total > 0 ? ((associated / total) * 100).toFixed(1) : '0'
  const unassocPct = total > 0 ? ((unassociated / total) * 100).toFixed(1) : '0'

  return (
    <div className="soc-breakdown-card">
      <h3 className="breakdown-title">Investigation & Triage State</h3>
      {total === 0 ? (
        <p className="empty-subtext">No alerts in pipeline.</p>
      ) : (
        <>
          <div className="segmented-progress-bar">
            {associated > 0 && (
              <div
                className="seg-bar seg-assoc"
                style={{ width: `${assocPct}%` }}
                title={`Under Investigation: ${associated} (${assocPct}%)`}
              />
            )}
            {unassociated > 0 && (
              <div
                className="seg-bar seg-unassoc"
                style={{ width: `${unassocPct}%` }}
                title={`Triage Backlog: ${unassociated} (${unassocPct}%)`}
              />
            )}
          </div>
          <div className="breakdown-legend">
            <div className="legend-item">
              <span className="legend-dot dot-assoc" />
              Under Investigation: <strong>{associated}</strong> ({assocPct}%)
            </div>
            <div className="legend-item">
              <span className="legend-dot dot-unassoc" />
              Triage Backlog: <strong>{unassociated}</strong> ({unassocPct}%)
            </div>
          </div>
          <div className="case-substats">
            <span className="case-substat-item">
              Open Cases: <strong>{cases.open}</strong>
            </span>
            <span className="case-substat-item">
              Total Cases: <strong>{cases.total}</strong>
            </span>
          </div>
        </>
      )}
    </div>
  )
}

// ── Threat Intel & Coverage ──────────────────────────────────────────────────

function ThreatIntelSection({
  mitre,
  iocs,
}: {
  mitre: MITREAnalytics
  iocs: IOCSummary
}) {
  const hasTechniques = mitre.top_techniques && mitre.top_techniques.length > 0
  const hasTactics = mitre.top_tactics && mitre.top_tactics.length > 0
  const hasIocs = iocs.total_indicators > 0

  return (
    <section className="dash-section">
      <div className="section-header">
        <h2>Threat Intelligence & Coverage</h2>
        <span className="section-sub">Automated analysis of ingested alerts</span>
      </div>

      <div className="threat-intel-grid">
        {/* MITRE ATT&CK card */}
        <div className="threat-card">
          <div className="threat-card-header">
            <h3>MITRE ATT&CK Matrix Coverage</h3>
            <span className="threat-badge">
              {mitre.top_techniques.length} Techniques | {mitre.top_tactics.length} Tactics
            </span>
          </div>

          <div className="threat-card-content">
            <div className="threat-block">
              <span className="threat-block-label">Top Observed Techniques</span>
              {!hasTechniques ? (
                <p className="empty-subtext">No MITRE techniques detected yet.</p>
              ) : (
                <div className="mitre-chips-wrap">
                  {mitre.top_techniques.map((t) => (
                    <span key={t.technique_id} className="mitre-tech-chip">
                      <span className="chip-id">{t.technique_id}</span>
                      <span className="chip-count">{t.count}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="threat-block">
              <span className="threat-block-label">Tactics Observed</span>
              {!hasTactics ? (
                <p className="empty-subtext">No tactics recorded.</p>
              ) : (
                <div className="mitre-tactics-wrap">
                  {mitre.top_tactics.map((tac) => (
                    <span key={tac.tactic} className="mitre-tactic-chip">
                      {tac.tactic} <span className="chip-count">{tac.count}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* IOC Summary card */}
        <div className="threat-card">
          <div className="threat-card-header">
            <h3>Extracted Indicators of Compromise (IOCs)</h3>
            <span className="threat-badge">
              {iocs.total_indicators} Indicators ({iocs.analyzed_alert_count} alerts)
            </span>
          </div>

          <div className="threat-card-content">
            <div className="threat-block">
              <span className="threat-block-label">Indicator Types</span>
              {!hasIocs ? (
                <p className="empty-subtext">No indicators extracted from current alerts.</p>
              ) : (
                <div className="ioc-types-wrap">
                  {Object.entries(iocs.by_type).map(([type, count]) => (
                    <span key={type} className="ioc-type-pill">
                      <span className="ioc-type-name">{type}</span>
                      <span className="ioc-type-count">{count}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>

            {hasIocs && Object.keys(iocs.samples).length > 0 && (
              <div className="threat-block">
                <span className="threat-block-label">Sample Artifacts</span>
                <div className="ioc-samples-list">
                  {Object.entries(iocs.samples).slice(0, 4).map(([type, samples]) => (
                    <div key={type} className="ioc-sample-row">
                      <span className="ioc-sample-type">{type}:</span>
                      <div className="ioc-sample-values">
                        {samples.slice(0, 3).map((val, idx) => (
                          <code key={idx} className="ioc-sample-val">{val}</code>
                        ))}
                        {samples.length > 3 && (
                          <span className="ioc-sample-more">+{samples.length - 3} more</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}

// ── Recent Activity Feed ─────────────────────────────────────────────────────

function RecentActivitySection({ activity }: { activity: RecentActivitySummary[] }) {
  return (
    <section className="dash-section">
      <div className="section-header">
        <h2>Recent Investigation Notes</h2>
        <Link to="/cases" className="section-link">View all cases →</Link>
      </div>
      {activity.length === 0 ? (
        <p className="empty-text">No investigation notes recorded yet.</p>
      ) : (
        <div className="activity-timeline-list">
          {activity.map((note) => (
            <div key={note.id} className="activity-item-card">
              <div className="activity-item-header">
                <div className="activity-author-meta">
                  <span className="activity-author">{note.author_username}</span>
                  <span className="activity-case-ref">
                    on{' '}
                    <Link to={`/cases/${note.case_id}`} className="table-link">
                      Case #{note.case_id}: {note.case_title}
                    </Link>
                  </span>
                </div>
                <span className="activity-time">{formatTs(note.created_at)}</span>
              </div>
              <p className="activity-content-preview">{note.content}</p>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}

// ── Main Dashboard Component ────────────────────────────────────────────────

export default function Dashboard() {
  const [backend, setBackend] = useState<ConnectionState>('loading')
  const [db, setDb] = useState<ConnectionState>('loading')
  const [wazuh, setWazuh] = useState<ConnectionState>('loading')
  const [agentCount, setAgentCount] = useState<number | null>(null)
  const [activeAgents, setActiveAgents] = useState<number | null>(null)
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [refreshTrigger, setRefreshTrigger] = useState(0)

  useEffect(() => {
    let cancelled = false

    async function load() {
      // 1. Health checks
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
        } else if (e instanceof DatabaseUnavailableError) {
          setBackend('connected')
          setDb('unavailable')
          setWazuh('unavailable')
        } else {
          setBackend('unavailable')
          setDb('unavailable')
          setWazuh('unavailable')
        }
      }

      // 2. Wazuh health + agents (best effort)
      try {
        await fetchWazuhHealth()
        const ar = await fetchWazuhAgents()
        if (!cancelled) {
          setWazuh('connected')
          setAgentCount(ar.data.total_affected_items ?? ar.data.affected_items.length)
          setActiveAgents(ar.data.affected_items.filter((a) => a.status === 'active').length)
        }
      } catch {
        if (!cancelled) setWazuh('unavailable')
      }

      // 3. Complete Dashboard Analytics Summary
      try {
        const data = await fetchDashboardSummary()
        if (!cancelled) {
          setSummary(data)
          setError(null)
        }
      } catch (e) {
        if (!cancelled) setError(String(e))
      } finally {
        if (!cancelled) setIsRefreshing(false)
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [refreshTrigger])

  function handleRefresh() {
    setIsRefreshing(true)
    setRefreshTrigger((prev) => prev + 1)
  }

  return (
    <div className="page">
      <div className="page-header page-header--split">
        <div>
          <h1 className="page-title">SOC Dashboard</h1>
          <p className="page-subtitle">Security Operations Center — SentinelX v1.0</p>
        </div>
        <div className="header-actions">
          <button
            type="button"
            className="btn btn-secondary btn-xs"
            onClick={handleRefresh}
            disabled={isRefreshing}
          >
            {isRefreshing ? 'Refreshing…' : '↻ Refresh Analytics'}
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {/* Health strip */}
      <section className="health-strip">
        <div className="health-item">
          <span className="health-label">Backend API</span>
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
            {wazuh === 'loading'
              ? '…'
              : wazuh === 'unavailable'
              ? '—'
              : `${activeAgents ?? 0} / ${agentCount ?? 0} active`}
          </span>
        </div>
      </section>

      {summary === null ? (
        <Spinner label="Loading SOC analytics…" />
      ) : (
        <>
          {/* Executive & Triage KPI grid */}
          <section className="stat-grid">
            <StatCard
              label="Total Alerts"
              value={summary.alerts.total}
              sublabel="All-time ingested"
              accent="neutral"
            />
            <StatCard
              label="Last 24 Hours"
              value={summary.alerts.last_24h}
              sublabel="Recent alert volume"
              accent="high"
            />
            <StatCard
              label="Last 7 Days"
              value={summary.alerts.last_7d}
              sublabel="Weekly volume"
              accent="neutral"
            />
            <StatCard
              label="Open Cases"
              value={summary.cases.open}
              sublabel={`of ${summary.cases.total} total cases`}
              accent="critical"
            />
            <StatCard
              label="Critical Alerts"
              value={summary.alerts.by_severity['critical'] || 0}
              sublabel="Level 12+"
              accent="critical"
            />
            <StatCard
              label="High Alerts"
              value={summary.alerts.by_severity['high'] || 0}
              sublabel="Level 8–11"
              accent="high"
            />
          </section>

          {/* Quick Actions Bar */}
          <div className="quick-actions-bar">
            <span className="quick-actions-label">Quick Actions:</span>
            <Link to="/alerts" className="btn btn-secondary btn-xs">
              Search Alerts
            </Link>
            <Link to="/cases/new" className="btn btn-primary btn-xs">
              + New Case
            </Link>
            <Link to="/cases" className="btn btn-secondary btn-xs">
              Review Cases
            </Link>
            <Link to="/status" className="btn btn-secondary btn-xs">
              System Status
            </Link>
          </div>

          {/* Alert Volume Time Series + Breakdown Grid */}
          <section className="dash-two-col">
            <VolumeChart
              series24h={summary.time_series_24h}
              series7d={summary.time_series_7d}
            />
            <div className="dash-breakdown-col">
              <SeverityDistribution
                bySeverity={summary.alerts.by_severity}
                total={summary.alerts.total}
              />
              <StatusDistribution
                byStatus={summary.alerts.by_status}
                total={summary.alerts.total}
                cases={summary.cases}
              />
            </div>
          </section>

          {/* Threat Intelligence & Coverage */}
          <ThreatIntelSection mitre={summary.mitre} iocs={summary.iocs} />

          {/* Recent Investigation Notes Feed */}
          <RecentActivitySection activity={summary.recent_activity} />

          {/* Recent Alerts Feed */}
          <section className="dash-section">
            <div className="section-header">
              <h2>Recent Alerts</h2>
              <Link to="/alerts" className="section-link">View all →</Link>
            </div>
            {summary.recent_alerts.length === 0 ? (
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
                    {summary.recent_alerts.map((a) => (
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
            {summary.recent_cases.length === 0 ? (
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
                    {summary.recent_cases.map((c) => (
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
