import { useEffect, useState } from 'react'

import {
  BackendUnavailableError,
  DatabaseUnavailableError,
  fetchDatabaseHealth,
  fetchWazuhAgents,
  fetchWazuhAlerts,
  fetchWazuhHealth,
  type WazuhAgent,
  type WazuhAlert,
} from './api/client'

type ConnectionState = 'loading' | 'connected' | 'unavailable'

type SystemStatusState = {
  loading: boolean
  backend: ConnectionState
  database: ConnectionState
  wazuh: ConnectionState
}

function labelFor(state: ConnectionState): string {
  if (state === 'loading') return 'Checking...'
  return state === 'connected' ? 'Connected' : 'Unavailable'
}

function severityClass(level: number | null): string {
  if (level === null) return 'sev-unknown'
  if (level >= 12) return 'sev-critical'
  if (level >= 8) return 'sev-high'
  if (level >= 5) return 'sev-medium'
  return 'sev-low'
}

function formatTimestamp(value: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

function formatMitre(alert: WazuhAlert): string {
  const techniques = alert.mitre_techniques.join(', ')
  const tactics = alert.mitre_tactics.join(', ')
  if (techniques && tactics) return `${techniques} (${tactics})`
  if (techniques) return techniques
  if (tactics) return tactics
  return '—'
}

export default function SystemStatus() {
  const [status, setStatus] = useState<SystemStatusState>({
    loading: true,
    backend: 'loading',
    database: 'loading',
    wazuh: 'loading',
  })

  const [agents, setAgents] = useState<WazuhAgent[]>([])
  const [agentCount, setAgentCount] = useState(0)
  const [activeAgentCount, setActiveAgentCount] = useState(0)
  const [alerts, setAlerts] = useState<WazuhAlert[]>([])
  const [alertTotal, setAlertTotal] = useState(0)
  const [alertsUnavailable, setAlertsUnavailable] = useState(false)

  useEffect(() => {
    let cancelled = false

    async function loadStatus() {
      try {
        await fetchDatabaseHealth()
        if (!cancelled) {
          setStatus({
            loading: false,
            backend: 'connected',
            database: 'connected',
            wazuh: 'loading',
          })
        }
      } catch (error) {
        if (cancelled) return

        if (error instanceof DatabaseUnavailableError) {
          setStatus({
            loading: false,
            backend: 'connected',
            database: 'unavailable',
            wazuh: 'unavailable',
          })
          return
        }

        if (error instanceof BackendUnavailableError) {
          setStatus({
            loading: false,
            backend: 'unavailable',
            database: 'unavailable',
            wazuh: 'unavailable',
          })
          return
        }

        setStatus({
          loading: false,
          backend: 'unavailable',
          database: 'unavailable',
          wazuh: 'unavailable',
        })
        return
      }

      try {
        await fetchWazuhHealth()
        const wazuhResponse = await fetchWazuhAgents()
        if (cancelled) return

        const items = wazuhResponse.data.affected_items ?? []
        setAgents(items)
        setAgentCount(wazuhResponse.data.total_affected_items ?? items.length)
        setActiveAgentCount(
          items.filter((agent) => agent.status === 'active').length,
        )
        setStatus({
          loading: false,
          backend: 'connected',
          database: 'connected',
          wazuh: 'connected',
        })
      } catch {
        if (cancelled) return
        setStatus({
          loading: false,
          backend: 'connected',
          database: 'connected',
          wazuh: 'unavailable',
        })
      }

      try {
        const alertsResponse = await fetchWazuhAlerts(20)
        if (cancelled) return
        setAlerts(alertsResponse.alerts)
        setAlertTotal(alertsResponse.total)
        setAlertsUnavailable(false)
      } catch {
        if (cancelled) return
        setAlertsUnavailable(true)
      }
    }

    void loadStatus()

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <main className="status-page dashboard">
      <h1>SentinelX SOC</h1>
      <h2>Security Operations Dashboard</h2>

      <p className="status-note">
        {status.loading
          ? 'Checking SentinelX services...'
          : 'Live infrastructure status'}
      </p>

      <section className="status-list">
        <div>
          <dt>Backend</dt>
          <dd data-state={status.backend}>{labelFor(status.backend)}</dd>
        </div>
        <div>
          <dt>Database</dt>
          <dd data-state={status.database}>{labelFor(status.database)}</dd>
        </div>
        <div>
          <dt>Wazuh API</dt>
          <dd data-state={status.wazuh}>{labelFor(status.wazuh)}</dd>
        </div>
        <div>
          <dt>Active agents</dt>
          <dd data-state={status.wazuh === 'connected' ? 'connected' : status.wazuh}>
            {status.wazuh === 'connected' ? String(activeAgentCount) : labelFor(status.wazuh)}
          </dd>
        </div>
      </section>

      <section className="agents-section">
        <div className="section-header">
          <h2>Wazuh Agents</h2>
          <span>{agentCount} agents</span>
        </div>

        {agents.length === 0 ? (
          <p>No agents found.</p>
        ) : (
          <div className="agent-grid">
            {agents.map((agent) => (
              <article className="agent-card" key={agent.id}>
                <div className="agent-header">
                  <h3>{agent.name}</h3>
                  <span data-state={agent.status}>{agent.status}</span>
                </div>
                <p>
                  <strong>ID:</strong> {agent.id}
                </p>
                <p>
                  <strong>IP:</strong> {agent.ip}
                </p>
                <p>
                  <strong>OS:</strong> {agent.os?.name ?? 'Unknown'}
                </p>
                <p>
                  <strong>Version:</strong> {agent.version}
                </p>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="alerts-section">
        <div className="section-header">
          <h2>Recent Alerts</h2>
          <span>
            {alertsUnavailable
              ? 'Unavailable'
              : `${alerts.length} shown / ${alertTotal} total`}
          </span>
        </div>

        {alertsUnavailable ? (
          <p>Could not load alerts from the Wazuh indexer.</p>
        ) : alerts.length === 0 ? (
          <p>No recent alerts.</p>
        ) : (
          <div className="alerts-table-wrap">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Level</th>
                  <th>Rule</th>
                  <th>Description</th>
                  <th>Agent</th>
                  <th>Timestamp</th>
                  <th>MITRE</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <span className={`sev ${severityClass(alert.rule_level)}`}>
                        {alert.rule_level ?? '—'}
                      </span>
                    </td>
                    <td>{alert.rule_id ?? '—'}</td>
                    <td>{alert.rule_description ?? '—'}</td>
                    <td>{alert.agent_name ?? alert.agent_id ?? '—'}</td>
                    <td>{formatTimestamp(alert.timestamp)}</td>
                    <td>{formatMitre(alert)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  )
}
