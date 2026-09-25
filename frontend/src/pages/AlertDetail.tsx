import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  fetchAlertById,
  type AlertDetailOut,
  NotFoundError,
} from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'
import Spinner from '../components/Spinner'
import ErrorBanner from '../components/ErrorBanner'

function formatTs(value: string | null | undefined): string {
  if (!value) return '—'
  const d = new Date(value)
  return isNaN(d.getTime()) ? value : d.toLocaleString()
}

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [alert, setAlert] = useState<AlertDetailOut | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showRaw, setShowRaw] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      if (!id) return
      setLoading(true)
      try {
        const data = await fetchAlertById(Number(id))
        if (!cancelled) setAlert(data)
      } catch (e) {
        if (!cancelled) {
          if (e instanceof NotFoundError) {
            setError(`Alert #${id} not found.`)
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

  if (loading) return <Spinner label="Loading alert detail…" />
  if (error) return (
    <div className="page">
      <ErrorBanner message={error} />
      <button className="btn btn-secondary" onClick={() => navigate('/alerts')}>
        ← Back to Alerts
      </button>
    </div>
  )
  if (!alert) return null

  return (
    <div className="page">
      <div className="page-header page-header--split">
        <div>
          <div className="breadcrumb">
            <Link to="/alerts">Alerts</Link> / <span>#{alert.id}</span>
          </div>
          <h1 className="page-title">{alert.description ?? `Alert #${alert.id}`}</h1>
        </div>
        <div className="header-actions">
          <Link
            to={`/cases/new?alert_id=${alert.id}`}
            className="btn btn-primary"
          >
            + Create Case from Alert
          </Link>
        </div>
      </div>

      {/* Metadata Grid */}
      <div className="meta-grid">
        <div className="meta-card">
          <h3>Alert Info</h3>
          <dl className="meta-list">
            <div><dt>Internal ID</dt><dd>#{alert.id}</dd></div>
            <div><dt>Wazuh Alert ID</dt><dd className="mono">{alert.wazuh_alert_id}</dd></div>
            <div><dt>Rule Level</dt><dd><SeverityBadge level={alert.rule_level} /></dd></div>
            <div><dt>Rule ID</dt><dd>{alert.rule_id ?? '—'}</dd></div>
            <div><dt>Timestamp</dt><dd>{formatTs(alert.timestamp)}</dd></div>
            <div><dt>Ingested</dt><dd>{formatTs(alert.created_at)}</dd></div>
          </dl>
        </div>

        <div className="meta-card">
          <h3>Agent & Origin</h3>
          <dl className="meta-list">
            <div><dt>Agent Name</dt><dd>{alert.agent_name ?? '—'}</dd></div>
            <div><dt>Agent ID</dt><dd>{alert.agent_id ?? '—'}</dd></div>
            <div><dt>Decoder</dt><dd>{alert.decoder ?? '—'}</dd></div>
            <div><dt>Location</dt><dd className="mono">{alert.location ?? '—'}</dd></div>
          </dl>
        </div>

        <div className="meta-card">
          <h3>Network</h3>
          <dl className="meta-list">
            <div><dt>Source IP</dt><dd>{alert.src_ip ?? '—'}</dd></div>
            <div><dt>Source Port</dt><dd>{alert.src_port ?? '—'}</dd></div>
            <div><dt>Dest IP</dt><dd>{alert.dst_ip ?? '—'}</dd></div>
            <div><dt>Dest Port</dt><dd>{alert.dst_port ?? '—'}</dd></div>
          </dl>
        </div>

        <div className="meta-card">
          <h3>MITRE ATT&CK</h3>
          <dl className="meta-list">
            <div>
              <dt>Tactics</dt>
              <dd>
                {alert.mitre_tactics.length > 0 ? (
                  <div className="tag-list">
                    {alert.mitre_tactics.map((t) => (
                      <span key={t} className="tag tag-tactic">{t}</span>
                    ))}
                  </div>
                ) : '—'}
              </dd>
            </div>
            <div>
              <dt>Techniques</dt>
              <dd>
                {alert.mitre_techniques.length > 0 ? (
                  <div className="tag-list">
                    {alert.mitre_techniques.map((t) => (
                      <span key={t} className="tag tag-technique">{t}</span>
                    ))}
                  </div>
                ) : '—'}
              </dd>
            </div>
          </dl>
        </div>
      </div>

      {/* Raw Alert JSON */}
      <section className="raw-alert-section">
        <button
          className="btn btn-secondary raw-toggle-btn"
          onClick={() => setShowRaw(!showRaw)}
        >
          {showRaw ? '▾ Hide' : '▸ Show'} Raw Wazuh Alert JSON
        </button>
        {showRaw && (
          <pre className="json-viewer">
            {JSON.stringify(alert.raw_alert, null, 2)}
          </pre>
        )}
      </section>
    </div>
  )
}
