import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  addCaseEvidence,
  fetchAlertById,
  fetchCases,
  getAlertEnrichment,
  type AlertDetailOut,
  type AlertEnrichmentResponse,
  type CaseOut,
  type IOCIndicator,
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

const IOC_CATEGORIES: { type: string; label: string }[] = [
  { type: 'ipv4', label: 'IPv4' },
  { type: 'ipv6', label: 'IPv6' },
  { type: 'domain', label: 'Domains' },
  { type: 'url', label: 'URLs' },
  { type: 'email', label: 'Emails' },
  { type: 'md5', label: 'MD5 Hashes' },
  { type: 'sha1', label: 'SHA1 Hashes' },
  { type: 'sha256', label: 'SHA256 Hashes' },
]

function mapIocToEvidenceType(iocType: string): string {
  const t = iocType.toLowerCase()
  if (t === 'ipv4' || t === 'ipv6') return 'ip'
  if (t === 'domain') return 'domain'
  if (t === 'url') return 'url'
  if (t === 'sha256') return 'hash_sha256'
  if (t === 'md5') return 'hash_md5'
  if (t === 'email') return 'user_account'
  return 'ip'
}

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [alert, setAlert] = useState<AlertDetailOut | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showRaw, setShowRaw] = useState(false)
  const [actionSuccess, setActionSuccess] = useState<{ msg: string; caseId?: number } | null>(null)

  // Enrichment state
  const [enrichment, setEnrichment] = useState<AlertEnrichmentResponse | null>(null)
  const [enrichmentLoading, setEnrichmentLoading] = useState(true)
  const [enrichmentError, setEnrichmentError] = useState<string | null>(null)
  const [includePrivateIps, setIncludePrivateIps] = useState(false)

  // Promote IOC to Evidence Modal State
  const [promotingIoc, setPromotingIoc] = useState<{ type: string; value: string } | null>(null)
  const [promoteCaseId, setPromoteCaseId] = useState<string>('')
  const [promoteEvidenceType, setPromoteEvidenceType] = useState<string>('ip')
  const [promoteVerdict, setPromoteVerdict] = useState<'malicious' | 'suspicious' | 'benign' | 'informational'>('suspicious')
  const [promoteNotes, setPromoteNotes] = useState<string>('')
  const [recentCases, setRecentCases] = useState<CaseOut[]>([])
  const [promoting, setPromoting] = useState(false)
  const [promoteError, setPromoteError] = useState<string | null>(null)

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

  useEffect(() => {
    let cancelled = false
    async function loadEnrichment() {
      if (!id) return
      setEnrichmentLoading(true)
      setEnrichmentError(null)
      try {
        const data = await getAlertEnrichment(Number(id), includePrivateIps)
        if (!cancelled) setEnrichment(data)
      } catch (e) {
        if (!cancelled) {
          setEnrichmentError(e instanceof Error ? e.message : String(e))
        }
      } finally {
        if (!cancelled) setEnrichmentLoading(false)
      }
    }
    void loadEnrichment()
    return () => { cancelled = true }
  }, [id, includePrivateIps])

  const indicatorsByType = useMemo(() => {
    const map: Record<string, IOCIndicator[]> = {}
    if (!enrichment?.indicators) return map
    for (const ind of enrichment.indicators) {
      if (!map[ind.ioc_type]) {
        map[ind.ioc_type] = []
      }
      map[ind.ioc_type].push(ind)
    }
    return map
  }, [enrichment])

  const allActiveCategories = useMemo(() => {
    const knownTypes = new Set(IOC_CATEGORIES.map((c) => c.type))
    const standardActive = IOC_CATEGORIES.filter((cat) => {
      const fromIndicators = indicatorsByType[cat.type]
      if (fromIndicators && fromIndicators.length > 0) return true
      const fromIocs = enrichment?.iocs?.[cat.type]
      return fromIocs && fromIocs.length > 0
    })

    const allTypes = new Set([
      ...Object.keys(indicatorsByType),
      ...(enrichment?.iocs ? Object.keys(enrichment.iocs) : []),
    ])
    const extra: { type: string; label: string }[] = []
    for (const t of allTypes) {
      if (!knownTypes.has(t)) {
        extra.push({ type: t, label: t.toUpperCase() })
      }
    }
    return [...standardActive, ...extra]
  }, [indicatorsByType, enrichment])

  const mitreTactics = enrichment?.mitre?.tactics ?? []
  const mitreTechniques = enrichment?.mitre?.techniques ?? []
  const hasMitre = mitreTactics.length > 0 || mitreTechniques.length > 0

  async function handleOpenPromoteModal(iocType: string, value: string) {
    const mapped = mapIocToEvidenceType(iocType)
    setPromotingIoc({ type: iocType, value })
    setPromoteEvidenceType(mapped)
    setPromoteVerdict('suspicious')
    setPromoteNotes(`Promoted from Alert #${id} (${alert?.description ?? 'Wazuh Alert'})`)
    setPromoteError(null)

    // Load recent active cases for convenient selection
    try {
      const resp = await fetchCases({ page: 1, page_size: 20, sort_by: 'updated_at', sort_order: 'desc' })
      setRecentCases(resp.items)
      if (resp.items.length > 0 && !promoteCaseId) {
        setPromoteCaseId(String(resp.items[0].id))
      }
    } catch {
      // Continue even if case list fails
    }
  }

  async function handlePromoteSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!alert || !promotingIoc) return
    const caseIdNum = parseInt(promoteCaseId, 10)
    if (isNaN(caseIdNum) || caseIdNum <= 0) {
      setPromoteError('Please select or specify a valid Case ID.')
      return
    }
    setPromoting(true)
    setPromoteError(null)
    try {
      await addCaseEvidence(caseIdNum, {
        evidence_type: promoteEvidenceType,
        value: promotingIoc.value,
        verdict: promoteVerdict,
        notes: promoteNotes.trim() || undefined,
        alert_id: alert.id,
      })
      setActionSuccess({
        msg: `Promoted "${promotingIoc.value}" to Evidence in Case #${caseIdNum}`,
        caseId: caseIdNum,
      })
      setPromotingIoc(null)
      setTimeout(() => setActionSuccess(null), 5000)
    } catch (e) {
      setPromoteError(String(e))
    } finally {
      setPromoting(false)
    }
  }

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

      {actionSuccess && (
        <div className="success-banner">
          <span>{actionSuccess.msg}</span>
          {actionSuccess.caseId && (
            <Link to={`/cases/${actionSuccess.caseId}`} className="banner-link">
              View Case #{actionSuccess.caseId} →
            </Link>
          )}
        </div>
      )}

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
          <h3>MITRE ATT&CK Overview</h3>
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

      {/* Threat Intelligence & Enrichment Panels */}
      <section className="enrichment-section">
        <div className="section-header">
          <h2>Threat Intelligence & Enrichment</h2>
          <span className="enrichment-badge">Automated Analysis</span>
        </div>

        {enrichmentLoading ? (
          <div className="enrichment-loading-card">
            <Spinner label="Extracting IOCs and normalizing MITRE ATT&CK mappings…" />
          </div>
        ) : enrichmentError ? (
          <div className="enrichment-error-card">
            <ErrorBanner message={`Enrichment service error: ${enrichmentError}`} />
            <button
              type="button"
              className="btn btn-secondary btn-xs"
              onClick={() => {
                setEnrichmentLoading(true)
                setEnrichmentError(null)
                void getAlertEnrichment(Number(id), includePrivateIps)
                  .then(setEnrichment)
                  .catch((err) => setEnrichmentError(String(err)))
                  .finally(() => setEnrichmentLoading(false))
              }}
            >
              Retry Enrichment
            </button>
          </div>
        ) : (
          <div className="enrichment-grid">
            {/* IOC Intelligence Panel */}
            <div className="meta-card enrichment-panel">
              <div className="enrichment-panel-header">
                <h3>IOC Intelligence</h3>
                <label className="private-ip-toggle" title="Include RFC-1918 and loopback IP addresses">
                  <input
                    type="checkbox"
                    checked={includePrivateIps}
                    onChange={(e) => setIncludePrivateIps(e.target.checked)}
                  />
                  <span>Include internal IPs</span>
                </label>
              </div>

              {allActiveCategories.length === 0 ? (
                <div className="empty-enrichment">
                  <span className="empty-enrichment-icon">ℹ</span>
                  <span>No indicators of compromise (IP, domain, URL, email, or hash) detected in this alert.</span>
                </div>
              ) : (
                allActiveCategories.map((cat) => {
                  const items = indicatorsByType[cat.type] ?? (enrichment?.iocs?.[cat.type] ?? []).map((val) => ({
                    ioc_type: cat.type,
                    value: val,
                    source_field: null,
                  }))
                  return (
                    <div key={cat.type} className="ioc-category-group">
                      <div className="ioc-category-header">
                        <span className="ioc-category-name">{cat.label}</span>
                        <span className="ioc-count-badge">{items.length}</span>
                      </div>
                      <ul className="ioc-list">
                        {items.map((ind, idx) => (
                          <li key={`${ind.value}-${idx}`} className="ioc-item">
                            <div className="ioc-item-content">
                              <span className="ioc-value mono">{ind.value}</span>
                              {ind.source_field ? (
                                <span className="ioc-source" title={`Extracted from: ${ind.source_field}`}>
                                  source: {ind.source_field}
                                </span>
                              ) : null}
                            </div>
                            <button
                              type="button"
                              className="btn btn-xs btn-secondary promote-btn"
                              title="Promote indicator to Case Evidence Locker"
                              onClick={() => void handleOpenPromoteModal(ind.ioc_type, ind.value)}
                            >
                              + Promote to Evidence
                            </button>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )
                })
              )}
            </div>

            {/* MITRE ATT&CK Panel */}
            <div className="meta-card enrichment-panel">
              <div className="enrichment-panel-header">
                <h3>MITRE ATT&CK</h3>
              </div>

              {!hasMitre ? (
                <div className="empty-enrichment">
                  <span className="empty-enrichment-icon">ℹ</span>
                  <span>No MITRE ATT&CK techniques or tactics mapped to this alert.</span>
                </div>
              ) : (
                <>
                  {mitreTactics.length > 0 && (
                    <div className="mitre-block">
                      <h4 className="mitre-subtitle">Tactics ({mitreTactics.length})</h4>
                      <div className="tag-list" style={{ justifyContent: 'flex-start' }}>
                        {mitreTactics.map((t) => (
                          <span
                            key={t.slug}
                            className="tag tag-tactic"
                            title={t.is_known ? 'Standard ATT&CK Tactic' : 'Custom/Unverified Tactic'}
                          >
                            {t.slug}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {mitreTechniques.length > 0 && (
                    <div className="mitre-block">
                      <h4 className="mitre-subtitle">Techniques ({mitreTechniques.length})</h4>
                      <div className="mitre-techniques-list">
                        {mitreTechniques.map((tech) => (
                          <div key={tech.id} className="mitre-technique-row">
                            <div className="mitre-technique-main">
                              <span className="tag tag-technique mono">{tech.id}</span>
                              {tech.name ? (
                                <span className="mitre-technique-name">{tech.name}</span>
                              ) : null}
                              {tech.is_subtechnique && (
                                <span className="tag tag-subtechnique">Sub-technique</span>
                              )}
                            </div>
                            {tech.parent_id && (
                              <span className="mitre-parent-ref">
                                Parent: <span className="mono">{tech.parent_id}</span>
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </section>

      {/* Raw Alert JSON */}
      <section className="raw-alert-section">
        <button
          type="button"
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

      {/* Promote to Evidence Modal */}
      {promotingIoc && (
        <div className="modal-backdrop">
          <div className="modal-box">
            <div className="modal-header">
              <h3>Promote IOC to Incident Evidence</h3>
              <button
                type="button"
                className="btn-icon"
                onClick={() => setPromotingIoc(null)}
              >
                ✕
              </button>
            </div>
            {promoteError && <ErrorBanner message={promoteError} />}
            <form onSubmit={handlePromoteSubmit}>
              <div className="form-group">
                <label>Indicator Value</label>
                <div className="mono mono-strong readonly-box">{promotingIoc.value}</div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="p-type">Evidence Type</label>
                  <select
                    id="p-type"
                    value={promoteEvidenceType}
                    onChange={(e) => setPromoteEvidenceType(e.target.value)}
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
                  <label htmlFor="p-verdict">Analyst Verdict</label>
                  <select
                    id="p-verdict"
                    value={promoteVerdict}
                    onChange={(e) =>
                      setPromoteVerdict(
                        e.target.value as 'malicious' | 'suspicious' | 'benign' | 'informational',
                      )
                    }
                  >
                    <option value="malicious">Malicious (Confirmed threat)</option>
                    <option value="suspicious">Suspicious (Requires validation)</option>
                    <option value="benign">Benign (Legitimate)</option>
                    <option value="informational">Informational (Telemetry)</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="p-case">Target Incident Case</label>
                {recentCases.length > 0 ? (
                  <select
                    id="p-case"
                    value={promoteCaseId}
                    onChange={(e) => setPromoteCaseId(e.target.value)}
                  >
                    {recentCases.map((rc) => (
                      <option key={rc.id} value={rc.id}>
                        #{rc.id} - {rc.title} ({rc.status})
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    id="p-case"
                    type="number"
                    required
                    placeholder="Enter Case ID (e.g. 1)"
                    value={promoteCaseId}
                    onChange={(e) => setPromoteCaseId(e.target.value)}
                  />
                )}
              </div>

              <div className="form-group">
                <label htmlFor="p-notes">Evidence Context / Notes</label>
                <textarea
                  id="p-notes"
                  rows={2}
                  value={promoteNotes}
                  onChange={(e) => setPromoteNotes(e.target.value)}
                />
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setPromotingIoc(null)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={promoting || !promoteCaseId}
                >
                  {promoting ? 'Promoting…' : 'Promote to Evidence'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
