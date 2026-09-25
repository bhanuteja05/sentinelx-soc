export type DatabaseHealthResponse = {
  status: string
  database: string
}

export type WazuhHealthResponse = {
  status: string
  service: string
  url: string
}

export type WazuhAgent = {
  id: string
  name: string
  status: string
  version: string
  ip: string
  os?: {
    name?: string
    version?: string
    platform?: string
    arch?: string
  }
}

export type WazuhAgentsResponse = {
  data: {
    affected_items: WazuhAgent[]
    total_affected_items: number
    total_failed_items: number
  }
  message: string
  error: number
}

export type WazuhAlert = {
  id: string
  timestamp: string | null
  agent_id: string | null
  agent_name: string | null
  rule_id: string | null
  rule_level: number | null
  rule_description: string | null
  rule_groups: string[]
  mitre_tactics: string[]
  mitre_techniques: string[]
  decoder: string | null
  location: string | null
}

export type WazuhAlertsResponse = {
  status: string
  source: string
  index: string
  total: number
  count: number
  alerts: WazuhAlert[]
}

// ── Persisted alert types ────────────────────────────────────────────────────

export type AlertOut = {
  id: number
  wazuh_alert_id: string
  timestamp: string
  agent_id: string | null
  agent_name: string | null
  rule_id: string | null
  rule_level: number | null
  description: string | null
  src_ip: string | null
  dst_ip: string | null
  src_port: number | null
  dst_port: number | null
  location: string | null
  decoder: string | null
  mitre_tactics: string[]
  mitre_techniques: string[]
}

export type AlertDetailOut = AlertOut & {
  created_at: string
  raw_alert: Record<string, unknown>
}

export type PaginatedAlertsResponse = {
  items: AlertOut[]
  total: number
  page: number
  page_size: number
  pages: number
}

export type AlertsQuery = {
  page?: number
  page_size?: number
  sort_by?: string
  sort_order?: 'asc' | 'desc'
  rule_level?: number
  min_rule_level?: number
  max_rule_level?: number
  agent_id?: string
  agent_name?: string
  rule_id?: string
  mitre_tactic?: string
  mitre_technique?: string
  start_time?: string
  end_time?: string
}

// ── Case types ───────────────────────────────────────────────────────────────

export type CaseOut = {
  id: number
  title: string
  description: string | null
  status: string
  severity: string
  created_at: string
  updated_at: string
  alert_count: number
}

export type CaseDetailOut = CaseOut & {
  alerts: AlertOut[]
}

export type PaginatedCasesResponse = {
  items: CaseOut[]
  total: number
  page: number
  page_size: number
  pages: number
}

export type CasesQuery = {
  page?: number
  page_size?: number
  sort_by?: string
  sort_order?: 'asc' | 'desc'
  status?: string
  severity?: string
}

export type CreateCaseBody = {
  title: string
  description?: string
  severity?: string
  status?: string
}

export type UpdateCaseBody = {
  title?: string
  description?: string
  status?: string
  severity?: string
}

export type CaseAlertAssociationOut = {
  case_id: number
  alert_id: number
  created_at: string
  is_new: boolean
}

export type CaseNoteAuthor = {
  id: number
  username: string
  email: string
  role: string
}

export type CaseNote = {
  id: number
  case_id: number
  author_id: number
  author_username: string
  author?: CaseNoteAuthor | null
  content: string
  created_at: string
  updated_at: string
}

export type CreateCaseNoteBody = {
  content: string
}

export type UpdateCaseNoteBody = {
  content: string
}

// ── Error classes ────────────────────────────────────────────────────────────

export class BackendUnavailableError extends Error {
  constructor() {
    super('Backend unavailable')
    this.name = 'BackendUnavailableError'
  }
}

export class DatabaseUnavailableError extends Error {
  constructor() {
    super('Database unavailable')
    this.name = 'DatabaseUnavailableError'
  }
}

export class WazuhUnavailableError extends Error {
  constructor() {
    super('Wazuh unavailable')
    this.name = 'WazuhUnavailableError'
  }
}

export class NotFoundError extends Error {
  constructor() {
    super('Not found')
    this.name = 'NotFoundError'
  }
}

// ── Auth types ───────────────────────────────────────────────────────────────

export type AuthUser = {
  id: number
  username: string
  email: string
  role: 'analyst' | 'admin'
  is_active: boolean
  created_at: string
}

export type LoginCredentials = {
  username: string
  password: string
}

export type LoginResponse = {
  access_token: string
  token_type: string
  user: AuthUser
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

const TOKEN_STORAGE_KEY = 'sentinelx_token'

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY)
  } catch {
    return null
  }
}

export function setStoredToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_STORAGE_KEY, token)
  } catch {
    // ignore storage quota errors in edge environments
  }
}

export function removeStoredToken(): void {
  try {
    localStorage.removeItem(TOKEN_STORAGE_KEY)
  } catch {
    // ignore
  }
}

const DATABASE_HEALTH_PATH = '/api/v1/health/db'
const WAZUH_HEALTH_PATH = '/api/v1/wazuh/health'
const WAZUH_AGENTS_PATH = '/api/v1/wazuh/agents'

async function requestJson<T>(path: string, unavailable: Error): Promise<T> {
  let response: Response
  const token = getStoredToken()
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }

  try {
    response = await fetch(path, { headers })
  } catch {
    throw new BackendUnavailableError()
  }

  if (response.status === 401) {
    removeStoredToken()
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
    }
    throw new ApiError(401, 'Unauthorized')
  }

  if (!response.ok) {
    throw unavailable
  }

  return (await response.json()) as T
}

/** Generic fetch that throws NotFoundError on 404 and ApiError on other failures */
async function apiFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  let response: Response
  const token = getStoredToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(init?.headers as Record<string, string> | undefined),
  }

  try {
    response = await fetch(path, {
      ...init,
      headers,
    })
  } catch {
    throw new BackendUnavailableError()
  }

  if (response.status === 401) {
    removeStoredToken()
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
    }
    const text = await response.text().catch(() => 'Unauthorized')
    throw new ApiError(401, text || 'Unauthorized')
  }

  if (response.status === 404) throw new NotFoundError()
  if (!response.ok) {
    let text = ''
    try {
      const err = await response.json()
      if (err.detail) {
        text = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail)
      }
    } catch {
      text = await response.text().catch(() => response.statusText)
    }
    throw new ApiError(response.status, text || response.statusText)
  }

  // 204 No Content
  if (response.status === 204) return undefined as T

  return (await response.json()) as T
}

// ── Auth API calls ────────────────────────────────────────────────────────────

export async function login(credentials: LoginCredentials): Promise<LoginResponse> {
  const response = await fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      username_or_email: credentials.username,
      username: credentials.username,
      password: credentials.password,
    }),
  })

  if (!response.ok) {
    let msg = response.statusText
    try {
      const err = await response.json()
      if (err.detail) {
        msg = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail)
      }
    } catch {
      // ignore
    }
    throw new ApiError(response.status, msg)
  }

  return (await response.json()) as LoginResponse
}

export async function fetchMe(): Promise<AuthUser> {
  return apiFetch<AuthUser>('/api/v1/auth/me')
}

export async function logout(): Promise<void> {
  try {
    await apiFetch<void>('/api/v1/auth/logout', { method: 'POST' })
  } finally {
    removeStoredToken()
  }
}

export async function fetchDatabaseHealth(): Promise<DatabaseHealthResponse> {
  const payload = await requestJson<DatabaseHealthResponse>(
    DATABASE_HEALTH_PATH,
    new DatabaseUnavailableError(),
  )

  if (payload.status !== 'ok' || payload.database !== 'reachable') {
    throw new DatabaseUnavailableError()
  }

  return payload
}

export async function fetchWazuhHealth(): Promise<WazuhHealthResponse> {
  const payload = await requestJson<WazuhHealthResponse>(
    WAZUH_HEALTH_PATH,
    new WazuhUnavailableError(),
  )

  if (payload.status !== 'ok') {
    throw new WazuhUnavailableError()
  }

  return payload
}

export async function fetchWazuhAgents(): Promise<WazuhAgentsResponse> {
  return requestJson<WazuhAgentsResponse>(
    WAZUH_AGENTS_PATH,
    new WazuhUnavailableError(),
  )
}

export async function fetchWazuhAlerts(
  limit = 20,
): Promise<WazuhAlertsResponse> {
  return requestJson<WazuhAlertsResponse>(
    `/api/v1/wazuh/alerts?limit=${limit}`,
    new WazuhUnavailableError(),
  )
}

// ── Persisted alert API calls ─────────────────────────────────────────────────

function buildQuery(params: Record<string, string | number | undefined>): string {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') qs.set(k, String(v))
  }
  const s = qs.toString()
  return s ? `?${s}` : ''
}

export async function fetchAlerts(
  query: AlertsQuery = {},
): Promise<PaginatedAlertsResponse> {
  return apiFetch<PaginatedAlertsResponse>(
    `/api/v1/alerts${buildQuery(query as Record<string, string | number | undefined>)}`,
  )
}

export async function fetchAlertById(id: number): Promise<AlertDetailOut> {
  return apiFetch<AlertDetailOut>(`/api/v1/alerts/${id}`)
}

export async function fetchAlertCount(): Promise<{ count: number }> {
  return apiFetch<{ count: number }>('/api/v1/alerts/count')
}

// ── Case API calls ────────────────────────────────────────────────────────────

export async function fetchCases(
  query: CasesQuery = {},
): Promise<PaginatedCasesResponse> {
  return apiFetch<PaginatedCasesResponse>(
    `/api/v1/cases${buildQuery(query as Record<string, string | number | undefined>)}`,
  )
}

export async function fetchCaseById(id: number): Promise<CaseDetailOut> {
  return apiFetch<CaseDetailOut>(`/api/v1/cases/${id}`)
}

export async function createCase(body: CreateCaseBody): Promise<CaseOut> {
  return apiFetch<CaseOut>('/api/v1/cases', {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export async function updateCase(
  id: number,
  body: UpdateCaseBody,
): Promise<CaseOut> {
  return apiFetch<CaseOut>(`/api/v1/cases/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  })
}

export async function closeCase(id: number): Promise<CaseOut> {
  return apiFetch<CaseOut>(`/api/v1/cases/${id}/close`, { method: 'POST' })
}

export async function deleteCase(id: number): Promise<void> {
  return apiFetch<void>(`/api/v1/cases/${id}`, { method: 'DELETE' })
}

export async function associateAlertToCase(
  caseId: number,
  alertId: number,
): Promise<CaseAlertAssociationOut> {
  return apiFetch<CaseAlertAssociationOut>(
    `/api/v1/cases/${caseId}/alerts/${alertId}`,
    { method: 'POST' },
  )
}

export async function detachAlertFromCase(
  caseId: number,
  alertId: number,
): Promise<void> {
  return apiFetch<void>(`/api/v1/cases/${caseId}/alerts/${alertId}`, {
    method: 'DELETE',
  })
}

export async function fetchCaseAlerts(
  caseId: number,
  query: AlertsQuery = {},
): Promise<PaginatedAlertsResponse> {
  return apiFetch<PaginatedAlertsResponse>(
    `/api/v1/cases/${caseId}/alerts${buildQuery(query as Record<string, string | number | undefined>)}`,
  )
}

// ── Case Notes API calls ──────────────────────────────────────────────────────

export async function fetchCaseNotes(caseId: number): Promise<CaseNote[]> {
  return apiFetch<CaseNote[]>(`/api/v1/cases/${caseId}/notes`)
}

export async function createCaseNote(
  caseId: number,
  content: string,
): Promise<CaseNote> {
  return apiFetch<CaseNote>(`/api/v1/cases/${caseId}/notes`, {
    method: 'POST',
    body: JSON.stringify({ content }),
  })
}

export async function updateCaseNote(
  caseId: number,
  noteId: number,
  content: string,
): Promise<CaseNote> {
  return apiFetch<CaseNote>(`/api/v1/cases/${caseId}/notes/${noteId}`, {
    method: 'PATCH',
    body: JSON.stringify({ content }),
  })
}

export async function deleteCaseNote(
  caseId: number,
  noteId: number,
): Promise<void> {
  return apiFetch<void>(`/api/v1/cases/${caseId}/notes/${noteId}`, {
    method: 'DELETE',
  })
}

// ── Enrichment types ─────────────────────────────────────────────────────────

export type IOCIndicator = {
  ioc_type: string
  value: string
  source_field: string | null
}

export type MITRETechnique = {
  id: string
  is_subtechnique: boolean
  parent_id: string | null
  name?: string
  source_field?: string | null
}

export type MITRETactic = {
  slug: string
  is_known: boolean
  source_field?: string | null
}

export type MITREEnrichment = {
  techniques: MITRETechnique[]
  tactics: MITRETactic[]
}

export type AlertEnrichmentResponse = {
  alert_id: number
  wazuh_alert_id: string
  iocs: Record<string, string[]>
  indicators: IOCIndicator[]
  mitre: MITREEnrichment
}

export async function fetchAlertEnrichment(
  alertId: number,
  includePrivateIps = false,
): Promise<AlertEnrichmentResponse> {
  const query = includePrivateIps ? '?include_private_ips=true' : ''
  return apiFetch<AlertEnrichmentResponse>(`/api/v1/alerts/${alertId}/enrich${query}`)
}

export const getAlertEnrichment = fetchAlertEnrichment

// ── Dashboard Analytics types ────────────────────────────────────────────────

export type TimeSeriesBucket = {
  timestamp: string
  label: string
  count: number
}

export type DaySeriesBucket = {
  date: string
  label: string
  count: number
}

export type MITRETechniqueSummary = {
  technique_id: string
  count: number
}

export type MITRETacticSummary = {
  tactic: string
  count: number
}

export type MITREAnalytics = {
  top_techniques: MITRETechniqueSummary[]
  top_tactics: MITRETacticSummary[]
}

export type IOCSummary = {
  source: string
  analyzed_alert_count: number
  total_indicators: number
  by_type: Record<string, number>
  samples: Record<string, string[]>
}

export type RecentAlertSummary = {
  id: number
  wazuh_alert_id: string
  timestamp: string
  agent_id: string | null
  agent_name: string | null
  rule_id: string
  rule_level: number | null
  description: string | null
  mitre_tactics: string[]
  mitre_techniques: string[]
}

export type RecentCaseSummary = {
  id: number
  title: string
  status: string
  severity: string
  alert_count: number
  created_at: string
}

export type RecentActivitySummary = {
  id: number
  case_id: number
  case_title: string
  author_username: string
  content: string
  created_at: string
}

export type AlertMetrics = {
  total: number
  last_24h: number
  last_7d: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
}

export type CaseMetrics = {
  total: number
  open: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
}

export type DashboardSummary = {
  generated_at: string
  alerts: AlertMetrics
  cases: CaseMetrics
  time_series_24h: TimeSeriesBucket[]
  time_series_7d: DaySeriesBucket[]
  mitre: MITREAnalytics
  iocs: IOCSummary
  recent_alerts: RecentAlertSummary[]
  recent_cases: RecentCaseSummary[]
  recent_activity: RecentActivitySummary[]
}

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  return apiFetch<DashboardSummary>('/api/v1/dashboard/summary')
}

// ── Triage Automation types ──────────────────────────────────────────────────

export type TriageRule = {
  id: number
  name: string
  description: string | null
  is_active: boolean
  min_rule_level: number | null
  rule_ids: string[]
  mitre_techniques: string[]
  mitre_tactics: string[]
  action_type: string
  case_severity: string
  case_title_template: string
  created_at: string
  updated_at: string
}

export type CreateTriageRuleBody = {
  name: string
  description?: string
  is_active?: boolean
  min_rule_level?: number | null
  rule_ids?: string[]
  mitre_techniques?: string[]
  mitre_tactics?: string[]
  action_type?: string
  case_severity?: string
  case_title_template?: string
}

export type UpdateTriageRuleBody = {
  name?: string
  description?: string
  is_active?: boolean
  min_rule_level?: number | null
  rule_ids?: string[]
  mitre_techniques?: string[]
  mitre_tactics?: string[]
  action_type?: string
  case_severity?: string
  case_title_template?: string
}

export type TriageActionDetail = {
  action: string
  case_id: number
  case_title: string
  rule_id: number
  rule_name: string
  alert_id: number
}

export type TriageEvaluationResult = {
  evaluated_alerts: number
  matched_alerts: number
  cases_created: number
  alerts_correlated: number
  unmatched_alerts: number
  details: TriageActionDetail[]
}

export async function fetchTriageRules(isActive?: boolean): Promise<TriageRule[]> {
  const query = isActive !== undefined ? `?is_active=${isActive}` : ''
  return apiFetch<TriageRule[]>(`/api/v1/triage/rules${query}`)
}

export async function createTriageRule(body: CreateTriageRuleBody): Promise<TriageRule> {
  return apiFetch<TriageRule>('/api/v1/triage/rules', {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export async function updateTriageRule(
  ruleId: number,
  body: UpdateTriageRuleBody,
): Promise<TriageRule> {
  return apiFetch<TriageRule>(`/api/v1/triage/rules/${ruleId}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  })
}

export async function deleteTriageRule(ruleId: number): Promise<void> {
  return apiFetch<void>(`/api/v1/triage/rules/${ruleId}`, {
    method: 'DELETE',
  })
}

export async function evaluateTriageBacklog(limit = 100): Promise<TriageEvaluationResult> {
  return apiFetch<TriageEvaluationResult>('/api/v1/triage/evaluate', {
    method: 'POST',
    body: JSON.stringify({ limit }),
  })
}
