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

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

const DATABASE_HEALTH_PATH = '/api/v1/health/db'
const WAZUH_HEALTH_PATH = '/api/v1/wazuh/health'
const WAZUH_AGENTS_PATH = '/api/v1/wazuh/agents'

async function requestJson<T>(path: string, unavailable: Error): Promise<T> {
  let response: Response

  try {
    response = await fetch(path, {
      headers: { Accept: 'application/json' },
    })
  } catch {
    throw new BackendUnavailableError()
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
  try {
    response = await fetch(path, {
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      ...init,
    })
  } catch {
    throw new BackendUnavailableError()
  }

  if (response.status === 404) throw new NotFoundError()
  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText)
    throw new ApiError(response.status, text)
  }

  // 204 No Content
  if (response.status === 204) return undefined as T

  return (await response.json()) as T
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
