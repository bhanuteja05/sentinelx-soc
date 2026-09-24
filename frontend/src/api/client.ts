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
