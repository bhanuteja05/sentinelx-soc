export type DatabaseHealthResponse = {
  status: string
  database: string
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

const DATABASE_HEALTH_PATH = '/api/v1/health/db'

export async function fetchDatabaseHealth(): Promise<DatabaseHealthResponse> {
  let response: Response

  try {
    response = await fetch(DATABASE_HEALTH_PATH, {
      headers: { Accept: 'application/json' },
    })
  } catch {
    throw new BackendUnavailableError()
  }

  if (!response.ok) {
    throw new DatabaseUnavailableError()
  }

  const payload = (await response.json()) as DatabaseHealthResponse

  if (payload.status !== 'ok' || payload.database !== 'reachable') {
    throw new DatabaseUnavailableError()
  }

  return payload
}
