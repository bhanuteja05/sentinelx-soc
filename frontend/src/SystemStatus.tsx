import { useEffect, useState } from 'react'

import {
  BackendUnavailableError,
  DatabaseUnavailableError,
  fetchDatabaseHealth,
} from './api/client'

type ConnectionState = 'loading' | 'connected' | 'unavailable'

type SystemStatusState = {
  loading: boolean
  backend: ConnectionState
  database: ConnectionState
}

function labelFor(state: ConnectionState): string {
  if (state === 'loading') {
    return 'Checking…'
  }
  return state === 'connected' ? 'Connected' : 'Unavailable'
}

export default function SystemStatus() {
  const [status, setStatus] = useState<SystemStatusState>({
    loading: true,
    backend: 'loading',
    database: 'loading',
  })

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
          })
        }
      } catch (error) {
        if (cancelled) {
          return
        }
        if (error instanceof DatabaseUnavailableError) {
          setStatus({
            loading: false,
            backend: 'connected',
            database: 'unavailable',
          })
          return
        }
        if (error instanceof BackendUnavailableError) {
          setStatus({
            loading: false,
            backend: 'unavailable',
            database: 'unavailable',
          })
          return
        }
        setStatus({
          loading: false,
          backend: 'unavailable',
          database: 'unavailable',
        })
      }
    }

    void loadStatus()

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <main className="status-page">
      <h1>SentinelX</h1>
      <h2>System Status</h2>
      <p className="status-note" aria-live="polite">
        {status.loading ? 'Checking backend and database…' : 'Status from /api/v1/health/db'}
      </p>
      <dl className="status-list">
        <div>
          <dt>Backend</dt>
          <dd data-state={status.backend}>{labelFor(status.backend)}</dd>
        </div>
        <div>
          <dt>Database</dt>
          <dd data-state={status.database}>{labelFor(status.database)}</dd>
        </div>
      </dl>
    </main>
  )
}
