/**
 * API client.
 *
 * Every path here is relative, which is the single-origin architecture paying
 * off: no base URL to configure, no CORS preflight, and the session cookie added
 * in P2 stays first-party.
 *
 * This module is hand-written only until P1, where it is replaced by types
 * generated from the FastAPI OpenAPI schema plus a CI check that fails on drift.
 */

export interface Liveness {
  status: 'ok'
  env: string
  version: string
  git_sha: string
}

export interface Readiness {
  status: 'ready' | 'degraded'
  database: 'ok' | 'unreachable'
  detail: string | null
}

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function getJson<T>(path: string, acceptedStatuses: number[] = [200]): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: 'application/json' },
    // Same-origin, so this is not a cross-site credential grant — it just means
    // the session cookie rides along once P2 issues one.
    credentials: 'same-origin',
  })

  if (!acceptedStatuses.includes(response.status)) {
    throw new ApiError(response.status, `${path} returned ${response.status}`)
  }

  return (await response.json()) as T
}

export function fetchLiveness(): Promise<Liveness> {
  return getJson<Liveness>('/api/health')
}

/**
 * Readiness answers 503 when Postgres is unreachable, and that response body is
 * exactly the diagnostic we want to render. So 503 is a successful read of a
 * degraded state, not a transport failure — otherwise the UI shows "request
 * failed" precisely when it has something useful to say.
 */
export function fetchReadiness(): Promise<Readiness> {
  return getJson<Readiness>('/api/health/ready', [200, 503])
}
