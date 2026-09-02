import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import Dashboard from './Dashboard'

const COUNTS = {
  users: 1284,
  active_users: 1199,
  groups: 42,
  applications: 17,
  sso_applications: 12,
  audit_events: 45829,
}
const LIVENESS = { status: 'ok', env: 'ci', version: '0.1.0', git_sha: 'abc1234' }
const READY = { status: 'ready', database: 'ok', detail: null }
const DEGRADED = { status: 'degraded', database: 'unreachable', detail: 'ConnectionRefusedError' }

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/**
 * Get the URL out of whatever fetch was handed.
 *
 * openapi-fetch passes a Request object, not a string. String(request) gives
 * "[object Request]", so matching on that quietly matches nothing.
 */
function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.toString()
  return input.url
}

function stubApi(readiness: unknown, readinessStatus = 200): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = urlOf(input)
      if (url.includes('/api/health/ready')) {
        return Promise.resolve(jsonResponse(readiness, readinessStatus))
      }
      if (url.includes('/api/health')) return Promise.resolve(jsonResponse(LIVENESS))
      if (url.includes('/api/dashboard')) return Promise.resolve(jsonResponse(COUNTS))
      return Promise.reject(new Error(`unexpected fetch: ${url}`))
    }),
  )
}

function renderDashboard() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  stubApi(READY)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

test('shows the directory counts with thousands separators', async () => {
  renderDashboard()

  // Formatted, not raw. "45829" on screen reads as a mistake.
  expect(await screen.findByText('1,284')).toBeInTheDocument()
  expect(screen.getByText('45,829')).toBeInTheDocument()
  expect(screen.getByText('42')).toBeInTheDocument()
})

test('works out how many users are deactivated', async () => {
  renderDashboard()

  // 1284 total minus 1199 active. Worth asserting because it's the one number the
  // frontend calculates rather than reads.
  expect(await screen.findByText('85')).toBeInTheDocument()
})

test('reports the running build so you can tell what is deployed', async () => {
  renderDashboard()

  const api = within(await screen.findByRole('region', { name: 'API' }))
  expect(await api.findByText('abc1234')).toBeInTheDocument()
  expect(api.getByText('0.1.0')).toBeInTheDocument()
})

test('shows the database as ok when the readiness check passes', async () => {
  renderDashboard()

  const database = within(await screen.findByRole('region', { name: 'Database' }))
  expect(await database.findByText('ready')).toBeInTheDocument()
  expect(database.getByText('ok')).toBeInTheDocument()
})

test('surfaces a broken database instead of a failed request', async () => {
  // The readiness endpoint answers 503 here. The client treats that as a real
  // answer, so the reason reaches the screen.
  stubApi(DEGRADED, 503)
  renderDashboard()

  const database = within(await screen.findByRole('region', { name: 'Database' }))
  expect(await database.findByText('degraded')).toBeInTheDocument()
  expect(database.getByText('unreachable')).toBeInTheDocument()
  expect(database.getByText('ConnectionRefusedError')).toBeInTheDocument()
})

test('nothing on the dashboard promises a feature that does not exist', async () => {
  renderDashboard()
  await screen.findByText('Users')

  // There was an "Access packages — arrives in P4" tile here. It was honest while
  // P4 was ahead of us and became a false promise the moment P4 shipped: the
  // capability was delivered as access requests and access rules, and the Entra-style
  // package abstraction never was. A placeholder that outlives its deadline reads as
  // a broken feature rather than as a decision.
  expect(screen.queryByText('Access packages')).not.toBeInTheDocument()
  expect(screen.queryByText(/arrives in P/)).not.toBeInTheDocument()
})
