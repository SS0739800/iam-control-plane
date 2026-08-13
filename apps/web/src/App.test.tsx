import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import App from './App'

const LIVENESS = { status: 'ok', env: 'ci', version: '0.1.0', git_sha: 'abc1234' }
const READY = { status: 'ready', database: 'ok', detail: null }
const DEGRADED = { status: 'degraded', database: 'unreachable', detail: 'ConnectionRefusedError' }

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Stub fetch so the readiness endpoint answers with `readiness`. */
function stubApi(readiness: unknown, readinessStatus = 200): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api/health/ready')) {
        return Promise.resolve(jsonResponse(readiness, readinessStatus))
      }
      if (url.includes('/api/health')) {
        return Promise.resolve(jsonResponse(LIVENESS))
      }
      return Promise.reject(new Error(`unexpected fetch: ${url}`))
    }),
  )
}

function renderApp() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  stubApi(READY)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

test('renders the running build so you can tell what is deployed', async () => {
  renderApp()

  expect(await screen.findByText('abc1234')).toBeInTheDocument()
  expect(screen.getByText('0.1.0')).toBeInTheDocument()
})

test('reports the database as ok when readiness succeeds', async () => {
  renderApp()

  // Scoped to the panel: "ok" also appears as the API's liveness value.
  const database = within(await screen.findByRole('region', { name: 'Database' }))

  expect(await database.findByText('ready')).toBeInTheDocument()
  expect(database.getByText('ok')).toBeInTheDocument()
})

test('surfaces a degraded database rather than a failed request', async () => {
  // Readiness answers 503 here. The client treats that as a successful read of a
  // degraded state, so the diagnostic reaches the screen instead of a generic
  // "request failed".
  stubApi(DEGRADED, 503)
  renderApp()

  const database = within(await screen.findByRole('region', { name: 'Database' }))

  expect(await database.findByText('degraded')).toBeInTheDocument()
  expect(database.getByText('unreachable')).toBeInTheDocument()
  expect(database.getByText('ConnectionRefusedError')).toBeInTheDocument()
})

test('lists the phase 0 surface as live and later ones as planned', async () => {
  renderApp()

  expect(await screen.findByText('/api/health')).toBeInTheDocument()
  expect(screen.getByText('P0 · live')).toBeInTheDocument()
  expect(screen.getByText('P3 · planned')).toBeInTheDocument()
})
