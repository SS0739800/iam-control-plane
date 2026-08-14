/**
 * Tests for the login inspector screen.
 *
 * The thing worth testing is that a refused login shows which check failed and
 * why. That is the entire reason this screen exists, so a version of it that
 * renders "refused" and nothing else would be a regression the backend tests
 * cannot see.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import LoginsPage from './Logins'

const PROVIDERS = [{ slug: 'authentik', name: 'authentik (local)' }]

const REFUSED = {
  id: 91,
  occurred_at: '2026-08-14T12:00:00Z',
  outcome: 'failure',
  idp: 'authentik',
  who: 'Upstream IdP <authentik>',
  reason: 'This login failed 1 of its checks: timing.',
  checks: [
    { name: 'signature', passed: true, detail: "signed with the provider's key" },
    {
      name: 'timing',
      passed: false,
      detail: 'expired at 2026-08-14T11:55:00Z, it is now 2026-08-14T12:00:00Z',
    },
  ],
  failed_checks: ['timing'],
  assertion_id: 'id-assertion-abc',
  session_id: null,
  directory: null,
  has_response: true,
}

const ACCEPTED = {
  id: 90,
  occurred_at: '2026-08-14T11:00:00Z',
  outcome: 'success',
  idp: 'authentik',
  who: 'Ada Bergman <ada.bergman@demo.local>',
  reason: null,
  checks: [{ name: 'signature', passed: true, detail: "signed with the provider's key" }],
  failed_checks: [],
  assertion_id: 'id-assertion-xyz',
  session_id: '11111111-2222-3333-4444-555555555555',
  directory: 'created on first login',
  has_response: false,
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.toString()
  return input.url
}

function stubApi(): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = urlOf(input)
      if (url.includes('/api/identity-providers')) {
        return Promise.resolve(jsonResponse(PROVIDERS))
      }
      if (url.includes('/api/saml/logins/91')) {
        return Promise.resolve(
          jsonResponse({
            ...REFUSED,
            decoded_response: '<samlp:Response>the document that arrived</samlp:Response>',
            response_truncated: false,
          }),
        )
      }
      if (url.includes('/api/saml/logins')) {
        return Promise.resolve(
          jsonResponse({ items: [REFUSED, ACCEPTED], limit: 25, next_cursor: null }),
        )
      }
      return Promise.resolve(jsonResponse({ detail: `unexpected ${url}` }, 404))
    }),
  )
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <LoginsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(stubApi)
afterEach(() => vi.unstubAllGlobals())

test('lists both accepted and refused attempts', async () => {
  renderPage()

  expect(await screen.findByText('Upstream IdP <authentik>')).toBeInTheDocument()
  expect(screen.getByText('Ada Bergman <ada.bergman@demo.local>')).toBeInTheDocument()
  expect(screen.getByText('refused')).toBeInTheDocument()
  expect(screen.getByText('accepted')).toBeInTheDocument()
})

test('names the failed check in the row', async () => {
  renderPage()

  // Without this the screen says "refused" and leaves you to guess, which is the
  // one thing it exists not to do.
  expect(await screen.findByText('timing')).toBeInTheDocument()
})

test('expanding an attempt shows every check and why it failed', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: '#91' }))

  expect(await screen.findByText(/expired at 2026-08-14T11:55:00Z/)).toBeInTheDocument()
  expect(screen.getByText(/signed with the provider's key/)).toBeInTheDocument()
})

test('expanding a refused attempt shows the document that arrived', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: '#91' }))

  expect(
    await screen.findByText(/the document that arrived/, { collapseWhitespace: false }),
  ).toBeInTheDocument()
})

test('an accepted attempt says why nothing was kept', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: '#90' }))

  await waitFor(() =>
    expect(screen.getByText(/Only failed logins keep the document/)).toBeInTheDocument(),
  )
})
