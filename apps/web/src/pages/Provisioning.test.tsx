/**
 * Tests for the provisioning screen.
 *
 * The revoke tests exist because of a real mistake: the button used to revoke on
 * a single click, and somebody killed the token their live sync was using. The
 * action cannot be undone — a revoked token stays dead and you have to issue a
 * new one — so it has to ask first, and say what it is about to break.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import ProvisioningPage from './Provisioning'

const OVERVIEW = {
  users_from_scim: 1031,
  groups_from_scim: 2,
  users_from_login: 0,
  active_clients: 1,
  last_sync_at: '2026-08-16T19:05:01Z',
}

const ACTIVE_CLIENT = {
  id: '11111111-1111-1111-1111-111111111111',
  name: 'authentik provisioning',
  description: 'Pushes users and groups from authentik',
  enabled: true,
  created_at: '2026-08-16T18:41:21Z',
  last_used_at: '2026-08-16T19:05:00Z',
  revoked_at: null,
  revoked_reason: null,
  usable: true,
}

const REVOKED_CLIENT = {
  ...ACTIVE_CLIENT,
  id: '22222222-2222-2222-2222-222222222222',
  name: 'an old token',
  enabled: false,
  revoked_at: '2026-08-16T18:52:04Z',
  revoked_reason: 'rotated',
  usable: false,
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

let revokeCalls = 0

function stubApi(): void {
  revokeCalls = 0
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = urlOf(input)
      const method = init?.method ?? (input instanceof Request ? input.method : 'GET')

      if (url.includes('/revoke')) {
        revokeCalls += 1
        return Promise.resolve(jsonResponse({ ...ACTIVE_CLIENT, usable: false }))
      }
      if (url.includes('/api/provisioning/overview')) return Promise.resolve(jsonResponse(OVERVIEW))
      if (url.includes('/api/provisioning/activity')) return Promise.resolve(jsonResponse([]))
      if (url.includes('/api/provisioning/clients') && method === 'POST') {
        return Promise.resolve(
          jsonResponse({ ...ACTIVE_CLIENT, name: 'new one', token: 'the-secret-token' }, 201),
        )
      }
      if (url.includes('/api/provisioning/clients')) {
        return Promise.resolve(jsonResponse([ACTIVE_CLIENT, REVOKED_CLIENT]))
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
        <ProvisioningPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(stubApi)
afterEach(() => vi.unstubAllGlobals())

test('shows what the sync owns', async () => {
  renderPage()

  expect(await screen.findByText('1,031')).toBeInTheDocument()
  expect(screen.getByText('People from SCIM')).toBeInTheDocument()
})

test('lists active and revoked tokens, with the reason', async () => {
  renderPage()

  expect(await screen.findByText('authentik provisioning')).toBeInTheDocument()
  expect(screen.getByText('an old token')).toBeInTheDocument()
  expect(screen.getByText('revoked')).toBeInTheDocument()
  expect(screen.getByText('rotated')).toBeInTheDocument()
})

test('a revoked token offers no revoke button', async () => {
  renderPage()
  await screen.findByText('an old token')

  // One button, for the one token that is still live.
  expect(screen.getAllByRole('button', { name: 'Revoke' })).toHaveLength(1)
})

test('revoking asks first and says what it will break', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))

  expect(screen.getByText(/cannot be\s+undone/)).toBeInTheDocument()
  expect(revokeCalls).toBe(0)
})

test('cancelling leaves the token alone', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

  expect(revokeCalls).toBe(0)
  expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument()
})

test('confirming actually revokes', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
  fireEvent.click(screen.getByRole('button', { name: 'Yes, revoke it' }))

  await waitFor(() => expect(revokeCalls).toBe(1))
})

test('a new token is shown once, with a warning that it will not be again', async () => {
  renderPage()
  await screen.findByText('authentik provisioning')

  fireEvent.change(screen.getByRole('textbox', { name: /name/i }), {
    target: { value: 'new one' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Issue token' }))

  expect(await screen.findByText('the-secret-token')).toBeInTheDocument()
  expect(screen.getByText(/only time it can be shown/)).toBeInTheDocument()
})
