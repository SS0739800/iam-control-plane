/**
 * Tests for the console role panel.
 *
 * The two that matter are the ones about not showing things: somebody without
 * roles:write must not see a grant form or a revoke button, and revoking must
 * ask before it happens. The permission check here is cosmetic — the API enforces
 * it — but a form that always fails is its own kind of bug.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import RoleGrantPanel from './RoleGrantPanel'

const USER_ID = '11111111-1111-1111-1111-111111111111'

const HELPDESK_GRANT = {
  id: 'aaaaaaaa-0000-0000-0000-000000000001',
  role: 'helpdesk',
  source: 'direct',
  reason: 'Joining the service desk',
  granted_by_label: 'Platform Admin <admin@demo.local>',
  created_at: '2026-08-01T09:00:00Z',
  expires_at: null,
  revoked_at: null,
  revoked_by_label: null,
  revoked_reason: null,
  live: true,
}

const OLD_ADMIN_GRANT = {
  ...HELPDESK_GRANT,
  id: 'aaaaaaaa-0000-0000-0000-000000000002',
  role: 'admin',
  reason: 'Covering the migration weekend',
  created_at: '2026-03-01T09:00:00Z',
  revoked_at: '2026-03-21T09:00:00Z',
  revoked_reason: 'expired',
  live: false,
}

const SUMMARY = {
  user_id: USER_ID,
  user_name: 'ada@demo.local',
  display_name: 'Ada Bergman',
  active: true,
  role: 'helpdesk',
  role_granted_by: 'Platform Admin <admin@demo.local>',
  role_granted_at: '2026-08-01T09:00:00Z',
  role_expires_at: null,
  groups: ['Engineering'],
  grant_history: [HELPDESK_GRANT, OLD_ADMIN_GRANT],
}

let revokeCalls = 0
let grantBodies: unknown[] = []

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

function methodOf(input: RequestInfo | URL, init?: RequestInit): string {
  if (init?.method) return init.method
  if (input instanceof Request) return input.method
  return 'GET'
}

async function bodyOf(input: RequestInfo | URL, init?: RequestInit): Promise<unknown> {
  if (init?.body) return JSON.parse(String(init.body))
  if (input instanceof Request) return input.clone().json()
  return null
}

function stubApi(summary: unknown = SUMMARY): void {
  revokeCalls = 0
  grantBodies = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = urlOf(input)
      const method = methodOf(input, init)

      if (url.includes('/role-grants') && method === 'DELETE') {
        revokeCalls += 1
        return jsonResponse({ ...(summary as object), role: 'employee' })
      }
      if (url.includes('/role-grants') && method === 'POST') {
        grantBodies.push(await bodyOf(input, init))
        return jsonResponse(HELPDESK_GRANT, 201)
      }
      if (url.includes('/access')) return jsonResponse(summary)
      return jsonResponse({ detail: `unexpected ${method} ${url}` }, 404)
    }),
  )
}

function renderPanel(canWrite = true) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <RoleGrantPanel userId={USER_ID} canWrite={canWrite} />
    </QueryClientProvider>,
  )
}

beforeEach(() => stubApi())
afterEach(() => vi.unstubAllGlobals())

test('shows the current role and who granted it', async () => {
  renderPanel()

  // Both the current role and every history row say "granted by", so this pins to
  // the "... on <date>" wording that only the current line uses.
  expect(await screen.findByText(/granted by Platform Admin.* on \d/)).toBeInTheDocument()
  expect(screen.getByRole('combobox')).toBeInTheDocument()
})

test('keeps finished grants on screen, with how they ended', async () => {
  renderPanel()
  await screen.findByText('History')

  // The old admin grant is the whole reason the history exists.
  expect(screen.getByText(/expired/)).toBeInTheDocument()
  expect(screen.getByText(/Covering the migration weekend/)).toBeInTheDocument()
})

test('somebody without roles:write gets no controls', async () => {
  renderPanel(false)
  await screen.findByText('History')

  expect(screen.queryByRole('button', { name: 'Revoke role' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Grant role' })).not.toBeInTheDocument()
})

test('revoking asks first', async () => {
  renderPanel()

  fireEvent.click(await screen.findByRole('button', { name: 'Revoke role' }))

  expect(screen.getByText(/lose access to this\s+console/)).toBeInTheDocument()
  expect(revokeCalls).toBe(0)
})

test('cancelling a revoke does nothing', async () => {
  renderPanel()

  fireEvent.click(await screen.findByRole('button', { name: 'Revoke role' }))
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

  expect(revokeCalls).toBe(0)
  expect(screen.getByRole('button', { name: 'Revoke role' })).toBeInTheDocument()
})

test('confirming a revoke sends it', async () => {
  renderPanel()

  fireEvent.click(await screen.findByRole('button', { name: 'Revoke role' }))
  fireEvent.click(screen.getByRole('button', { name: 'Yes, revoke it' }))

  await waitFor(() => expect(revokeCalls).toBe(1))
})

test('warns about admin with no end date', async () => {
  renderPanel()
  await screen.findByText('History')

  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'admin' } })

  expect(screen.getByText(/unnoticed admin/)).toBeInTheDocument()
})

test('granting sends the role and the reason', async () => {
  renderPanel()
  await screen.findByText('History')

  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'auditor' } })
  fireEvent.change(screen.getByPlaceholderText(/Covering the migration/), {
    target: { value: 'Quarterly review' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Grant role' }))

  await waitFor(() => expect(grantBodies).toHaveLength(1))
  expect(grantBodies[0]).toMatchObject({ role: 'auditor', reason: 'Quarterly review' })
})

test('somebody with no role is described rather than left blank', async () => {
  stubApi({ ...SUMMARY, role: 'employee', role_granted_by: null, grant_history: [] })
  renderPanel()

  expect(await screen.findByText(/cannot use this console/)).toBeInTheDocument()
  expect(screen.getByText('Never had a console role.')).toBeInTheDocument()
})
