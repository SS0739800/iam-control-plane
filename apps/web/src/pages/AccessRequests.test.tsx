/**
 * Tests for the access requests screen.
 *
 * Three claims worth holding:
 *
 * An employee can use it. They hold no permissions, so a page that needs one would
 * make the whole request flow useless to the people it exists for.
 *
 * Your own request offers no decide buttons, and says why. The API refuses
 * self-approval anyway; this is so somebody reads the reason before hitting it.
 *
 * The reason is always visible. It is the only thing an approver can weigh.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import AccessRequestsPage from './AccessRequests'

const ME_ID = 'me-0000-0000-0000-000000000001'
const OTHER_ID = 'her-0000-0000-0000-000000000002'
const GROUP_ID = 'grp-0000-0000-0000-000000000003'

const THEIR_REQUEST = {
  id: 'req-0000-0000-0000-000000000010',
  state: 'pending',
  requester_id: OTHER_ID,
  requester_label: 'Ada Bergman <ada@demo.local>',
  group_id: GROUP_ID,
  group_label: 'Finance',
  reason: 'Covering month-end close while Priya is away.',
  decided_by_label: null,
  decided_at: null,
  decision_note: null,
  expires_at: null,
  created_at: '2026-08-17T09:00:00Z',
  is_open: true,
}

const MY_REQUEST = {
  ...THEIR_REQUEST,
  id: 'req-0000-0000-0000-000000000011',
  requester_id: ME_ID,
  requester_label: 'Platform Admin <admin@demo.local>',
  group_label: 'AWS Admins',
  reason: 'Need it for the migration weekend.',
}

let approveBodies: unknown[] = []
let denyCalls = 0
let askBodies: unknown[] = []
let withdrawCalls = 0

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
  if (input instanceof Request) {
    const text = await input.clone().text()
    return text ? JSON.parse(text) : null
  }
  return null
}

function stubApi(
  options: {
    permissions?: string[]
    queue?: unknown[]
    mine?: unknown[]
  } = {},
): void {
  approveBodies = []
  denyCalls = 0
  askBodies = []
  withdrawCalls = 0

  const permissions = options.permissions ?? ['groups:read', 'groups:write']
  const queue = options.queue ?? [THEIR_REQUEST]
  const mine = options.mine ?? [MY_REQUEST]

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = urlOf(input)
      const method = methodOf(input, init)

      if (url.includes('/approve')) {
        approveBodies.push(await bodyOf(input, init))
        return jsonResponse({ ...THEIR_REQUEST, state: 'approved' })
      }
      if (url.includes('/deny')) {
        denyCalls += 1
        return jsonResponse({ ...THEIR_REQUEST, state: 'denied' })
      }
      if (url.includes('/withdraw')) {
        withdrawCalls += 1
        return jsonResponse({ ...MY_REQUEST, state: 'withdrawn' })
      }
      if (url.includes('/access-requests/mine')) return jsonResponse(mine)
      if (url.includes('/access-requests') && method === 'POST') {
        askBodies.push(await bodyOf(input, init))
        return jsonResponse(MY_REQUEST, 201)
      }
      if (url.includes('/access-requests')) return jsonResponse(queue)
      if (url.includes('/api/groups')) {
        return jsonResponse({
          items: [{ id: GROUP_ID, name: 'Finance', member_count: 4 }],
          total: 1,
          limit: 200,
          offset: 0,
        })
      }
      if (url.includes('/api/me')) {
        return jsonResponse({
          id: ME_ID,
          user_name: 'admin@demo.local',
          display_name: 'Platform Admin',
          role: 'admin',
          permissions,
          via_saml_session: false,
        })
      }
      return jsonResponse({ detail: `unexpected ${method} ${url}` }, 404)
    }),
  )
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AccessRequestsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => stubApi())
afterEach(() => vi.unstubAllGlobals())

test('the reason is shown in full', async () => {
  renderPage()

  expect(
    await screen.findByText('Covering month-end close while Priya is away.'),
  ).toBeInTheDocument()
})

test('an approver can approve, with a note and an end date', async () => {
  renderPage()
  await screen.findByText('Covering month-end close while Priya is away.')

  fireEvent.change(screen.getByPlaceholderText(/Agreed with their manager/), {
    target: { value: 'Fine until the close' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Approve' }))

  await waitFor(() => expect(approveBodies).toHaveLength(1))
  expect(approveBodies[0]).toMatchObject({ note: 'Fine until the close' })
})

test('approving with no end date says the access is permanent', async () => {
  renderPage()
  await screen.findByText('Covering month-end close while Priya is away.')

  expect(screen.getByText(/access is permanent/)).toBeInTheDocument()
})

test('an approver can deny', async () => {
  renderPage()
  await screen.findByText('Covering month-end close while Priya is away.')

  fireEvent.click(screen.getByRole('button', { name: 'Deny' }))

  await waitFor(() => expect(denyCalls).toBe(1))
})

test('your own request offers no decide buttons, and says why', async () => {
  renderPage()

  // The queue and "what you asked for" load from separate queries, so wait for
  // the queue's card before counting buttons or this races it.
  await screen.findByText('Covering month-end close while Priya is away.')
  expect(screen.getByText(/you can't decide it/i)).toBeInTheDocument()

  // The only Approve button on screen belongs to somebody else's request.
  expect(screen.getAllByRole('button', { name: 'Approve' })).toHaveLength(1)
})

test('you can withdraw your own', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Withdraw it' }))

  await waitFor(() => expect(withdrawCalls).toBe(1))
})

test('an employee sees no queue but can still ask', async () => {
  stubApi({ permissions: [], queue: [], mine: [] })
  renderPage()

  expect(await screen.findByRole('button', { name: 'Ask for access' })).toBeInTheDocument()
  expect(screen.queryByText(/Waiting for a decision/)).not.toBeInTheDocument()
})

test('asking sends the group and the reason', async () => {
  stubApi({ permissions: [], queue: [], mine: [] })
  renderPage()
  // Wait for the group option itself, not just the form. The groups load from
  // their own query, and firing a change for a value whose <option> does not exist
  // yet leaves the select empty and the submit button disabled.
  await screen.findByRole('option', { name: 'Finance' })

  fireEvent.change(screen.getByRole('combobox'), { target: { value: GROUP_ID } })
  fireEvent.change(screen.getByPlaceholderText(/Covering month-end close/), {
    target: { value: 'I need it for the audit' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Ask for access' }))

  await waitFor(() => expect(askBodies).toHaveLength(1))
  expect(askBodies[0]).toMatchObject({ group_id: GROUP_ID, reason: 'I need it for the audit' })
})

test('a decided request shows who decided and when', async () => {
  stubApi({
    queue: [],
    mine: [
      {
        ...MY_REQUEST,
        state: 'approved',
        is_open: false,
        decided_by_label: 'Priya Nair <priya@demo.local>',
        decided_at: '2026-08-18T10:00:00Z',
        decision_note: 'Agreed for the weekend',
        expires_at: '2026-08-24T23:59:59Z',
      },
    ],
  })
  renderPage()

  expect(await screen.findByText(/approved by Priya Nair/)).toBeInTheDocument()
  expect(screen.getByText(/Agreed for the weekend/)).toBeInTheDocument()
  expect(screen.getByText(/access ends/)).toBeInTheDocument()
})

test('a cancelled request explains itself rather than just saying cancelled', async () => {
  stubApi({
    queue: [],
    mine: [
      {
        ...MY_REQUEST,
        state: 'cancelled',
        is_open: false,
        decided_at: '2026-08-18T10:00:00Z',
        decision_note: 'The person who asked was deactivated.',
      },
    ],
  })
  renderPage()

  expect(await screen.findByText(/was deactivated/)).toBeInTheDocument()
})
