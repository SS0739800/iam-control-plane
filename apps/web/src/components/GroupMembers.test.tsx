/**
 * Tests for group membership.
 *
 * The group page listed members and offered no way to change them, which left the
 * scalable half of the entitlement model half-built: an application can be granted to
 * a group, but nobody could be put in the group. So the console could grant access
 * broadly and only take it away one person at a time.
 *
 * What these mostly guard is the searching. The other pickers in this codebase load
 * two hundred people into a dropdown, and the seeded directory has more than a
 * thousand — so most of the company is silently unselectable, which looks like
 * somebody having left rather than a truncated list. This one searches instead, and
 * the tests check it does not offer people who are already in the group, because
 * adding somebody twice is the mistake the list would otherwise invite.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { type GroupDetail } from '../lib/api'
import GroupMembers from './GroupMembers'

const ADA = { id: 'user-1', display_name: 'Ada Bergman', user_name: 'ada@demo.local', active: true }
const OMAR = {
  id: 'user-2',
  display_name: 'Omar Haddad',
  user_name: 'omar@demo.local',
  active: false,
}

const GROUP = {
  id: 'group-1',
  name: 'Engineering',
  description: 'Everybody in engineering',
  hrms_role: null,
  external_id: null,
  source: 'scim',
  member_count: 2,
  members: [ADA, OMAR],
  applications: [],
  created_at: '2026-08-01T09:00:00Z',
  updated_at: '2026-08-20T09:00:00Z',
} as unknown as GroupDetail

/** Somebody the search can find who is not already a member. */
const NADIA = {
  id: 'user-3',
  display_name: 'Nadia Okonkwo',
  user_name: 'nadia@demo.local',
  active: true,
  department: null,
  job_title: null,
  platform_role: 'employee',
  source: 'manual',
}

let calls: { method: string; url: string }[] = []

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

/**
 * `found` is deliberately loose. The search returns UserSummary rows, but the
 * members on a group are the thinner MemberRef shape, and one test hands a member
 * back from the search to check they are not offered twice. Typing this to either
 * shape would make that test unwritable for a reason that has nothing to do with
 * the behaviour.
 */
function stubApi(found: Record<string, unknown>[] = [NADIA]): void {
  calls = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = urlOf(input)
      const method = methodOf(input, init)
      calls.push({ method, url })

      if (url.includes('/api/users')) {
        return jsonResponse({ items: found, total: found.length, limit: 10, offset: 0 })
      }
      // PUT and DELETE on the membership route answer 204 with no body.
      return new Response(null, { status: 204 })
    }),
  )
}

function renderMembers(group: GroupDetail = GROUP, canWrite = true) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <GroupMembers group={group} canWrite={canWrite} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => stubApi())
afterEach(() => vi.unstubAllGlobals())

// ------------------------------------------------------------------ listing

test('it lists the members', () => {
  renderMembers()

  expect(screen.getByText('Ada Bergman')).toBeInTheDocument()
  expect(screen.getByText('Omar Haddad')).toBeInTheDocument()
})

test('a deactivated member is marked as such', () => {
  renderMembers()

  expect(screen.getByText('deactivated')).toBeInTheDocument()
})

test('the count comes from the server, not from the rows shown', () => {
  renderMembers({ ...GROUP, member_count: 1284 } as GroupDetail)

  // Two rows, 1,284 members: the page must say the larger number rather than implying
  // the group is small because the list is.
  expect(screen.getByText(/Members \(1,284\)/)).toBeInTheDocument()
  expect(screen.getByText(/Showing the first 2 of 1,284/)).toBeInTheDocument()
})

// ------------------------------------------------------------------ adding

test('it searches rather than listing everybody', async () => {
  renderMembers()

  fireEvent.change(screen.getByRole('textbox', { name: /Add somebody/ }), {
    target: { value: 'nad' },
  })

  expect(await screen.findByText('Nadia Okonkwo')).toBeInTheDocument()
  expect(calls.some((c) => c.url.includes('q=nad'))).toBe(true)
})

test('it does not search on one character', () => {
  renderMembers()

  fireEvent.change(screen.getByRole('textbox', { name: /Add somebody/ }), {
    target: { value: 'n' },
  })

  expect(calls.some((c) => c.url.includes('/api/users'))).toBe(false)
})

test('somebody already in the group is not offered again', async () => {
  stubApi([NADIA, ADA])
  renderMembers()

  fireEvent.change(screen.getByRole('textbox', { name: /Add somebody/ }), {
    target: { value: 'a' + 'da' },
  })

  await screen.findByText('Nadia Okonkwo')
  // Ada appears once — as a member — and not a second time as a candidate.
  expect(screen.getAllByText('Ada Bergman')).toHaveLength(1)
})

test('adding somebody sends a PUT', async () => {
  renderMembers()

  fireEvent.change(screen.getByRole('textbox', { name: /Add somebody/ }), {
    target: { value: 'nad' },
  })
  fireEvent.click(await screen.findByRole('button', { name: 'Add' }))

  await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true))
  const put = calls.find((c) => c.method === 'PUT')
  expect(put?.url).toContain('/groups/group-1')
})

test('it says a hand-added member survives the rules engine', () => {
  renderMembers()

  // The provenance point: group_members.source is what stops a reconciler tidying
  // away somebody a person deliberately added.
  expect(screen.getByText(/will\s+not remove them/)).toBeInTheDocument()
})

// ---------------------------------------------------------------- removing

test('removing asks first and names the group', async () => {
  renderMembers()

  fireEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0]!)

  expect(await screen.findByText(/Take Ada Bergman out of Engineering/)).toBeInTheDocument()
  expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
})

test('cancelling a removal changes nothing', async () => {
  renderMembers()

  fireEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0]!)
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))

  expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
})

test('confirming sends a DELETE', async () => {
  renderMembers()

  fireEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0]!)
  fireEvent.click(await screen.findByRole('button', { name: 'Yes, remove' }))

  await waitFor(() => expect(calls.some((c) => c.method === 'DELETE')).toBe(true))
})

// -------------------------------------------------------------- permissions

test('without groups:write there are no controls at all', () => {
  renderMembers(GROUP, false)

  expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument()
  expect(screen.queryByRole('textbox', { name: /Add somebody/ })).not.toBeInTheDocument()
  // But the list is still readable, which is the point of separating the two.
  expect(screen.getByText('Ada Bergman')).toBeInTheDocument()
})
