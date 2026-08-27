/**
 * Tests for the SAML side of an application's page.
 *
 * The claims worth holding:
 *
 * An application that is not wired up says so, rather than offering a sign-in link
 * that would be refused. "No entity ID" is a fixable sentence; a 404 from a launch
 * button is not.
 *
 * Removing access asks first — same lesson as the provisioning tokens, and for the
 * same reason: it takes something away from a real person.
 *
 * Somebody without apps:write gets no controls at all. The API enforces it; a form
 * that always fails is its own kind of bug.
 *
 * A group grant says out loud that it reaches more than one person, because that is
 * the difference between the two options nobody reads the docs for.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { ApplicationAccessPanels, ApplicationSamlPanels } from './ApplicationSamlPanels'

const APP_ID = 'app-0000-0000-0000-000000000001'
const GROUP_ID = 'grp-0000-0000-0000-000000000002'
const USER_ID = 'usr-0000-0000-0000-000000000003'

const WIRED = {
  id: APP_ID,
  name: 'Expenses',
  slug: 'expenses',
  description: 'Expense claims',
  protocol: 'saml2',
  status: 'active',
  assignment_count: 2,
  entity_id: 'https://expenses.demo.local/saml/metadata',
  acs_url: 'https://expenses.demo.local/saml/acs',
  slo_url: 'https://expenses.demo.local/saml/slo',
  nameid_format: null,
  signing_cert: null,
  created_at: '2026-08-19T09:00:00Z',
  updated_at: '2026-08-19T09:00:00Z',
  assigned_groups: [{ id: GROUP_ID, name: 'Finance', hrms_role: 'Finance' }],
  assigned_users: [
    {
      id: USER_ID,
      user_name: 'ada@demo.local',
      display_name: 'Ada Bergman',
      active: true,
    },
  ],
}

const NOT_WIRED = { ...WIRED, entity_id: null, acs_url: null }

let removedUsers: string[] = []
let removedGroups: string[] = []
let grants: string[] = []

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

function stubApi(): void {
  removedUsers = []
  removedGroups = []
  grants = []

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = urlOf(input)
      const method = methodOf(input, init)

      if (url.includes('/users/') && method === 'DELETE') {
        removedUsers.push(url)
        return new Response(null, { status: 204 })
      }
      if (url.includes('/groups/') && method === 'DELETE') {
        removedGroups.push(url)
        return new Response(null, { status: 204 })
      }
      if (method === 'PUT') {
        grants.push(url)
        return new Response(null, { status: 204 })
      }
      if (url.includes('/api/groups')) {
        return jsonResponse({
          items: [{ id: GROUP_ID, name: 'Finance', member_count: 4 }],
          total: 1,
          limit: 200,
          offset: 0,
        })
      }
      if (url.includes('/api/users')) {
        return jsonResponse({
          items: [
            {
              id: USER_ID,
              user_name: 'ada@demo.local',
              display_name: 'Ada Bergman',
              active: true,
              platform_role: 'employee',
              source: 'scim',
            },
          ],
          total: 1,
          limit: 200,
          offset: 0,
        })
      }
      return jsonResponse({ detail: `unexpected ${method} ${url}` }, 404)
    }),
  )
}

type App = Parameters<typeof ApplicationSamlPanels>[0]['app']

function wrap(children: React.ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>,
  )
}

/** The SAML wiring panel. Read-only, so it takes no canWrite. */
function renderPanels(app: unknown = WIRED) {
  // The component takes the already-fetched application, so no fetch is needed here.
  return wrap(<ApplicationSamlPanels app={app as App} />)
}

/**
 * The access panels, which used to be part of the component above.
 *
 * They were split out because rendering them behind `protocol === 'saml2'` meant an
 * application we only provision into had no way to grant anybody access. These tests
 * came with them unchanged — the behaviour did not move, only where it is shown.
 */
function renderAccess(app: unknown = WIRED, canWrite = true) {
  return wrap(<ApplicationAccessPanels app={app as App} canWrite={canWrite} />)
}

/**
 * Indexed access into a query result is possibly-undefined under the strict
 * settings this project uses, so this asserts presence rather than using `!`. A
 * missing element should fail with "no combobox at 1", not with a null dereference
 * several lines later.
 */
function at<T>(items: T[], index: number, what: string): T {
  const found = items[index]
  if (found === undefined) throw new Error(`no ${what} at index ${index}`)
  return found
}

beforeEach(stubApi)
afterEach(() => vi.unstubAllGlobals())

test('a wired application shows what a login actually reads', () => {
  renderPanels()

  expect(screen.getByText('https://expenses.demo.local/saml/metadata')).toBeInTheDocument()
  expect(screen.getByText('https://expenses.demo.local/saml/acs')).toBeInTheDocument()
})

test('a wired application offers a sign-in link', () => {
  renderPanels()

  const link = screen.getByRole('link', { name: 'Sign in to it' })
  expect(link).toHaveAttribute('href', expect.stringContaining('/idp/sso/expenses'))
})

test('the sign-in link says the assertion is real even when nothing receives it', () => {
  renderPanels()

  expect(screen.getByText(/does not resolve/)).toBeInTheDocument()
  expect(screen.getByText(/audit log and the sign-in inspector/)).toBeInTheDocument()
})

test('an application that is not wired up says what is missing', () => {
  renderPanels(NOT_WIRED)

  expect(screen.getByText(/no entity ID and no login response URL/)).toBeInTheDocument()
})

test('an application that is not wired up offers no sign-in link', () => {
  renderPanels(NOT_WIRED)

  expect(screen.queryByRole('link', { name: 'Sign in to it' })).not.toBeInTheDocument()
})

test('somebody without apps:write gets no controls', () => {
  renderAccess(WIRED, false)

  expect(screen.queryAllByRole('button', { name: 'Remove' })).toHaveLength(0)
  expect(screen.queryByRole('button', { name: 'Give access' })).not.toBeInTheDocument()
})

test('removing access asks first', () => {
  renderAccess()

  fireEvent.click(at(screen.getAllByRole('button', { name: 'Remove' }), 0, 'Remove button'))

  expect(screen.getByText(/Take away/)).toBeInTheDocument()
  expect(removedGroups).toHaveLength(0)
  expect(removedUsers).toHaveLength(0)
})

test('cancelling a removal does nothing', () => {
  renderAccess()

  fireEvent.click(at(screen.getAllByRole('button', { name: 'Remove' }), 0, 'Remove button'))
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

  expect(removedGroups).toHaveLength(0)
  expect(removedUsers).toHaveLength(0)
})

test('confirming a group removal sends it', async () => {
  renderAccess()

  fireEvent.click(at(screen.getAllByRole('button', { name: 'Remove' }), 0, 'Remove button'))
  fireEvent.click(screen.getByRole('button', { name: 'Yes, remove it' }))

  await waitFor(() => expect(removedGroups).toHaveLength(1))
  expect(removedGroups[0]).toContain(GROUP_ID)
})

test('granting to a group warns that it reaches more than one person', () => {
  renderAccess()

  expect(screen.getByText(/everybody in it now and everybody added to it later/)).toBeInTheDocument()
})

test('granting to one person drops that warning', () => {
  renderAccess()

  // The grant form's first select chooses between a group and one person.
  const kind = at(screen.getAllByRole('combobox'), 0, 'combobox')
  fireEvent.change(kind, { target: { value: 'user' } })

  expect(
    screen.queryByText(/everybody in it now and everybody added to it later/),
  ).not.toBeInTheDocument()
})

test('granting sends the chosen subject', async () => {
  renderAccess()

  await screen.findByRole('option', { name: 'Finance' })
  const subject = at(screen.getAllByRole('combobox'), 1, 'combobox')
  fireEvent.change(subject, { target: { value: GROUP_ID } })
  fireEvent.click(screen.getByRole('button', { name: 'Give access' }))

  await waitFor(() => expect(grants).toHaveLength(1))
  expect(grants[0]).toContain(GROUP_ID)
})

test('a deactivated person with access is marked', () => {
  renderAccess({
    ...WIRED,
    assigned_users: [{ ...WIRED.assigned_users[0], active: false }],
  })

  expect(screen.getByText('deactivated')).toBeInTheDocument()
})
