/**
 * Tests for the leaver control.
 *
 * This is the most consequential button in the console: it takes away every access a
 * person has, and it is what makes their accounts switch off in systems we do not
 * own. So the tests are mostly about the things that would make it dangerous rather
 * than the happy path.
 *
 * Two of them matter more than the rest.
 *
 * It must ask first, and the confirmation must say what will actually happen. A
 * one-click offboarding sitting on a page somebody opens to read a phone number is a
 * mis-click away from locking a colleague out of everything.
 *
 * And it must not claim the downstream work is done. Deactivating marks somebody as
 * having left here; their accounts elsewhere switch off on the next provisioning
 * sync. A panel that implied otherwise would have somebody believe a leaver is locked
 * out everywhere when they are not, which is worse than saying nothing.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { type UserDetail } from '../lib/api'
import LeaverPanel from './LeaverPanel'

const ACTIVE = {
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  user_name: 'nadia.okonkwo@demo.local',
  display_name: 'Nadia Okonkwo',
  email: 'nadia.okonkwo@demo.local',
  active: true,
  department: 'People Operations',
  job_title: 'Analyst',
  employee_number: 'E-1042',
  external_id: null,
  family_name: 'Okonkwo',
  given_name: 'Nadia',
  manager: null,
  platform_role: 'employee',
  source: 'manual',
  created_at: '2026-08-01T09:00:00Z',
  updated_at: '2026-08-20T09:00:00Z',
  groups: [],
  applications: [
    { id: 'app-1', name: 'HRMS', slug: 'hrms', role: null, via: 'group' },
    { id: 'app-2', name: 'Slack', slug: 'slack', role: null, via: 'direct' },
  ],
} as unknown as UserDetail

const LEFT = { ...ACTIVE, active: false } as UserDetail
const FROM_PROVIDER = { ...ACTIVE, source: 'scim' } as UserDetail

let patches: { body: unknown }[] = []

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/**
 * The method and body live on the Request, not on init.
 *
 * lib/api.ts builds the client with `fetch: (request) => globalThis.fetch(request)`,
 * so openapi-fetch hands over a single Request object and the second argument is
 * undefined. Reading `init.body` gets you `undefined` and a mock that records
 * nothing — which looks exactly like the component never firing.
 */
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

function stubApi(failWith?: number): void {
  patches = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (methodOf(input, init) === 'PATCH') {
        patches.push({ body: await bodyOf(input, init) })
        if (failWith) {
          return jsonResponse({ detail: 'that field is managed by the provider' }, failWith)
        }
        return jsonResponse(ACTIVE)
      }
      return jsonResponse({})
    }),
  )
}

function renderPanel(person: UserDetail = ACTIVE, canWrite = true) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <LeaverPanel person={person} canWrite={canWrite} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => stubApi())
afterEach(() => vi.unstubAllGlobals())

// ------------------------------------------------------------ asking first

test('it asks before marking somebody as having left', () => {
  renderPanel()

  fireEvent.click(screen.getByRole('button', { name: 'Mark as having left' }))

  // The confirm button appears and nothing has been sent yet. Matching on a role and
  // an exact name rather than loose text: /Mark/ matches both the opening button and
  // the confirmation sentence, and getByText throws on two hits.
  expect(screen.getByRole('button', { name: 'Yes, they have left' })).toBeInTheDocument()
  expect(patches).toHaveLength(0)
})

test('the confirmation names the person and counts what they lose', () => {
  renderPanel()

  fireEvent.click(screen.getByRole('button', { name: 'Mark as having left' }))

  // Not a generic "are you sure" — the two facts somebody needs to catch a mis-click.
  expect(screen.getByText('Nadia Okonkwo')).toBeInTheDocument()
  expect(screen.getByText(/2 applications/)).toBeInTheDocument()
})

test('cancelling changes nothing', () => {
  renderPanel()

  fireEvent.click(screen.getByRole('button', { name: 'Mark as having left' }))
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

  expect(patches).toHaveLength(0)
  expect(screen.getByRole('button', { name: 'Mark as having left' })).toBeInTheDocument()
})

test('confirming sends active false', async () => {
  renderPanel()

  fireEvent.click(screen.getByRole('button', { name: 'Mark as having left' }))
  fireEvent.click(screen.getByRole('button', { name: 'Yes, they have left' }))

  await waitFor(() => expect(patches).toHaveLength(1))
  expect(patches[0]?.body).toEqual({ active: false })
})

// ------------------------------------------- not overclaiming what happened

test('it says downstream accounts switch off on the next sync, not now', () => {
  renderPanel()

  fireEvent.click(screen.getByRole('button', { name: 'Mark as having left' }))

  // The dangerous lie would be implying a leaver is already locked out everywhere.
  expect(screen.getByText(/next provisioning sync, not now/)).toBeInTheDocument()
})

test('it says nothing is deleted', () => {
  renderPanel()

  expect(screen.getByText(/Nothing is deleted/)).toBeInTheDocument()
})

// ------------------------------------------------------------- coming back

test('somebody who has left is offered a way back', () => {
  renderPanel(LEFT)

  expect(screen.getByRole('button', { name: 'Bring them back' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Mark as having left' })).not.toBeInTheDocument()
})

test('bringing them back sends active true, and does not ask first', async () => {
  renderPanel(LEFT)

  fireEvent.click(screen.getByRole('button', { name: 'Bring them back' }))

  // No confirmation: restoring access is reversible by the button that was just there,
  // and the asymmetry is deliberate.
  await waitFor(() => expect(patches).toHaveLength(1))
  expect(patches[0]?.body).toEqual({ active: true })
})

test('a rehire is told they keep their old downstream account', () => {
  renderPanel(LEFT)

  expect(screen.getByText(/old account switched back on rather than a/)).toBeInTheDocument()
})

// --------------------------------------------------------------- the edges

test('somebody without users:write gets no panel at all', () => {
  const { container } = renderPanel(ACTIVE, false)

  expect(container).toBeEmptyDOMElement()
})

test('a provider-managed person carries a warning that the sync can undo it', () => {
  renderPanel(FROM_PROVIDER)

  // Deactivating somebody the provider still sends is not the end of it, and a console
  // that let you believe otherwise would be setting up a nasty surprise.
  expect(screen.getByText(/Removing them at the provider is what makes it stick/))
    .toBeInTheDocument()
})

test('a locally created person carries no such warning', () => {
  renderPanel(ACTIVE)

  expect(screen.queryByText(/Removing them at the provider/)).not.toBeInTheDocument()
})

test('a refusal is shown rather than swallowed', async () => {
  stubApi(409)
  renderPanel()

  fireEvent.click(screen.getByRole('button', { name: 'Mark as having left' }))
  fireEvent.click(screen.getByRole('button', { name: 'Yes, they have left' }))

  await waitFor(() =>
    expect(screen.getByText(/managed by the provider/)).toBeInTheDocument(),
  )
})
