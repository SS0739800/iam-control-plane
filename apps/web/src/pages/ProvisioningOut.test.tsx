/**
 * Tests for the outbound provisioning screen.
 *
 * Two things here are worth guarding rather than eyeballing.
 *
 * The orphan warning: an orphan is somebody we could not remove from a downstream, so
 * they still have access there and nobody would know. It is the only number on the page
 * that means somebody has to go and do something, and a page that shows it as one figure
 * among five is a page that hides it.
 *
 * The delete confirmation: "stop provisioning" sounds like it removes access, and it
 * does the opposite — everybody keeps their downstream account, we just stop touching
 * it. If the confirmation ever stops saying that, somebody will use this button to
 * offboard a system and leave every account live.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { type ProvisioningTarget } from '../lib/api'
import ProvisioningOutPage from './ProvisioningOut'

// Typed, so a nullable field in the schema stays nullable here. Without the
// annotation the literal narrows to a non-null type and every variant below is a
// type error instead of a test.
const HEALTHY: ProvisioningTarget = {
  id: '33333333-3333-3333-3333-333333333333',
  application_id: '44444444-4444-4444-4444-444444444444',
  application_name: 'HRMS',
  application_slug: 'hrms',
  base_url: 'http://hrms:8000/scim/v2',
  enabled: true,
  address_concession: 'plain HTTP, which is only allowed outside production',
  last_sync_at: '2026-08-20T01:12:00Z',
  last_sync_ok: true,
  last_error: null,
  created_at: '2026-08-20T01:00:00Z',
  updated_at: '2026-08-20T01:12:00Z',
  accounts_active: 1199,
  accounts_pending: 0,
  accounts_failed: 0,
  accounts_orphaned: 0,
  accounts_deprovisioned: 3,
  accounts_waiting_to_push: 0,
}

const WITH_ORPHANS: ProvisioningTarget = {
  ...HEALTHY,
  id: '55555555-5555-5555-5555-555555555555',
  application_name: 'Payroll',
  application_slug: 'payroll',
  base_url: 'https://payroll.example.test/scim/v2',
  address_concession: null,
  accounts_active: 40,
  accounts_failed: 2,
  accounts_orphaned: 2,
}

const LINKS = [
  {
    user_id: '66666666-6666-6666-6666-666666666666',
    user_name: 'ada.dlamini2@demo.local',
    display_name: 'Ada Dlamini',
    active: true,
    remote_id: 'a47e0f01',
    state: 'active',
    last_pushed_at: '2026-08-20T01:12:00Z',
    last_error: null,
    attempts: 0,
  },
  {
    user_id: '77777777-7777-7777-7777-777777777777',
    user_name: 'omar.haddad@demo.local',
    display_name: 'Omar Haddad',
    active: false,
    remote_id: 'b91d2c03',
    state: 'orphaned',
    last_pushed_at: '2026-08-19T22:04:00Z',
    last_error: 'the downstream returned 500',
    attempts: 5,
  },
]

const RUN = {
  correlation_id: '88888888-8888-8888-8888-888888888888',
  created: 2,
  adopted: 1,
  updated: 0,
  deactivated: 1,
  reactivated: 0,
  unchanged: 1195,
  failed: 0,
  skipped_exhausted: 0,
  stopped_early: null,
  ok: true,
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

let deleteCalls = 0
let syncCalls: string[] = []
let targets: ProvisioningTarget[] = [HEALTHY]

function stubApi(): void {
  deleteCalls = 0
  syncCalls = []
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = urlOf(input)
      const method = init?.method ?? (input instanceof Request ? input.method : 'GET')

      if (method === 'DELETE') {
        deleteCalls += 1
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      if (url.includes('/sync')) {
        syncCalls.push(url)
        return Promise.resolve(jsonResponse(RUN))
      }
      if (url.includes('/probe')) {
        return Promise.resolve(
          jsonResponse({ reachable: true, detail: 'http://hrms:8000/docs' }),
        )
      }
      if (url.includes('/accounts')) return Promise.resolve(jsonResponse(LINKS))
      if (url.includes('/api/provisioning/targets')) return Promise.resolve(jsonResponse(targets))
      if (url.includes('/api/applications')) {
        return Promise.resolve(
          jsonResponse({
            items: [
              {
                id: HEALTHY.application_id,
                name: 'HRMS',
                slug: 'hrms',
                description: null,
                protocol: 'scim2',
                status: 'active',
                assignment_count: 12,
              },
            ],
            total: 1,
            limit: 200,
            offset: 0,
          }),
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
        <ProvisioningOutPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  targets = [HEALTHY]
  stubApi()
})
afterEach(() => vi.unstubAllGlobals())

test('lists a target with its counts', async () => {
  renderPage()

  expect(await screen.findByText('HRMS')).toBeInTheDocument()
  expect(screen.getByText('http://hrms:8000/scim/v2')).toBeInTheDocument()
  expect(screen.getByText('1,199')).toBeInTheDocument()
  expect(screen.getByText('in step')).toBeInTheDocument()
})

test('says when an address was allowed by relaxing a rule', async () => {
  renderPage()

  expect(await screen.findByText(/plain HTTP, which is only allowed outside production/))
    .toBeInTheDocument()
})

test('orphans get said out loud, not just counted', async () => {
  targets = [WITH_ORPHANS]
  renderPage()

  expect(await screen.findByText('orphans')).toBeInTheDocument()
  // The sentence, not the number. Somebody has to know what to do about it.
  expect(screen.getByText(/still.*have access there and we could not remove it/s))
    .toBeInTheDocument()
})

test('a target with nothing wrong shows no orphan warning', async () => {
  renderPage()
  await screen.findByText('HRMS')

  expect(screen.queryByText(/could not remove it/)).not.toBeInTheDocument()
})

test('a sync says what it did, in words', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Sync now' }))

  expect(await screen.findByText(/2 created/)).toBeInTheDocument()
  expect(screen.getByText(/1 already existed and were linked/)).toBeInTheDocument()
  expect(screen.getByText(/1 switched off/)).toBeInTheDocument()
})

test('the retry-the-given-up button only appears when something has failed', async () => {
  renderPage()
  await screen.findByText('HRMS')
  expect(screen.queryByRole('button', { name: /Retry the given-up/ })).not.toBeInTheDocument()
})

test('the forced retry passes force through', async () => {
  targets = [WITH_ORPHANS]
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: /Retry the given-up/ }))

  await waitFor(() => expect(syncCalls).toHaveLength(1))
  expect(syncCalls[0]).toContain('force=true')
})

test('the accounts list puts the worst rows first', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Show accounts' }))

  const rows = await screen.findAllByRole('row')
  // Header, then the orphan, then the healthy one.
  expect(rows[1]?.textContent).toContain('Omar Haddad')
  expect(rows[2]?.textContent).toContain('Ada Dlamini')
})

test('an account we could not remove shows why and how many tries', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Show accounts' }))

  expect(await screen.findByText(/the downstream returned 500/)).toBeInTheDocument()
  expect(screen.getByText(/5 tries/)).toBeInTheDocument()
})

test('stopping provisioning asks first, and says what it does not do', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Stop provisioning' }))

  // The whole point of the confirmation: this is not offboarding.
  expect(screen.getByText(/Nobody loses their account at the other end/)).toBeInTheDocument()
  expect(deleteCalls).toBe(0)
})

test('cancelling leaves the target alone', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Stop provisioning' }))
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

  expect(deleteCalls).toBe(0)
  expect(screen.getByRole('button', { name: 'Stop provisioning' })).toBeInTheDocument()
})

test('confirming actually removes it', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Stop provisioning' }))
  fireEvent.click(screen.getByRole('button', { name: 'Yes, stop' }))

  await waitFor(() => expect(deleteCalls).toBe(1))
})

test('the token field is never a text input', async () => {
  renderPage()
  await screen.findByText('HRMS')

  fireEvent.click(screen.getByRole('button', { name: 'Replace token' }))

  const field = screen.getByLabelText('New token for HRMS')
  // Not a readback — there is nothing to read back — but a value on screen in a
  // shared-screen demo is a value leaked.
  expect(field).toHaveAttribute('type', 'password')
})

test('a paused target cannot be synced', async () => {
  targets = [{ ...HEALTHY, enabled: false }]
  renderPage()

  expect(await screen.findByText('paused')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Sync now' })).toBeDisabled()
})

test('a target nobody has ever synced says so', async () => {
  targets = [{ ...HEALTHY, last_sync_at: null, last_sync_ok: null, accounts_active: 0 }]
  renderPage()

  // Not the same as healthy, and the more interesting case: registered and forgotten.
  expect(await screen.findByText('never synced')).toBeInTheDocument()
})

test('nothing registered yet says what to do about it', async () => {
  targets = []
  renderPage()

  expect(await screen.findByText(/Nothing is being provisioned outward yet/)).toBeInTheDocument()
})


// ------------------------------------------- work that has not been pushed yet

test('a target with changes waiting does not claim to be in step', async () => {
  targets = [{ ...HEALTHY, accounts_waiting_to_push: 1 }]
  renderPage()

  // The bug this replaced: a leaver was marked in the console, the sync had run
  // twenty-eight seconds earlier, and the panel said "in step" while the downstream
  // still had them switched on.
  expect(await screen.findByText('changes waiting')).toBeInTheDocument()
  expect(screen.queryByText('in step')).not.toBeInTheDocument()
})

test('it says what waiting means, and that nothing pushes on its own', async () => {
  targets = [{ ...HEALTHY, accounts_waiting_to_push: 2 }]
  renderPage()

  expect(await screen.findByText(/2 people have changes this system has not been told about/))
    .toBeInTheDocument()
  expect(screen.getByText(/Nothing\s+pushes on its own/)).toBeInTheDocument()
})

test('one person waiting reads as one person', async () => {
  targets = [{ ...HEALTHY, accounts_waiting_to_push: 1 }]
  renderPage()

  expect(await screen.findByText(/1 person has changes/)).toBeInTheDocument()
})

test('nothing waiting shows no warning at all', async () => {
  renderPage()
  await screen.findByText('HRMS')

  expect(screen.queryByText(/has not been told about/)).not.toBeInTheDocument()
  expect(screen.getByText('in step')).toBeInTheDocument()
})

test('a failure still outranks waiting work', async () => {
  // Work waiting is ordinary; work that failed needs somebody. If both are true the
  // panel should say the one that needs a person.
  targets = [{ ...HEALTHY, accounts_failed: 1, accounts_waiting_to_push: 3 }]
  renderPage()

  expect(await screen.findByText('some failures')).toBeInTheDocument()
})

test('orphans still outrank everything', async () => {
  targets = [{ ...HEALTHY, accounts_orphaned: 1, accounts_waiting_to_push: 3 }]
  renderPage()

  expect(await screen.findByText('orphans')).toBeInTheDocument()
})
