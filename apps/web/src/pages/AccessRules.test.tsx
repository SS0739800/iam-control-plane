/**
 * Tests for the access rules screen.
 *
 * The ones that matter are about the preview gate. A rule quietly grants access to
 * an unknown number of people and a mistyped value is perfectly valid, so the only
 * protection is making somebody look at the count first. These check that the
 * first click previews rather than saves, that editing a field invalidates a
 * preview somebody already saw, and that a big blast radius is called out.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import AccessRulesPage from './AccessRules'

const GROUP_ID = '22222222-2222-2222-2222-222222222222'

const RULE = {
  id: '11111111-1111-1111-1111-111111111111',
  name: 'Engineering staff',
  description: null,
  enabled: true,
  attribute: 'department',
  operator: 'equals',
  value: 'Engineering',
  group_id: GROUP_ID,
  group_name: 'Engineering',
  sentence: "Department is 'Engineering'",
  member_count: 12,
  created_by_label: 'Platform Admin <admin@demo.local>',
  created_at: '2026-08-17T09:00:00Z',
  updated_at: '2026-08-17T09:00:00Z',
}

let previewCalls = 0
let createCalls = 0
let deleteCalls = 0
let patchBodies: unknown[] = []
let previewMatches = 3

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

function stubApi(rules: unknown[] = [RULE], permissions: string[] = ['groups:write']): void {
  previewCalls = 0
  createCalls = 0
  deleteCalls = 0
  patchBodies = []

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = urlOf(input)
      const method = methodOf(input, init)

      if (url.includes('/access-rules/preview')) {
        previewCalls += 1
        return jsonResponse({
          sentence: "Department is 'Engineering'",
          group_name: 'Engineering',
          matches: previewMatches,
          already_in_group: 1,
          would_be_added: previewMatches - 1,
          sample: [
            {
              id: 'aaa',
              user_name: 'ada@demo.local',
              display_name: 'Ada Bergman',
              department: 'Engineering',
              job_title: 'Engineer',
            },
          ],
        })
      }
      if (url.includes('/access-rules/attributes')) {
        return jsonResponse([
          { name: 'department', label: 'Department' },
          { name: 'job_title', label: 'Job title' },
        ])
      }
      if (url.match(/\/access-rules\/[^/]+$/) && method === 'PATCH') {
        patchBodies.push(await bodyOf(input, init))
        return jsonResponse({ ...RULE, enabled: false })
      }
      if (url.match(/\/access-rules\/[^/]+$/) && method === 'DELETE') {
        deleteCalls += 1
        return jsonResponse({ added: [], removed: ['ada@demo.local -> Engineering'], unchanged: false })
      }
      if (url.includes('/access-rules') && method === 'POST') {
        createCalls += 1
        return jsonResponse(RULE, 201)
      }
      if (url.includes('/access-rules')) return jsonResponse(rules)
      if (url.includes('/api/groups')) {
        return jsonResponse({
          items: [{ id: GROUP_ID, name: 'Engineering', member_count: 12 }],
          total: 1,
          limit: 200,
          offset: 0,
        })
      }
      if (url.includes('/api/me')) {
        return jsonResponse({
          id: 'me',
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
        <AccessRulesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** Indexing into getAllByRole is not type-safe on its own, and a silently
 * undefined element would make a test pass for the wrong reason. */
function nth(elements: HTMLElement[], index: number): HTMLElement {
  const found = elements.at(index)
  if (!found) throw new Error(`expected an element at index ${index}, found ${elements.length}`)
  return found
}

async function fillForm() {
  fireEvent.change(await screen.findByPlaceholderText(/Engineering staff get/), {
    target: { value: 'A new rule' },
  })
  fireEvent.change(screen.getByPlaceholderText('Engineering'), {
    target: { value: 'Engineering' },
  })
  const selects = screen.getAllByRole('combobox')
  fireEvent.change(nth(selects, -1), { target: { value: GROUP_ID } })
}

beforeEach(() => {
  previewMatches = 3
  stubApi()
})
afterEach(() => vi.unstubAllGlobals())

test('shows rules as sentences, not as three fields', async () => {
  renderPage()

  expect(await screen.findByText("Department is 'Engineering'")).toBeInTheDocument()
  expect(screen.getByText('Engineering staff')).toBeInTheDocument()
})

test('the first click previews and saves nothing', async () => {
  renderPage()
  await fillForm()

  fireEvent.click(screen.getByRole('button', { name: 'See who this affects' }))

  await waitFor(() => expect(previewCalls).toBe(1))
  expect(createCalls).toBe(0)
})

test('saving is only offered after a preview', async () => {
  renderPage()
  await fillForm()

  expect(screen.queryByRole('button', { name: 'Save this rule' })).not.toBeInTheDocument()

  fireEvent.click(screen.getByRole('button', { name: 'See who this affects' }))

  expect(await screen.findByRole('button', { name: 'Save this rule' })).toBeInTheDocument()
})

test('the preview leads with how many people it would affect', async () => {
  renderPage()
  await fillForm()

  fireEvent.click(screen.getByRole('button', { name: 'See who this affects' }))

  expect(await screen.findByText(/Would add/)).toBeInTheDocument()
  expect(screen.getByText(/already in the group/)).toBeInTheDocument()
})

test('a big blast radius is called out', async () => {
  previewMatches = 400
  renderPage()
  await fillForm()

  fireEvent.click(screen.getByRole('button', { name: 'See who this affects' }))

  expect(await screen.findByText(/That is a lot of people/)).toBeInTheDocument()
})

test('editing a field throws away a preview somebody already saw', async () => {
  /** Otherwise the count on screen could describe a different rule than the one
   * about to be saved, which is worse than showing no count at all. */
  renderPage()
  await fillForm()
  fireEvent.click(screen.getByRole('button', { name: 'See who this affects' }))
  await screen.findByRole('button', { name: 'Save this rule' })

  fireEvent.change(screen.getByPlaceholderText('Engineering'), { target: { value: 'Sales' } })

  expect(screen.queryByRole('button', { name: 'Save this rule' })).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'See who this affects' })).toBeInTheDocument()
})

test('confirming after a preview actually saves', async () => {
  renderPage()
  await fillForm()
  fireEvent.click(screen.getByRole('button', { name: 'See who this affects' }))

  fireEvent.click(await screen.findByRole('button', { name: 'Save this rule' }))

  await waitFor(() => expect(createCalls).toBe(1))
})

test('the value field disappears for an operator that takes none', async () => {
  renderPage()
  await screen.findByText('Engineering staff')

  const selects = screen.getAllByRole('combobox')
  fireEvent.change(nth(selects, 1), { target: { value: 'is_set' } })

  expect(screen.queryByPlaceholderText('Engineering')).not.toBeInTheDocument()
})

test('turning a rule off sends enabled false', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Turn off' }))

  await waitFor(() => expect(patchBodies).toHaveLength(1))
  expect(patchBodies[0]).toMatchObject({ enabled: false })
})

test('deleting asks first and says what it will take away', async () => {
  renderPage()

  fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))

  expect(screen.getByText(/loses that membership/)).toBeInTheDocument()
  expect(deleteCalls).toBe(0)

  fireEvent.click(screen.getByRole('button', { name: 'Yes, delete it' }))
  await waitFor(() => expect(deleteCalls).toBe(1))
})

test('somebody without groups:write gets no controls', async () => {
  stubApi([RULE], ['groups:read'])
  renderPage()
  await screen.findByText('Engineering staff')

  expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Turn off' })).not.toBeInTheDocument()
  expect(screen.queryByText('Write a rule')).not.toBeInTheDocument()
})

test('no rules yet says so plainly', async () => {
  stubApi([])
  renderPage()

  expect(await screen.findByText(/Everything is granted by hand/)).toBeInTheDocument()
})
