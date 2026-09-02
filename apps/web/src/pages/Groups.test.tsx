/**
 * The groups list, and the difference between "nothing found" and "nothing here".
 *
 * The page said "No groups match that search" whether or not anybody had searched.
 * On a fresh deployment that reads as a broken filter — you look for the search box
 * you did not type in — when the truth is simply that no groups exist yet, and the
 * useful thing to say is where they come from.
 *
 * Small, but it is the same failure as the access-packages tile and the "in step"
 * indicator: text that is accurate in one state and misleading in another, shown in
 * both.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { GroupsPage } from './Groups'

const ENGINEERING = {
  id: 'group-1',
  name: 'Engineering',
  description: 'Everybody in engineering',
  hrms_role: null,
  source: 'scim',
  member_count: 12,
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

let items: unknown[] = []

function stubApi(): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = urlOf(input)
      if (url.includes('/api/groups')) {
        // A search that matches nothing and an empty directory look identical from
        // here, which is exactly why the page has to tell them apart itself.
        const searching = url.includes('q=')
        return Promise.resolve(
          jsonResponse({
            items: searching ? [] : items,
            total: searching ? 0 : items.length,
            limit: 25,
            offset: 0,
          }),
        )
      }
      return Promise.resolve(jsonResponse({}))
    }),
  )
}

function renderGroups() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  items = []
  stubApi()
})
afterEach(() => vi.unstubAllGlobals())

test('an empty directory says there are none yet, not that a search failed', async () => {
  renderGroups()

  expect(await screen.findByText(/No groups yet/)).toBeInTheDocument()
  expect(screen.queryByText(/match that search/)).not.toBeInTheDocument()
})

test('and says where groups come from, which is the useful part', async () => {
  renderGroups()

  // Somebody on a fresh deployment does not need to be told the list is empty. They
  // need to know groups arrive over SCIM rather than being created here.
  expect(await screen.findByText(/over SCIM/)).toBeInTheDocument()
})

test('a search that matches nothing says so', async () => {
  items = [ENGINEERING]
  renderGroups()
  await screen.findByText('Engineering')

  fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'nothing' } })

  expect(await screen.findByText(/No groups match that search/)).toBeInTheDocument()
})

test('groups are listed when there are some', async () => {
  items = [ENGINEERING]
  renderGroups()

  expect(await screen.findByText('Engineering')).toBeInTheDocument()
})
