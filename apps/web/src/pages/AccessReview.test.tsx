/**
 * Tests for the access review screen.
 *
 * The empty state gets a test of its own, and it is the one worth having. "Nothing
 * to look at" is what a review is trying to reach, so the screen has to say that
 * rather than showing a blank panel somebody reads as broken.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, test, vi } from 'vitest'

import AccessReviewPage from './AccessReview'

const USER_ID = '11111111-1111-1111-1111-111111111111'

const FINDING = {
  kind: 'standing_privilege',
  severity: 'high',
  subject: 'Platform Admin <admin@demo.local>',
  subject_user_id: USER_ID,
  concern: 'Has been admin since 17 Aug 2026 with no end date.',
  suggested_action: 'Put an end date on it, or confirm it is meant to be permanent.',
  since: '2026-08-17T09:00:00Z',
}

const GROUP_FINDING = {
  kind: 'empty_group',
  severity: 'low',
  subject: 'authentik Read-only',
  subject_user_id: null,
  concern: 'Nobody is in this group.',
  suggested_action: 'Delete it, or write down what it is for.',
  since: null,
}

function stubReview(body: unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AccessReviewPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => vi.unstubAllGlobals())

test('shows each finding with what to do about it', async () => {
  stubReview({
    checked_at: '2026-08-17T12:00:00Z',
    clean: false,
    counts: { high: 1, medium: 0, low: 1 },
    findings: [FINDING, GROUP_FINDING],
  })
  renderPage()

  expect(await screen.findByText(/no end date/)).toBeInTheDocument()
  expect(screen.getByText(/→ Put an end date on it/)).toBeInTheDocument()
  expect(screen.getByText(/→ Delete it/)).toBeInTheDocument()
})

test('a finding about a person links to them', async () => {
  stubReview({
    checked_at: '2026-08-17T12:00:00Z',
    clean: false,
    counts: { high: 1, medium: 0, low: 0 },
    findings: [FINDING],
  })
  renderPage()

  const link = await screen.findByRole('link', { name: /Platform Admin/ })

  expect(link).toHaveAttribute('href', `/users/${USER_ID}`)
})

test('a finding about a group is not a broken link', async () => {
  stubReview({
    checked_at: '2026-08-17T12:00:00Z',
    clean: false,
    counts: { high: 0, medium: 0, low: 1 },
    findings: [GROUP_FINDING],
  })
  renderPage()

  expect(await screen.findByText('authentik Read-only')).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: 'authentik Read-only' })).not.toBeInTheDocument()
})

test('nothing to look at is stated as the goal, not left blank', async () => {
  stubReview({
    checked_at: '2026-08-17T12:00:00Z',
    clean: true,
    counts: { high: 0, medium: 0, low: 0 },
    findings: [],
  })
  renderPage()

  expect(await screen.findByText('Nothing to look at.')).toBeInTheDocument()
  expect(screen.getByText(/state a review is trying to reach/)).toBeInTheDocument()
})

test('the counts explain what each one means', async () => {
  stubReview({
    checked_at: '2026-08-17T12:00:00Z',
    clean: false,
    counts: { high: 2, medium: 5, low: 1 },
    findings: [FINDING],
  })
  renderPage()

  expect(await screen.findByText('Needs attention now')).toBeInTheDocument()
  expect(screen.getByText(/Somebody has access they should not/)).toBeInTheDocument()
  expect(screen.getByText(/nobody can prove it/)).toBeInTheDocument()
})
