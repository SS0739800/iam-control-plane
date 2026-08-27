/**
 * Tests for the frame, and mostly for the gate in front of it.
 *
 * A signed-out visitor used to get the whole console: every section in the navigation,
 * the dashboard layout, and a row of red "Missing required permission" boxes where data
 * would be. Nothing sensitive leaked, because the API refuses each of those calls, but
 * it published the shape of the system and looked broken while doing it.
 *
 * These check the gate holds in both directions — that a stranger sees only a sign-in
 * page, and that somebody signed in still gets the console. The second matters as much
 * as the first: a gate that never opens is not an improvement.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import App from './App'

const SIGNED_IN = {
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  user_name: 'shetty.suda@northeastern.edu',
  display_name: 'shetty.suda@northeastern.edu',
  email: 'shetty.suda@northeastern.edu',
  role: 'admin',
  permissions: ['users:read', 'apps:write'],
  via_saml_session: true,
}

const OPTIONS = [
  { slug: 'okta', name: 'Okta', login_url: 'https://example.test/saml/login?idp=okta' },
]

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

let signedIn = true
let options = OPTIONS

function stubApi(): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = urlOf(input)

      if (url.includes('/api/identity-providers/sign-in-options')) {
        return Promise.resolve(jsonResponse(options))
      }
      if (url.includes('/api/me')) {
        return signedIn
          ? Promise.resolve(jsonResponse(SIGNED_IN))
          : Promise.resolve(
              jsonResponse({ detail: 'Not signed in. Start at /saml/login.' }, 401),
            )
      }
      // Everything the child pages might ask for. They are not what these tests are
      // about, and an unhandled request would fail them for the wrong reason.
      return Promise.resolve(jsonResponse({ items: [], total: 0, limit: 25, offset: 0 }))
    }),
  )
}

function renderApp() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  signedIn = true
  options = OPTIONS
  stubApi()
})
afterEach(() => vi.unstubAllGlobals())

// -------------------------------------------------------- signed out

test('a signed-out visitor gets a sign-in page', async () => {
  signedIn = false
  renderApp()

  expect(await screen.findByRole('link', { name: /Sign in with Okta/ })).toBeInTheDocument()
})

test('a signed-out visitor sees no navigation at all', async () => {
  signedIn = false
  renderApp()

  await screen.findByRole('link', { name: /Sign in with Okta/ })

  // The list the console used to publish to anybody who loaded the page.
  for (const section of ['Users', 'Groups', 'Applications', 'Audit log', 'Provisioning out']) {
    expect(screen.queryByRole('link', { name: section })).not.toBeInTheDocument()
  }
  expect(screen.queryByRole('navigation', { name: 'Sections' })).not.toBeInTheDocument()
})

test('a signed-out visitor is not offered a sign-out button', async () => {
  signedIn = false
  renderApp()

  await screen.findByRole('link', { name: /Sign in with Okta/ })
  expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument()
})

test('the sign-in page says what a login does and does not grant', async () => {
  signedIn = false
  renderApp()

  // The thing somebody signing in should not be surprised by: they arrive with nothing.
  expect(await screen.findByText(/ordinary employee/)).toBeInTheDocument()
})

test('with no provider registered it says so instead of offering a dead link', async () => {
  signedIn = false
  options = []
  renderApp()

  expect(await screen.findByText(/No identity provider is registered yet/)).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: /Sign in with/ })).not.toBeInTheDocument()
})

// --------------------------------------------------------- signed in

test('somebody signed in gets the console', async () => {
  renderApp()

  expect(await screen.findByRole('link', { name: 'Users' })).toBeInTheDocument()
  expect(screen.getByRole('navigation', { name: 'Sections' })).toBeInTheDocument()
})

test('the banner names who is signed in, and their role', async () => {
  renderApp()

  await screen.findByRole('link', { name: 'Users' })
  expect(screen.getByText('shetty.suda@northeastern.edu')).toBeInTheDocument()
  expect(screen.getByText('(admin)')).toBeInTheDocument()
})

test('signing out is a form, not a link', async () => {
  renderApp()

  const button = await screen.findByRole('button', { name: 'Sign out' })
  // A sign-out reachable by GET means any page on the internet can sign our users out
  // with an image tag.
  const form = button.closest('form')
  expect(form).not.toBeNull()
  expect(form?.getAttribute('method')).toBe('post')
  expect(form?.getAttribute('action')).toBe('/saml/logout')
})

test('the development stand-in is called impersonation, not a login', async () => {
  signedIn = true
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = urlOf(input)
      if (url.includes('/api/identity-providers/sign-in-options')) {
        return Promise.resolve(jsonResponse(OPTIONS))
      }
      if (url.includes('/api/me')) {
        return Promise.resolve(jsonResponse({ ...SIGNED_IN, via_saml_session: false }))
      }
      return Promise.resolve(jsonResponse({ items: [], total: 0, limit: 25, offset: 0 }))
    }),
  )
  renderApp()

  await waitFor(() =>
    expect(screen.getByText(/development stand-in, not a login/)).toBeInTheDocument(),
  )
})
