/**
 * The app shell: top bar, nav, and whoever is signed in. Signed out, you get only
 * the sign-in page — no nav, no panels. That's just to avoid showing a stranger the
 * whole console with permission errors everywhere; the API still enforces access on
 * its own regardless of what this file renders.
 */

import { useState } from 'react'

import { useQuery } from '@tanstack/react-query'
import { NavLink, Outlet } from 'react-router-dom'

import { fetchMe, fetchSignInOptions } from './lib/api'

/** Left nav, grouped into sections instead of one flat list of 11 links. */
const NAV: { heading: string; items: { to: string; label: string; end?: boolean }[] }[] = [
  {
    heading: 'Overview',
    items: [{ to: '/', label: 'Dashboard', end: true }],
  },
  {
    heading: 'Directory',
    items: [
      { to: '/users', label: 'Users' },
      { to: '/groups', label: 'Groups' },
      { to: '/applications', label: 'Applications' },
    ],
  },
  {
    heading: 'Governance',
    items: [
      { to: '/access-rules', label: 'Access rules' },
      { to: '/access-requests', label: 'Requests' },
      { to: '/access-review', label: 'Review' },
    ],
  },
  {
    heading: 'Provisioning',
    // In and out are separate pages, not one page with a toggle.
    items: [
      { to: '/provisioning', label: 'Provisioning in' },
      { to: '/provisioning-out', label: 'Provisioning out' },
    ],
  },
  {
    heading: 'Monitoring',
    items: [
      { to: '/logins', label: 'Sign-ins' },
      { to: '/audit', label: 'Audit log' },
    ],
  },
]

/** Sign-in links, one per identity provider actually registered. */
function SignInLinks({ className }: { className?: string }) {
  const options = useQuery({
    queryKey: ['sign-in-options'],
    queryFn: fetchSignInOptions,
    retry: false,
  })

  if (options.isPending) return null

  // No providers, or the request failed — either way there's no link to offer.
  if (options.isError || (options.data?.length ?? 0) === 0) {
    return (
      <span className="text-xs text-slate-500 dark:text-slate-400">
        No identity provider is registered yet, so there is no way to sign in.
      </span>
    )
  }

  return (
    <span className={className ?? 'flex flex-wrap gap-3'}>
      {options.data.map((option) => (
        <a
          key={option.slug}
          href={`/saml/login?idp=${option.slug}`}
          className="whitespace-nowrap text-brass-700 underline-offset-2 hover:underline dark:text-brass-400"
        >
          Sign in with {option.name}
        </a>
      ))}
    </span>
  )
}

/** A small chevron, rotated by the caller to show open vs. closed. */
function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 12 12"
      aria-hidden="true"
      className={`h-3 w-3 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`}
    >
      <path
        d="M2.5 4.5L6 8l3.5-3.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

/**
 * Left nav with collapsible sections, like Entra's.
 * Collapsing only applies at `sm` and up — on mobile it's a flat scroll strip with no
 * headings, so there's nothing to collapse there.
 */
function SectionNav() {
  const [closed, setClosed] = useState<Record<string, boolean>>({})

  return (
    <nav
      aria-label="Sections"
      className="flex gap-1 overflow-x-auto border-b border-neutral-40 bg-neutral-10 px-2 py-2 sm:block sm:w-56 sm:shrink-0 sm:overflow-visible sm:border-r sm:border-b-0 sm:py-4 dark:border-neutral-160 dark:bg-neutral-190"
    >
      {NAV.map((section) => {
        const isOpen = !closed[section.heading]
        return (
          <div key={section.heading} className="contents sm:block sm:pb-3">
            <button
              type="button"
              aria-expanded={isOpen}
              onClick={() =>
                setClosed((prev) => ({ ...prev, [section.heading]: !prev[section.heading] }))
              }
              className="hidden w-full items-center justify-between px-3 pb-1 text-xs font-semibold text-neutral-130 sm:flex dark:text-neutral-90"
            >
              {section.heading}
              <Chevron open={isOpen} />
            </button>
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  // sm:hidden only, so a closed section never touches the mobile strip.
                  `rounded-fluent px-3 py-1.5 text-sm whitespace-nowrap sm:rounded-none sm:border-l-2 ${
                    isOpen ? 'sm:block' : 'sm:hidden'
                  } ${
                    isActive
                      ? 'bg-fluent-50 font-semibold text-fluent-700 sm:border-fluent-500 dark:bg-neutral-160 dark:text-fluent-200'
                      : 'text-neutral-160 hover:bg-neutral-20 sm:border-transparent dark:text-neutral-20 dark:hover:bg-neutral-160'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </div>
        )
      })}
    </nav>
  )
}

/** Who's signed in, shown in the top bar. */
function WhoAmI() {
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })

  // App already waits for this query before rendering the shell, so it's resolved by now.
  if (me.isPending || me.isError) return null

  const who = me.data

  return (
    <span className="flex flex-wrap items-center gap-3 text-sm">
      {!who.via_saml_session ? (
        <span className="rounded-fluent bg-amber-400 px-2 py-0.5 text-xs font-semibold text-neutral-190">
          development stand-in, not a login
        </span>
      ) : null}
      <span className="text-neutral-30">
        {who.display_name} <span className="text-neutral-90">({who.role})</span>
      </span>
      {/* Form, not a link — a link would let any page on the web sign users out via an img tag. */}
      <form method="post" action="/saml/logout">
        <button type="submit" className="text-sm text-neutral-30 hover:underline">
          Sign out
        </button>
      </form>
    </span>
  )
}

/** What a signed-out visitor sees — no nav, no panels, just this. */
function SignInPage() {
  return (
    <div className="mx-auto flex min-h-screen max-w-lg flex-col justify-center gap-6 px-6 py-10">
      <header className="flex flex-col gap-2">
        <p className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
          Identity platform
        </p>
        <h1 className="text-2xl font-bold tracking-tight">IAM Control Plane</h1>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          SAML 2.0 and SCIM 2.0, in both directions. Sign in with your identity provider
          to continue.
        </p>
      </header>

      <div className="flex flex-col gap-3 rounded-sm border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
        <SignInLinks className="flex flex-col gap-2" />
      </div>

      <p className="text-xs text-slate-500 dark:text-slate-400">
        Signing in creates nothing but an ordinary employee. Console permissions are
        granted separately, by an admin, and recorded as a grant with a reason.
      </p>
    </div>
  )
}

export default function App() {
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })

  // Render nothing while we check — a flash of the console before the login page is worse.
  if (me.isPending) return null

  // 401 means no session (outside production, the dev stand-in answers instead of this).
  if (me.isError) return <SignInPage />

  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between gap-4 bg-neutral-160 px-4 py-2 text-white dark:bg-black">
        <span className="text-sm font-semibold">IAM Control Plane</span>
        <WhoAmI />
      </header>

      <div className="flex">
        {/* One nav, not two — on mobile the same links become a horizontal scroll strip
            via `display: contents`, rather than rendering a second hidden copy for
            screen readers to trip over. */}
        <SectionNav />

        <main className="min-w-0 flex-1 px-6 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
