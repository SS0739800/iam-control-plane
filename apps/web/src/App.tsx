/**
 * The frame every page sits in: title, navigation, and who you are.
 *
 * The banner is the interesting part. Login is real now, but a request arriving
 * with no session cookie is still answered by the development stand-in outside
 * production, and that is impersonation rather than authentication. /api/me says
 * which of the two happened, so the banner reports what is actually going on
 * instead of a fixed warning that nobody rereads.
 */

import { useQuery } from '@tanstack/react-query'
import { NavLink, Outlet } from 'react-router-dom'

import { fetchMe } from './lib/api'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/users', label: 'Users', end: false },
  { to: '/groups', label: 'Groups', end: false },
  { to: '/applications', label: 'Applications', end: false },
  { to: '/logins', label: 'Sign-ins', end: false },
  { to: '/audit', label: 'Audit log', end: false },
]

/** Who the API thinks we are, and how it worked that out. */
function WhoAmI() {
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })

  if (me.isPending) return null

  if (me.isError) {
    return (
      <p className="flex flex-wrap items-center justify-between gap-3 rounded-sm border border-slate-300 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
        <span>Not signed in.</span>
        <a
          href="/saml/login?idp=authentik"
          className="text-brass-700 underline-offset-2 hover:underline dark:text-brass-400"
        >
          Sign in with authentik
        </a>
      </p>
    )
  }

  const who = me.data

  if (!who.via_saml_session) {
    return (
      <p className="flex flex-wrap items-center justify-between gap-3 rounded-sm border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
        <span>
          Acting as <strong>{who.display_name}</strong> because no session cookie was sent. This is
          the development stand-in, not a login, and it never runs in production.
        </span>
        <a
          href="/saml/login?idp=authentik"
          className="whitespace-nowrap underline underline-offset-2"
        >
          Sign in properly
        </a>
      </p>
    )
  }

  return (
    <p className="flex flex-wrap items-center justify-between gap-3 rounded-sm border border-slate-300 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
      <span>
        Signed in as <strong>{who.display_name}</strong>{' '}
        <span className="text-slate-500 dark:text-slate-400">({who.role})</span>
      </span>
      {/* A form, not a link. A sign-out you can trigger with a link means any page
          on the internet can sign our users out with an image tag. */}
      <form method="post" action="/saml/logout">
        <button
          type="submit"
          className="text-brass-700 underline-offset-2 hover:underline dark:text-brass-400"
        >
          Sign out
        </button>
      </form>
    </p>
  )
}

export default function App() {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-6 py-10">
      <header className="flex flex-col gap-3 border-b-2 border-slate-900 pb-4 dark:border-slate-100">
        <p className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
          Phase 2 · inbound single sign-on
        </p>
        <h1 className="text-2xl font-bold tracking-tight">IAM Control Plane</h1>

        <nav aria-label="Sections" className="flex flex-wrap gap-1">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `rounded-sm px-3 py-1.5 text-sm ${
                  isActive
                    ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                    : 'text-slate-600 hover:bg-slate-200 dark:text-slate-300 dark:hover:bg-slate-800'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </header>

      <WhoAmI />

      <main>
        <Outlet />
      </main>

      <footer className="border-t border-slate-200 pt-4 text-sm text-slate-500 dark:border-slate-800 dark:text-slate-400">
        The frontend and the API are served from one address, so the session cookie stays
        first-party and there is no CORS to configure.
      </footer>
    </div>
  )
}
