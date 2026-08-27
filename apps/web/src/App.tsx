/**
 * The frame every page sits in: title, navigation, and who you are — or, for somebody
 * who is not signed in, a sign-in page and nothing else.
 *
 * The gate is the outer decision. /api/me answers 401 when there is no session, and
 * that is the whole of it: no navigation, no panels, no shell. It used to render the
 * console regardless, so a stranger saw every section name and a grid of red "missing
 * permission" boxes. Nothing leaked — the API refuses those calls — but it advertised
 * the shape of the system and looked broken doing it.
 *
 * Worth being clear that this is presentation, not access control. Every endpoint
 * behind it checks permissions itself, which is the part somebody editing the frontend
 * cannot switch off.
 *
 * The banner is the other interesting part. Outside production a request with no
 * session cookie is answered by the development stand-in, and that is impersonation
 * rather than authentication — so /api/me reports which of the two happened and the
 * banner says so, instead of a fixed warning nobody rereads.
 */

import { useQuery } from '@tanstack/react-query'
import { NavLink, Outlet } from 'react-router-dom'

import { fetchMe, fetchSignInOptions } from './lib/api'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/users', label: 'Users', end: false },
  { to: '/groups', label: 'Groups', end: false },
  { to: '/applications', label: 'Applications', end: false },
  { to: '/logins', label: 'Sign-ins', end: false },
  { to: '/access-rules', label: 'Access rules', end: false },
  { to: '/access-requests', label: 'Requests', end: false },
  { to: '/access-review', label: 'Review', end: false },
  // Two entries rather than one, because the two directions are not variations on
  // a theme: one manages who may write to us, the other manages where we write.
  { to: '/provisioning', label: 'Provisioning in', end: false },
  { to: '/provisioning-out', label: 'Provisioning out', end: false },
  { to: '/audit', label: 'Audit log', end: false },
]

/**
 * The sign-in links, built from the providers actually registered.
 *
 * These used to be one hard-coded `?idp=authentik`, which worked locally and pointed
 * at a provider that does not exist in production — so the first person to deploy this
 * had to be handed a URL by hand to get in at all. The list now comes from the one
 * unauthenticated endpoint, because a sign-in screen cannot ask for a permission:
 * whoever is reading it has no session, which is precisely why they are reading it.
 */
function SignInLinks({ className }: { className?: string }) {
  const options = useQuery({
    queryKey: ['sign-in-options'],
    queryFn: fetchSignInOptions,
    retry: false,
  })

  if (options.isPending) return null

  // Nothing registered, or the request failed. Saying so beats offering a dead link:
  // on a fresh deployment this is the true state of affairs, and the fix is a command
  // somebody runs rather than anything on this page.
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

/** Who the API thinks we are, and how it worked that out. */
function WhoAmI() {
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })

  // Both branches are unreachable in practice: App does not render this until the same
  // query has resolved, and shares its cache. Kept as a guard rather than an assertion,
  // because a component that throws on a null is a worse failure than one that renders
  // nothing for a moment.
  if (me.isPending || me.isError) return null

  const who = me.data

  if (!who.via_saml_session) {
    return (
      <p className="flex flex-wrap items-center justify-between gap-3 rounded-sm border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
        <span>
          Acting as <strong>{who.display_name}</strong> because no session cookie was sent. This is
          the development stand-in, not a login, and it never runs in production.
        </span>
        <SignInLinks className="flex flex-wrap gap-3 whitespace-nowrap underline underline-offset-2" />
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

/**
 * What a signed-out visitor gets: this, and nothing else.
 *
 * No navigation, no panels, no shell. The frame used to render regardless of whether
 * anybody was signed in, so a stranger saw the whole console — every section name, the
 * dashboard layout, and a row of red "Missing required permission" boxes where the data
 * would be. Nothing sensitive leaked, because the API refuses every one of those calls,
 * but it advertised the shape of the system and looked broken while doing it.
 *
 * The API is still the thing that enforces this. Hiding a screen is not access control
 * and this component is not load-bearing for security — every endpoint behind it checks
 * permissions on its own, which is what a person editing the frontend cannot switch off.
 */
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

  // Nothing at all while we find out. A flash of the full console followed by a login
  // page is worse than a blank moment, and this request is fast.
  if (me.isPending) return null

  // 401 from /api/me. Outside production the development stand-in answers instead, so
  // this branch is only reached when there is genuinely no session — which is every
  // visitor in production and anybody who has signed out.
  if (me.isError) return <SignInPage />

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-6 py-10">
      <header className="flex flex-col gap-3 border-b-2 border-slate-900 pb-4 dark:border-slate-100">
        <p className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
          Phase 7 · ready to deploy
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
