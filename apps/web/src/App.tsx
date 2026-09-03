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

import { useState } from 'react'

import { useQuery } from '@tanstack/react-query'
import { NavLink, Outlet } from 'react-router-dom'

import { fetchMe, fetchSignInOptions } from './lib/api'

/**
 * The left rail, grouped the way the portal groups things.
 *
 * Eleven flat entries across the top was a lot to scan. Entra splits its navigation
 * into headed sections — who exists, what they can reach, how it is governed — and
 * that grouping is doing real work rather than decoration: "Requests" and "Review"
 * mean nothing next to "Users" and everything next to each other.
 */
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
    // Two entries rather than one, because the two directions are not variations on
    // a theme: one manages who may write to us, the other manages where we write.
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
 * The left rail's sections, each one collapsible the way Entra's are.
 *
 * Collapsing only applies from `sm` up. Below that the sections flatten into one
 * horizontal scrolling strip (see the comment on NAV above) with the headings already
 * hidden, so there is nothing there to collapse — every link stays reachable by
 * scrolling. On the rail, closing a section keeps its links in the DOM and only hides
 * them past `sm`, so the mobile strip is never affected by rail state.
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
                  /* Selected is a tint, plus a left bar once there is a rail to
                     put it against. The portal marks position rather than shouting
                     about it — a solid dark chip in a rail this size reads as a
                     button somebody should press. Closed sections hide their links
                     from `sm` up only — the mobile strip never reads `isOpen`. */
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

/** Who the API thinks we are, and how it worked that out. */
function WhoAmI() {
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })

  // Both branches are unreachable in practice: App does not render this until the same
  // query has resolved, and shares its cache. Kept as a guard rather than an assertion,
  // because a component that throws on a null is a worse failure than one that renders
  // nothing for a moment.
  if (me.isPending || me.isError) return null

  const who = me.data

  // Sits in the dark top bar, so this is light-on-dark in both colour schemes rather
  // than the bordered panel it used to be.
  return (
    <span className="flex flex-wrap items-center gap-3 text-sm">
      {!who.via_saml_session ? (
        /* Still loud, because it is still impersonation rather than authentication —
           but it has to be loud against a dark bar now, so it is an amber chip rather
           than a tinted box. */
        <span className="rounded-fluent bg-amber-400 px-2 py-0.5 text-xs font-semibold text-neutral-190">
          development stand-in, not a login
        </span>
      ) : null}
      <span className="text-neutral-30">
        {who.display_name} <span className="text-neutral-90">({who.role})</span>
      </span>
      {/* A form, not a link. A sign-out you can trigger with a link means any page
          on the internet can sign our users out with an image tag. */}
      <form method="post" action="/saml/logout">
        <button type="submit" className="text-sm text-neutral-30 hover:underline">
          Sign out
        </button>
      </form>
    </span>
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
    <div className="min-h-screen">
      {/* The top bar. Thin, dark, and always there — in the portal it is where the
          product name and your account live, and it is the thing that makes the page
          feel like part of a suite rather than a standalone app. */}
      <header className="flex items-center justify-between gap-4 bg-neutral-160 px-4 py-2 text-white dark:bg-black">
        <span className="text-sm font-semibold">IAM Control Plane</span>
        <WhoAmI />
      </header>

      <div className="flex">
        {/* The left rail. The single most recognisable thing about the portal, and
            the reason this redesign is a layout change rather than a repaint.

            One nav, two shapes. The first version rendered a rail and a separate
            horizontal strip, hiding one with CSS — which put every link in the
            document twice and read as two identical menus to a screen reader. So the
            sections use `display: contents` on small screens: the headings hide, the
            wrappers stop being boxes, and the links become direct children of a
            scrolling row. Same DOM, same order, one menu. */}
        <SectionNav />

        <main className="min-w-0 flex-1 px-6 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
