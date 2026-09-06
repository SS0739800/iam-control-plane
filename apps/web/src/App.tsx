/**
 * The app shell: top bar, nav, and whoever is signed in. Signed out, you get only
 * the sign-in page — no nav, no panels. That's just to avoid showing a stranger the
 * whole console with permission errors everywhere; the API still enforces access on
 * its own regardless of what this file renders.
 */

import { type ComponentType, useState } from 'react'

import { useQuery } from '@tanstack/react-query'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'

import styles from './App.module.css'
import {
  AppIcon,
  AuditIcon,
  DashboardIcon,
  GroupIcon,
  ProvisionInIcon,
  ProvisionOutIcon,
  RequestIcon,
  ReviewIcon,
  RuleIcon,
  SignInIcon,
  UserIcon,
} from './components/icons'
import { LandingPage } from './components/LandingPage'
import { cx } from './lib/cx'
import { fetchMe } from './lib/api'

type NavItem = { to: string; label: string; end?: boolean; icon: ComponentType<{ className?: string }> }

/** Left nav, grouped into sections instead of one flat list of 11 links. */
const NAV: { heading: string; items: NavItem[] }[] = [
  {
    heading: 'Overview',
    items: [{ to: '/', label: 'Dashboard', end: true, icon: DashboardIcon }],
  },
  {
    heading: 'Directory',
    items: [
      { to: '/users', label: 'Users', icon: UserIcon },
      { to: '/groups', label: 'Groups', icon: GroupIcon },
      { to: '/applications', label: 'Applications', icon: AppIcon },
    ],
  },
  {
    heading: 'Governance',
    items: [
      { to: '/access-rules', label: 'Access rules', icon: RuleIcon },
      { to: '/access-requests', label: 'Requests', icon: RequestIcon },
      { to: '/access-review', label: 'Review', icon: ReviewIcon },
    ],
  },
  {
    heading: 'Provisioning',
    // In and out are separate pages, not one page with a toggle.
    items: [
      { to: '/provisioning', label: 'Provisioning in', icon: ProvisionInIcon },
      { to: '/provisioning-out', label: 'Provisioning out', icon: ProvisionOutIcon },
    ],
  },
  {
    heading: 'Monitoring',
    items: [
      { to: '/logins', label: 'Sign-ins', icon: SignInIcon },
      { to: '/audit', label: 'Audit log', icon: AuditIcon },
    ],
  },
]

/** A small chevron, rotated by the caller to show open vs. closed. */
function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 12 12"
      aria-hidden="true"
      className={cx(styles.chevron, open && styles.chevronOpen)}
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
    <nav aria-label="Sections" className={styles.nav}>
      {NAV.map((section) => {
        const isOpen = !closed[section.heading]
        return (
          <div key={section.heading} className={styles.navSection}>
            <button
              type="button"
              aria-expanded={isOpen}
              onClick={() =>
                setClosed((prev) => ({ ...prev, [section.heading]: !prev[section.heading] }))
              }
              className={styles.navHeading}
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
                  cx(
                    styles.navLink,
                    isOpen ? styles.navLinkOpen : styles.navLinkClosed,
                    isActive ? styles.navLinkActive : styles.navLinkInactive,
                  )
                }
              >
                <item.icon className={styles.navIcon} />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        )
      })}
    </nav>
  )
}

/**
 * Search from the top bar. There's no endpoint that searches everything, so this
 * searches people — the list somebody is nearly always after — and hands off to
 * the users page with the term already in the URL.
 */
function GlobalSearch() {
  const [term, setTerm] = useState('')
  const navigate = useNavigate()

  return (
    <form
      role="search"
      className={styles.topSearch}
      onSubmit={(event) => {
        event.preventDefault()
        navigate(term.trim() ? `/users?q=${encodeURIComponent(term.trim())}` : '/users')
      }}
    >
      <input
        type="search"
        value={term}
        onChange={(event) => setTerm(event.target.value)}
        placeholder="Search people"
        aria-label="Search people"
        className={styles.topSearchInput}
      />
    </form>
  )
}

/** Who's signed in, shown in the top bar. */
function WhoAmI() {
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })

  // App already waits for this query before rendering the shell, so it's resolved by now.
  if (me.isPending || me.isError) return null

  const who = me.data

  return (
    <span className={styles.whoAmI}>
      {!who.via_saml_session ? (
        <span className={styles.devBadge}>development stand-in, not a login</span>
      ) : null}
      <span className={styles.whoAmIName}>
        {who.display_name} <span className={styles.whoAmIRole}>({who.role})</span>
      </span>
      {/* Form, not a link — a link would let any page on the web sign users out via an img tag. */}
      <form method="post" action="/saml/logout">
        <button type="submit" className={styles.signOutButton}>
          Sign out
        </button>
      </form>
    </span>
  )
}

export default function App() {
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })

  // Render nothing while we check — a flash of the console before the login page is worse.
  if (me.isPending) return null

  // 401 means no session (outside production, the dev stand-in answers instead of this).
  if (me.isError) return <LandingPage />

  return (
    <div className={styles.shell}>
      <header className={styles.topBar}>
        <Link to="/" className={styles.topBarTitle}>
          IAM Control Plane
        </Link>
        <GlobalSearch />
        <WhoAmI />
      </header>

      <div className={styles.contentRow}>
        {/* One nav, not two — on mobile the same links become a horizontal scroll strip
            via `display: contents`, rather than rendering a second hidden copy for
            screen readers to trip over. */}
        <SectionNav />

        <main className={styles.main}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
