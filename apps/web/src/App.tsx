/**
 * The app shell: top bar, nav, and whoever is signed in. Signed out, you get only
 * the sign-in page — no nav, no panels. That's just to avoid showing a stranger the
 * whole console with permission errors everywhere; the API still enforces access on
 * its own regardless of what this file renders.
 */

import { type ComponentType, useState } from 'react'

import { useQuery } from '@tanstack/react-query'
import { NavLink, Outlet } from 'react-router-dom'

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
import { cx } from './lib/cx'
import { fetchMe, fetchSignInOptions } from './lib/api'

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

/** Sign-in links, one per identity provider actually registered. */
function SignInLinks({ column }: { column?: boolean }) {
  const options = useQuery({
    queryKey: ['sign-in-options'],
    queryFn: fetchSignInOptions,
    retry: false,
  })

  if (options.isPending) return null

  // No providers, or the request failed — either way there's no link to offer.
  if (options.isError || (options.data?.length ?? 0) === 0) {
    return (
      <span className={styles.signInEmpty}>
        No identity provider is registered yet, so there is no way to sign in.
      </span>
    )
  }

  return (
    <span className={column ? styles.signInLinksColumn : styles.signInLinksRow}>
      {options.data.map((option) => (
        <a key={option.slug} href={`/saml/login?idp=${option.slug}`} className={styles.signInLink}>
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

/** What a signed-out visitor sees — no nav, no panels, just this. */
function SignInPage() {
  return (
    <div className={styles.signInPage}>
      <header>
        <p className={styles.signInKicker}>Identity platform</p>
        <h1 className={styles.signInTitle}>IAM Control Plane</h1>
        <p className={styles.signInSubtitle}>
          SAML 2.0 and SCIM 2.0, in both directions. Sign in with your identity provider
          to continue.
        </p>
      </header>

      <div className={styles.signInBox}>
        <SignInLinks column />
      </div>

      <p className={styles.signInFooter}>
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
    <div className={styles.shell}>
      <header className={styles.topBar}>
        <span className={styles.topBarTitle}>IAM Control Plane</span>
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
