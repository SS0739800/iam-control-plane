/** The frame every page sits in: title, navigation, and a warning about login. */

import { NavLink, Outlet } from 'react-router-dom'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/users', label: 'Users', end: false },
  { to: '/groups', label: 'Groups', end: false },
  { to: '/applications', label: 'Applications', end: false },
  { to: '/audit', label: 'Audit log', end: false },
]

export default function App() {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-6 py-10">
      <header className="flex flex-col gap-3 border-b-2 border-slate-900 pb-4 dark:border-slate-100">
        <p className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
          Phase 1 · core directory
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

      <p className="rounded-sm border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
        There is no login yet. Every request is treated as the demo admin. Real sign-in arrives in
        P2 with SAML.
      </p>

      <main>
        <Outlet />
      </main>

      <footer className="border-t border-slate-200 pt-4 text-sm text-slate-500 dark:border-slate-800 dark:text-slate-400">
        The frontend and the API are served from one address, so the login cookie added in P2 stays
        first-party and there is no CORS to configure.
      </footer>
    </div>
  )
}
