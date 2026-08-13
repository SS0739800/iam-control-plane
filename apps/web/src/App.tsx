import { useQuery } from '@tanstack/react-query'

import { fetchLiveness, fetchReadiness } from './lib/api'

type Tone = 'ok' | 'bad' | 'pending'

const DOT_CLASS: Record<Tone, string> = {
  ok: 'bg-emerald-500',
  bad: 'bg-rose-500',
  pending: 'bg-slate-400 animate-pulse',
}

/** Planned HTTP surfaces. Caddy's route table mirrors this exactly. */
const SURFACES = [
  { path: '/api/health', purpose: 'Liveness and readiness probes', phase: 'P0', live: true },
  { path: '/api/users', purpose: 'Admin API — users, groups, apps, audit', phase: 'P1', live: false },
  { path: '/saml/acs', purpose: 'Inbound SSO — assertions from the IdP', phase: 'P2', live: false },
  { path: '/scim/v2/Users', purpose: 'Inbound provisioning — SCIM server', phase: 'P3', live: false },
  { path: '/idp/sso', purpose: 'Outbound SSO — this platform as IdP', phase: 'P5', live: false },
] as const

function Dot({ tone }: { tone: Tone }) {
  return <span className={`inline-block size-2 shrink-0 rounded-full ${DOT_CLASS[tone]}`} aria-hidden="true" />
}

function Row({ label, value, tone }: { label: string; value: string; tone?: Tone }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-slate-200 py-2 last:border-0 dark:border-slate-800">
      <dt className="text-sm text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="flex items-center gap-2 font-mono text-sm">
        {tone === undefined ? null : <Dot tone={tone} />}
        <span>{value}</span>
      </dd>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  // Naming the section promotes it to a landmark, so "ok" in the API panel and
  // "ok" in the Database panel are distinguishable to a screen reader — and to a
  // test.
  const headingId = `panel-${title.toLowerCase().replace(/\s+/g, '-')}`

  return (
    <section
      aria-labelledby={headingId}
      className="rounded-sm border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900"
    >
      <h2
        id={headingId}
        className="mb-3 font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400"
      >
        {title}
      </h2>
      <dl>{children}</dl>
    </section>
  )
}

export default function App() {
  const liveness = useQuery({ queryKey: ['liveness'], queryFn: fetchLiveness })
  const readiness = useQuery({
    queryKey: ['readiness'],
    queryFn: fetchReadiness,
    refetchInterval: 10_000,
  })

  const apiTone: Tone = liveness.isPending ? 'pending' : liveness.isError ? 'bad' : 'ok'

  let dbTone: Tone = 'pending'
  if (!readiness.isPending) {
    dbTone = readiness.data?.database === 'ok' ? 'ok' : 'bad'
  }

  return (
    <main className="mx-auto flex max-w-3xl flex-col gap-8 px-6 py-16">
      <header className="flex flex-col gap-3 border-b-2 border-slate-900 pb-6 dark:border-slate-100">
        <p className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
          Phase 0 · foundation
        </p>
        <h1 className="text-3xl font-bold tracking-tight text-balance">IAM Control Plane</h1>
        <p className="max-w-prose text-slate-600 dark:text-slate-300">
          SAML 2.0 and SCIM 2.0 in both directions, with an HRMS as the downstream application that
          proves it works. This page exists to confirm one thing: the SPA and the API are being
          served from the same origin.
        </p>
      </header>

      <div className="grid gap-5 sm:grid-cols-2">
        <Panel title="API">
          <Row
            label="Liveness"
            tone={apiTone}
            value={liveness.isPending ? 'checking' : liveness.isError ? 'unreachable' : 'ok'}
          />
          <Row label="Environment" value={liveness.data?.env ?? '—'} />
          <Row label="Version" value={liveness.data?.version ?? '—'} />
          <Row label="Build" value={liveness.data?.git_sha ?? '—'} />
        </Panel>

        <Panel title="Database">
          <Row
            label="Readiness"
            tone={dbTone}
            value={readiness.isPending ? 'checking' : (readiness.data?.status ?? 'unknown')}
          />
          <Row label="Postgres" value={readiness.data?.database ?? '—'} />
          <Row label="Detail" value={readiness.data?.detail ?? 'none'} />
          <Row label="Polling" value="every 10s" />
        </Panel>
      </div>

      <section className="flex flex-col gap-3">
        <h2 className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
          HTTP surfaces
        </h2>
        <ul className="flex flex-col">
          {SURFACES.map((surface) => (
            <li
              key={surface.path}
              className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-slate-200 py-2 last:border-0 dark:border-slate-800"
            >
              <code className="font-mono text-sm text-brass-700 dark:text-brass-400">
                {surface.path}
              </code>
              <span className="flex-1 text-sm text-slate-600 dark:text-slate-300">
                {surface.purpose}
              </span>
              <span
                className={`font-mono text-xs ${
                  surface.live
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-slate-400 dark:text-slate-500'
                }`}
              >
                {surface.phase}
                {surface.live ? ' · live' : ' · planned'}
              </span>
            </li>
          ))}
        </ul>
      </section>

      <footer className="border-t border-slate-200 pt-4 text-sm text-slate-500 dark:border-slate-800 dark:text-slate-400">
        Every path above is relative. One origin means the session cookie stays first-party and
        there is no CORS layer to configure.
      </footer>
    </main>
  )
}
