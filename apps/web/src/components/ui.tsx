/**
 * Small pieces the pages share.
 *
 * Plain Tailwind for now. shadcn/ui components can replace these later without
 * touching the pages, as long as the props stay the same.
 */

import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

export type Tone = 'ok' | 'bad' | 'warn' | 'muted'

const DOT: Record<Tone, string> = {
  ok: 'bg-emerald-500',
  bad: 'bg-rose-500',
  warn: 'bg-amber-500',
  muted: 'bg-slate-400',
}

export function Dot({ tone }: { tone: Tone }) {
  return (
    <span
      className={`inline-block size-2 shrink-0 rounded-full ${DOT[tone]}`}
      aria-hidden="true"
    />
  )
}

/** A small label with a coloured dot, for status columns. */
export function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm whitespace-nowrap">
      <Dot tone={tone} />
      {children}
    </span>
  )
}

/** Section wrapper with a heading. The heading names it for screen readers. */
export function Panel({
  title,
  action,
  children,
}: {
  title: string
  action?: ReactNode
  children: ReactNode
}) {
  const headingId = `panel-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
  return (
    <section
      aria-labelledby={headingId}
      className="rounded-sm border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
    >
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <h2
          id={headingId}
          className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400"
        >
          {title}
        </h2>
        {action}
      </header>
      <div className="p-4">{children}</div>
    </section>
  )
}

/** One big number on the dashboard. */
export function Stat({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-sm border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
      <span className="font-mono text-xs tracking-[0.12em] text-slate-500 uppercase dark:text-slate-400">
        {label}
      </span>
      <span className="text-2xl font-semibold tabular-nums">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </span>
      {hint ? <span className="text-xs text-slate-500 dark:text-slate-400">{hint}</span> : null}
    </div>
  )
}

/** Label and value, side by side. Used on every detail page. */
export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-4 border-b border-slate-200 py-2 last:border-0 dark:border-slate-800">
      <dt className="text-sm text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="text-right text-sm">{children}</dd>
    </div>
  )
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-sm break-all">{children}</span>
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">{children}</p>
}

export function Loading() {
  return <Empty>Loading…</Empty>
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error)
  return (
    <p className="rounded-sm border border-rose-300 bg-rose-50 p-3 text-sm text-rose-800 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-200">
      {message}
    </p>
  )
}

/** Scrollable table wrapper. Wide tables scroll themselves, not the page. */
export function TableWrap({ children }: { children: ReactNode }) {
  return <div className="-mx-4 overflow-x-auto px-4">{children}</div>
}

export function Th({ children, right }: { children: ReactNode; right?: boolean }) {
  return (
    <th
      className={`border-b border-slate-200 pb-2 font-mono text-[0.68rem] font-medium tracking-[0.1em] whitespace-nowrap text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400 ${
        right ? 'pl-4 text-right' : 'pr-4 text-left'
      }`}
    >
      {children}
    </th>
  )
}

export function Td({ children, right }: { children: ReactNode; right?: boolean }) {
  return (
    <td
      className={`border-b border-slate-100 py-2 align-top text-sm dark:border-slate-800/60 ${
        right ? 'pl-4 text-right tabular-nums' : 'pr-4'
      }`}
    >
      {children}
    </td>
  )
}

/** Page-number controls for the offset-paginated lists. */
export function Pager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number
  limit: number
  offset: number
  onChange: (offset: number) => void
}) {
  const from = total === 0 ? 0 : offset + 1
  const to = Math.min(offset + limit, total)

  return (
    <div className="flex items-center justify-between gap-4 pt-3 text-sm">
      <span className="text-slate-500 tabular-nums dark:text-slate-400">
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <span className="flex gap-2">
        <button
          type="button"
          className="rounded-sm border border-slate-300 px-2 py-1 disabled:opacity-40 dark:border-slate-700"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Previous
        </button>
        <button
          type="button"
          className="rounded-sm border border-slate-300 px-2 py-1 disabled:opacity-40 dark:border-slate-700"
          disabled={to >= total}
          onClick={() => onChange(offset + limit)}
        >
          Next
        </button>
      </span>
    </div>
  )
}

export function LinkCell({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="text-brass-700 underline-offset-2 hover:underline dark:text-brass-400">
      {children}
    </Link>
  )
}
