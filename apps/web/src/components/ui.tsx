/**
 * Small pieces the pages share, in the shape the Entra admin centre uses.
 *
 * Nearly all of the visual change lives here rather than in the eleven pages, which
 * is the payoff for having routed everything through these in the first place: the
 * pages ask for a Panel or a Th and get whatever a Panel currently looks like.
 *
 * What actually makes the portal recognisable
 * -------------------------------------------
 *
 * Fewer things than you would expect, and none of them are components. One blue for
 * anything actionable. Hairline borders instead of shadows. Two-pixel radii — eight
 * reads as a consumer app. Sentence-case headings rather than the uppercase monospace
 * labels this console had, which read as a terminal. And density: a portal shows you
 * a lot of rows, so the padding is smaller than feels comfortable at first.
 *
 * Colour is never the only signal. Status here is a coloured dot *and* a word, which
 * matters for the eight percent of men with a colour vision deficiency, and matters
 * more in a console where the difference between states is somebody's access.
 */

import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

export type Tone = 'ok' | 'bad' | 'warn' | 'muted'

const DOT: Record<Tone, string> = {
  ok: 'bg-status-ok',
  bad: 'bg-status-bad',
  warn: 'bg-amber-500',
  muted: 'bg-neutral-90',
}

export function Dot({ tone }: { tone: Tone }) {
  return (
    <span className={`inline-block size-2 shrink-0 rounded-full ${DOT[tone]}`} aria-hidden="true" />
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

/**
 * Section wrapper with a heading. The heading names it for screen readers.
 *
 * The title is sentence case now. It was uppercase monospace with wide tracking,
 * which is a handsome look and the wrong one — it read as a build tool rather than
 * as somewhere you administer people's access.
 */
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
      className="rounded-fluent border border-neutral-40 bg-white dark:border-neutral-160 dark:bg-neutral-190"
    >
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-neutral-30 px-4 py-3 dark:border-neutral-160">
        <h2 id={headingId} className="text-sm font-semibold">
          {title}
        </h2>
        {action}
      </header>
      <div className="p-4">{children}</div>
    </section>
  )
}

/** One number, in a card. */
export function Stat({
  label,
  value,
  hint,
}: {
  label: string
  value: number | string
  hint?: string
}) {
  return (
    <div className="rounded-fluent flex flex-col gap-1 border border-neutral-40 bg-white p-4 dark:border-neutral-160 dark:bg-neutral-190">
      <span className="text-xs text-neutral-130 dark:text-neutral-60">{label}</span>
      <span className="text-2xl font-semibold tabular-nums">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </span>
      {hint ? <span className="text-xs text-neutral-130 dark:text-neutral-90">{hint}</span> : null}
    </div>
  )
}

/** Label and value, side by side. Used on every detail page. */
export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-4 border-b border-neutral-30 py-2 last:border-0 dark:border-neutral-160">
      <dt className="text-sm text-neutral-130 dark:text-neutral-60">{label}</dt>
      <dd className="text-right text-sm">{children}</dd>
    </div>
  )
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-sm break-all">{children}</span>
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <p className="py-6 text-center text-sm text-neutral-130 dark:text-neutral-90">{children}</p>
  )
}

export function Loading() {
  return <Empty>Loading…</Empty>
}

/**
 * A failure, in the shape Fluent calls a MessageBar: a bar across the content with a
 * coloured edge, rather than a tinted box. The left border is the tell.
 */
export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error)
  return (
    <p className="rounded-fluent border border-l-4 border-red-200 border-l-[var(--color-status-bad)] bg-red-50 p-3 text-sm text-neutral-160 dark:border-red-900 dark:bg-red-950/40 dark:text-neutral-20">
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
      className={`border-b border-neutral-40 pb-2 text-xs font-semibold whitespace-nowrap text-neutral-130 dark:border-neutral-160 dark:text-neutral-60 ${
        right ? 'pl-4 text-right' : 'pr-4 text-left'
      }`}
    >
      {children}
    </th>
  )
}

export function Td({
  children,
  right,
  colSpan,
}: {
  children: ReactNode
  right?: boolean
  // For a row that spans the table — an expanded detail panel under its own row,
  // where a cell per column would be meaningless.
  colSpan?: number
}) {
  return (
    <td
      colSpan={colSpan}
      className={`border-b border-neutral-30 py-2 align-top text-sm dark:border-neutral-160/70 ${
        right ? 'pl-4 text-right tabular-nums' : 'pr-4'
      }`}
    >
      {children}
    </td>
  )
}

/**
 * A row of actions above a list, which the portal calls a command bar.
 *
 * Text beside any icon, always. An icon-only toolbar is a guessing game, and this is
 * a console where the guesses are about somebody's access.
 */
export function CommandBar({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-1 border-b border-neutral-30 pb-2 dark:border-neutral-160">
      {children}
    </div>
  )
}

/** One command. `primary` is the blue one — at most one per bar. */
export function Command({
  children,
  onClick,
  disabled,
  primary,
  type = 'button',
}: {
  children: ReactNode
  onClick?: () => void
  disabled?: boolean
  primary?: boolean
  type?: 'button' | 'submit'
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={
        primary
          ? 'rounded-fluent bg-fluent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-fluent-600 disabled:opacity-40'
          : 'rounded-fluent px-3 py-1.5 text-sm text-neutral-160 hover:bg-neutral-20 disabled:opacity-40 dark:text-neutral-20 dark:hover:bg-neutral-160'
      }
    >
      {children}
    </button>
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
      <span className="tabular-nums text-neutral-130 dark:text-neutral-60">
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <span className="flex gap-2">
        <button
          type="button"
          className="rounded-fluent border border-neutral-60 px-2 py-1 hover:bg-neutral-20 disabled:opacity-40 dark:border-neutral-130 dark:hover:bg-neutral-160"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Previous
        </button>
        <button
          type="button"
          className="rounded-fluent border border-neutral-60 px-2 py-1 hover:bg-neutral-20 disabled:opacity-40 dark:border-neutral-130 dark:hover:bg-neutral-160"
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
    <Link
      to={to}
      className="text-fluent-600 hover:underline dark:text-fluent-400"
    >
      {children}
    </Link>
  )
}

/**
 * Where you are, across the top of a page.
 *
 * The portal leans on these because its navigation goes deep. Ours goes two levels,
 * so this is mostly a way back — but "mostly a way back" is what a breadcrumb is for.
 */
export function Breadcrumbs({ trail }: { trail: { label: string; to?: string }[] }) {
  return (
    <nav aria-label="Breadcrumb" className="text-sm text-neutral-130 dark:text-neutral-60">
      <ol className="flex flex-wrap items-center gap-1">
        {trail.map((step, index) => (
          <li key={`${step.label}-${index}`} className="flex items-center gap-1">
            {index > 0 ? (
              <span aria-hidden="true" className="text-neutral-90">
                ›
              </span>
            ) : null}
            {step.to ? (
              <Link to={step.to} className="text-fluent-600 hover:underline dark:text-fluent-400">
                {step.label}
              </Link>
            ) : (
              <span aria-current="page">{step.label}</span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  )
}
