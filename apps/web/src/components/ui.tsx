/**
 * Shared UI pieces, styled after the Entra admin center: one blue, hairline borders,
 * 2px radii, sentence-case headings, dense rows. Status is always a dot plus a word,
 * not color alone, so it still reads for colorblind users.
 */

import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

import { cx } from '../lib/cx'
import styles from './ui.module.css'

export type Tone = 'ok' | 'bad' | 'warn' | 'muted'

export function Dot({ tone }: { tone: Tone }) {
  return <span className={styles.dot} data-tone={tone} aria-hidden="true" />
}

/** A small label with a coloured dot, for status columns. */
export function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={styles.pill}>
      <Dot tone={tone} />
      {children}
    </span>
  )
}

/* Picked to stay readable with white text on top. */
const AVATAR_COLORS = ['#0078d4', '#8764b8', '#038387', '#a4262c', '#498205', '#8e562e', '#005b70']

/** Somebody's initials in a coloured disc. Same name always gets the same colour. */
export function Avatar({ name }: { name: string }) {
  const initials = name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? '')
    .join('')

  let hash = 0
  for (let i = 0; i < name.length; i += 1) hash = (hash * 31 + name.charCodeAt(i)) | 0
  const background = AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length]

  return (
    <span className={styles.avatar} style={{ background }} aria-hidden="true">
      {initials}
    </span>
  )
}

/** A name with its avatar, for the first column of a people table. */
export function NameCell({ name, children }: { name: string; children: ReactNode }) {
  return (
    <span className={styles.nameCell}>
      <Avatar name={name} />
      {children}
    </span>
  )
}

/** Section wrapper with a heading, used for screen readers too. */
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
    <section aria-labelledby={headingId} className={styles.panel}>
      <header className={styles.panelHeader}>
        <h2 id={headingId} className={styles.panelHeading}>
          {title}
        </h2>
        {action}
      </header>
      <div className={styles.panelBody}>{children}</div>
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
    <div className={styles.stat}>
      <span className={styles.statLabel}>{label}</span>
      <span className={styles.statValue}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </span>
      {hint ? <span className={styles.statHint}>{hint}</span> : null}
    </div>
  )
}

/** Label and value, side by side. Used on every detail page. */
export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className={styles.row}>
      <dt className={styles.rowLabel}>{label}</dt>
      <dd className={styles.rowValue}>{children}</dd>
    </div>
  )
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className={styles.mono}>{children}</span>
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className={styles.empty}>{children}</p>
}

export function Loading() {
  return <Empty>Loading…</Empty>
}

/** An error, shown as a Fluent-style MessageBar: a colored left edge, not a tinted box. */
export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error)
  return <p className={styles.errorBox}>{message}</p>
}

/** Scrollable table wrapper. Wide tables scroll themselves, not the page. */
export function TableWrap({ children }: { children: ReactNode }) {
  return <div className={styles.tableWrap}>{children}</div>
}

export function Th({ children, right }: { children: ReactNode; right?: boolean }) {
  return <th className={cx(styles.th, right && styles.thRight)}>{children}</th>
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
    <td colSpan={colSpan} className={cx(styles.td, right && styles.tdRight)}>
      {children}
    </td>
  )
}

/** Row of actions above a list. Always label icons with text — no icon-only guessing. */
export function CommandBar({ children }: { children: ReactNode }) {
  return <div className={styles.commandBar}>{children}</div>
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
      className={cx(styles.command, primary && styles.commandPrimary)}
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
    <div className={styles.pager}>
      <span className={styles.pagerCount}>
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <span className={styles.pagerButtons}>
        <button
          type="button"
          className={styles.pagerButton}
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Previous
        </button>
        <button
          type="button"
          className={styles.pagerButton}
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
    <Link to={to} className={styles.link}>
      {children}
    </Link>
  )
}

/** Breadcrumb trail across the top of a page. */
export function Breadcrumbs({ trail }: { trail: { label: string; to?: string }[] }) {
  return (
    <nav aria-label="Breadcrumb" className={styles.breadcrumbs}>
      <ol className={styles.breadcrumbList}>
        {trail.map((step, index) => (
          <li key={`${step.label}-${index}`} className={styles.breadcrumbItem}>
            {index > 0 ? (
              <span aria-hidden="true" className={styles.breadcrumbSeparator}>
                ›
              </span>
            ) : null}
            {step.to ? (
              <Link to={step.to} className={styles.link}>
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
