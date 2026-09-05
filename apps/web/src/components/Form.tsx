/**
 * Form pieces every page shares, so a label on one screen matches a label on
 * another. Each page was carrying its own copy of these styles before.
 *
 * `Field` wraps its control in the <label>, so clicking the text focuses the
 * input without anyone having to keep an id and a htmlFor in step.
 */

import type { ReactNode } from 'react'

import { cx } from '../lib/cx'
import styles from './Form.module.css'

export function Form({
  onSubmit,
  children,
}: {
  onSubmit?: () => void
  children: ReactNode
}) {
  return (
    <form
      className={styles.form}
      onSubmit={(event) => {
        event.preventDefault()
        onSubmit?.()
      }}
    >
      {children}
    </form>
  )
}

/** A titled group of fields. */
export function FormSection({
  title,
  description,
  children,
}: {
  title?: string
  description?: ReactNode
  children: ReactNode
}) {
  return (
    <div className={styles.section}>
      {title ? <h3 className={styles.sectionTitle}>{title}</h3> : null}
      {description ? <p className={styles.sectionDescription}>{description}</p> : null}
      {children}
    </div>
  )
}

/** Fields laid out across a row, wrapping when they run out of space. */
export function FieldRow({ children }: { children: ReactNode }) {
  return <div className={styles.fieldRow}>{children}</div>
}

export function Field({
  label,
  description,
  error,
  required,
  grow,
  children,
}: {
  label: ReactNode
  description?: ReactNode
  error?: ReactNode
  required?: boolean
  /** 1 takes an equal share of the row, 2 takes double. */
  grow?: 1 | 2
  children: ReactNode
}) {
  return (
    <label
      className={cx(
        styles.field,
        grow === 1 && styles.grow,
        grow === 2 && styles.growTwice,
        !grow && styles.fullWidth,
      )}
    >
      <span className={styles.label}>
        {label}
        {required ? (
          <span className={styles.required} aria-hidden="true">
            {' '}
            *
          </span>
        ) : null}
      </span>
      {children}
      {description ? <span className={styles.description}>{description}</span> : null}
      {error ? <span className={styles.error}>{error}</span> : null}
    </label>
  )
}

/** The shared input/select/textarea look. Spread onto whichever element you need. */
export function controlClass(mono?: boolean): string {
  return cx(styles.control, mono && styles.mono)
}

/** The row of buttons that ends a form. */
export function FormActions({ children }: { children: ReactNode }) {
  return <div className={styles.actions}>{children}</div>
}
