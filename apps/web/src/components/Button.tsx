/** One button style used everywhere, so "remove" looks the same on every page. */

import type { ReactNode } from 'react'

import { cx } from '../lib/cx'
import styles from './Button.module.css'

export type ButtonVariant = 'primary' | 'accent' | 'secondary' | 'danger' | 'danger-solid'

const VARIANT_CLASS: Record<ButtonVariant, string | undefined> = {
  primary: styles.primary,
  accent: styles.accent,
  secondary: styles.secondary,
  danger: styles.danger,
  'danger-solid': styles.dangerSolid,
}

export function Button({
  children,
  onClick,
  disabled,
  variant = 'secondary',
  type = 'button',
  title,
}: {
  children: ReactNode
  onClick?: () => void
  disabled?: boolean
  variant?: ButtonVariant
  type?: 'button' | 'submit'
  title?: string
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={cx(styles.button, VARIANT_CLASS[variant])}
    >
      {children}
    </button>
  )
}
