/**
 * The "are you sure?" pattern used all over the app: a button that, once clicked,
 * turns into a question with a real answer and a way out. No popup, nothing that
 * covers the rest of the page.
 *
 * This holds no state of its own — the caller owns `open` and decides what closes
 * it. Provisioning.tsx needs that: it keeps one "which row is confirming" value for
 * the whole list, so opening one row's confirm closes anyone else's. If this
 * component kept its own state, that behavior would quietly break.
 */

import type { ReactNode } from 'react'

import { Button, type ButtonVariant } from './Button'
import styles from './ConfirmInline.module.css'

export function ConfirmInline({
  open,
  onOpen,
  onCancel,
  onConfirm,
  pending,
  triggerLabel,
  confirmLabel,
  pendingLabel,
  message,
  layout = 'inline',
  triggerVariant = 'danger',
}: {
  open: boolean
  onOpen: () => void
  onCancel: () => void
  onConfirm: () => void
  pending?: boolean
  triggerLabel: ReactNode
  confirmLabel: ReactNode
  pendingLabel?: ReactNode
  message: ReactNode
  layout?: 'inline' | 'block'
  triggerVariant?: 'danger' | 'accent'
}) {
  if (!open) {
    return (
      <Button variant={triggerVariant} onClick={onOpen}>
        {triggerLabel}
      </Button>
    )
  }

  const confirmVariant: ButtonVariant = triggerVariant === 'accent' ? 'primary' : 'danger-solid'

  return (
    <div className={layout === 'block' ? styles.block : styles.inline}>
      <div className={styles.message}>{message}</div>
      <span className={styles.actions}>
        <Button variant={confirmVariant} disabled={pending} onClick={onConfirm}>
          {pending ? (pendingLabel ?? confirmLabel) : confirmLabel}
        </Button>
        <Button variant="secondary" disabled={pending} onClick={onCancel}>
          Cancel
        </Button>
      </span>
    </div>
  )
}
