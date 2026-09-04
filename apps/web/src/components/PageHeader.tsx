/**
 * The top of every page: what you're looking at, one line on what it's for, and
 * the actions that belong to the whole page. Detail pages pass a breadcrumb trail
 * so there's a way back up.
 */

import type { ReactNode } from 'react'

import styles from './PageHeader.module.css'
import { Breadcrumbs } from './ui'

export function PageHeader({
  title,
  description,
  actions,
  trail,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
  trail?: { label: string; to?: string }[]
}) {
  return (
    <div>
      {trail ? <Breadcrumbs trail={trail} /> : null}
      <div className={styles.header}>
        <div className={styles.titleBlock}>
          <h1 className={styles.title}>{title}</h1>
          {description ? <p className={styles.description}>{description}</p> : null}
        </div>
        {actions ? <div className={styles.actions}>{actions}</div> : null}
      </div>
    </div>
  )
}
