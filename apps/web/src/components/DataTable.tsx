/**
 * The table shell every list page shares: a command bar, a search box, filter
 * chips, the loading/empty/error states, and the table itself.
 *
 * Pages hand it columns and rows and stop worrying about any of that. What it
 * does not do is sort, select rows or export — the API has no sort parameter and
 * no bulk endpoints, so controls for those would be decoration.
 */

import { Fragment, type ReactNode } from 'react'

import styles from './DataTable.module.css'
import { Button } from './Button'
import { Td, Th } from './ui'

export type Column<T> = {
  key: string
  header: ReactNode
  /** Right-aligns the column and lines its numbers up. */
  numeric?: boolean
  /** The API's name for this column. Set it to make the header sortable. */
  sortKey?: string
  cell: (row: T) => ReactNode
}

export type Sort = { key: string; order: 'asc' | 'desc' }

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  status,
  error,
  onRetry,
  search,
  actions,
  filters,
  count,
  empty,
  footer,
  expanded,
  sort,
}: {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  status: 'pending' | 'error' | 'success'
  error?: unknown
  onRetry?: () => void
  /** The search box, when the list is searchable. */
  search?: { value: string; onChange: (value: string) => void; label: string; placeholder: string }
  /** Buttons that act on the whole list. */
  actions?: ReactNode
  /** Filter chips, sitting on their own row under the command bar. */
  filters?: ReactNode
  /** "1,289 users found" — pass the whole sentence. */
  count?: ReactNode
  empty: { title: string; body?: ReactNode; actions?: ReactNode }
  /** Pagination, usually a Pager or a "Load more" button. */
  footer?: ReactNode
  /** Detail for one row, shown in a full-width row under it when open. */
  expanded?: { isOpen: (row: T) => boolean; render: (row: T) => ReactNode }
  /** Current sort, and what to do when a sortable header is clicked. */
  sort?: { value: Sort; onChange: (next: Sort) => void }
}) {
  const hasCommandBar = Boolean(actions || search)

  return (
    <>
      {hasCommandBar ? (
        <div className={styles.toolbar}>
          {actions}
          <span className={styles.toolbarSpacer} />
          {search ? (
            <input
              type="search"
              value={search.value}
              onChange={(event) => search.onChange(event.target.value)}
              placeholder={search.placeholder}
              aria-label={search.label}
              className={styles.search}
            />
          ) : null}
        </div>
      ) : null}

      {filters ? <div className={styles.filterRow}>{filters}</div> : null}

      {status === 'error' ? (
        <TableError error={error} onRetry={onRetry} />
      ) : status === 'pending' ? (
        <TableSkeleton columns={columns.length} />
      ) : rows.length === 0 ? (
        <div className={styles.state}>
          <p className={styles.stateTitle}>{empty.title}</p>
          {empty.body ? <p className={styles.stateBody}>{empty.body}</p> : null}
          {empty.actions ? <div className={styles.stateActions}>{empty.actions}</div> : null}
        </div>
      ) : (
        <>
          {count ? <p className={styles.count}>{count}</p> : null}
          <div className={styles.wrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  {columns.map((column) => {
                    const sorted = sort && column.sortKey === sort.value.key
                    return (
                      <Th
                        key={column.key}
                        right={column.numeric}
                        ariaSort={
                          !sort || !column.sortKey
                            ? undefined
                            : sorted
                              ? sort.value.order === 'asc'
                                ? 'ascending'
                                : 'descending'
                              : 'none'
                        }
                      >
                        {sort && column.sortKey ? (
                          <SortableHeader column={column} sort={sort} />
                        ) : (
                          column.header
                        )}
                      </Th>
                    )
                  })}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const open = expanded?.isOpen(row) ?? false
                  return (
                    <Fragment key={rowKey(row)}>
                      <tr>
                        {columns.map((column) => (
                          <Td key={column.key} right={column.numeric}>
                            {column.cell(row)}
                          </Td>
                        ))}
                      </tr>
                      {open ? (
                        <tr>
                          <Td colSpan={columns.length}>{expanded?.render(row)}</Td>
                        </tr>
                      ) : null}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
          {footer}
        </>
      )}
    </>
  )
}

/** Grey bars in the table's shape, so the page doesn't jump when rows arrive. */
export function TableSkeleton({ columns, rows = 6 }: { columns: number; rows?: number }) {
  return (
    <div className={styles.wrap}>
      <table className={styles.table}>
        <tbody>
          {Array.from({ length: rows }, (_, rowIndex) => (
            <tr key={rowIndex}>
              {Array.from({ length: columns }, (_, cellIndex) => (
                <td key={cellIndex} className={styles.skeletonCell}>
                  <div
                    className={styles.skeletonBar}
                    style={{ width: cellIndex === 0 ? '55%' : '75%' }}
                  />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <span role="status" aria-live="polite" hidden>
        Loading
      </span>
    </div>
  )
}

/** What went wrong, and a way to try again. */
export function TableError({ error, onRetry }: { error?: unknown; onRetry?: () => void }) {
  const message = error instanceof Error ? error.message : error ? String(error) : null
  return (
    <div className={styles.state}>
      <p className={styles.stateTitle}>Couldn&apos;t load this list</p>
      {message ? <p className={styles.stateBody}>{message}</p> : null}
      {onRetry ? (
        <div className={styles.stateActions}>
          <Button variant="secondary" onClick={onRetry}>
            Try again
          </Button>
        </div>
      ) : null}
    </div>
  )
}

/** One action in a table's command bar: an icon, a label, no border. */
export function ToolbarButton({
  children,
  onClick,
  disabled,
  icon,
}: {
  children: ReactNode
  onClick?: () => void
  disabled?: boolean
  icon?: ReactNode
}) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} className={styles.toolbarButton}>
      {icon}
      {children}
    </button>
  )
}

/** A header that sorts the list, and says which way it's sorting. */
function SortableHeader<T>({
  column,
  sort,
}: {
  column: Column<T>
  sort: { value: Sort; onChange: (next: Sort) => void }
}) {
  const active = sort.value.key === column.sortKey
  const nextOrder = active && sort.value.order === 'asc' ? 'desc' : 'asc'

  return (
    <button
      type="button"
      className={styles.sortButton}
      onClick={() => sort.onChange({ key: column.sortKey as string, order: nextOrder })}
    >
      {column.header}
      {active ? (
        <span className={styles.sortArrow} aria-hidden="true">
          {sort.value.order === 'asc' ? '▲' : '▼'}
        </span>
      ) : null}
    </button>
  )
}
