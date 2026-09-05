/**
 * A filter that is switched on, and the button that switches one on.
 *
 * Every filter here maps to a real query parameter, so turning one on narrows the
 * search in Postgres rather than hiding rows we already fetched.
 */

import styles from './FilterChip.module.css'
import { CloseIcon, FilterIcon } from './icons'

export function FilterChip({
  label,
  value,
  options,
  onChange,
  onRemove,
}: {
  label: string
  value: string
  /** [value, label] pairs. */
  options: [string, string][]
  onChange: (value: string) => void
  onRemove: () => void
}) {
  return (
    <span className={styles.chip}>
      <span className={styles.chipLabel}>{label} ==</span>
      <select
        aria-label={`Filter by ${label.toLowerCase()}`}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className={styles.chipSelect}
      >
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
      <button
        type="button"
        aria-label={`Remove ${label.toLowerCase()} filter`}
        className={styles.chipRemove}
        onClick={onRemove}
      >
        <CloseIcon />
      </button>
    </span>
  )
}

export function AddFilter({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button type="button" className={styles.addFilter} onClick={onClick}>
      <FilterIcon />
      {label}
    </button>
  )
}
