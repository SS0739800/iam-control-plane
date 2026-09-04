/**
 * Granting and revoking somebody's console role, with the history underneath.
 *
 * The history is the point of the panel, not decoration. "She was an admin for
 * three weeks in March, granted by Priya for the migration, and it expired on its
 * own" is the sentence an access review needs, and it only exists if superseded
 * and expired grants stay on screen instead of being replaced by the current one.
 *
 * Revoking asks first, for the same reason the provisioning screen does: it takes
 * access away from a real person, and one stray click should not do that.
 *
 * The backend refuses to remove the last admin. This shows that refusal as a
 * plain message rather than hiding the button, because a disabled control with no
 * explanation reads as a bug.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import {
  type AccessSummary,
  type PlatformRole,
  type RoleGrant,
  fetchAccessSummary,
  grantRole,
  revokeRole,
} from '../lib/api'
import { Button } from './Button'
import { cx } from '../lib/cx'
import styles from './RoleGrantPanel.module.css'
import { Empty, ErrorBox, Loading, Mono, Panel, Pill, type Tone } from './ui'

/** Employee is missing on purpose: it is what somebody is with no grant. */
const GRANTABLE: PlatformRole[] = ['admin', 'helpdesk', 'auditor']

function when(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : '—'
}

function grantTone(grant: RoleGrant): Tone {
  if (grant.live) return grant.role === 'admin' ? 'warn' : 'ok'
  return 'muted'
}

function endedHow(grant: RoleGrant): string {
  if (grant.live)
    return grant.expires_at
      ? `expires ${when(grant.expires_at)}`
      : 'no end date'
  if (grant.revoked_reason === 'superseded') return 'replaced by a later grant'
  if (grant.revoked_reason === 'expired')
    return `expired ${when(grant.revoked_at)}`
  if (grant.revoked_reason === 'user_deactivated')
    return 'ended when they were deactivated'
  return `revoked ${when(grant.revoked_at)}`
}

function GrantForm({ userId, onDone }: { userId: string; onDone: () => void }) {
  const [role, setRole] = useState<PlatformRole>('helpdesk')
  const [reason, setReason] = useState('')
  const [expires, setExpires] = useState('')

  const grant = useMutation({
    mutationFn: () =>
      grantRole(userId, {
        role,
        reason: reason || null,
        // A date input gives a bare day; the API wants a moment. End of that day
        // local time is the reading a person means by "until the 30th".
        expires_at: expires
          ? new Date(`${expires}T23:59:59`).toISOString()
          : null,
      }),
    onSuccess: onDone,
  })

  return (
    <form
      className={styles.form}
      onSubmit={(event) => {
        event.preventDefault()
        grant.mutate()
      }}
    >
      <div className={styles.formRow}>
        <label className={styles.label}>
          <span className={styles.labelText}>Role</span>
          <select
            value={role}
            onChange={(event) => setRole(event.target.value as PlatformRole)}
            className={styles.field}
          >
            {GRANTABLE.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <label className={cx(styles.label, styles.labelGrow)}>
          <span className={styles.labelText}>Why</span>
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Covering the migration weekend"
            className={styles.field}
          />
        </label>

        <label className={styles.label}>
          <span className={styles.labelText}>
            Until (optional)
          </span>
          <input
            type="date"
            value={expires}
            onChange={(event) => setExpires(event.target.value)}
            className={styles.field}
          />
        </label>
      </div>

      {role === 'admin' && !expires ? (
        <p className={styles.warning}>
          Admin with no end date. Standing access nobody revisits is how an
          unnoticed admin happens — consider a date.
        </p>
      ) : null}

      {grant.isError ? <ErrorBox error={grant.error} /> : null}

      <Button type="submit" variant="accent" disabled={grant.isPending}>
        {grant.isPending ? 'Granting…' : 'Grant role'}
      </Button>
    </form>
  )
}

function CurrentRole({
  summary,
  canWrite,
  onRevoked,
}: {
  summary: AccessSummary
  canWrite: boolean
  onRevoked: () => void
}) {
  const [confirming, setConfirming] = useState(false)

  const revoke = useMutation({
    mutationFn: () => revokeRole(summary.user_id, 'revoked from the console'),
    onSuccess: () => {
      setConfirming(false)
      onRevoked()
    },
  })

  const hasRole = summary.role !== "employee"

  return (
    <div className={styles.current}>
      <div className={styles.currentRow}>
        <Pill
          tone={summary.role === 'admin' ? 'warn' : hasRole ? 'ok' : 'muted'}
        >
          {summary.role}
        </Pill>
        {hasRole ? (
          <span className={styles.muted}>
            granted by {summary.role_granted_by ?? 'unknown'} on{' '}
            {when(summary.role_granted_at)}
            {summary.role_expires_at
              ? `, until ${when(summary.role_expires_at)}`
              : ""}
          </span>
        ) : (
          <span className={styles.muted}>
            No role granted. Employees can sign in but cannot use this console.
          </span>
        )}
      </div>

      {revoke.isError ? <ErrorBox error={revoke.error} /> : null}

      {hasRole && canWrite ? (
        confirming ? (
          <div className={styles.confirm}>
            <p className={styles.confirmText}>
              Take {summary.display_name}&apos;s {summary.role} role away? They
              keep their account and can still sign in, but lose access to this
              console.
            </p>
            <div className={styles.confirmActions}>
              <Button
                variant="danger-solid"
                onClick={() => revoke.mutate()}
                disabled={revoke.isPending}
              >
                {revoke.isPending ? 'Revoking…' : 'Yes, revoke it'}
              </Button>
              <Button variant="secondary" onClick={() => setConfirming(false)}>
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <Button variant="danger" onClick={() => setConfirming(true)}>
            Revoke role
          </Button>
        )
      ) : null}
    </div>
  )
}

export default function RoleGrantPanel({
  userId,
  canWrite,
}: {
  userId: string
  canWrite: boolean
}) {
  const queryClient = useQueryClient()
  const summary = useQuery({
    queryKey: ['access-summary', userId],
    queryFn: () => fetchAccessSummary(userId),
  })

  const refresh = () => {
    void queryClient.invalidateQueries({
      queryKey: ['access-summary', userId],
    })
    void queryClient.invalidateQueries({ queryKey: ['user', userId] })
  }

  if (summary.isPending)
    return (
      <Panel title="Console role">
        <Loading />
      </Panel>
    )
  if (summary.isError)
    return (
      <Panel title="Console role">
        <ErrorBox error={summary.error} />
      </Panel>
    )

  const history = summary.data.grant_history ?? []

  return (
    <Panel title="Console role">
      <div className={styles.body}>
        <CurrentRole
          summary={summary.data}
          canWrite={canWrite}
          onRevoked={refresh}
        />

        <div>
          <p className={styles.historyHeading}>
            History
          </p>
          {history.length === 0 ? (
            <Empty>Never had a console role.</Empty>
          ) : (
            <ul className={styles.historyList}>
              {history.map((grant) => (
                <li
                  key={grant.id}
                  className={styles.historyItem}
                >
                  <div className={styles.historyRow}>
                    <Pill tone={grantTone(grant)}>{grant.role}</Pill>
                    <span className={styles.historyHow}>{endedHow(grant)}</span>
                    <span className={styles.historyMeta}>
                      <Mono>{grant.source}</Mono>
                    </span>
                  </div>
                  <span className={styles.historyMeta}>
                    {when(grant.created_at)} · granted by{' '}
                    {grant.granted_by_label}
                    {grant.reason ? ` · ${grant.reason}` : ""}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {canWrite ? <GrantForm userId={userId} onDone={refresh} /> : null}
      </div>
    </Panel>
  )
}
