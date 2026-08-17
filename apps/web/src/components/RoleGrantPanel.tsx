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
      className="flex flex-col gap-3 border-t border-slate-200 pt-4 dark:border-slate-800"
      onSubmit={(event) => {
        event.preventDefault()
        grant.mutate()
      }}
    >
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">Role</span>
          <select
            value={role}
            onChange={(event) => setRole(event.target.value as PlatformRole)}
            className="rounded-sm border border-slate-300 bg-white px-2 py-1 dark:border-slate-700 dark:bg-slate-900"
          >
            {GRANTABLE.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-1 flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">Why</span>
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Covering the migration weekend"
            className="rounded-sm border border-slate-300 bg-white px-2 py-1 dark:border-slate-700 dark:bg-slate-900"
          />
        </label>

        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">
            Until (optional)
          </span>
          <input
            type="date"
            value={expires}
            onChange={(event) => setExpires(event.target.value)}
            className="rounded-sm border border-slate-300 bg-white px-2 py-1 dark:border-slate-700 dark:bg-slate-900"
          />
        </label>
      </div>

      {role === 'admin' && !expires ? (
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Admin with no end date. Standing access nobody revisits is how an
          unnoticed admin happens — consider a date.
        </p>
      ) : null}

      {grant.isError ? <ErrorBox error={grant.error} /> : null}

      <button
        type="submit"
        disabled={grant.isPending}
        className="self-start rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
      >
        {grant.isPending ? 'Granting…' : 'Grant role'}
      </button>
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
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <Pill
          tone={summary.role === 'admin' ? 'warn' : hasRole ? 'ok' : 'muted'}
        >
          {summary.role}
        </Pill>
        {hasRole ? (
          <span className="text-sm text-slate-500 dark:text-slate-400">
            granted by {summary.role_granted_by ?? 'unknown'} on{' '}
            {when(summary.role_granted_at)}
            {summary.role_expires_at
              ? `, until ${when(summary.role_expires_at)}`
              : ""}
          </span>
        ) : (
          <span className="text-sm text-slate-500 dark:text-slate-400">
            No role granted. Employees can sign in but cannot use this console.
          </span>
        )}
      </div>

      {revoke.isError ? <ErrorBox error={revoke.error} /> : null}

      {hasRole && canWrite ? (
        confirming ? (
          <div className="flex flex-col gap-2">
            <p className="text-sm text-rose-700 dark:text-rose-400">
              Take {summary.display_name}&apos;s {summary.role} role away? They
              keep their account and can still sign in, but lose access to this
              console.
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => revoke.mutate()}
                disabled={revoke.isPending}
                className="rounded-sm border border-rose-500 bg-rose-600 px-2 py-1 text-xs text-white disabled:opacity-40"
              >
                {revoke.isPending ? 'Revoking…' : 'Yes, revoke it'}
              </button>
              <button
                type="button"
                onClick={() => setConfirming(false)}
                className="rounded-sm border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setConfirming(true)}
            className="self-start rounded-sm border border-rose-400 px-2 py-1 text-xs text-rose-700 dark:border-rose-800 dark:text-rose-400"
          >
            Revoke role
          </button>
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
      <div className="flex flex-col gap-4">
        <CurrentRole
          summary={summary.data}
          canWrite={canWrite}
          onRevoked={refresh}
        />

        <div>
          <p className="pb-2 text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
            History
          </p>
          {history.length === 0 ? (
            <Empty>Never had a console role.</Empty>
          ) : (
            <ul className="flex flex-col">
              {history.map((grant) => (
                <li
                  key={grant.id}
                  className="flex flex-col gap-1 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
                >
                  <div className="flex flex-wrap items-baseline gap-2">
                    <Pill tone={grantTone(grant)}>{grant.role}</Pill>
                    <span className="text-sm">{endedHow(grant)}</span>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      <Mono>{grant.source}</Mono>
                    </span>
                  </div>
                  <span className="text-xs text-slate-500 dark:text-slate-400">
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
