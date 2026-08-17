/**
 * Access requests: asking for access, and deciding.
 *
 * Two audiences on one screen, and the split is deliberate. Everybody sees what
 * they have asked for. Only somebody who can decide sees the queue. An employee
 * holds no permissions at all, so a page they cannot open would make the whole
 * request flow useless to the people who need it most.
 *
 * The reason is shown at full width and never truncated. It is the only thing an
 * approver has to weigh, and a queue that hides it behind a "…" turns approving
 * into clicking.
 *
 * Your own request shows no decide buttons, with a line saying why. The API
 * refuses self-approval regardless — this is so somebody understands the refusal
 * before they hit it rather than after.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { Empty, ErrorBox, Loading, Panel, Pill, type Tone } from '../components/ui'
import {
  type AccessRequest,
  type RequestState,
  approveAccessRequest,
  denyAccessRequest,
  fetchGroups,
  fetchMe,
  fetchMyRequests,
  fetchRequestQueue,
  raiseAccessRequest,
  withdrawAccessRequest,
} from '../lib/api'

const FIELD =
  'rounded-sm border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'

function when(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : '—'
}

function stateTone(state: RequestState): Tone {
  if (state === 'approved') return 'ok'
  if (state === 'denied') return 'bad'
  if (state === 'pending') return 'warn'
  return 'muted'
}

/** What happened, in words, rather than just the state name. */
function outcome(request: AccessRequest): string {
  if (request.state === 'pending') return 'waiting for a decision'
  if (request.state === 'withdrawn') return `withdrawn ${when(request.decided_at)}`
  if (request.state === 'cancelled') return request.decision_note ?? 'cancelled'
  return `${request.state} by ${request.decided_by_label ?? 'somebody'} on ${when(
    request.decided_at,
  )}`
}

function DecideForm({ request, onDone }: { request: AccessRequest; onDone: () => void }) {
  const [note, setNote] = useState('')
  const [until, setUntil] = useState('')

  const body = () => ({
    note: note.trim() || null,
    // A date input gives a bare day. End of that day is what somebody means by
    // "until the 30th".
    expires_at: until ? new Date(`${until}T23:59:59`).toISOString() : null,
  })

  const approve = useMutation({
    mutationFn: () => approveAccessRequest(request.id, body()),
    onSuccess: onDone,
  })
  const deny = useMutation({
    mutationFn: () => denyAccessRequest(request.id, { note: note.trim() || null }),
    onSuccess: onDone,
  })

  const busy = approve.isPending || deny.isPending

  return (
    <div className="flex flex-col gap-2 border-t border-slate-200 pt-3 dark:border-slate-800">
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-1 flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">What you decided, and why</span>
          <input
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Agreed with their manager. Ends with the quarter."
            className={FIELD}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">Until (optional)</span>
          <input
            type="date"
            value={until}
            onChange={(event) => setUntil(event.target.value)}
            className={FIELD}
          />
        </label>
      </div>

      {!until ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          No end date means this access is permanent. Most requests are for a piece of work
          that finishes.
        </p>
      ) : null}

      {approve.isError ? <ErrorBox error={approve.error} /> : null}
      {deny.isError ? <ErrorBox error={deny.error} /> : null}

      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => approve.mutate()}
          disabled={busy}
          className="rounded-sm border border-emerald-600 px-3 py-1 text-sm text-emerald-700 disabled:opacity-50 dark:border-emerald-500 dark:text-emerald-400"
        >
          {approve.isPending ? 'Approving…' : 'Approve'}
        </button>
        <button
          type="button"
          onClick={() => deny.mutate()}
          disabled={busy}
          className="rounded-sm border border-rose-400 px-3 py-1 text-sm text-rose-700 disabled:opacity-50 dark:border-rose-800 dark:text-rose-400"
        >
          {deny.isPending ? 'Denying…' : 'Deny'}
        </button>
      </div>
    </div>
  )
}

function RequestCard({
  request,
  myUserId,
  canDecide,
  onChanged,
}: {
  request: AccessRequest
  myUserId: string | undefined
  canDecide: boolean
  onChanged: () => void
}) {
  const mine = request.requester_id === myUserId
  const withdraw = useMutation({
    mutationFn: () => withdrawAccessRequest(request.id),
    onSuccess: onChanged,
  })

  return (
    <li className="flex flex-col gap-2 border-b border-slate-100 py-4 last:border-0 dark:border-slate-800/60">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="font-medium">
          {request.requester_label} → {request.group_label}
        </span>
        <Pill tone={stateTone(request.state)}>{request.state}</Pill>
      </div>

      {/* Full width, never truncated. It is the only thing an approver can weigh. */}
      <p className="rounded-sm bg-slate-50 px-3 py-2 text-sm whitespace-pre-wrap dark:bg-slate-950">
        {request.reason}
      </p>

      <p className="text-xs text-slate-500 dark:text-slate-400">
        Asked {when(request.created_at)} · {outcome(request)}
        {request.expires_at ? ` · access ends ${when(request.expires_at)}` : ''}
      </p>

      {/* Skipped when the note is already the outcome line above — for a
          cancellation the note is the explanation, and printing it twice reads as
          though two separate things happened. */}
      {request.decision_note && request.state !== 'cancelled' ? (
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Decision note: {request.decision_note}
        </p>
      ) : null}

      {withdraw.isError ? <ErrorBox error={withdraw.error} /> : null}

      {request.state === 'pending' && mine ? (
        <div className="flex flex-col gap-1">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            This is your own request, so you can&apos;t decide it — somebody else has to look
            at it.
          </p>
          <button
            type="button"
            onClick={() => withdraw.mutate()}
            disabled={withdraw.isPending}
            className="self-start rounded-sm border border-slate-300 px-2 py-1 text-xs disabled:opacity-40 dark:border-slate-700"
          >
            {withdraw.isPending ? 'Withdrawing…' : 'Withdraw it'}
          </button>
        </div>
      ) : null}

      {request.state === 'pending' && canDecide && !mine ? (
        <DecideForm request={request} onDone={onChanged} />
      ) : null}
    </li>
  )
}

function AskForm({ onDone }: { onDone: () => void }) {
  const [groupId, setGroupId] = useState('')
  const [reason, setReason] = useState('')

  const groups = useQuery({
    queryKey: ['groups', 'for-requests'],
    queryFn: () => fetchGroups({ limit: 200 }),
  })

  const ask = useMutation({
    mutationFn: () => raiseAccessRequest({ group_id: groupId, reason: reason.trim() }),
    onSuccess: () => {
      setGroupId('')
      setReason('')
      onDone()
    },
  })

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault()
        if (groupId && reason.trim()) ask.mutate()
      }}
    >
      <label className="flex flex-col gap-1 text-sm">
        <span className="text-slate-500 dark:text-slate-400">What do you need?</span>
        <select
          value={groupId}
          onChange={(event) => setGroupId(event.target.value)}
          className={FIELD}
          required
        >
          <option value="">choose a group…</option>
          {(groups.data?.items ?? []).map((group) => (
            <option key={group.id} value={group.id}>
              {group.name}
            </option>
          ))}
        </select>
      </label>

      <label className="flex flex-col gap-1 text-sm">
        <span className="text-slate-500 dark:text-slate-400">Why do you need it?</span>
        <textarea
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          rows={3}
          placeholder="Covering month-end close while Priya is away."
          className={FIELD}
          required
        />
        <span className="text-xs text-slate-500 dark:text-slate-400">
          Whoever decides this will read only what you write here.
        </span>
      </label>

      {ask.isError ? <ErrorBox error={ask.error} /> : null}

      <button
        type="submit"
        disabled={ask.isPending || !groupId || !reason.trim()}
        className="self-start rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
      >
        {ask.isPending ? 'Sending…' : 'Ask for access'}
      </button>
    </form>
  )
}

export default function AccessRequestsPage() {
  const queryClient = useQueryClient()
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })
  const canDecide = me.data?.permissions.includes('groups:write') ?? false
  const canSeeQueue = me.data?.permissions.includes('groups:read') ?? false

  const mine = useQuery({ queryKey: ['my-requests'], queryFn: fetchMyRequests })
  const queue = useQuery({
    queryKey: ['request-queue'],
    queryFn: fetchRequestQueue,
    enabled: canSeeQueue,
  })

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['my-requests'] })
    void queryClient.invalidateQueries({ queryKey: ['request-queue'] })
  }

  return (
    <div className="flex flex-col gap-6">
      {canSeeQueue ? (
        <Panel title={`Waiting for a decision${queue.data ? ` (${queue.data.length})` : ''}`}>
          {queue.isError ? (
            <ErrorBox error={queue.error} />
          ) : queue.isPending ? (
            <Loading />
          ) : queue.data.length === 0 ? (
            <Empty>Nothing waiting.</Empty>
          ) : (
            <>
              <p className="pb-2 text-sm text-slate-600 dark:text-slate-300">
                Oldest first, which is the order they should be worked in.
              </p>
              <ul className="flex flex-col">
                {queue.data.map((request) => (
                  <RequestCard
                    key={request.id}
                    request={request}
                    myUserId={me.data?.id}
                    canDecide={canDecide}
                    onChanged={refresh}
                  />
                ))}
              </ul>
            </>
          )}
        </Panel>
      ) : null}

      <Panel title="Need something?">
        <AskForm onDone={refresh} />
      </Panel>

      <Panel title="What you have asked for">
        {mine.isError ? (
          <ErrorBox error={mine.error} />
        ) : mine.isPending ? (
          <Loading />
        ) : mine.data.length === 0 ? (
          <Empty>You haven&apos;t asked for anything.</Empty>
        ) : (
          <ul className="flex flex-col">
            {mine.data.map((request) => (
              <RequestCard
                key={request.id}
                request={request}
                myUserId={me.data?.id}
                canDecide={false}
                onChanged={refresh}
              />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}
