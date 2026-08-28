/**
 * Who is in a group, and putting people in or taking them out.
 *
 * The group page listed members and offered no way to change them, which left the
 * scalable half of the entitlement model half-built: an application can be granted to
 * a group, but nobody could be put in the group. Access at scale runs through groups,
 * so the console could grant broadly and only revoke one person at a time.
 *
 * Provenance is the part worth understanding
 * ------------------------------------------
 *
 * `group_members.source` records *why* somebody is in a group — a rule worked it out,
 * a provider sent it, somebody asked for it, or a person decided. The rule engine
 * reconciles rather than adds, and it only ever removes memberships it created
 * itself. That is what lets a hand-added member survive the next rule run instead of
 * being tidied away by a system that never knew a human meant it.
 *
 * Adding somebody here records MANUAL, so the engine leaves them alone. Removing
 * somebody the rule put there works too, but the next run will put them back —
 * because the rule still says they belong, and the honest fix is to change the rule.
 * The panel says so rather than letting somebody fight a reconciler by hand.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import {
  type GroupDetail,
  addToGroup,
  fetchUsers,
  removeFromGroup,
} from '../lib/api'
import { Empty, ErrorBox, Panel, Pill } from './ui'

const FIELD =
  'rounded-sm border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'

function AddMember({ group }: { group: GroupDetail }) {
  const [query, setQuery] = useState('')
  const queryClient = useQueryClient()

  // Searched rather than listed. The seeded directory has more than a thousand
  // people, and a dropdown capped at a couple of hundred silently hides most of
  // them — which looks like somebody having left rather than a truncated list.
  const found = useQuery({
    queryKey: ['users', 'for-group', query],
    queryFn: () => fetchUsers({ q: query, limit: 10 }),
    enabled: query.trim().length >= 2,
  })

  const add = useMutation({
    mutationFn: (userId: string) => addToGroup(userId, group.id),
    onSuccess: () => {
      setQuery('')
      void queryClient.invalidateQueries({ queryKey: ['group', group.id] })
      // Their own page lists their groups, and the rules screen counts members.
      void queryClient.invalidateQueries({ queryKey: ['user'] })
      void queryClient.invalidateQueries({ queryKey: ['groups'] })
    },
  })

  const already = new Set(group.members.map((member) => member.id))
  const candidates = (found.data?.items ?? []).filter((person) => !already.has(person.id))

  return (
    <div className="flex flex-col gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
      <label className="flex flex-col gap-1 text-sm">
        <span className="text-slate-500 dark:text-slate-400">Add somebody</span>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search by name or login"
          className={FIELD}
        />
      </label>

      {query.trim().length >= 2 && found.data && candidates.length === 0 ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Nobody matching who is not already in this group.
        </p>
      ) : null}

      {candidates.length > 0 ? (
        <ul className="flex flex-col">
          {candidates.map((person) => (
            <li
              key={person.id}
              className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
            >
              <span>
                {person.display_name}{' '}
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  {person.user_name}
                </span>
              </span>
              <button
                type="button"
                onClick={() => add.mutate(person.id)}
                disabled={add.isPending}
                className="rounded-sm border border-brass-600 px-2 py-1 text-xs text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
              >
                Add
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      <p className="text-xs text-slate-500 dark:text-slate-400">
        Somebody added here counts as put there by a person, so the rules engine will
        not remove them. Everything this group grants reaches them immediately.
      </p>

      {add.isError ? <ErrorBox error={add.error} /> : null}
    </div>
  )
}

function RemoveButton({ group, userId, name }: { group: GroupDetail; userId: string; name: string }) {
  const [confirming, setConfirming] = useState(false)
  const queryClient = useQueryClient()

  const remove = useMutation({
    mutationFn: () => removeFromGroup(userId, group.id),
    onSuccess: () => {
      setConfirming(false)
      void queryClient.invalidateQueries({ queryKey: ['group', group.id] })
      void queryClient.invalidateQueries({ queryKey: ['user'] })
      void queryClient.invalidateQueries({ queryKey: ['groups'] })
    },
  })

  if (!confirming) {
    return (
      <button
        type="button"
        onClick={() => setConfirming(true)}
        className="rounded-sm border border-rose-400 px-2 py-1 text-xs text-rose-700 dark:border-rose-800 dark:text-rose-400"
      >
        Remove
      </button>
    )
  }

  return (
    <span className="flex flex-wrap items-center justify-end gap-2">
      <span className="text-xs text-rose-700 dark:text-rose-400">
        Take {name} out of {group.name}? They lose whatever this group grants.
      </span>
      <button
        type="button"
        onClick={() => remove.mutate()}
        disabled={remove.isPending}
        className="rounded-sm border border-rose-500 bg-rose-600 px-2 py-1 text-xs text-white disabled:opacity-40"
      >
        {remove.isPending ? 'Removing…' : 'Yes, remove'}
      </button>
      <button
        type="button"
        onClick={() => setConfirming(false)}
        className="rounded-sm border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
      >
        Cancel
      </button>
      {remove.isError ? <ErrorBox error={remove.error} /> : null}
    </span>
  )
}

export default function GroupMembers({
  group,
  canWrite,
}: {
  group: GroupDetail
  canWrite: boolean
}) {
  const showingAll = group.members.length >= group.member_count

  return (
    <Panel title={`Members (${group.member_count.toLocaleString()})`}>
      {group.members.length === 0 ? (
        <Empty>No members.</Empty>
      ) : (
        <>
          <ul className="flex flex-col">
            {group.members.map((member) => (
              <li
                key={member.id}
                className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
              >
                <Link
                  to={`/users/${member.id}`}
                  className="text-brass-700 underline-offset-2 hover:underline dark:text-brass-400"
                >
                  {member.display_name}
                </Link>
                <span className="flex items-center gap-3">
                  <Pill tone={member.active ? 'ok' : 'muted'}>
                    {member.active ? 'active' : 'deactivated'}
                  </Pill>
                  {canWrite ? (
                    <RemoveButton
                      group={group}
                      userId={member.id}
                      name={member.display_name}
                    />
                  ) : null}
                </span>
              </li>
            ))}
          </ul>
          {showingAll ? null : (
            <p className="pt-3 text-sm text-slate-500 dark:text-slate-400">
              Showing the first {group.members.length} of{' '}
              {group.member_count.toLocaleString()}.
            </p>
          )}
        </>
      )}

      {canWrite ? <AddMember group={group} /> : null}
    </Panel>
  )
}
