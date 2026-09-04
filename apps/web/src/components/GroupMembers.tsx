/**
 * Who is in a group, and putting people in or taking them out.
 *
 * Adding somebody here is recorded as a person's decision, so the rules engine
 * leaves them alone — it only ever removes memberships it created itself. You can
 * remove somebody a rule put there, but the next run puts them back, since the rule
 * still says they belong. The fix for that is to change the rule.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { Button } from './Button'
import {
  type GroupDetail,
  addToGroup,
  fetchUsers,
  removeFromGroup,
} from '../lib/api'
import styles from './GroupMembers.module.css'
import { Empty, ErrorBox, Panel, Pill } from './ui'

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
    <div className={styles.addMember}>
      <label className={styles.label}>
        <span className={styles.labelText}>Add somebody</span>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search by name or login"
          className={styles.field}
        />
      </label>

      {query.trim().length >= 2 && found.data && candidates.length === 0 ? (
        <p className={styles.hint}>
          Nobody matching who is not already in this group.
        </p>
      ) : null}

      {candidates.length > 0 ? (
        <ul className={styles.list}>
          {candidates.map((person) => (
            <li key={person.id} className={styles.row}>
              <span>
                {person.display_name}{' '}
                <span className={styles.hint}>
                  {person.user_name}
                </span>
              </span>
              <Button
                variant="accent"
                onClick={() => add.mutate(person.id)}
                disabled={add.isPending}
              >
                Add
              </Button>
            </li>
          ))}
        </ul>
      ) : null}

      <p className={styles.hint}>
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
      <Button variant="danger" onClick={() => setConfirming(true)}>
        Remove
      </Button>
    )
  }

  return (
    <span className={styles.confirm}>
      <span className={styles.confirmText}>
        Take {name} out of {group.name}? They lose whatever this group grants.
      </span>
      <Button variant="danger-solid" onClick={() => remove.mutate()} disabled={remove.isPending}>
        {remove.isPending ? 'Removing…' : 'Yes, remove'}
      </Button>
      <Button variant="secondary" onClick={() => setConfirming(false)}>
        Cancel
      </Button>
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
          <ul className={styles.list}>
            {group.members.map((member) => (
              <li key={member.id} className={styles.row}>
                <Link to={`/users/${member.id}`} className={styles.memberLink}>
                  {member.display_name}
                </Link>
                <span className={styles.memberActions}>
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
            <p className={styles.truncated}>
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
