/**
 * Marking somebody as having left, and bringing them back.
 *
 * Nobody is ever deleted. Their groups, grants, sign-in history and audit trail stay,
 * since "who had access to what, and when" outlives their employment — so offboarding
 * is just setting active to false, here and downstream.
 *
 * It does not sync. Downstream accounts switch off on the next provisioning run, and
 * the panel says so — telling somebody access is already gone everywhere would be the
 * dangerous version.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { Button } from './Button'
import { type UserDetail, updateUser } from '../lib/api'
import styles from './LeaverPanel.module.css'
import { ErrorBox, Panel } from './ui'

/**
 * Fields the identity provider owns for somebody it created. The API refuses these
 * with a 409 when source is scim, since the next inbound sync would overwrite them.
 */
const IDP_OWNED = ['department', 'job_title'] as const

export default function LeaverPanel({
  person,
  canWrite,
}: {
  person: UserDetail
  canWrite: boolean
}) {
  const [confirming, setConfirming] = useState(false)
  const queryClient = useQueryClient()

  const change = useMutation({
    mutationFn: (active: boolean) => updateUser(person.id, { active }),
    onSuccess: () => {
      setConfirming(false)
      void queryClient.invalidateQueries({ queryKey: ['user', person.id] })
      // The directory list and the dashboard both count active people, and a stale
      // number next to a person you have just deactivated reads as a bug.
      void queryClient.invalidateQueries({ queryKey: ['users'] })
      void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  if (!canWrite) return null

  const managedByProvider = person.source === 'scim'

  return (
    <Panel title={person.active ? 'When they leave' : 'They have left'}>
      <div className={styles.body}>
        {person.active ? (
          <>
            <p className={styles.text}>
              Marking somebody as having left takes away every access they have: they stop
              being counted as entitled to any application, and their accounts in the
              systems we provision into are switched off on the next sync.
            </p>
            <p className={styles.text}>
              Nothing is deleted. Their groups, role grants and sign-in history stay, because
              those answer questions that outlive their employment.
            </p>

            {confirming ? (
              <div className={styles.confirm}>
                <p className={styles.confirmText}>
                  Mark <strong>{person.display_name}</strong> as having left? They will lose
                  access to {person.applications.length}{' '}
                  {person.applications.length === 1 ? 'application' : 'applications'} and will
                  not be able to sign in.
                </p>
                <p className={styles.confirmNote}>
                  Downstream accounts switch off on the next provisioning sync, not now. Run
                  one from <strong>Provisioning out</strong> if it needs to happen
                  immediately.
                </p>
                <div className={styles.confirmActions}>
                  <Button
                    variant="danger-solid"
                    onClick={() => change.mutate(false)}
                    disabled={change.isPending}
                  >
                    {change.isPending ? 'Marking…' : 'Yes, they have left'}
                  </Button>
                  <Button variant="secondary" onClick={() => setConfirming(false)}>
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <Button variant="danger" onClick={() => setConfirming(true)}>
                Mark as having left
              </Button>
            )}
          </>
        ) : (
          <>
            <p className={styles.text}>
              They are marked as having left, so they cannot sign in and count as entitled to
              nothing. Bringing them back restores what their groups and grants say they
              should have — it does not restore anything that was taken away separately.
            </p>
            <p className={styles.text}>
              Downstream, a rehire gets their old account switched back on rather than a
              second one, because the link to it was kept.
            </p>
            <Button
              variant="accent"
              onClick={() => change.mutate(true)}
              disabled={change.isPending}
            >
              {change.isPending ? 'Bringing them back…' : 'Bring them back'}
            </Button>
          </>
        )}

        {managedByProvider ? (
          <p className={styles.note}>
            This person came from the identity provider, which owns their{' '}
            {IDP_OWNED.join(' and ').replace('job_title', 'job title')}. Whether they are
            active is ours to decide — but if the provider still sends them, an inbound sync
            can bring them back. Removing them at the provider is what makes it stick.
          </p>
        ) : null}

        {change.isError ? <ErrorBox error={change.error} /> : null}
      </div>
    </Panel>
  )
}

