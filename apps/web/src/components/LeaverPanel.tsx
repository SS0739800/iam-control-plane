/**
 * Marking somebody as having left, and bringing them back.
 *
 * The one lifecycle action the console could not do. `PATCH /api/users/{id}` with
 * `active: false` has existed since P1 and `updateUser` since the client was
 * generated, but nothing ever called it — so the step that actually triggers
 * deprovisioning was reachable only by running a script against the database.
 *
 * That mattered more than a missing button. Deactivating is what `entitled_people`
 * filters on, so it is what makes an account switch off in every downstream system.
 * A console that can grant access and cannot take it away is telling half a story.
 *
 * Why this is not a "delete"
 * --------------------------
 *
 * Nobody is ever deleted here, and the same reasoning runs all the way down: their
 * group memberships, role grants, sign-in history and audit trail stay, because the
 * questions those answer ("who had access to what, and when") outlive the person's
 * employment. Downstream we send `PATCH active: false` rather than `DELETE` for the
 * same reason. Deactivating is the whole of offboarding.
 *
 * What it deliberately does not do
 * --------------------------------
 *
 * It does not sync. Downstream accounts switch off on the next provisioning run, and
 * the panel says so rather than implying the change has already reached the systems
 * it will eventually reach. Pretending otherwise would be the more dangerous lie —
 * somebody reading "access removed" and believing a leaver is locked out everywhere.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { type UserDetail, updateUser } from '../lib/api'
import { ErrorBox, Panel } from './ui'

/**
 * Fields the identity provider owns for somebody it created.
 *
 * The API refuses these with a 409 when `source` is scim, because the next inbound
 * sync would overwrite whatever was typed here. Matching that on this side means the
 * refusal is explained before it happens rather than after.
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
      <div className="flex flex-col gap-4">
        {person.active ? (
          <>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Marking somebody as having left takes away every access they have: they stop
              being counted as entitled to any application, and their accounts in the
              systems we provision into are switched off on the next sync.
            </p>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Nothing is deleted. Their groups, role grants and sign-in history stay, because
              those answer questions that outlive their employment.
            </p>

            {confirming ? (
              <div className="flex flex-col gap-3 rounded-sm border border-rose-300 bg-rose-50 p-3 dark:border-rose-900 dark:bg-rose-950">
                <p className="text-sm text-rose-900 dark:text-rose-200">
                  Mark <strong>{person.display_name}</strong> as having left? They will lose
                  access to {person.applications.length}{' '}
                  {person.applications.length === 1 ? 'application' : 'applications'} and will
                  not be able to sign in.
                </p>
                <p className="text-xs text-rose-800 dark:text-rose-300">
                  Downstream accounts switch off on the next provisioning sync, not now. Run
                  one from <strong>Provisioning out</strong> if it needs to happen
                  immediately.
                </p>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => change.mutate(false)}
                    disabled={change.isPending}
                    className="rounded-sm border border-rose-500 bg-rose-600 px-3 py-1 text-sm text-white disabled:opacity-40"
                  >
                    {change.isPending ? 'Marking…' : 'Yes, they have left'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirming(false)}
                    className="rounded-sm border border-slate-300 px-3 py-1 text-sm dark:border-slate-700"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => setConfirming(true)}
                className="self-start rounded-sm border border-rose-400 px-3 py-1 text-sm text-rose-700 dark:border-rose-800 dark:text-rose-400"
              >
                Mark as having left
              </button>
            )}
          </>
        ) : (
          <>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              They are marked as having left, so they cannot sign in and count as entitled to
              nothing. Bringing them back restores what their groups and grants say they
              should have — it does not restore anything that was taken away separately.
            </p>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Downstream, a rehire gets their old account switched back on rather than a
              second one, because the link to it was kept.
            </p>
            <button
              type="button"
              onClick={() => change.mutate(true)}
              disabled={change.isPending}
              className="self-start rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
            >
              {change.isPending ? 'Bringing them back…' : 'Bring them back'}
            </button>
          </>
        )}

        {managedByProvider ? (
          <p className="text-xs text-slate-500 dark:text-slate-400">
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

