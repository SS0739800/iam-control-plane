/**
 * The SAML side of an application: how it is wired to us, and who may use it.
 *
 * Split out of Applications.tsx because it is the part with buttons. The rest of
 * that page reads; this writes.
 *
 * Two things it deliberately shows rather than hides.
 *
 * The launch link is offered even when the ACS URL points somewhere that does not
 * resolve, which is true of every seeded application. Clicking it produces a real
 * signed assertion posted to an address nothing answers — and that is worth being
 * able to do, because the assertion is visible in the audit log and the sign-in
 * inspector either way. Hiding the button would hide the only way to see it.
 *
 * Removing access asks first. It takes something away from a real person, and it is
 * the same lesson as the provisioning tokens: one stray click should not do that.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import {
  type ApplicationDetail,
  fetchGroups,
  fetchUsers,
  grantAppAccessToGroup,
  grantAppAccessToUser,
  revokeAppAccessFromGroup,
  revokeAppAccessFromUser,
} from '../lib/api'
import { Empty, ErrorBox, LinkCell, Mono, Panel, Pill, Row } from './ui'

const FIELD =
  'rounded-sm border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'

/** Whether this application is wired up enough for a login to be possible. */
function readiness(app: ApplicationDetail): { ready: boolean; missing: string[] } {
  const missing: string[] = []
  if (!app.entity_id) missing.push('entity ID')
  if (!app.acs_url) missing.push('login response URL')
  return { ready: missing.length === 0, missing }
}

function RemoveButton({
  label,
  onConfirm,
  pending,
}: {
  label: string
  onConfirm: () => void
  pending: boolean
}) {
  const [confirming, setConfirming] = useState(false)

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
        Take away {label}&apos;s access?
      </span>
      <button
        type="button"
        onClick={onConfirm}
        disabled={pending}
        className="rounded-sm border border-rose-500 bg-rose-600 px-2 py-1 text-xs text-white disabled:opacity-40"
      >
        {pending ? 'Removing…' : 'Yes, remove it'}
      </button>
      <button
        type="button"
        onClick={() => setConfirming(false)}
        className="rounded-sm border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
      >
        Cancel
      </button>
    </span>
  )
}

function GrantForm({ appId, onDone }: { appId: string; onDone: () => void }) {
  const [kind, setKind] = useState<'group' | 'user'>('group')
  const [subject, setSubject] = useState('')
  const [role, setRole] = useState('')

  const groups = useQuery({
    queryKey: ['groups', 'for-app-access'],
    queryFn: () => fetchGroups({ limit: 200 }),
  })
  const users = useQuery({
    queryKey: ['users', 'for-app-access'],
    queryFn: () => fetchUsers({ limit: 200, active: true }),
  })

  const grant = useMutation({
    mutationFn: () =>
      kind === 'group'
        ? grantAppAccessToGroup(appId, subject, role || undefined)
        : grantAppAccessToUser(appId, subject, role || undefined),
    onSuccess: () => {
      setSubject('')
      setRole('')
      onDone()
    },
  })

  return (
    <form
      className="flex flex-col gap-3 border-t border-slate-200 pt-4 dark:border-slate-800"
      onSubmit={(event) => {
        event.preventDefault()
        if (subject) grant.mutate()
      }}
    >
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">Give access to</span>
          <select
            value={kind}
            onChange={(event) => {
              setKind(event.target.value as 'group' | 'user')
              setSubject('')
            }}
            className={FIELD}
          >
            <option value="group">a group</option>
            <option value="user">one person</option>
          </select>
        </label>

        <label className="flex flex-1 flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">
            {kind === 'group' ? 'Which group' : 'Who'}
          </span>
          <select
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
            className={FIELD}
            required
          >
            <option value="">choose…</option>
            {kind === 'group'
              ? (groups.data?.items ?? []).map((group) => (
                  <option key={group.id} value={group.id}>
                    {group.name}
                  </option>
                ))
              : (users.data?.items ?? []).map((person) => (
                  <option key={person.id} value={person.id}>
                    {person.display_name} ({person.user_name})
                  </option>
                ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">Role in the app (optional)</span>
          <input
            value={role}
            onChange={(event) => setRole(event.target.value)}
            placeholder="Employee"
            className={FIELD}
          />
        </label>
      </div>

      {kind === 'group' ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          A group reaches everybody in it now and everybody added to it later, including by an
          access rule. One person reaches one person.
        </p>
      ) : null}

      {grant.isError ? <ErrorBox error={grant.error} /> : null}

      <button
        type="submit"
        disabled={grant.isPending || !subject}
        className="self-start rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
      >
        {grant.isPending ? 'Granting…' : 'Give access'}
      </button>
    </form>
  )
}

/**
 * How one application is wired to us as a SAML service provider.
 *
 * Genuinely protocol-specific, which is why it is the half that stayed behind the
 * `protocol === 'saml2'` check. Who has access is not, and now lives in
 * ApplicationAccessPanels below.
 *
 * Takes no `canWrite`: everything here is read-only. Changing how an application is
 * wired means pasting new metadata, which is a different form on the list page.
 */
export function ApplicationSamlPanels({ app }: { app: ApplicationDetail }) {
  const { ready, missing } = readiness(app)
  const loginUrl = `${window.location.origin}/idp/sso/${app.slug}`

  return (
    <>
      <Panel title="How this application is wired to us">
        {ready ? (
          <p className="pb-3 text-sm text-slate-600 dark:text-slate-300">
            Read on every login. The entity ID is what an incoming request is matched against,
            and the login response URL is where a signed assertion is posted.
          </p>
        ) : (
          <p className="pb-3 text-sm text-amber-700 dark:text-amber-400">
            Not wired up yet — no {missing.join(' and no ')}. Logins for this application are
            refused until its metadata is registered.
          </p>
        )}

        <dl>
          <Row label="Entity ID">
            <Mono>{app.entity_id ?? '—'}</Mono>
          </Row>
          <Row label="Login response URL">
            <Mono>{app.acs_url ?? '—'}</Mono>
          </Row>
          <Row label="Logout URL">
            <Mono>{app.slo_url ?? '—'}</Mono>
          </Row>
          <Row label="Its certificate">
            {app.signing_cert ? 'on file — it signs what it sends us' : 'none, which is normal'}
          </Row>
          <Row label="Sign-in link">
            {ready ? <Mono>{loginUrl}</Mono> : '—'}
          </Row>
        </dl>

        {ready ? (
          <div className="flex flex-col gap-2 pt-3">
            <a
              href={loginUrl}
              className="self-start rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 dark:border-brass-400 dark:text-brass-400"
            >
              Sign in to it
            </a>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Issues a real signed assertion and posts it to the address above. For a seeded
              application that address does not resolve, so nothing receives it — the assertion
              still appears in the audit log and the sign-in inspector, which is the point.
            </p>
          </div>
        ) : null}
      </Panel>
    </>
  )
}


/**
 * Who has access to an application, and how to change it.
 *
 * Split out of ApplicationSamlPanels, where it lived until a deployment found the
 * consequence: the whole component was rendered only for `protocol === 'saml2'`, so an
 * application we merely provision into — the HRMS, which is scim2 and has no SSO at all
 * — offered no way to give anybody access to it. Access is not a SAML concept and had
 * no business being filed under one.
 *
 * Rendered for every application now. The SAML panel above it is the part that really
 * is protocol-specific.
 *
 * Known limitation, pre-dating the split: the pickers below load 200 groups and 200
 * people and put them in dropdowns. The seeded directory has 1,284 people, so most of
 * them cannot be chosen. Fine in production, where the directory is small; wrong in
 * general, and a search box is the fix.
 */
export function ApplicationAccessPanels({
  app,
  canWrite,
}: {
  app: ApplicationDetail
  canWrite: boolean
}) {
  const queryClient = useQueryClient()
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['application', app.id] })
    // The counts on the list page and the provisioning screen both move when access
    // does, and a stale number there reads as a bug rather than as a cache.
    void queryClient.invalidateQueries({ queryKey: ['applications'] })
    void queryClient.invalidateQueries({ queryKey: ['provisioning-targets'] })
  }

  const removeUser = useMutation({
    mutationFn: (userId: string) => revokeAppAccessFromUser(app.id, userId),
    onSuccess: refresh,
  })
  const removeGroup = useMutation({
    mutationFn: (groupId: string) => revokeAppAccessFromGroup(app.id, groupId),
    onSuccess: refresh,
  })

  return (
    <>
      <Panel title={`Access via groups (${app.assigned_groups.length})`}>
        {app.assigned_groups.length === 0 ? (
          <Empty>No groups grant access to this application.</Empty>
        ) : (
          <ul className="flex flex-col">
            {app.assigned_groups.map((group) => (
              <li
                key={group.id}
                className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
              >
                <span>
                  <LinkCell to={`/groups/${group.id}`}>{group.name}</LinkCell>
                  {group.hrms_role ? (
                    <span className="text-slate-500 dark:text-slate-400">
                      {' '}
                      · HRMS role {group.hrms_role}
                    </span>
                  ) : null}
                </span>
                {canWrite ? (
                  <RemoveButton
                    label={`everybody in ${group.name}`}
                    pending={removeGroup.isPending}
                    onConfirm={() => removeGroup.mutate(group.id)}
                  />
                ) : null}
              </li>
            ))}
          </ul>
        )}
        {removeGroup.isError ? <ErrorBox error={removeGroup.error} /> : null}
      </Panel>

      <Panel title={`Access given directly (${app.assigned_users.length})`}>
        {app.assigned_users.length === 0 ? (
          <Empty>Nobody has been given access directly.</Empty>
        ) : (
          <ul className="flex flex-col">
            {app.assigned_users.map((person) => (
              <li
                key={person.id}
                className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
              >
                <span className="flex flex-wrap items-baseline gap-2">
                  <LinkCell to={`/users/${person.id}`}>{person.display_name}</LinkCell>
                  <span className="text-slate-500 dark:text-slate-400">{person.user_name}</span>
                  {!person.active ? <Pill tone="muted">deactivated</Pill> : null}
                </span>
                {canWrite ? (
                  <RemoveButton
                    label={person.display_name}
                    pending={removeUser.isPending}
                    onConfirm={() => removeUser.mutate(person.id)}
                  />
                ) : null}
              </li>
            ))}
          </ul>
        )}
        {removeUser.isError ? <ErrorBox error={removeUser.error} /> : null}

        {canWrite ? <GrantForm appId={app.id} onDone={refresh} /> : null}
      </Panel>
    </>
  )
}
