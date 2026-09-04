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
import { Button } from './Button'
import { cx } from '../lib/cx'
import styles from './ApplicationSamlPanels.module.css'
import { Empty, ErrorBox, LinkCell, Mono, Panel, Pill, Row } from './ui'

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
      <Button variant="danger" onClick={() => setConfirming(true)}>
        Remove
      </Button>
    )
  }

  return (
    <span className={styles.confirm}>
      <span className={styles.confirmText}>
        Take away {label}&apos;s access?
      </span>
      <Button variant="danger-solid" onClick={onConfirm} disabled={pending}>
        {pending ? 'Removing…' : 'Yes, remove it'}
      </Button>
      <Button variant="secondary" onClick={() => setConfirming(false)}>
        Cancel
      </Button>
    </span>
  )
}

function GrantForm({ appId, onDone }: { appId: string; onDone: () => void }) {
  const [kind, setKind] = useState<'group' | 'user'>('group')
  const [subject, setSubject] = useState('')
  const [role, setRole] = useState('')
  const [query, setQuery] = useState('')

  // Groups are listed, people are searched, and the difference is not a style
  // choice: there are 44 groups and 1,289 people. A dropdown capped at 200 is the
  // right control for the first and silently hides four fifths of the second — which
  // reads as somebody having left the company rather than as a truncated list.
  const groups = useQuery({
    queryKey: ['groups', 'for-app-access'],
    queryFn: () => fetchGroups({ limit: 200 }),
  })
  const people = useQuery({
    queryKey: ['users', 'for-app-access', query],
    queryFn: () => fetchUsers({ q: query, limit: 10, active: true }),
    enabled: kind === 'user' && query.trim().length >= 2,
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
      className={styles.form}
      onSubmit={(event) => {
        event.preventDefault()
        if (subject) grant.mutate()
      }}
    >
      <div className={styles.formRow}>
        <label className={styles.label}>
          <span className={styles.labelText}>Give access to</span>
          <select
            value={kind}
            onChange={(event) => {
              setKind(event.target.value as 'group' | 'user')
              setSubject('')
            }}
            className={styles.field}
          >
            <option value="group">a group</option>
            <option value="user">one person</option>
          </select>
        </label>

        {kind === 'group' ? (
          <label className={cx(styles.label, styles.labelGrow)}>
            <span className={styles.labelText}>Which group</span>
            <select
              value={subject}
              onChange={(event) => setSubject(event.target.value)}
              className={styles.field}
              required
            >
              <option value="">choose…</option>
              {(groups.data?.items ?? []).map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </select>
          </label>
        ) : (
          <label className={cx(styles.label, styles.labelGrow)}>
            <span className={styles.labelText}>Who</span>
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value)
                // Typing again means the earlier choice is stale. Leaving it selected
                // would let somebody search for one person and grant access to another.
                setSubject('')
              }}
              placeholder="Search by name or login"
              className={styles.field}
            />
            {query.trim().length >= 2 ? (
              <span className={styles.picker}>
                {(people.data?.items ?? []).length === 0 ? (
                  <span className={styles.pickerEmpty}>
                    Nobody active matching that.
                  </span>
                ) : (
                  (people.data?.items ?? []).map((person) => (
                    <button
                      key={person.id}
                      type="button"
                      onClick={() => {
                        setSubject(person.id)
                        setQuery(`${person.display_name} (${person.user_name})`)
                      }}
                      className={cx(
                        styles.pickerOption,
                        subject === person.id && styles.pickerOptionChosen,
                      )}
                    >
                      {person.display_name}{' '}
                      <span className={styles.hint}>
                        {person.user_name}
                      </span>
                    </button>
                  ))
                )}
              </span>
            ) : null}
          </label>
        )}

        <label className={styles.label}>
          <span className={styles.labelText}>Role in the app (optional)</span>
          <input
            value={role}
            onChange={(event) => setRole(event.target.value)}
            placeholder="Employee"
            className={styles.field}
          />
        </label>
      </div>

      {kind === 'group' ? (
        <p className={styles.hint}>
          A group reaches everybody in it now and everybody added to it later, including by an
          access rule. One person reaches one person.
        </p>
      ) : null}

      {grant.isError ? <ErrorBox error={grant.error} /> : null}

      <Button type="submit" variant="accent" disabled={grant.isPending || !subject}>
        {grant.isPending ? 'Granting…' : 'Give access'}
      </Button>
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
          <p className={styles.intro}>
            Read on every login. The entity ID is what an incoming request is matched against,
            and the login response URL is where a signed assertion is posted.
          </p>
        ) : (
          <p className={styles.warning}>
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
          <div className={styles.launch}>
            <a
              href={loginUrl}
              className={styles.launchLink}
            >
              Sign in to it
            </a>
            <p className={styles.hint}>
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
          <ul className={styles.picker}>
            {app.assigned_groups.map((group) => (
              <li
                key={group.id}
                className={styles.row}
              >
                <span>
                  <LinkCell to={`/groups/${group.id}`}>{group.name}</LinkCell>
                  {group.hrms_role ? (
                    <span className={styles.labelText}>
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
          <ul className={styles.picker}>
            {app.assigned_users.map((person) => (
              <li
                key={person.id}
                className={styles.row}
              >
                <span className={styles.personRow}>
                  <LinkCell to={`/users/${person.id}`}>{person.display_name}</LinkCell>
                  <span className={styles.labelText}>{person.user_name}</span>
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
