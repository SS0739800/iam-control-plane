/**
 * Provisioning: the systems allowed to write to the directory, and what they did.
 *
 * The screen exists because a credential nobody can see or revoke without a
 * database client is not really being managed. Issuing, revoking and "when was
 * this last used" all belong somewhere a person can reach.
 *
 * The token is shown once, in a panel that says so plainly. There is no
 * "show token" anywhere because there is nothing to show: only the hash is
 * stored, and a button offering to reveal it would either be lying or would mean
 * we had kept it.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { Button } from '../components/Button'
import { cx } from '../lib/cx'
import styles from './Provisioning.module.css'
import {
  Empty,
  ErrorBox,
  Loading,
  Mono,
  Panel,
  Pill,
  Row,
  Stat,
  TableWrap,
  Td,
  Th,
  type Tone,
} from '../components/ui'
import {
  type ScimClient,
  type ScimClientIssued,
  fetchProvisioningActivity,
  fetchProvisioningOverview,
  fetchScimClients,
  issueScimClient,
  revokeScimClient,
} from '../lib/api'

function when(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : '—'
}

function clientTone(client: ScimClient): Tone {
  if (client.revoked_at) return 'bad'
  return client.usable ? 'ok' : 'warn'
}

function clientState(client: ScimClient): string {
  if (client.revoked_at) return 'revoked'
  return client.enabled ? 'active' : 'disabled'
}

/** The token, shown once. */
function IssuedToken({ issued, onDone }: { issued: ScimClientIssued; onDone: () => void }) {
  return (
    <div className={styles.issued}>
      <p className={styles.issuedTitle}>Token for {issued.name}</p>
      <pre className={styles.issuedToken}>
        {issued.token}
      </pre>
      <p className={styles.issuedBody}>
        Copy it now. Only its hash is stored, so this is the only time it can be shown — if it is
        lost, issue another and revoke this one.
      </p>
      <p className={styles.issuedNote}>
        The provider wants it as <Mono>Authorization: Bearer &lt;token&gt;</Mono>.
      </p>
      <Button variant="secondary" onClick={onDone}>
        I have copied it
      </Button>
    </div>
  )
}

function IssueForm({ onIssued }: { onIssued: (issued: ScimClientIssued) => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const queryClient = useQueryClient()

  const issue = useMutation({
    mutationFn: () => issueScimClient({ name, description: description || null }),
    onSuccess: (issued) => {
      onIssued(issued)
      setName('')
      setDescription('')
      void queryClient.invalidateQueries({ queryKey: ['scim-clients'] })
      void queryClient.invalidateQueries({ queryKey: ['provisioning-overview'] })
    },
  })

  return (
    <form
      className={styles.form}
      onSubmit={(event) => {
        event.preventDefault()
        if (name.trim()) issue.mutate()
      }}
    >
      <div className={styles.formRow}>
        <label className={cx(styles.label, styles.labelName)}>
          <span className={styles.labelText}>Name</span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="authentik (local)"
            required
            className={styles.field}
          />
        </label>
        <label className={cx(styles.label, styles.labelPurpose)}>
          <span className={styles.labelText}>What it is for</span>
          <input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="Pushes users and groups from authentik"
            className={styles.field}
          />
        </label>
      </div>

      {issue.isError ? <ErrorBox error={issue.error} /> : null}

      <Button type="submit" variant="accent" disabled={issue.isPending || !name.trim()}>
        {issue.isPending ? 'Issuing…' : 'Issue token'}
      </Button>
    </form>
  )
}

export default function ProvisioningPage() {
  const [issued, setIssued] = useState<ScimClientIssued | null>(null)
  // Which token is mid-revoke. Revoking cannot be undone — the row is kept but
  // the credential is dead — so it takes two clicks, and the second one says
  // what is about to break.
  const [confirming, setConfirming] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const overview = useQuery({
    queryKey: ['provisioning-overview'],
    queryFn: fetchProvisioningOverview,
  })
  const clients = useQuery({ queryKey: ['scim-clients'], queryFn: fetchScimClients })
  const activity = useQuery({
    queryKey: ['provisioning-activity'],
    queryFn: () => fetchProvisioningActivity(25),
  })

  const revoke = useMutation({
    mutationFn: (client: ScimClient) => revokeScimClient(client.id, 'revoked from the console'),
    onSuccess: () => {
      setConfirming(null)
      void queryClient.invalidateQueries({ queryKey: ['scim-clients'] })
      void queryClient.invalidateQueries({ queryKey: ['provisioning-overview'] })
    },
  })

  return (
    <div className={styles.page}>
      <Panel title="What the sync owns">
        {overview.isError ? (
          <ErrorBox error={overview.error} />
        ) : overview.isPending ? (
          <Loading />
        ) : (
          <div className={styles.section}>
            <div className={styles.statGrid}>
              <Stat label="People from SCIM" value={overview.data.users_from_scim} />
              <Stat label="Groups from SCIM" value={overview.data.groups_from_scim} />
              <Stat
                label="Arrived by logging in"
                value={overview.data.users_from_login}
                hint="SCIM had not sent them yet"
              />
              <Stat label="Active tokens" value={overview.data.active_clients} />
            </div>
            <p className={styles.muted}>
              Last write from a provisioning system: {when(overview.data.last_sync_at)}
            </p>
          </div>
        )}
      </Panel>

      <Panel title="Provisioning tokens">
        <div className={styles.section}>
          {issued ? <IssuedToken issued={issued} onDone={() => setIssued(null)} /> : null}

          {clients.isError ? (
            <ErrorBox error={clients.error} />
          ) : clients.isPending ? (
            <Loading />
          ) : clients.data.length === 0 ? (
            <Empty>No system can write to the directory yet.</Empty>
          ) : (
            <TableWrap>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <Th>Name</Th>
                    <Th>State</Th>
                    <Th>Last used</Th>
                    <Th>Created</Th>
                    <Th right>{''}</Th>
                  </tr>
                </thead>
                <tbody>
                  {clients.data.map((client) => (
                    <tr key={client.id}>
                      <Td>
                        <span className={styles.clientName}>{client.name}</span>
                        {client.description ? (
                          <span className={styles.clientDetail}>
                            {client.description}
                          </span>
                        ) : null}
                        {client.revoked_reason ? (
                          <span className={styles.clientRevoked}>
                            {client.revoked_reason}
                          </span>
                        ) : null}
                      </Td>
                      <Td>
                        <Pill tone={clientTone(client)}>{clientState(client)}</Pill>
                      </Td>
                      <Td>{when(client.last_used_at)}</Td>
                      <Td>{when(client.created_at)}</Td>
                      <Td right>
                        {client.revoked_at ? null : confirming === client.id ? (
                          <span className={styles.confirm}>
                            <span className={styles.confirmText}>
                              Revoke this? Anything using it stops syncing, and it cannot be
                              undone — you would have to issue a new token.
                            </span>
                            <span className={styles.confirmActions}>
                              <Button
                                variant="danger-solid"
                                onClick={() => revoke.mutate(client)}
                                disabled={revoke.isPending}
                              >
                                {revoke.isPending ? 'Revoking…' : 'Yes, revoke it'}
                              </Button>
                              <Button variant="secondary" onClick={() => setConfirming(null)}>
                                Cancel
                              </Button>
                            </span>
                          </span>
                        ) : (
                          <Button variant="danger" onClick={() => setConfirming(client.id)}>
                            Revoke
                          </Button>
                        )}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}

          {revoke.isError ? <ErrorBox error={revoke.error} /> : null}

          <div className={styles.divider}>
            <IssueForm onIssued={setIssued} />
          </div>
        </div>
      </Panel>

      <Panel title="Recent activity">
        {activity.isError ? (
          <ErrorBox error={activity.error} />
        ) : activity.isPending ? (
          <Loading />
        ) : activity.data.length === 0 ? (
          <Empty>Nothing has been provisioned yet.</Empty>
        ) : (
          <TableWrap>
            <table className={styles.table}>
              <thead>
                <tr>
                  <Th>When</Th>
                  <Th>Client</Th>
                  <Th>What</Th>
                  <Th>Target</Th>
                  <Th>Detail</Th>
                </tr>
              </thead>
              <tbody>
                {activity.data.map((entry) => (
                  <tr key={entry.id}>
                    <Td>
                      <span className={styles.whenCell}>{when(entry.occurred_at)}</span>
                    </Td>
                    <Td>{entry.client ?? '—'}</Td>
                    <Td>
                      <Mono>{entry.action}</Mono>
                    </Td>
                    <Td>{entry.target ?? '—'}</Td>
                    <Td>
                      <span className={styles.labelText}>
                        {entry.summary ?? '—'}
                      </span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Panel>

      <Panel title="Pointing a provider at this">
        <dl>
          <Row label="SCIM base URL">
            <Mono>{window.location.origin}/scim/v2</Mono>
          </Row>
          <Row label="From another container">
            <Mono>http://caddy:8080/scim/v2</Mono>
          </Row>
          <Row label="Authentication">
            <Mono>Authorization: Bearer &lt;token&gt;</Mono>
          </Row>
        </dl>
        <p className={styles.footnote}>
          A provider running in the compose network has to use the second one. Its own{' '}
          <Mono>localhost</Mono> is itself, not this console.
        </p>
      </Panel>
    </div>
  )
}
