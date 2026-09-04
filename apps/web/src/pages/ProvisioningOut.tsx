/**
 * The other direction: systems we push accounts into.
 *
 * The inbound page manages who may write to us. This one manages where we write, and
 * the two are different enough to be different screens — a token we accept is hashed
 * and shown once, a token we send is encrypted and never shown at all.
 *
 * What the page is really for is the orphan count. Everything else here can be read
 * from a log: an account was created, a change went out, somebody was switched off.
 * An orphan is a person we tried to remove from a downstream and could not, which
 * means they still have access somewhere and nobody would know. That number is the
 * reason this screen exists, and it is why it is the one thing coloured red when it is
 * not zero.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { Button } from '../components/Button'
import { cx } from '../lib/cx'
import styles from './ProvisioningOut.module.css'
import { PageHeader } from '../components/PageHeader'
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
  type ApplicationSummary,
  type ProvisioningLink,
  type ProvisioningTarget,
  type SyncResult,
  createProvisioningTarget,
  deleteProvisioningTarget,
  fetchApplications,
  fetchProvisioningAccounts,
  fetchProvisioningTargets,
  probeProvisioningTarget,
  syncProvisioningTarget,
  updateProvisioningTarget,
} from '../lib/api'

function when(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : '—'
}

/**
 * How a target is doing, in one word.
 *
 * A target that has never been synced is not the same as one that is fine, and calling
 * both of them "ok" would hide the more interesting case: something registered months
 * ago that nobody ever pointed at anything.
 *
 * "changes waiting" was added after watching this lie. A leaver had been marked in the
 * console and the downstream had not been told, because the sync ran twenty-eight
 * seconds before the deactivation arrived — and the panel said "in step" throughout.
 * Every count beside it described what the *links* were; none answered whether
 * anything had changed since the last push. With no background worker nothing pushes
 * on its own, so the one word on this panel was telling somebody a leaver was
 * offboarded everywhere when they were not.
 *
 * It sits below the failures on purpose. Work waiting is ordinary; work that failed
 * needs somebody.
 */
function healthOf(target: ProvisioningTarget): { tone: Tone; label: string } {
  if (!target.enabled) return { tone: 'muted', label: 'paused' }
  if (target.accounts_orphaned > 0) return { tone: 'bad', label: 'orphans' }
  if (target.last_sync_ok === null) return { tone: 'warn', label: 'never synced' }
  if (!target.last_sync_ok) return { tone: 'bad', label: 'last sync failed' }
  if (target.accounts_failed > 0) return { tone: 'warn', label: 'some failures' }
  if (target.accounts_waiting_to_push > 0) return { tone: 'warn', label: 'changes waiting' }
  return { tone: 'ok', label: 'in step' }
}

function linkTone(state: ProvisioningLink['state']): Tone {
  if (state === 'active') return 'ok'
  if (state === 'orphaned' || state === 'failed') return 'bad'
  if (state === 'pending') return 'warn'
  return 'muted'
}

/** What one sync run did, in a sentence a person can read. */
function describeRun(run: SyncResult): string {
  const parts: string[] = []
  if (run.created) parts.push(`${run.created} created`)
  if (run.adopted) parts.push(`${run.adopted} already existed and were linked`)
  if (run.updated) parts.push(`${run.updated} updated`)
  if (run.deactivated) parts.push(`${run.deactivated} switched off`)
  if (run.reactivated) parts.push(`${run.reactivated} switched back on`)
  if (run.failed) parts.push(`${run.failed} failed`)
  if (run.skipped_exhausted) parts.push(`${run.skipped_exhausted} skipped after too many tries`)
  if (parts.length === 0) return `Nothing needed doing. ${run.unchanged} already in step.`
  return `${parts.join(', ')}. ${run.unchanged} already in step.`
}

// --------------------------------------------------------------- registering

function RegisterForm({ onDone }: { onDone: () => void }) {
  const [applicationId, setApplicationId] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [token, setToken] = useState('')
  const queryClient = useQueryClient()

  const applications = useQuery({
    queryKey: ['applications', 'for-targets'],
    // Enough to cover every application in the seeded directory. A target is
    // registered once, by hand, so a picker is the right shape here and a paged one
    // would be worse.
    queryFn: () => fetchApplications({ limit: 200 }),
  })

  const register = useMutation({
    mutationFn: () =>
      createProvisioningTarget({
        application_id: applicationId,
        base_url: baseUrl.trim(),
        token,
        enabled: true,
      }),
    onSuccess: () => {
      setApplicationId('')
      setBaseUrl('')
      setToken('')
      void queryClient.invalidateQueries({ queryKey: ['provisioning-targets'] })
      onDone()
    },
  })

  const options: ApplicationSummary[] = applications.data?.items ?? []
  const ready = applicationId !== '' && baseUrl.trim() !== '' && token !== ''

  return (
    <form
      className={styles.form}
      onSubmit={(event) => {
        event.preventDefault()
        if (ready) register.mutate()
      }}
    >
      <div className={styles.formRow}>
        <label className={cx(styles.label, styles.labelOne)}>
          <span className={styles.labelText}>Application</span>
          <select
            value={applicationId}
            onChange={(event) => setApplicationId(event.target.value)}
            required
            className={styles.field}
          >
            <option value="">Choose one…</option>
            {options.map((application) => (
              <option key={application.id} value={application.id}>
                {application.name}
              </option>
            ))}
          </select>
        </label>
        <label className={cx(styles.label, styles.labelTwo)}>
          <span className={styles.labelText}>Its SCIM root</span>
          <input
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
            placeholder="http://hrms:8000/scim/v2"
            required
            className={styles.field}
          />
        </label>
      </div>

      <label className={styles.label}>
        <span className={styles.labelText}>The token it issued us</span>
        <input
          value={token}
          onChange={(event) => setToken(event.target.value)}
          type="password"
          required
          className={cx(styles.field, styles.fieldMono)}
        />
        <span className={styles.hint}>
          Stored encrypted. No screen and no endpoint can read it back, so keep it wherever
          you keep the rest of your secrets — changing it means sending a new one.
        </span>
      </label>

      <p className={styles.hint}>
        Who gets pushed is whoever has access to the application, directly or through a
        group. There is no second list to keep in step.
      </p>

      {register.isError ? <ErrorBox error={register.error} /> : null}

      <Button
        type="submit"
        variant="accent"
        disabled={register.isPending || !ready}
      >
        {register.isPending ? 'Registering…' : 'Register target'}
      </Button>
    </form>
  )
}

// -------------------------------------------------------------- rotating a token

function RotateForm({ target, onDone }: { target: ProvisioningTarget; onDone: () => void }) {
  const [token, setToken] = useState('')
  const queryClient = useQueryClient()

  const rotate = useMutation({
    mutationFn: () => updateProvisioningTarget(target.id, { token }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['provisioning-targets'] })
      onDone()
    },
  })

  return (
    <form
      className={styles.confirm}
      onSubmit={(event) => {
        event.preventDefault()
        if (token) rotate.mutate()
      }}
    >
      <input
        value={token}
        onChange={(event) => setToken(event.target.value)}
        type="password"
        placeholder="the new token"
        aria-label={`New token for ${target.application_name}`}
        className={cx(styles.field, styles.fieldMonoSmall)}
      />
      <span className={styles.confirmActions}>
        <Button type="submit" variant="accent" disabled={rotate.isPending || !token}>
          {rotate.isPending ? 'Saving…' : 'Save token'}
        </Button>
        <Button variant="secondary" onClick={onDone}>
          Cancel
        </Button>
      </span>
      {rotate.isError ? <ErrorBox error={rotate.error} /> : null}
    </form>
  )
}

// -------------------------------------------------------------------- accounts

function Accounts({ target }: { target: ProvisioningTarget }) {
  const accounts = useQuery({
    queryKey: ['provisioning-accounts', target.id],
    queryFn: () => fetchProvisioningAccounts(target.id),
  })

  if (accounts.isError) return <ErrorBox error={accounts.error} />
  if (accounts.isPending) return <Loading />
  if (accounts.data.length === 0) {
    return <Empty>Nobody has an account there yet. Sync to send the first one.</Empty>
  }

  // Worst first. A page of a thousand fine accounts with four orphans buried in it is
  // a page that hides the only rows worth looking at.
  const order: Record<string, number> = {
    orphaned: 0,
    failed: 1,
    pending: 2,
    active: 3,
    deprovisioned: 4,
  }
  const rows = [...accounts.data].sort(
    (left, right) => (order[left.state] ?? 9) - (order[right.state] ?? 9),
  )

  return (
    <TableWrap>
      <table className={styles.table}>
        <thead>
          <tr>
            <Th>Person</Th>
            <Th>State</Th>
            <Th>Their account there</Th>
            <Th>Last pushed</Th>
            <Th>Trouble</Th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 100).map((link) => (
            <tr key={link.user_id}>
              <Td>
                <span className={styles.name}>{link.display_name}</span>
                <span className={styles.hintBlock}>
                  {link.user_name}
                </span>
              </Td>
              <Td>
                <Pill tone={linkTone(link.state)}>{link.state}</Pill>
                {link.active ? null : (
                  <span className={styles.hintBlock}>
                    inactive with us
                  </span>
                )}
              </Td>
              <Td>{link.remote_id ? <Mono>{link.remote_id}</Mono> : '—'}</Td>
              <Td>
                <span className={styles.whenCell}>{when(link.last_pushed_at)}</span>
              </Td>
              <Td>
                {link.last_error ? (
                  <span className={styles.badText}>
                    {link.last_error}
                    {link.attempts > 1 ? ` (${link.attempts} tries)` : ''}
                  </span>
                ) : (
                  '—'
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 100 ? (
        <p className={styles.hintSpaced}>
          Showing the first 100 of {rows.length}, worst first.
        </p>
      ) : null}
    </TableWrap>
  )
}

// ---------------------------------------------------------------- one target

function TargetPanel({ target }: { target: ProvisioningTarget }) {
  const [open, setOpen] = useState(false)
  const [rotating, setRotating] = useState(false)
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [lastRun, setLastRun] = useState<SyncResult | null>(null)
  const queryClient = useQueryClient()

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['provisioning-targets'] })
    void queryClient.invalidateQueries({ queryKey: ['provisioning-accounts', target.id] })
  }

  const probe = useMutation({ mutationFn: () => probeProvisioningTarget(target.id) })
  const sync = useMutation({
    mutationFn: (force: boolean) => syncProvisioningTarget(target.id, force),
    onSuccess: (run) => {
      setLastRun(run)
      refresh()
    },
  })
  const pause = useMutation({
    mutationFn: () => updateProvisioningTarget(target.id, { enabled: !target.enabled }),
    onSuccess: refresh,
  })
  const remove = useMutation({
    mutationFn: () => deleteProvisioningTarget(target.id),
    onSuccess: () => {
      setConfirmingDelete(false)
      refresh()
    },
  })

  const health = healthOf(target)

  return (
    <Panel
      title={target.application_name}
      action={<Pill tone={health.tone}>{health.label}</Pill>}
    >
      <div className={styles.section}>
        <dl>
          <Row label="Its SCIM root">
            <Mono>{target.base_url}</Mono>
          </Row>
          <Row label="Last sync">
            {when(target.last_sync_at)}
            {target.last_sync_ok === false ? (
              <span className={styles.badBlock}>
                {target.last_error ?? 'it did not say why'}
              </span>
            ) : null}
          </Row>
          {target.address_concession ? (
            <Row label="Allowed with a concession">
              <span className={styles.body}>{target.address_concession}</span>
            </Row>
          ) : null}
        </dl>

        <div className={styles.statGrid}>
          <Stat label="Active" value={target.accounts_active} />
          <Stat
            label="Waiting"
            value={target.accounts_pending}
            hint="entitled, no account there yet"
          />
          <Stat label="Failed" value={target.accounts_failed} />
          <Stat
            label="Orphaned"
            value={target.accounts_orphaned}
            hint="still have access there, and we could not take it away"
          />
          <Stat label="Switched off" value={target.accounts_deprovisioned} />
        </div>

        {target.accounts_waiting_to_push > 0 ? (
          <p className={styles.noticeWarn}>
            {target.accounts_waiting_to_push}{' '}
            {target.accounts_waiting_to_push === 1 ? 'person has' : 'people have'} changes
            this system has not been told about — somebody newly entitled, somebody
            changed, or somebody who has left and still has an account there. Nothing
            pushes on its own, so this stays true until you sync.
          </p>
        ) : null}

        {target.accounts_orphaned > 0 ? (
          <p className={styles.noticeBad}>
            {target.accounts_orphaned} {target.accounts_orphaned === 1 ? 'person' : 'people'} still
            {' '}
            {target.accounts_orphaned === 1 ? 'has' : 'have'} access there and we could not remove
            it. Nothing else on this page matters as much. Syncing again is worth trying; if it
            keeps failing, somebody has to remove them by hand at the other end.
          </p>
        ) : null}

        {lastRun ? (
          <p className={styles.noticeNeutral}>
            {describeRun(lastRun)}
            {lastRun.stopped_early ? (
              <span className={styles.bad}>
                Stopped early: {lastRun.stopped_early}
              </span>
            ) : null}
            <span className={styles.hintBlock}>
              Every audit entry from this run is tagged <Mono>{lastRun.correlation_id}</Mono>.
            </span>
          </p>
        ) : null}

        {probe.data ? (
          <p className={probe.data.reachable ? styles.noticeOk : styles.noticeBad}>
            {probe.data.reachable ? 'It answers and takes our token.' : 'No good: '}
            {probe.data.detail}
          </p>
        ) : null}

        {probe.isError ? <ErrorBox error={probe.error} /> : null}
        {sync.isError ? <ErrorBox error={sync.error} /> : null}
        {pause.isError ? <ErrorBox error={pause.error} /> : null}
        {remove.isError ? <ErrorBox error={remove.error} /> : null}

        <div className={styles.actions}>
          <Button variant="secondary" onClick={() => probe.mutate()} disabled={probe.isPending}>
            {probe.isPending ? 'Checking…' : 'Check it answers'}
          </Button>

          <Button variant="accent" onClick={() => sync.mutate(false)} disabled={sync.isPending || !target.enabled}>
            {sync.isPending ? 'Syncing…' : 'Sync now'}
          </Button>

          {target.accounts_failed > 0 ? (
            <Button variant="secondary" onClick={() => sync.mutate(true)} disabled={sync.isPending || !target.enabled} title="Also retry the ones that have failed too many times to be picked up on their own">
              Retry the given-up ones
            </Button>
          ) : null}

          <Button variant="secondary" onClick={() => setOpen(!open)}>
            {open ? 'Hide accounts' : 'Show accounts'}
          </Button>

          <Button variant="secondary" onClick={() => pause.mutate()} disabled={pause.isPending}>
            {target.enabled ? 'Pause pushing' : 'Resume pushing'}
          </Button>

          {rotating ? null : (
            <Button variant="secondary" onClick={() => setRotating(true)}>
              Replace token
            </Button>
          )}

          <span className={styles.pushRight}>
            {confirmingDelete ? (
              <span className={styles.confirm}>
                <span className={styles.badText}>
                  Stop provisioning this? Nobody loses their account at the other end — this
                  only makes us stop pushing, so anyone with access there keeps it until
                  somebody removes it by hand.
                </span>
                <span className={styles.confirmActions}>
                  <Button variant="danger-solid" onClick={() => remove.mutate()} disabled={remove.isPending}>
                    {remove.isPending ? 'Removing…' : 'Yes, stop'}
                  </Button>
                  <Button variant="secondary" onClick={() => setConfirmingDelete(false)}>
                    Cancel
                  </Button>
                </span>
              </span>
            ) : (
              <Button variant="danger" onClick={() => setConfirmingDelete(true)}>
                Stop provisioning
              </Button>
            )}
          </span>
        </div>

        {sync.isPending ? (
          <p className={styles.hint}>
            This runs while you wait — there is no background worker yet — so a first sync
            against a big directory takes a while. Leave the page open.
          </p>
        ) : null}

        {rotating ? <RotateForm target={target} onDone={() => setRotating(false)} /> : null}

        {open ? <Accounts target={target} /> : null}
      </div>
    </Panel>
  )
}

// ------------------------------------------------------------------ the page

export default function ProvisioningOutPage() {
  const [registering, setRegistering] = useState(false)
  const targets = useQuery({
    queryKey: ['provisioning-targets'],
    queryFn: fetchProvisioningTargets,
  })

  return (
    <div className={styles.page}>
      <PageHeader title="Provisioning out" description="Systems we push accounts into, and whether they are in step." />
      <Panel
        title="Where we push accounts"
        action={
          registering ? null : (
            <Button variant="accent" onClick={() => setRegistering(true)}>
              Register a target
            </Button>
          )
        }
      >
        <div className={styles.section}>
          <p className={styles.mutedText}>
            Granting somebody access to one of these applications gets them an account in the
            system behind it. Losing that access switches the account off rather than deleting
            it, because the system at the other end usually has reasons to keep the record.
          </p>

          {registering ? <RegisterForm onDone={() => setRegistering(false)} /> : null}

          {targets.isError ? (
            <ErrorBox error={targets.error} />
          ) : targets.isPending ? (
            <Loading />
          ) : targets.data.length === 0 ? (
            <Empty>
              Nothing is being provisioned outward yet. Register a target to start pushing
              accounts into a downstream system.
            </Empty>
          ) : null}
        </div>
      </Panel>

      {targets.data?.map((target) => <TargetPanel key={target.id} target={target} />)}

      <Panel title="What is sent, and what is not">
        <dl>
          <Row label="Sent">
            login, display name, given and family name, work email, department, and our own id
            as <Mono>externalId</Mono>
          </Row>
          <Row label="Never sent">
            passwords, session data, audit history, or anything a downstream did not ask for
          </Row>
          <Row label="Leavers">
            <Mono>PATCH active: false</Mono>, not <Mono>DELETE</Mono> — a leaver loses their
            access and keeps their record
          </Row>
          <Row label="Addresses">
            checked when registered, not on every push. Link-local addresses are refused
            outright; private addresses and plain HTTP are allowed outside production and
            recorded as a concession
          </Row>
        </dl>
      </Panel>
    </div>
  )
}
