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
 */
function healthOf(target: ProvisioningTarget): { tone: Tone; label: string } {
  if (!target.enabled) return { tone: 'muted', label: 'paused' }
  if (target.accounts_orphaned > 0) return { tone: 'bad', label: 'orphans' }
  if (target.last_sync_ok === null) return { tone: 'warn', label: 'never synced' }
  if (!target.last_sync_ok) return { tone: 'bad', label: 'last sync failed' }
  if (target.accounts_failed > 0) return { tone: 'warn', label: 'some failures' }
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
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault()
        if (ready) register.mutate()
      }}
    >
      <div className="flex flex-wrap gap-3">
        <label className="flex flex-1 flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">Application</span>
          <select
            value={applicationId}
            onChange={(event) => setApplicationId(event.target.value)}
            required
            className="rounded-sm border border-slate-300 bg-white px-2 py-1 dark:border-slate-700 dark:bg-slate-900"
          >
            <option value="">Choose one…</option>
            {options.map((application) => (
              <option key={application.id} value={application.id}>
                {application.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-[2] flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">Its SCIM root</span>
          <input
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
            placeholder="http://hrms:8000/scim/v2"
            required
            className="rounded-sm border border-slate-300 bg-white px-2 py-1 dark:border-slate-700 dark:bg-slate-900"
          />
        </label>
      </div>

      <label className="flex flex-col gap-1 text-sm">
        <span className="text-slate-500 dark:text-slate-400">The token it issued us</span>
        <input
          value={token}
          onChange={(event) => setToken(event.target.value)}
          type="password"
          required
          className="rounded-sm border border-slate-300 bg-white px-2 py-1 font-mono dark:border-slate-700 dark:bg-slate-900"
        />
        <span className="text-xs text-slate-500 dark:text-slate-400">
          Stored encrypted. No screen and no endpoint can read it back, so keep it wherever
          you keep the rest of your secrets — changing it means sending a new one.
        </span>
      </label>

      <p className="text-xs text-slate-500 dark:text-slate-400">
        Who gets pushed is whoever has access to the application, directly or through a
        group. There is no second list to keep in step.
      </p>

      {register.isError ? <ErrorBox error={register.error} /> : null}

      <button
        type="submit"
        disabled={register.isPending || !ready}
        className="self-start rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
      >
        {register.isPending ? 'Registering…' : 'Register target'}
      </button>
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
      className="flex flex-col items-end gap-1"
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
        className="rounded-sm border border-slate-300 bg-white px-2 py-1 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
      />
      <span className="flex gap-2">
        <button
          type="submit"
          disabled={rotate.isPending || !token}
          className="rounded-sm border border-brass-600 px-2 py-1 text-xs text-brass-700 disabled:opacity-40 dark:border-brass-400 dark:text-brass-400"
        >
          {rotate.isPending ? 'Saving…' : 'Save token'}
        </button>
        <button
          type="button"
          onClick={onDone}
          className="rounded-sm border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
        >
          Cancel
        </button>
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
      <table className="w-full border-collapse">
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
                <span className="font-medium">{link.display_name}</span>
                <span className="block text-xs text-slate-500 dark:text-slate-400">
                  {link.user_name}
                </span>
              </Td>
              <Td>
                <Pill tone={linkTone(link.state)}>{link.state}</Pill>
                {link.active ? null : (
                  <span className="block text-xs text-slate-500 dark:text-slate-400">
                    inactive with us
                  </span>
                )}
              </Td>
              <Td>{link.remote_id ? <Mono>{link.remote_id}</Mono> : '—'}</Td>
              <Td>
                <span className="whitespace-nowrap">{when(link.last_pushed_at)}</span>
              </Td>
              <Td>
                {link.last_error ? (
                  <span className="text-xs text-rose-700 dark:text-rose-400">
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
        <p className="pt-2 text-xs text-slate-500 dark:text-slate-400">
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
      <div className="flex flex-col gap-4">
        <dl>
          <Row label="Its SCIM root">
            <Mono>{target.base_url}</Mono>
          </Row>
          <Row label="Last sync">
            {when(target.last_sync_at)}
            {target.last_sync_ok === false ? (
              <span className="block text-xs text-rose-700 dark:text-rose-400">
                {target.last_error ?? 'it did not say why'}
              </span>
            ) : null}
          </Row>
          {target.address_concession ? (
            <Row label="Allowed with a concession">
              <span className="text-sm">{target.address_concession}</span>
            </Row>
          ) : null}
        </dl>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
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

        {target.accounts_orphaned > 0 ? (
          <p className="rounded-sm border border-rose-300 bg-rose-50 px-3 py-2 text-sm text-rose-900 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-200">
            {target.accounts_orphaned} {target.accounts_orphaned === 1 ? 'person' : 'people'} still
            {' '}
            {target.accounts_orphaned === 1 ? 'has' : 'have'} access there and we could not remove
            it. Nothing else on this page matters as much. Syncing again is worth trying; if it
            keeps failing, somebody has to remove them by hand at the other end.
          </p>
        ) : null}

        {lastRun ? (
          <p className="rounded-sm border border-slate-300 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
            {describeRun(lastRun)}
            {lastRun.stopped_early ? (
              <span className="block text-rose-700 dark:text-rose-400">
                Stopped early: {lastRun.stopped_early}
              </span>
            ) : null}
            <span className="block text-xs text-slate-500 dark:text-slate-400">
              Every audit entry from this run is tagged <Mono>{lastRun.correlation_id}</Mono>.
            </span>
          </p>
        ) : null}

        {probe.data ? (
          <p
            className={`rounded-sm border px-3 py-2 text-sm ${
              probe.data.reachable
                ? 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-200'
                : 'border-rose-300 bg-rose-50 text-rose-900 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-200'
            }`}
          >
            {probe.data.reachable ? 'It answers and takes our token.' : 'No good: '}
            {probe.data.detail}
          </p>
        ) : null}

        {probe.isError ? <ErrorBox error={probe.error} /> : null}
        {sync.isError ? <ErrorBox error={sync.error} /> : null}
        {pause.isError ? <ErrorBox error={pause.error} /> : null}
        {remove.isError ? <ErrorBox error={remove.error} /> : null}

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => probe.mutate()}
            disabled={probe.isPending}
            className="rounded-sm border border-slate-400 px-3 py-1 text-sm disabled:opacity-50 dark:border-slate-600"
          >
            {probe.isPending ? 'Checking…' : 'Check it answers'}
          </button>

          <button
            type="button"
            onClick={() => sync.mutate(false)}
            disabled={sync.isPending || !target.enabled}
            className="rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
          >
            {sync.isPending ? 'Syncing…' : 'Sync now'}
          </button>

          {target.accounts_failed > 0 ? (
            <button
              type="button"
              onClick={() => sync.mutate(true)}
              disabled={sync.isPending || !target.enabled}
              className="rounded-sm border border-slate-400 px-3 py-1 text-sm disabled:opacity-50 dark:border-slate-600"
              title="Also retry the ones that have failed too many times to be picked up on their own"
            >
              Retry the given-up ones
            </button>
          ) : null}

          <button
            type="button"
            onClick={() => setOpen(!open)}
            className="rounded-sm border border-slate-300 px-3 py-1 text-sm dark:border-slate-700"
          >
            {open ? 'Hide accounts' : 'Show accounts'}
          </button>

          <button
            type="button"
            onClick={() => pause.mutate()}
            disabled={pause.isPending}
            className="rounded-sm border border-slate-300 px-3 py-1 text-sm disabled:opacity-50 dark:border-slate-700"
          >
            {target.enabled ? 'Pause pushing' : 'Resume pushing'}
          </button>

          {rotating ? null : (
            <button
              type="button"
              onClick={() => setRotating(true)}
              className="rounded-sm border border-slate-300 px-3 py-1 text-sm dark:border-slate-700"
            >
              Replace token
            </button>
          )}

          <span className="ml-auto">
            {confirmingDelete ? (
              <span className="flex flex-col items-end gap-1">
                <span className="text-xs text-rose-700 dark:text-rose-400">
                  Stop provisioning this? Nobody loses their account at the other end — this
                  only makes us stop pushing, so anyone with access there keeps it until
                  somebody removes it by hand.
                </span>
                <span className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => remove.mutate()}
                    disabled={remove.isPending}
                    className="rounded-sm border border-rose-500 bg-rose-600 px-2 py-1 text-xs text-white disabled:opacity-40"
                  >
                    {remove.isPending ? 'Removing…' : 'Yes, stop'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmingDelete(false)}
                    className="rounded-sm border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
                  >
                    Cancel
                  </button>
                </span>
              </span>
            ) : (
              <button
                type="button"
                onClick={() => setConfirmingDelete(true)}
                className="rounded-sm border border-rose-400 px-3 py-1 text-sm text-rose-700 dark:border-rose-800 dark:text-rose-400"
              >
                Stop provisioning
              </button>
            )}
          </span>
        </div>

        {sync.isPending ? (
          <p className="text-xs text-slate-500 dark:text-slate-400">
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
    <div className="flex flex-col gap-6">
      <Panel
        title="Where we push accounts"
        action={
          registering ? null : (
            <button
              type="button"
              onClick={() => setRegistering(true)}
              className="rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 dark:border-brass-400 dark:text-brass-400"
            >
              Register a target
            </button>
          )
        }
      >
        <div className="flex flex-col gap-4">
          <p className="text-sm text-slate-500 dark:text-slate-400">
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
