/**
 * The login inspector: every sign-in attempt, and why it went the way it did.
 *
 * The ten check results are the whole point of this screen. A login that stops
 * working against a new provider says "the clock is three minutes out" instead of
 * "invalid assertion", and that difference is the reason the checks are ours rather
 * than one library call — see docs/adr/0005-validate-assertions-ourselves.md.
 *
 * Failures are shown expanded by default. Nobody opens this screen to admire the
 * successes.
 */

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { Button } from '../components/Button'
import { DataTable } from '../components/DataTable'
import {
  Dot,
  ErrorBox,
  Loading,
  Mono,
  Panel,
  StatusBadge,
  Row,
  type Tone,
} from '../components/ui'
import {
  type LoginAttempt,
  fetchIdentityProviders,
  fetchLoginAttempt,
  fetchLoginAttempts,
} from '../lib/api'
import styles from './Logins.module.css'
import { PageHeader } from '../components/PageHeader'

const PAGE_SIZE = 25

type OutcomeFilter = 'all' | 'success' | 'failure'

function outcomeTone(outcome: LoginAttempt['outcome']): Tone {
  return outcome === 'success' ? 'ok' : 'bad'
}

/** The ten checks, in the order they ran. */
function Checklist({ attempt }: { attempt: LoginAttempt }) {
  if (attempt.checks.length === 0) {
    return (
      <p className={styles.muted}>
        No checks ran — the response could not be read at all, so there was nothing to check.
      </p>
    )
  }

  return (
    <ul className={styles.checklist}>
      {attempt.checks.map((check) => (
        <li key={check.name} className={styles.checkItem}>
          <span className={styles.checkDot}>
            <Dot tone={check.passed ? 'ok' : 'bad'} />
          </span>
          <span>
            <span className={styles.checkName}>{check.name}</span>
            <span className={styles.checkDetail}> — {check.detail}</span>
          </span>
        </li>
      ))}
    </ul>
  )
}

/** The assertion as it arrived. Only kept for failures. */
function Assertion({ eventId }: { eventId: number }) {
  const detail = useQuery({
    queryKey: ['login-attempt', eventId],
    queryFn: () => fetchLoginAttempt(eventId),
  })

  if (detail.isPending) return <Loading />
  if (detail.isError) return <ErrorBox error={detail.error} />

  const xml = detail.data?.decoded_response
  if (!xml) {
    return (
      <p className={styles.muted}>
        Nothing was kept. Only failed logins keep the document — one that passed every check has
        nothing to look at.
      </p>
    )
  }

  return (
    <div className={styles.assertionBody}>
      {detail.data?.response_truncated ? (
        <p className={styles.truncatedNote}>Cut short. Only the first 32 KB was kept.</p>
      ) : null}
      <pre className={styles.assertionXml}>{xml}</pre>
      <p className={styles.muted}>
        Shown exactly as it arrived, not reformatted. An inspector should show what was sent.
      </p>
    </div>
  )
}

export default function LoginsPage() {
  const [pages, setPages] = useState<LoginAttempt[][]>([])
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [outcome, setOutcome] = useState<OutcomeFilter>('all')
  const [idp, setIdp] = useState<string>('all')
  const [expanded, setExpanded] = useState<number | null>(null)

  const providers = useQuery({ queryKey: ['identity-providers'], queryFn: fetchIdentityProviders })

  const page = useQuery({
    queryKey: ['logins', outcome, idp, cursor],
    queryFn: async () => {
      const result = await fetchLoginAttempts({
        cursor,
        limit: PAGE_SIZE,
        outcome: outcome === 'all' ? undefined : outcome,
        idp: idp === 'all' ? undefined : idp,
      })
      setPages((previous) => [...previous, result.items])
      return result
    },
  })

  /** Changing a filter starts the list again rather than appending to it. */
  function refilter(change: () => void) {
    setPages([])
    setCursor(undefined)
    setExpanded(null)
    change()
  }

  const attempts = pages.flat()

  return (
    <div className={styles.page}>
      <PageHeader title="Sign-ins" description="Every sign-in attempt, and which check turned it away." />
      <Panel title="What this shows">
        <p className={styles.intro}>
          Every sign-in attempt, with all ten checks it had to pass. This is a view over the audit
          log rather than a table of its own, so nothing here can be edited or deleted and the
          tamper check covers it.
        </p>
      </Panel>

      <DataTable
          status={
            page.isError
              ? 'error'
              : attempts.length === 0 && page.isPending
                ? 'pending'
                : 'success'
          }
          error={page.error}
          onRetry={() => void page.refetch()}
          rows={attempts}
          rowKey={(attempt) => String(attempt.id)}
          filters={
            <>
              <label className={styles.filterLabel}>
                <span className={styles.filterLabelText}>Outcome</span>
                <select
                  value={outcome}
                  onChange={(event) =>
                    refilter(() => setOutcome(event.target.value as OutcomeFilter))
                  }
                  className={styles.select}
                >
                  <option value="all">All</option>
                  <option value="failure">Refused</option>
                  <option value="success">Accepted</option>
                </select>
              </label>
              <label className={styles.filterLabel}>
                <span className={styles.filterLabelText}>Provider</span>
                <select
                  value={idp}
                  onChange={(event) => refilter(() => setIdp(event.target.value))}
                  className={styles.select}
                >
                  <option value="all">All</option>
                  {(providers.data ?? []).map((provider) => (
                    <option key={provider.slug} value={provider.slug}>
                      {provider.slug}
                    </option>
                  ))}
                </select>
              </label>
            </>
          }
          empty={{
            title: 'No sign-in attempts yet',
            body: (
              <>
                Start one at <Mono>/saml/login?idp=authentik</Mono>.
              </>
            ),
          }}
          columns={[
            {
              key: 'when',
              header: 'When',
              cell: (attempt) => (
                <span className={styles.whenCell}>
                  {new Date(attempt.occurred_at).toLocaleString()}
                </span>
              ),
            },
            { key: 'who', header: 'Who', cell: (attempt) => attempt.who },
            {
              key: 'provider',
              header: 'Provider',
              cell: (attempt) => <Mono>{attempt.idp ?? '—'}</Mono>,
            },
            {
              key: 'result',
              header: 'Result',
              cell: (attempt) => (
                <StatusBadge tone={outcomeTone(attempt.outcome)}>
                  {attempt.outcome === 'success' ? 'accepted' : 'refused'}
                </StatusBadge>
              ),
            },
            {
              key: 'failed',
              header: 'Failed',
              cell: (attempt) =>
                attempt.failed_checks.length === 0 ? (
                  <span className={styles.mutedCell}>—</span>
                ) : (
                  <Mono>{attempt.failed_checks.join(', ')}</Mono>
                ),
            },
            {
              key: 'entry',
              header: 'Entry',
              numeric: true,
              cell: (attempt) => (
                <button
                  type="button"
                  onClick={() => setExpanded(expanded === attempt.id ? null : attempt.id)}
                  aria-expanded={expanded === attempt.id}
                  className={styles.entryLink}
                >
                  #{attempt.id}
                </button>
              ),
            },
          ]}
          expanded={{
            isOpen: (attempt) => expanded === attempt.id,
            render: (attempt) => <ExpandedAttempt attempt={attempt} />,
          }}
          footer={
            <div className={styles.footer}>
              <span className={styles.loadedCount}>{attempts.length.toLocaleString()} loaded</span>
              {page.data?.next_cursor ? (
                <Button
                  variant="secondary"
                  onClick={() => setCursor(page.data.next_cursor ?? undefined)}
                  disabled={page.isFetching}
                >
                  {page.isFetching ? 'Loading…' : 'Load more'}
                </Button>
              ) : (
                <span className={styles.endOfList}>End of the list</span>
              )}
            </div>
          }
        />
    </div>
  )
}

function ExpandedAttempt({ attempt }: { attempt: LoginAttempt }) {
  return (
    <div className={styles.expanded}>
      <dl>
        <Row label="Audit entry">
          <Mono>#{attempt.id}</Mono>
        </Row>
        {attempt.reason ? <Row label="Why">{attempt.reason}</Row> : null}
        {attempt.directory ? <Row label="Directory">{attempt.directory}</Row> : null}
        {attempt.assertion_id ? (
          <Row label="Assertion id">
            <Mono>{attempt.assertion_id}</Mono>
          </Row>
        ) : null}
        {attempt.session_id ? (
          <Row label="Session">
            <Mono>{attempt.session_id}</Mono>
          </Row>
        ) : null}
      </dl>

      <section className={styles.expandedSection}>
        <h3 className={styles.expandedHeading}>Checks</h3>
        <Checklist attempt={attempt} />
      </section>

      <section className={styles.expandedSection}>
        <h3 className={styles.expandedHeading}>What arrived</h3>
        <Assertion eventId={attempt.id} />
      </section>
    </div>
  )
}
