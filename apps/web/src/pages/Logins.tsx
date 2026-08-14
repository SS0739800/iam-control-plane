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

import {
  Dot,
  Empty,
  ErrorBox,
  Loading,
  Mono,
  Panel,
  Pill,
  Row,
  TableWrap,
  Td,
  Th,
  type Tone,
} from '../components/ui'
import {
  type LoginAttempt,
  fetchIdentityProviders,
  fetchLoginAttempt,
  fetchLoginAttempts,
} from '../lib/api'

const PAGE_SIZE = 25

type OutcomeFilter = 'all' | 'success' | 'failure'

function outcomeTone(outcome: LoginAttempt['outcome']): Tone {
  return outcome === 'success' ? 'ok' : 'bad'
}

/** The ten checks, in the order they ran. */
function Checklist({ attempt }: { attempt: LoginAttempt }) {
  if (attempt.checks.length === 0) {
    return (
      <p className="text-sm text-slate-500 dark:text-slate-400">
        No checks ran — the response could not be read at all, so there was nothing to check.
      </p>
    )
  }

  return (
    <ul className="flex flex-col gap-1.5">
      {attempt.checks.map((check) => (
        <li key={check.name} className="flex items-start gap-2 text-sm">
          <span className="mt-1.5">
            <Dot tone={check.passed ? 'ok' : 'bad'} />
          </span>
          <span>
            <span className="font-mono text-xs">{check.name}</span>
            <span className="text-slate-500 dark:text-slate-400"> — {check.detail}</span>
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
      <p className="text-sm text-slate-500 dark:text-slate-400">
        Nothing was kept. Only failed logins keep the document — one that passed every check has
        nothing to look at.
      </p>
    )
  }

  return (
    <div className="flex flex-col gap-2">
      {detail.data?.response_truncated ? (
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Cut short. Only the first 32 KB was kept.
        </p>
      ) : null}
      <pre className="max-h-96 overflow-auto rounded-sm bg-slate-100 p-3 font-mono text-[0.7rem] leading-relaxed whitespace-pre-wrap dark:bg-slate-950">
        {xml}
      </pre>
      <p className="text-xs text-slate-500 dark:text-slate-400">
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
    <div className="flex flex-col gap-6">
      <Panel title="What this shows">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Every sign-in attempt, with all ten checks it had to pass. This is a view over the audit
          log rather than a table of its own, so nothing here can be edited or deleted and the
          tamper check covers it.
        </p>
      </Panel>

      <Panel
        title="Sign-in attempts"
        action={
          <span className="flex flex-wrap gap-2">
            <label className="flex items-center gap-1.5 text-sm">
              <span className="text-slate-500 dark:text-slate-400">Outcome</span>
              <select
                value={outcome}
                onChange={(event) =>
                  refilter(() => setOutcome(event.target.value as OutcomeFilter))
                }
                className="rounded-sm border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
              >
                <option value="all">All</option>
                <option value="failure">Refused</option>
                <option value="success">Accepted</option>
              </select>
            </label>
            <label className="flex items-center gap-1.5 text-sm">
              <span className="text-slate-500 dark:text-slate-400">Provider</span>
              <select
                value={idp}
                onChange={(event) => refilter(() => setIdp(event.target.value))}
                className="rounded-sm border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
              >
                <option value="all">All</option>
                {(providers.data ?? []).map((provider) => (
                  <option key={provider.slug} value={provider.slug}>
                    {provider.slug}
                  </option>
                ))}
              </select>
            </label>
          </span>
        }
      >
        {page.isError ? (
          <ErrorBox error={page.error} />
        ) : attempts.length === 0 && page.isPending ? (
          <Loading />
        ) : attempts.length === 0 ? (
          <Empty>
            No sign-in attempts yet. Start one at <Mono>/saml/login?idp=authentik</Mono>.
          </Empty>
        ) : (
          <>
            <TableWrap>
              <table className="w-full border-collapse">
                <thead>
                  <tr>
                    <Th>When</Th>
                    <Th>Who</Th>
                    <Th>Provider</Th>
                    <Th>Result</Th>
                    <Th>Failed</Th>
                    <Th right>Entry</Th>
                  </tr>
                </thead>
                <tbody>
                  {attempts.map((attempt) => (
                    <tr key={attempt.id}>
                      <Td>
                        <span className="whitespace-nowrap">
                          {new Date(attempt.occurred_at).toLocaleString()}
                        </span>
                      </Td>
                      <Td>{attempt.who}</Td>
                      <Td>
                        <Mono>{attempt.idp ?? '—'}</Mono>
                      </Td>
                      <Td>
                        <Pill tone={outcomeTone(attempt.outcome)}>
                          {attempt.outcome === 'success' ? 'accepted' : 'refused'}
                        </Pill>
                      </Td>
                      <Td>
                        {attempt.failed_checks.length === 0 ? (
                          <span className="text-slate-400 dark:text-slate-500">—</span>
                        ) : (
                          <Mono>{attempt.failed_checks.join(', ')}</Mono>
                        )}
                      </Td>
                      <Td right>
                        <button
                          type="button"
                          onClick={() =>
                            setExpanded(expanded === attempt.id ? null : attempt.id)
                          }
                          aria-expanded={expanded === attempt.id}
                          className="font-mono text-xs text-brass-700 underline-offset-2 hover:underline dark:text-brass-400"
                        >
                          #{attempt.id}
                        </button>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>

            {expanded === null ? null : (
              <ExpandedAttempt attempt={attempts.find((row) => row.id === expanded)!} />
            )}

            <div className="flex items-center justify-between gap-4 pt-3 text-sm">
              <span className="text-slate-500 tabular-nums dark:text-slate-400">
                {attempts.length.toLocaleString()} loaded
              </span>
              {page.data?.next_cursor ? (
                <button
                  type="button"
                  onClick={() => setCursor(page.data.next_cursor ?? undefined)}
                  disabled={page.isFetching}
                  className="rounded-sm border border-slate-300 px-2 py-1 disabled:opacity-40 dark:border-slate-700"
                >
                  {page.isFetching ? 'Loading…' : 'Load more'}
                </button>
              ) : (
                <span className="text-slate-500 dark:text-slate-400">End of the list</span>
              )}
            </div>
          </>
        )}
      </Panel>
    </div>
  )
}

function ExpandedAttempt({ attempt }: { attempt: LoginAttempt }) {
  return (
    <div className="mt-4 flex flex-col gap-4 border-t border-slate-200 pt-4 dark:border-slate-800">
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

      <section className="flex flex-col gap-2">
        <h3 className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
          Checks
        </h3>
        <Checklist attempt={attempt} />
      </section>

      <section className="flex flex-col gap-2">
        <h3 className="font-mono text-xs tracking-[0.14em] text-slate-500 uppercase dark:text-slate-400">
          What arrived
        </h3>
        <Assertion eventId={attempt.id} />
      </section>
    </div>
  )
}
