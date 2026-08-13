/**
 * The audit log, plus the button that checks nobody has edited it.
 *
 * Paging works by "load more" rather than page numbers because the log uses
 * cursors. There is no page 7 to jump to, and that is on purpose — see
 * iam/api/pagination.py on the backend.
 *
 * The fingerprints are shown deliberately. They are the evidence that the log
 * hasn't been altered, and hiding them would make the whole feature invisible.
 */

import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import {
  Empty,
  ErrorBox,
  Loading,
  Mono,
  Panel,
  Pill,
  TableWrap,
  Td,
  Th,
  type Tone,
} from '../components/ui'
import { type AuditEvent, fetchAuditEvents, verifyAuditChain } from '../lib/api'

const PAGE_SIZE = 50

function outcomeTone(outcome: AuditEvent['outcome']): Tone {
  if (outcome === 'success') return 'ok'
  if (outcome === 'denied') return 'warn'
  return 'bad'
}

export default function AuditPage() {
  // Every page we've loaded so far, appended. The cursor points at where to
  // continue from.
  const [pages, setPages] = useState<AuditEvent[][]>([])
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [expanded, setExpanded] = useState<number | null>(null)

  const page = useQuery({
    queryKey: ['audit', cursor],
    queryFn: async () => {
      const result = await fetchAuditEvents({ cursor, limit: PAGE_SIZE })
      setPages((previous) => [...previous, result.items])
      return result
    },
  })

  const verify = useMutation({ mutationFn: verifyAuditChain })

  const events = pages.flat()
  const result = verify.data

  return (
    <div className="flex flex-col gap-6">
      <Panel
        title="Tamper check"
        action={
          <button
            type="button"
            onClick={() => verify.mutate()}
            disabled={verify.isPending}
            className="rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
          >
            {verify.isPending ? 'Checking…' : 'Run check'}
          </button>
        }
      >
        {verify.isError ? (
          <ErrorBox error={verify.error} />
        ) : result ? (
          <div className="flex flex-col gap-2">
            <Pill tone={result.valid ? 'ok' : 'bad'}>
              {result.valid ? 'Nothing has been altered' : 'Something has been altered'}
            </Pill>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Checked {result.events_checked.toLocaleString()} entries.
              {result.broken_at_id === null || result.broken_at_id === undefined
                ? ''
                : ` Entry ${result.broken_at_id} does not add up: ${result.reason ?? ''}`}
            </p>
          </div>
        ) : (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Walks the whole log and confirms every entry still matches its fingerprint. Editing
            any past entry breaks the chain from that point on.
          </p>
        )}
      </Panel>

      <Panel title="Activity">
        {page.isError ? (
          <ErrorBox error={page.error} />
        ) : events.length === 0 && page.isPending ? (
          <Loading />
        ) : events.length === 0 ? (
          <Empty>Nothing logged yet.</Empty>
        ) : (
          <>
            <TableWrap>
              <table className="w-full border-collapse">
                <thead>
                  <tr>
                    <Th>When</Th>
                    <Th>Who</Th>
                    <Th>What</Th>
                    <Th>Target</Th>
                    <Th>Result</Th>
                    <Th right>Entry</Th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr key={event.id}>
                      <Td>
                        <span className="whitespace-nowrap">
                          {new Date(event.occurred_at).toLocaleString()}
                        </span>
                      </Td>
                      <Td>{event.actor_label}</Td>
                      <Td>
                        <Mono>{event.action}</Mono>
                      </Td>
                      <Td>{event.target_label ?? '—'}</Td>
                      <Td>
                        <Pill tone={outcomeTone(event.outcome)}>{event.outcome}</Pill>
                      </Td>
                      <Td right>
                        <button
                          type="button"
                          onClick={() => setExpanded(expanded === event.id ? null : event.id)}
                          aria-expanded={expanded === event.id}
                          className="font-mono text-xs text-brass-700 underline-offset-2 hover:underline dark:text-brass-400"
                        >
                          #{event.id}
                        </button>
                        {expanded === event.id ? (
                          <dl className="mt-2 flex flex-col gap-1 text-left font-mono text-[0.7rem] break-all text-slate-500 dark:text-slate-400">
                            <div>
                              <dt className="inline">prev: </dt>
                              <dd className="inline">{event.prev_hash}</dd>
                            </div>
                            <div>
                              <dt className="inline">this: </dt>
                              <dd className="inline">{event.hash}</dd>
                            </div>
                            <div>
                              <dt className="inline">detail: </dt>
                              <dd className="inline">{JSON.stringify(event.detail)}</dd>
                            </div>
                          </dl>
                        ) : null}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>

            <div className="flex items-center justify-between gap-4 pt-3 text-sm">
              <span className="text-slate-500 tabular-nums dark:text-slate-400">
                {events.length.toLocaleString()} loaded
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
                <span className="text-slate-500 dark:text-slate-400">End of the log</span>
              )}
            </div>
          </>
        )}
      </Panel>
    </div>
  )
}
