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

import { Button } from '../components/Button'
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
import styles from './Audit.module.css'

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
    <div className={styles.page}>
      <Panel
        title="Tamper check"
        action={
          <Button variant="accent" onClick={() => verify.mutate()} disabled={verify.isPending}>
            {verify.isPending ? 'Checking…' : 'Run check'}
          </Button>
        }
      >
        {verify.isError ? (
          <ErrorBox error={verify.error} />
        ) : result ? (
          <div className={styles.tamperResult}>
            <Pill tone={result.valid ? 'ok' : 'bad'}>
              {result.valid ? 'Nothing has been altered' : 'Something has been altered'}
            </Pill>
            <p className={styles.muted}>
              Checked {result.events_checked.toLocaleString()} entries.
              {result.broken_at_id === null || result.broken_at_id === undefined
                ? ''
                : ` Entry ${result.broken_at_id} does not add up: ${result.reason ?? ''}`}
            </p>
          </div>
        ) : (
          <p className={styles.muted}>
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
              <table className={styles.table}>
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
                        <span className={styles.whenCell}>
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
                          className={styles.entryLink}
                        >
                          #{event.id}
                        </button>
                        {expanded === event.id ? (
                          <dl className={styles.entryDetail}>
                            <div>
                              <dt>prev: </dt>
                              <dd>{event.prev_hash}</dd>
                            </div>
                            <div>
                              <dt>this: </dt>
                              <dd>{event.hash}</dd>
                            </div>
                            <div>
                              <dt>detail: </dt>
                              <dd>{JSON.stringify(event.detail)}</dd>
                            </div>
                          </dl>
                        ) : null}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>

            <div className={styles.footer}>
              <span className={styles.loadedCount}>{events.length.toLocaleString()} loaded</span>
              {page.data?.next_cursor ? (
                <Button
                  variant="secondary"
                  onClick={() => setCursor(page.data.next_cursor ?? undefined)}
                  disabled={page.isFetching}
                >
                  {page.isFetching ? 'Loading…' : 'Load more'}
                </Button>
              ) : (
                <span className={styles.endOfLog}>End of the log</span>
              )}
            </div>
          </>
        )}
      </Panel>
    </div>
  )
}
