/**
 * The access review: things worth asking about.
 *
 * Not a list of who has what. That is a directory listing, it is already on the
 * Users page, and with a thousand people nobody finds anything by reading it.
 *
 * So this shows findings, worst first, and each one says what to do about it. The
 * empty state is the goal rather than a failure — "nothing to look at" is the
 * answer a review is trying to reach, so it says so plainly instead of showing a
 * shrug.
 *
 * Every finding links to the person it is about, because the next thing anybody
 * wants after reading one is to go and fix it.
 */

import { useQuery } from '@tanstack/react-query'

import { ErrorBox, Loading, Panel, Pill, Stat, type Tone } from '../components/ui'
import { type ReviewFinding, fetchAccessReview } from '../lib/api'
import { Link } from 'react-router-dom'

function severityTone(severity: string): Tone {
  if (severity === 'high') return 'bad'
  if (severity === 'medium') return 'warn'
  return 'muted'
}

function when(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleDateString() : ''
}

function FindingRow({ finding }: { finding: ReviewFinding }) {
  return (
    <li className="flex flex-col gap-1 border-b border-slate-100 py-3 last:border-0 dark:border-slate-800/60">
      <div className="flex flex-wrap items-baseline gap-2">
        <Pill tone={severityTone(finding.severity)}>{finding.severity}</Pill>
        {finding.subject_user_id ? (
          <Link
            to={`/users/${finding.subject_user_id}`}
            className="font-medium text-brass-700 underline-offset-2 hover:underline dark:text-brass-400"
          >
            {finding.subject}
          </Link>
        ) : (
          <span className="font-medium">{finding.subject}</span>
        )}
        {finding.since ? (
          <span className="text-xs text-slate-500 dark:text-slate-400">
            since {when(finding.since)}
          </span>
        ) : null}
      </div>

      <p className="text-sm">{finding.concern}</p>
      <p className="text-sm text-slate-600 dark:text-slate-300">→ {finding.suggested_action}</p>
    </li>
  )
}

export default function AccessReviewPage() {
  const review = useQuery({ queryKey: ['access-review'], queryFn: fetchAccessReview })

  return (
    <div className="flex flex-col gap-6">
      <Panel title="Access review">
        <p className="pb-4 text-sm text-slate-600 dark:text-slate-300">
          Not a list of who has what — that is the Users page. These are the things that
          warrant a question, worst first, each with something you can do about it.
        </p>

        {review.isError ? (
          <ErrorBox error={review.error} />
        ) : review.isPending ? (
          <Loading />
        ) : (
          <div className="flex flex-col gap-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <Stat
                label="Needs attention now"
                value={review.data.counts.high ?? 0}
                hint="Somebody has access they should not"
              />
              <Stat
                label="Cannot be justified"
                value={review.data.counts.medium ?? 0}
                hint="Probably fine, nobody can prove it"
              />
              <Stat label="Worth tidying" value={review.data.counts.low ?? 0} />
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Checked {new Date(review.data.checked_at).toLocaleString()}. Run fresh every time
              this page loads — a cached review is one that reports a problem somebody fixed
              last week.
            </p>
          </div>
        )}
      </Panel>

      {review.data ? (
        <Panel title={`Findings (${review.data.findings.length})`}>
          {review.data.clean ? (
            <div className="flex flex-col gap-2 rounded-sm border border-emerald-500 bg-emerald-50 p-4 text-sm dark:border-emerald-700 dark:bg-emerald-950">
              <p className="font-medium">Nothing to look at.</p>
              <p>
                Every console role has an end date and a reason, no deactivated account holds
                anything, and no request is waiting. This is the state a review is trying to
                reach, not an empty screen.
              </p>
            </div>
          ) : (
            <ul className="flex flex-col">
              {review.data.findings.map((finding, index) => (
                <FindingRow key={`${finding.kind}-${finding.subject}-${index}`} finding={finding} />
              ))}
            </ul>
          )}
        </Panel>
      ) : null}
    </div>
  )
}
