/** The front page: headline counts plus whether the API and database are alive. */

import { useQuery } from '@tanstack/react-query'

import { Empty, ErrorBox, Loading, Panel, Pill, Row, Stat, type Tone } from '../components/ui'
import { fetchDashboard, fetchLiveness, fetchReadiness } from '../lib/api'

export default function Dashboard() {
  const counts = useQuery({ queryKey: ['dashboard'], queryFn: fetchDashboard })
  const liveness = useQuery({ queryKey: ['liveness'], queryFn: fetchLiveness })
  const readiness = useQuery({
    queryKey: ['readiness'],
    queryFn: fetchReadiness,
    refetchInterval: 10_000,
  })

  const apiTone: Tone = liveness.isPending ? 'muted' : liveness.isError ? 'bad' : 'ok'
  let dbTone: Tone = 'muted'
  if (!readiness.isPending) {
    dbTone = readiness.data?.database === 'ok' ? 'ok' : 'bad'
  }

  return (
    <div className="flex flex-col gap-6">
      <Panel title="Directory">
        {counts.isPending ? (
          <Loading />
        ) : counts.isError ? (
          <ErrorBox error={counts.error} />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <Stat
              label="Users"
              value={counts.data.users}
              hint={`${counts.data.active_users.toLocaleString()} active`}
            />
            <Stat label="Groups" value={counts.data.groups} />
            <Stat
              label="Applications"
              value={counts.data.applications}
              hint={`${counts.data.sso_applications} using SAML`}
            />
            <Stat label="Audit events" value={counts.data.audit_events} />
            <Stat
              label="Deactivated"
              value={counts.data.users - counts.data.active_users}
              hint="kept for their history"
            />
            <Stat label="Access packages" value="—" hint="arrives in P4" />
          </div>
        )}
      </Panel>

      <div className="grid gap-5 sm:grid-cols-2">
        <Panel title="API">
          <dl>
            <Row label="Status">
              <Pill tone={apiTone}>
                {liveness.isPending ? 'checking' : liveness.isError ? 'unreachable' : 'ok'}
              </Pill>
            </Row>
            <Row label="Environment">{liveness.data?.env ?? '—'}</Row>
            <Row label="Version">{liveness.data?.version ?? '—'}</Row>
            <Row label="Build">{liveness.data?.git_sha ?? '—'}</Row>
          </dl>
        </Panel>

        <Panel title="Database">
          <dl>
            <Row label="Status">
              <Pill tone={dbTone}>
                {readiness.isPending ? 'checking' : (readiness.data?.status ?? 'unknown')}
              </Pill>
            </Row>
            <Row label="Postgres">{readiness.data?.database ?? '—'}</Row>
            <Row label="Detail">{readiness.data?.detail ?? 'none'}</Row>
            <Row label="Checked">every 10s</Row>
          </dl>
        </Panel>
      </div>

      {counts.data?.audit_events === 0 ? (
        <Empty>
          No data yet. Run <code>python -m scripts.seed --reset</code> in apps/api.
        </Empty>
      ) : null}
    </div>
  )
}
