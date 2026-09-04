/** The front page: headline counts plus whether the API and database are alive. */

import { useQuery } from '@tanstack/react-query'
import { PageHeader } from '../components/PageHeader'
import { Empty, ErrorBox, Loading, Panel, Pill, Row, Stat, type Tone } from '../components/ui'
import { fetchDashboard, fetchLiveness, fetchReadiness } from '../lib/api'
import styles from './Dashboard.module.css'

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
    <div className={styles.page}>
      <PageHeader
        title="Overview"
        description="What is in the directory, and whether the platform behind it is healthy."
      />

      {counts.data && counts.data.live_admins === 0 ? (
        <p className={styles.adminWarning}>
          <strong>Nobody can administer this deployment.</strong> There is no live
          admin grant, so no role can be granted from the console — including the one
          that would fix this. It needs{' '}
          <code>scripts.grant_first_admin</code> run against the database.
          <span className={styles.adminWarningDetail}>
            This is reachable without anybody doing something careless: an identity
            provider deactivating the last admin over SCIM revokes their grant, and
            the guard that refuses it in the console cannot see a SCIM write.
          </span>
        </p>
      ) : null}

      <div className={styles.columns}>
        <Panel title="Directory">
          {counts.isPending ? (
            <Loading />
          ) : counts.isError ? (
            <ErrorBox error={counts.error} />
          ) : (
            <>
              <p className={styles.groupLabel}>People</p>
              <div className={styles.statGrid}>
                <Stat
                  label="Users"
                  value={counts.data.users}
                  hint={`${counts.data.active_users.toLocaleString()} active`}
                />
                <Stat
                  label="Deactivated"
                  value={counts.data.users - counts.data.active_users}
                  hint="kept for their history"
                />
                <Stat
                  label="Admins"
                  value={counts.data.live_admins}
                  hint="who can grant anything"
                />
              </div>

              <p className={styles.groupLabel}>Access</p>
              <div className={styles.statGrid}>
                <Stat label="Groups" value={counts.data.groups} />
                <Stat
                  label="Applications"
                  value={counts.data.applications}
                  hint={`${counts.data.sso_applications} using SAML`}
                />
                <Stat
                  label="Audit events"
                  value={counts.data.audit_events}
                  hint="every change, hash-chained"
                />
              </div>
            </>
          )}
        </Panel>

        <div className={styles.healthList}>
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
      </div>

      {counts.data?.audit_events === 0 ? (
        <Empty>
          No data yet. Run <code>python -m scripts.seed --reset</code> in apps/api.
        </Empty>
      ) : null}
    </div>
  )
}
