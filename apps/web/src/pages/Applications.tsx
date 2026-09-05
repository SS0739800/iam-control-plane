/** The application list, and one application's page including its SAML settings. */

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useParams } from 'react-router-dom'

import {
  ErrorBox,
  LinkCell,
  Loading,
  Mono,
  Pager,
  Panel,
  StatusBadge,
  Row,
} from '../components/ui'
import {
  ApplicationAccessPanels,
  ApplicationSamlPanels,
} from '../components/ApplicationSamlPanels'
import { RegisterApplication } from '../components/RegisterApplication'
import { Button } from '../components/Button'
import { DataTable, ToolbarButton } from '../components/DataTable'
import { RefreshIcon } from '../components/icons'
import { Tabs } from '../components/Tabs'
import styles from './Applications.module.css'
import { PageHeader } from '../components/PageHeader'
import { fetchApplication, fetchApplications, fetchMe } from '../lib/api'

const PAGE_SIZE = 25

export function ApplicationsPage() {
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })
  const canWrite = me.data?.permissions.includes('apps:write') ?? false

  const apps = useQuery({
    queryKey: ['applications', search, offset],
    queryFn: () => fetchApplications({ q: search || undefined, limit: PAGE_SIZE, offset }),
    placeholderData: (previous) => previous,
  })

  return (
    <div className={styles.page}>
      <PageHeader
        title="Applications"
        description="What people sign in to, and who is allowed to."
      />
      <DataTable
          status={apps.isError ? 'error' : apps.isPending ? 'pending' : 'success'}
          error={apps.error}
          onRetry={() => void apps.refetch()}
          rows={apps.data?.items ?? []}
          rowKey={(app) => app.id}
          actions={
            <ToolbarButton
              icon={<RefreshIcon />}
              onClick={() => void apps.refetch()}
              disabled={apps.isFetching}
            >
              {apps.isFetching ? 'Refreshing…' : 'Refresh'}
            </ToolbarButton>
          }
          search={{
            value: search,
            onChange: (value) => {
              setSearch(value)
              setOffset(0)
            },
            label: 'Search applications',
            placeholder: 'Search name',
          }}
          count={
            apps.data
              ? `${apps.data.total.toLocaleString()} ${apps.data.total === 1 ? 'application' : 'applications'} found`
              : null
          }
          empty={{
            title: search ? 'No applications match that search' : 'No applications yet',
            body: search
              ? 'Try a different search term.'
              : 'Register one below to give people access to it.',
            actions: search ? (
              <Button
                variant="secondary"
                onClick={() => {
                  setSearch('')
                  setOffset(0)
                }}
              >
                Clear search
              </Button>
            ) : null,
          }}
          columns={[
            {
              key: 'name',
              header: 'Name',
              cell: (app) => <LinkCell to={`/applications/${app.id}`}>{app.name}</LinkCell>,
            },
            { key: 'protocol', header: 'Login method', cell: (app) => <Mono>{app.protocol}</Mono> },
            { key: 'description', header: 'Description', cell: (app) => app.description ?? '—' },
            {
              key: 'status',
              header: 'Status',
              cell: (app) => (
                <StatusBadge tone={app.status === 'active' ? 'ok' : 'muted'}>
                  {app.status}
                </StatusBadge>
              ),
            },
            {
              key: 'assignments',
              header: 'Assignments',
              numeric: true,
              cell: (app) => app.assignment_count.toLocaleString(),
            },
          ]}
          footer={
            apps.data ? (
              <Pager
                total={apps.data.total}
                limit={apps.data.limit}
                offset={apps.data.offset}
                onChange={setOffset}
              />
            ) : null
          }
        />

      {canWrite ? <RegisterApplication /> : null}
    </div>
  )
}

export function ApplicationDetailPage() {
  const { appId = '' } = useParams()
  // The API enforces this; asking only decides whether to draw the controls.
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })
  const canWrite = me.data?.permissions.includes('apps:write') ?? false
  const app = useQuery({ queryKey: ['application', appId], queryFn: () => fetchApplication(appId) })

  if (app.isPending) return <Loading />
  if (app.isError) return <ErrorBox error={app.error} />

  const data = app.data
  const isSaml = data.protocol === 'saml2'

  return (
    <div className={styles.page}>
      <PageHeader
        title={data.name}
        description={data.description ?? undefined}
        trail={[{ label: 'Applications', to: '/applications' }, { label: data.name }]}
        actions={
          <StatusBadge tone={data.status === 'active' ? 'ok' : 'muted'}>
            {data.status}
          </StatusBadge>
        }
      />

      <Tabs
        tabs={[
          {
            id: 'overview',
            label: 'Overview',
            content: (
              <Panel flush title="Properties">
                <dl>
                  <Row label="Login method">
                    <Mono>{data.protocol}</Mono>
                  </Row>
                  <Row label="Short name">
                    <Mono>{data.slug}</Mono>
                  </Row>
                </dl>
              </Panel>
            ),
          },
          {
            /* Access is the question somebody opens this page to answer, and it
               isn't a SAML concept — which is what left the HRMS with no way to
               grant anybody access. */
            id: 'access',
            label: 'Access',
            content: <ApplicationAccessPanels app={data} canWrite={canWrite} />,
          },
          ...(isSaml
            ? [
                {
                  id: 'saml',
                  label: 'SAML',
                  content: <ApplicationSamlPanels app={data} />,
                },
              ]
            : []),
        ]}
      />
    </div>
  )
}
