/** The application list, and one application's page including its SAML settings. */

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useParams } from 'react-router-dom'

import {
  Empty,
  ErrorBox,
  LinkCell,
  Loading,
  Mono,
  Pager,
  Panel,
  Pill,
  Row,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import { ApplicationSamlPanels } from '../components/ApplicationSamlPanels'
import { RegisterApplication } from '../components/RegisterApplication'
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
    <div className="flex flex-col gap-6">
      <Panel
        title="Applications"
        action={
        <input
          type="search"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value)
            setOffset(0)
          }}
          placeholder="Search name"
          aria-label="Search applications"
          className="rounded-sm border border-slate-300 px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-950"
        />
      }
    >
      {apps.isError ? (
        <ErrorBox error={apps.error} />
      ) : apps.isPending ? (
        <Loading />
      ) : apps.data.items.length === 0 ? (
        <Empty>No applications match that search.</Empty>
      ) : (
        <>
          <TableWrap>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Login method</Th>
                  <Th>Description</Th>
                  <Th>Status</Th>
                  <Th right>Assignments</Th>
                </tr>
              </thead>
              <tbody>
                {apps.data.items.map((app) => (
                  <tr key={app.id}>
                    <Td>
                      <LinkCell to={`/applications/${app.id}`}>{app.name}</LinkCell>
                    </Td>
                    <Td>
                      <Mono>{app.protocol}</Mono>
                    </Td>
                    <Td>{app.description ?? '—'}</Td>
                    <Td>
                      <Pill tone={app.status === 'active' ? 'ok' : 'muted'}>{app.status}</Pill>
                    </Td>
                    <Td right>{app.assignment_count.toLocaleString()}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pager
            total={apps.data.total}
            limit={apps.data.limit}
            offset={apps.data.offset}
            onChange={setOffset}
          />
        </>
      )}
      </Panel>

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
    <div className="flex flex-col gap-6">
      <Panel title={data.name}>
        <dl>
          <Row label="Description">{data.description ?? '—'}</Row>
          <Row label="Login method">
            <Mono>{data.protocol}</Mono>
          </Row>
          <Row label="Status">
            <Pill tone={data.status === 'active' ? 'ok' : 'muted'}>{data.status}</Pill>
          </Row>
          <Row label="Short name">
            <Mono>{data.slug}</Mono>
          </Row>
        </dl>
      </Panel>

      {isSaml ? <ApplicationSamlPanels app={data} canWrite={canWrite} /> : null}

    </div>
  )
}
