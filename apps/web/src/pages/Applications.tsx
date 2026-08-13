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
import { fetchApplication, fetchApplications } from '../lib/api'

const PAGE_SIZE = 25

export function ApplicationsPage() {
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)

  const apps = useQuery({
    queryKey: ['applications', search, offset],
    queryFn: () => fetchApplications({ q: search || undefined, limit: PAGE_SIZE, offset }),
    placeholderData: (previous) => previous,
  })

  return (
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
  )
}

export function ApplicationDetailPage() {
  const { appId = '' } = useParams()
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

      {isSaml ? (
        <Panel title="SAML settings">
          <p className="pb-3 text-sm text-slate-500 dark:text-slate-400">
            Shown so a mistyped value is easy to spot. Nothing reads these until P5, when this
            platform starts signing people in.
          </p>
          <dl>
            <Row label="Entity ID">
              <Mono>{data.entity_id ?? '—'}</Mono>
            </Row>
            <Row label="Login response URL">
              <Mono>{data.acs_url ?? '—'}</Mono>
            </Row>
            <Row label="Logout URL">
              <Mono>{data.slo_url ?? '—'}</Mono>
            </Row>
            <Row label="Name ID format">
              <Mono>{data.nameid_format ?? '—'}</Mono>
            </Row>
            <Row label="Certificate">
              {data.signing_cert ? 'on file' : 'not set'}
            </Row>
          </dl>
        </Panel>
      ) : null}

      <Panel title={`Access via groups (${data.assigned_groups.length})`}>
        {data.assigned_groups.length === 0 ? (
          <Empty>No groups grant access to this application.</Empty>
        ) : (
          <ul className="flex flex-col">
            {data.assigned_groups.map((group) => (
              <li
                key={group.id}
                className="border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
              >
                <LinkCell to={`/groups/${group.id}`}>{group.name}</LinkCell>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title={`Access given directly (${data.assigned_users.length})`}>
        {data.assigned_users.length === 0 ? (
          <Empty>Nobody has been given this directly. All access comes from groups.</Empty>
        ) : (
          <ul className="flex flex-col">
            {data.assigned_users.map((user) => (
              <li
                key={user.id}
                className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
              >
                <LinkCell to={`/users/${user.id}`}>{user.display_name}</LinkCell>
                <Pill tone={user.active ? 'ok' : 'muted'}>
                  {user.active ? 'active' : 'deactivated'}
                </Pill>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}
