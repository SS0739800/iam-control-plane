/** The group list, and one group's page. */

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useParams } from 'react-router-dom'

import {
  Empty,
  ErrorBox,
  LinkCell,
  Loading,
  Pager,
  Panel,
  Pill,
  Row,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import { fetchGroup, fetchGroups } from '../lib/api'

const PAGE_SIZE = 25

export function GroupsPage() {
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)

  const groups = useQuery({
    queryKey: ['groups', search, offset],
    queryFn: () => fetchGroups({ q: search || undefined, limit: PAGE_SIZE, offset }),
    placeholderData: (previous) => previous,
  })

  return (
    <Panel
      title="Groups"
      action={
        <input
          type="search"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value)
            setOffset(0)
          }}
          placeholder="Search group name"
          aria-label="Search groups"
          className="rounded-sm border border-slate-300 px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-950"
        />
      }
    >
      {groups.isError ? (
        <ErrorBox error={groups.error} />
      ) : groups.isPending ? (
        <Loading />
      ) : groups.data.items.length === 0 ? (
        <Empty>No groups match that search.</Empty>
      ) : (
        <>
          <TableWrap>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Description</Th>
                  <Th>HRMS role</Th>
                  <Th right>Members</Th>
                </tr>
              </thead>
              <tbody>
                {groups.data.items.map((group) => (
                  <tr key={group.id}>
                    <Td>
                      <LinkCell to={`/groups/${group.id}`}>{group.name}</LinkCell>
                    </Td>
                    <Td>{group.description ?? '—'}</Td>
                    <Td>{group.hrms_role ?? '—'}</Td>
                    <Td right>{group.member_count.toLocaleString()}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pager
            total={groups.data.total}
            limit={groups.data.limit}
            offset={groups.data.offset}
            onChange={setOffset}
          />
        </>
      )}
    </Panel>
  )
}

export function GroupDetailPage() {
  const { groupId = '' } = useParams()
  const group = useQuery({ queryKey: ['group', groupId], queryFn: () => fetchGroup(groupId) })

  if (group.isPending) return <Loading />
  if (group.isError) return <ErrorBox error={group.error} />

  const data = group.data
  const showingAll = data.members.length >= data.member_count

  return (
    <div className="flex flex-col gap-6">
      <Panel title={data.name}>
        <dl>
          <Row label="Description">{data.description ?? '—'}</Row>
          <Row label="HRMS role">{data.hrms_role ?? '—'}</Row>
          <Row label="Members">{data.member_count.toLocaleString()}</Row>
          <Row label="Created by">{data.source}</Row>
        </dl>
      </Panel>

      <Panel title={`Grants access to (${data.applications.length})`}>
        {data.applications.length === 0 ? (
          <Empty>This group does not grant any application access.</Empty>
        ) : (
          <ul className="flex flex-col">
            {data.applications.map((app) => (
              <li
                key={app.id}
                className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
              >
                <LinkCell to={`/applications/${app.id}`}>{app.name}</LinkCell>
                <span className="text-sm text-slate-500 dark:text-slate-400">
                  {app.role ?? 'no role'}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Members">
        {data.members.length === 0 ? (
          <Empty>No members.</Empty>
        ) : (
          <>
            <ul className="flex flex-col">
              {data.members.map((member) => (
                <li
                  key={member.id}
                  className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
                >
                  <LinkCell to={`/users/${member.id}`}>{member.display_name}</LinkCell>
                  <Pill tone={member.active ? 'ok' : 'muted'}>
                    {member.active ? 'active' : 'deactivated'}
                  </Pill>
                </li>
              ))}
            </ul>
            {showingAll ? null : (
              <p className="pt-3 text-sm text-slate-500 dark:text-slate-400">
                Showing the first {data.members.length} of {data.member_count.toLocaleString()}.
              </p>
            )}
          </>
        )}
      </Panel>
    </div>
  )
}
