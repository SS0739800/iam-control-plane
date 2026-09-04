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
  Row,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import GroupMembers from '../components/GroupMembers'
import styles from './Groups.module.css'
import { fetchGroup, fetchGroups, fetchMe } from '../lib/api'

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
          className={styles.search}
        />
      }
    >
      {groups.isError ? (
        <ErrorBox error={groups.error} />
      ) : groups.isPending ? (
        <Loading />
      ) : groups.data.items.length === 0 ? (
        <Empty>
          {search
            ? 'No groups match that search.'
            : 'No groups yet. They arrive from an identity provider over SCIM, or ' +
              'can be created there and pushed.'}
        </Empty>
      ) : (
        <>
          <TableWrap>
            <table className={styles.table}>
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
  // The API enforces this; asking here only decides whether to draw the controls.
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })
  const canWrite = me.data?.permissions.includes('groups:write') ?? false

  if (group.isPending) return <Loading />
  if (group.isError) return <ErrorBox error={group.error} />

  const data = group.data

  return (
    <div className={styles.page}>
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
          <ul className={styles.appList}>
            {data.applications.map((app) => (
              <li key={app.id} className={styles.appRow}>
                <LinkCell to={`/applications/${app.id}`}>{app.name}</LinkCell>
                <span className={styles.appRole}>
                  {app.role ?? 'no role'}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <GroupMembers group={data} canWrite={canWrite} />
    </div>
  )
}
