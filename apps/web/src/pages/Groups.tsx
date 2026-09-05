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
} from '../components/ui'
import GroupMembers from '../components/GroupMembers'
import { Button } from '../components/Button'
import { DataTable, ToolbarButton } from '../components/DataTable'
import { RefreshIcon } from '../components/icons'
import { Tabs } from '../components/Tabs'
import styles from './Groups.module.css'
import { PageHeader } from '../components/PageHeader'
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
    <>
      <PageHeader
        title="Groups"
        description="Groups carry access. Most arrive from the identity provider over SCIM."
      />
      <DataTable
          status={groups.isError ? 'error' : groups.isPending ? 'pending' : 'success'}
          error={groups.error}
          onRetry={() => void groups.refetch()}
          rows={groups.data?.items ?? []}
          rowKey={(group) => group.id}
          actions={
            <ToolbarButton
              icon={<RefreshIcon />}
              onClick={() => void groups.refetch()}
              disabled={groups.isFetching}
            >
              {groups.isFetching ? 'Refreshing…' : 'Refresh'}
            </ToolbarButton>
          }
          search={{
            value: search,
            onChange: (value) => {
              setSearch(value)
              setOffset(0)
            },
            label: 'Search groups',
            placeholder: 'Search group name',
          }}
          count={
            groups.data
              ? `${groups.data.total.toLocaleString()} ${groups.data.total === 1 ? 'group' : 'groups'} found`
              : null
          }
          empty={{
            title: search ? 'No groups match that search' : 'No groups yet',
            body: search
              ? 'Try a different search term.'
              : 'Groups arrive from an identity provider over SCIM, or can be created there and pushed.',
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
              cell: (group) => <LinkCell to={`/groups/${group.id}`}>{group.name}</LinkCell>,
            },
            { key: 'description', header: 'Description', cell: (group) => group.description ?? '—' },
            { key: 'role', header: 'HRMS role', cell: (group) => group.hrms_role ?? '—' },
            {
              key: 'members',
              header: 'Members',
              numeric: true,
              cell: (group) => group.member_count.toLocaleString(),
            },
          ]}
          footer={
            groups.data ? (
              <Pager
                total={groups.data.total}
                limit={groups.data.limit}
                offset={groups.data.offset}
                onChange={setOffset}
              />
            ) : null
          }
        />
    </>
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
      <PageHeader
        title={data.name}
        description={data.description ?? undefined}
        trail={[{ label: 'Groups', to: '/groups' }, { label: data.name }]}
      />

      <Tabs
        tabs={[
          {
            id: 'overview',
            label: 'Overview',
            content: (
              <Panel flush title="Properties">
                <dl>
                  <Row label="Description">{data.description ?? '—'}</Row>
                  <Row label="HRMS role">{data.hrms_role ?? '—'}</Row>
                  <Row label="Members">{data.member_count.toLocaleString()}</Row>
                  <Row label="Created by">{data.source}</Row>
                </dl>
              </Panel>
            ),
          },
          {
            id: 'members',
            label: `Members (${data.member_count.toLocaleString()})`,
            content: <GroupMembers group={data} canWrite={canWrite} />,
          },
          {
            id: 'applications',
            label: `Applications (${data.applications.length})`,
            content: (
              <Panel flush title="Grants access to">
                {data.applications.length === 0 ? (
                  <Empty>This group does not grant any application access.</Empty>
                ) : (
                  <ul className={styles.appList}>
                    {data.applications.map((app) => (
                      <li key={app.id} className={styles.appRow}>
                        <LinkCell to={`/applications/${app.id}`}>{app.name}</LinkCell>
                        <span className={styles.appRole}>{app.role ?? 'no role'}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
            ),
          },
        ]}
      />
    </div>
  )
}
