/** The user list, and one user's page. */

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'

import {
  Empty,
  ErrorBox,
  LinkCell,
  Loading,
  Mono,
  NameCell,
  Pager,
  Panel,
  Pill,
  Row,
  StatusBadge,
  TableWrap,
  Td,
  Th,
  type Tone,
} from '../components/ui'
import { type PlatformRole, fetchMe, fetchUser, fetchUsers } from '../lib/api'
import LeaverPanel from '../components/LeaverPanel'
import { DataTable, type Sort, ToolbarButton } from '../components/DataTable'
import { AddFilter, FilterChip } from '../components/FilterChip'
import { RefreshIcon } from '../components/icons'
import { Button } from '../components/Button'
import { PageHeader } from '../components/PageHeader'
import { Tabs } from '../components/Tabs'
import styles from './Users.module.css'
import RoleGrantPanel from '../components/RoleGrantPanel'

const PAGE_SIZE = 25

const ROLES: PlatformRole[] = ['employee', 'helpdesk', 'auditor', 'admin']

export function UsersPage() {
  // The search lives in the URL, so a filtered list can be linked to and the
  // search box in the top bar can land somebody straight on their results.
  const [params, setParams] = useSearchParams()
  const search = params.get('q') ?? ''
  const setSearch = (value: string) => {
    setParams(
      (previous) => {
        const next = new URLSearchParams(previous)
        if (value) next.set('q', value)
        else next.delete('q')
        return next
      },
      { replace: true },
    )
  }
  const [offset, setOffset] = useState(0)
  // Both of these are real query parameters on /api/users, so a chip narrows the
  // search in Postgres rather than hiding rows we already fetched.
  const [active, setActive] = useState<boolean | undefined>(undefined)
  const [role, setRole] = useState<PlatformRole | undefined>(undefined)
  const [sort, setSort] = useState<Sort>({ key: 'display_name', order: 'asc' })

  const users = useQuery({
    queryKey: ['users', search, offset, active, role, sort],
    queryFn: () =>
      fetchUsers({
        q: search || undefined,
        active,
        platform_role: role,
        sort: sort.key,
        order: sort.order,
        limit: PAGE_SIZE,
        offset,
      }),
    // Keeps the old rows on screen while the next page loads, so the table doesn't
    // collapse to "Loading…" on every keystroke.
    placeholderData: (previous) => previous,
  })

  // Any change to what is being asked for starts again at the first page.
  const refilter = (change: () => void) => {
    setOffset(0)
    change()
  }

  return (
    <>
      <PageHeader
        title="Users"
        description="Everybody in the directory, however they got here."
      />
      <DataTable
        status={users.isError ? 'error' : users.isPending ? 'pending' : 'success'}
        error={users.error}
        onRetry={() => void users.refetch()}
        actions={
          <ToolbarButton
            icon={<RefreshIcon />}
            onClick={() => void users.refetch()}
            disabled={users.isFetching}
          >
            {users.isFetching ? 'Refreshing…' : 'Refresh'}
          </ToolbarButton>
        }
        rows={users.data?.items ?? []}
        rowKey={(user) => user.id}
        sort={{
          value: sort,
          onChange: (next) => {
            setSort(next)
            setOffset(0)
          },
        }}
        search={{
          value: search,
          onChange: (value) => {
            setSearch(value)
            setOffset(0)
          },
          label: 'Search users',
          placeholder: 'Search name or email',
        }}
        filters={
          <>
            {active === undefined ? null : (
              <FilterChip
                label="Status"
                value={active ? 'active' : 'deactivated'}
                options={[
                  ['active', 'active'],
                  ['deactivated', 'deactivated'],
                ]}
                onChange={(value) => refilter(() => setActive(value === 'active'))}
                onRemove={() => refilter(() => setActive(undefined))}
              />
            )}
            {role === undefined ? null : (
              <FilterChip
                label="Role"
                value={role}
                options={ROLES.map((entry) => [entry, entry])}
                onChange={(value) => refilter(() => setRole(value as PlatformRole))}
                onRemove={() => refilter(() => setRole(undefined))}
              />
            )}
            {active === undefined ? (
              <AddFilter label="Status" onClick={() => refilter(() => setActive(true))} />
            ) : null}
            {role === undefined ? (
              <AddFilter label="Role" onClick={() => refilter(() => setRole('admin'))} />
            ) : null}
          </>
        }
        count={
          users.data
            ? `${users.data.total.toLocaleString()} ${users.data.total === 1 ? 'user' : 'users'} found`
            : null
        }
        empty={{
          title:
            search || active !== undefined || role !== undefined
              ? 'No users match these filters'
              : 'No users yet',
          body:
            search || active !== undefined || role !== undefined
              ? 'Try a different search, or clear the filters to see everyone.'
              : 'People arrive from an identity provider, or the first time somebody signs in.',
          actions:
            search || active !== undefined || role !== undefined ? (
              <Button
                variant="secondary"
                onClick={() =>
                  refilter(() => {
                    setSearch('')
                    setActive(undefined)
                    setRole(undefined)
                  })
                }
              >
                Clear filters
              </Button>
            ) : null,
        }}
        columns={[
          {
            key: 'name',
            sortKey: 'display_name',
            header: 'Name',
            cell: (user) => (
              <NameCell name={user.display_name}>
                <LinkCell to={`/users/${user.id}`}>{user.display_name}</LinkCell>
              </NameCell>
            ),
          },
          {
            key: 'login',
            sortKey: 'user_name',
            header: 'Login',
            cell: (user) => <Mono>{user.user_name}</Mono>,
          },
          {
            key: 'department',
            sortKey: 'department',
            header: 'Department',
            cell: (user) => user.department ?? '—',
          },
          {
            key: 'role',
            sortKey: 'platform_role',
            header: 'Role',
            cell: (user) => user.platform_role,
          },
          { key: 'source', header: 'Source', cell: (user) => user.source },
          {
            key: 'status',
            sortKey: 'active',
            header: 'Status',
            cell: (user) => (
              <StatusBadge tone={user.active ? 'ok' : 'muted'}>
                {user.active ? 'active' : 'deactivated'}
              </StatusBadge>
            ),
          },
        ]}
        footer={
          users.data ? (
            <Pager
              total={users.data.total}
              limit={users.data.limit}
              offset={users.data.offset}
              onChange={setOffset}
            />
          ) : null
        }
      />
    </>
  )
}

export function UserDetailPage() {
  const { userId = '' } = useParams()
  const user = useQuery({
    queryKey: ['user', userId],
    queryFn: () => fetchUser(userId),
  })
  // The API enforces this; asking here only decides whether to draw the form.
  // A control that always fails is worse than no control.
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })
  const canGrantRoles = me.data?.permissions.includes('roles:write') ?? false
  const canEditUsers = me.data?.permissions.includes('users:write') ?? false

  if (user.isPending) return <Loading />
  if (user.isError) return <ErrorBox error={user.error} />

  const person = user.data
  const statusTone: Tone = person.active ? 'ok' : 'muted'

  return (
    <div className={styles.page}>
      <PageHeader
        title={person.display_name}
        description={person.user_name}
        trail={[{ label: 'Users', to: '/users' }, { label: person.display_name }]}
        actions={<Pill tone={statusTone}>{person.active ? 'active' : 'deactivated'}</Pill>}
      />

      <Tabs
        tabs={[
          {
            id: 'overview',
            label: 'Overview',
            content: (
              <Panel flush title="Profile">
                <dl>
                  <Row label="Login">
                    <Mono>{person.user_name}</Mono>
                  </Row>
                  <Row label="Email">
                    <Mono>{person.email}</Mono>
                  </Row>
                  <Row label="Department">{person.department ?? '—'}</Row>
                  <Row label="Job title">{person.job_title ?? '—'}</Row>
                  <Row label="Employee number">{person.employee_number ?? '—'}</Row>
                  <Row label="Manager">
                    {person.manager ? (
                      <LinkCell to={`/users/${person.manager.id}`}>
                        {person.manager.display_name}
                      </LinkCell>
                    ) : (
                      '—'
                    )}
                  </Row>
                  <Row label="Created by">{person.source}</Row>
                  <Row label="External id">
                    <Mono>{person.external_id ?? '—'}</Mono>
                  </Row>
                </dl>
              </Panel>
            ),
          },
          {
            id: 'access',
            label: `Access (${person.groups.length + person.applications.length})`,
            content: (
              <div className={styles.page}>
                <Panel flush title={`Groups (${person.groups.length})`}>
                  {person.groups.length === 0 ? (
                    <Empty>Not in any groups.</Empty>
                  ) : (
                    <ul className={styles.groupList}>
                      {person.groups.map((group) => (
                        <li key={group.id} className={styles.groupRow}>
                          <LinkCell to={`/groups/${group.id}`}>{group.name}</LinkCell>
                          <span className={styles.groupSource}>
                            {group.hrms_role ? `HRMS role: ${group.hrms_role}` : ''}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </Panel>

                <Panel flush title={`Access (${person.applications.length})`}>
                  {person.applications.length === 0 ? (
                    <Empty>No application access.</Empty>
                  ) : (
                    <TableWrap>
                      <table className={styles.table}>
                        <thead>
                          <tr>
                            <Th>Application</Th>
                            <Th>Role</Th>
                            <Th>How they got it</Th>
                          </tr>
                        </thead>
                        <tbody>
                          {person.applications.map((app) => (
                            <tr key={app.id}>
                              <Td>
                                <LinkCell to={`/applications/${app.id}`}>{app.name}</LinkCell>
                              </Td>
                              <Td>{app.role ?? '—'}</Td>
                              <Td>
                                {app.via_group ? (
                                  <span className={styles.viaGroup}>
                                    via{' '}
                                    <strong className={styles.viaGroupName}>
                                      {app.via_group}
                                    </strong>
                                  </span>
                                ) : (
                                  <span className={styles.directGrant}>given directly</span>
                                )}
                              </Td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </TableWrap>
                  )}
                </Panel>
              </div>
            ),
          },
          {
            id: 'lifecycle',
            label: 'Role and lifecycle',
            content: (
              <div className={styles.page}>
                <RoleGrantPanel userId={userId} canWrite={canGrantRoles} />
                <LeaverPanel person={person} canWrite={canEditUsers} />
              </div>
            ),
          },
        ]}
      />
    </div>
  )
}
