/** The user list, and one user's page. */

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
  type Tone,
} from '../components/ui'
import { fetchMe, fetchUser, fetchUsers } from '../lib/api'
import LeaverPanel from '../components/LeaverPanel'
import { PageHeader } from '../components/PageHeader'
import { Tabs } from '../components/Tabs'
import styles from './Users.module.css'
import RoleGrantPanel from '../components/RoleGrantPanel'

const PAGE_SIZE = 25

export function UsersPage() {
  // Two pieces of state, not one: typing in the box shouldn't leave you on page 7
  // of results that no longer exist, so changing the search resets the offset.
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)

  const users = useQuery({
    queryKey: ['users', search, offset],
    queryFn: () => fetchUsers({ q: search || undefined, limit: PAGE_SIZE, offset }),
    // Keeps the old rows on screen while the next page loads, so the table doesn't
    // collapse to "Loading…" on every keystroke.
    placeholderData: (previous) => previous,
  })

  return (
    <>
      <PageHeader
        title="Users"
        description="Everybody in the directory, however they got here."
      />
      <Panel
        title={users.data ? `${users.data.total.toLocaleString()} people` : 'People'}
        action={
          <input
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setOffset(0)
            }}
            placeholder="Search name or email"
            aria-label="Search users"
            className={styles.search}
          />
        }
      >
        {users.isError ? (
          <ErrorBox error={users.error} />
        ) : users.isPending ? (
          <Loading />
        ) : users.data.items.length === 0 ? (
          <Empty>No users match that search.</Empty>
        ) : (
          <>
            <TableWrap>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <Th>Name</Th>
                    <Th>Login</Th>
                    <Th>Department</Th>
                    <Th>Role</Th>
                    <Th>Source</Th>
                    <Th>Status</Th>
                  </tr>
                </thead>
                <tbody>
                  {users.data.items.map((user) => (
                    <tr key={user.id}>
                      <Td>
                        <LinkCell to={`/users/${user.id}`}>{user.display_name}</LinkCell>
                      </Td>
                      <Td>
                        <Mono>{user.user_name}</Mono>
                      </Td>
                      <Td>{user.department ?? '—'}</Td>
                      <Td>{user.platform_role}</Td>
                      <Td>{user.source}</Td>
                      <Td>
                        <Pill tone={user.active ? 'ok' : 'muted'}>
                          {user.active ? 'active' : 'deactivated'}
                        </Pill>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
            <Pager
              total={users.data.total}
              limit={users.data.limit}
              offset={users.data.offset}
              onChange={setOffset}
            />
          </>
        )}
      </Panel>
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
              <Panel title="Profile">
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
                <Panel title={`Groups (${person.groups.length})`}>
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

                <Panel title={`Access (${person.applications.length})`}>
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
