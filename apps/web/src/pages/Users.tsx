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
import { fetchUser, fetchUsers } from '../lib/api'

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
    <Panel
      title="Users"
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
          className="rounded-sm border border-slate-300 px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-950"
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
            <table className="w-full border-collapse">
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
  )
}

export function UserDetailPage() {
  const { userId = '' } = useParams()
  const user = useQuery({ queryKey: ['user', userId], queryFn: () => fetchUser(userId) })

  if (user.isPending) return <Loading />
  if (user.isError) return <ErrorBox error={user.error} />

  const person = user.data
  const statusTone: Tone = person.active ? 'ok' : 'muted'

  return (
    <div className="flex flex-col gap-6">
      <Panel title={person.display_name}>
        <dl>
          <Row label="Login">
            <Mono>{person.user_name}</Mono>
          </Row>
          <Row label="Email">
            <Mono>{person.email}</Mono>
          </Row>
          <Row label="Status">
            <Pill tone={statusTone}>{person.active ? 'active' : 'deactivated'}</Pill>
          </Row>
          <Row label="Department">{person.department ?? '—'}</Row>
          <Row label="Job title">{person.job_title ?? '—'}</Row>
          <Row label="Employee number">{person.employee_number ?? '—'}</Row>
          <Row label="Manager">
            {person.manager ? (
              <LinkCell to={`/users/${person.manager.id}`}>{person.manager.display_name}</LinkCell>
            ) : (
              '—'
            )}
          </Row>
          <Row label="Console role">{person.platform_role}</Row>
          <Row label="Created by">{person.source}</Row>
          <Row label="External id">
            <Mono>{person.external_id ?? '—'}</Mono>
          </Row>
        </dl>
      </Panel>

      <Panel title={`Groups (${person.groups.length})`}>
        {person.groups.length === 0 ? (
          <Empty>Not in any groups.</Empty>
        ) : (
          <ul className="flex flex-col">
            {person.groups.map((group) => (
              <li
                key={group.id}
                className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-2 last:border-0 dark:border-slate-800/60"
              >
                <LinkCell to={`/groups/${group.id}`}>{group.name}</LinkCell>
                <span className="text-sm text-slate-500 dark:text-slate-400">
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
            <table className="w-full border-collapse">
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
                        <span className="text-slate-600 dark:text-slate-300">
                          via <strong className="font-medium">{app.via_group}</strong>
                        </span>
                      ) : (
                        <span className="text-slate-500 dark:text-slate-400">given directly</span>
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
  )
}
