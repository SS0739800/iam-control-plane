/**
 * Talking to the API.
 *
 * The types in api-schema.d.ts are generated from the API's own schema, so if the
 * backend changes a field and nobody regenerates, CI fails instead of the browser.
 * Regenerate with:
 *
 *   cd apps/api && python -m scripts.export_openapi
 *   cd apps/web && npm run generate:api
 *
 * Requests go to whatever address the page itself was served from, which is the
 * payoff for putting the frontend and the API behind one hostname: nothing to
 * configure, no CORS, and the login cookie we add in P2 counts as first-party.
 */

import createClient from 'openapi-fetch'

import type { components } from './api-schema'

/**
 * The address to send requests to.
 *
 * This is window.location.origin rather than just "/" because Node's Request
 * refuses a relative URL, and that's what the tests run against. In the browser
 * it's the page's own origin either way, so nothing about the single-address setup
 * changes. The fallback is only ever used if this somehow loads outside a browser.
 */
const baseUrl = typeof window === 'undefined' ? 'http://localhost' : window.location.origin

export const client = createClient<import('./api-schema').paths>({
  baseUrl,
  // Same address, so this isn't handing credentials to another site. It just means
  // the login cookie comes along once P2 starts issuing one.
  credentials: 'same-origin',
  // Look fetch up on each call instead of letting openapi-fetch grab a reference
  // when this module loads. Without this, a test that replaces global fetch never
  // gets called, because the client is still holding the original one.
  fetch: (request) => globalThis.fetch(request),
})

/** Shorthand for a generated response type. */
type Schema<K extends keyof components['schemas']> = components['schemas'][K]

export type Liveness = Schema<'Liveness'>
export type Readiness = Schema<'Readiness'>
export type DashboardCounts = Schema<'DashboardCounts'>
export type UserSummary = Schema<'UserSummary'>
export type UserDetail = Schema<'UserDetail'>
export type UserUpdate = Schema<'UserUpdate'>
export type GroupSummary = Schema<'GroupSummary'>
export type GroupDetail = Schema<'GroupDetail'>
export type ApplicationSummary = Schema<'ApplicationSummary'>
export type ApplicationDetail = Schema<'ApplicationDetail'>
export type AuditEvent = Schema<'AuditEventOut'>
export type ChainVerification = Schema<'ChainVerification'>
export type AppRef = Schema<'AppRef'>
export type GroupRef = Schema<'GroupRef'>
export type UserRef = Schema<'UserRef'>
export type SignedInUser = Schema<'SignedInUser'>
export type IdentityProviderSummary = Schema<'IdentityProviderSummary'>
export type LoginAttempt = Schema<'LoginAttempt'>
export type LoginAttemptDetail = Schema<'LoginAttemptDetail'>
export type LoginCheck = Schema<'LoginCheck'>

export type PlatformRole = UserSummary['platform_role']

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/**
 * Pull the message out of whatever the API sent back.
 *
 * FastAPI puts a string in `detail` for our own errors and an array of field
 * problems in there for validation failures, so this handles both.
 */
function messageFrom(error: unknown, status: number): string {
  if (error && typeof error === 'object' && 'detail' in error) {
    const detail = (error as { detail: unknown }).detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) {
      return detail
        .map((item) =>
          item && typeof item === 'object' && 'msg' in item ? String(item.msg) : String(item),
        )
        .join('; ')
    }
  }
  return `Request failed with status ${status}`
}

/** Return the data, or throw so react-query can show an error state. */
function unwrap<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.data === undefined) {
    throw new ApiError(result.response.status, messageFrom(result.error, result.response.status))
  }
  return result.data
}

// ---------------------------------------------------------------------- health

export async function fetchLiveness(): Promise<Liveness> {
  return unwrap(await client.GET('/api/health'))
}

/**
 * This one answers 503 when the database is down, and the body of that response is
 * exactly what we want to show. So we treat 503 as a successful answer about a
 * problem, not as a failed request. Otherwise the page says "request failed" at the
 * one moment it has something useful to tell you.
 */
export async function fetchReadiness(): Promise<Readiness> {
  const result = await client.GET('/api/health/ready')
  if (result.response.status === 503 && result.error) {
    return result.error as Readiness
  }
  return unwrap(result)
}

// ------------------------------------------------------------------- dashboard

export async function fetchDashboard(): Promise<DashboardCounts> {
  return unwrap(await client.GET('/api/dashboard'))
}

// ----------------------------------------------------------------------- users

export interface UserListParams {
  q?: string
  active?: boolean
  department?: string
  platform_role?: PlatformRole
  limit?: number
  offset?: number
}

export async function fetchUsers(params: UserListParams = {}) {
  return unwrap(await client.GET('/api/users', { params: { query: params } }))
}

export async function fetchUser(userId: string): Promise<UserDetail> {
  return unwrap(await client.GET('/api/users/{user_id}', { params: { path: { user_id: userId } } }))
}

export async function updateUser(userId: string, body: UserUpdate): Promise<UserDetail> {
  return unwrap(
    await client.PATCH('/api/users/{user_id}', {
      params: { path: { user_id: userId } },
      body,
    }),
  )
}

// ---------------------------------------------------------------------- groups

export async function fetchGroups(params: { q?: string; limit?: number; offset?: number } = {}) {
  return unwrap(await client.GET('/api/groups', { params: { query: params } }))
}

export async function fetchGroup(groupId: string): Promise<GroupDetail> {
  return unwrap(
    await client.GET('/api/groups/{group_id}', { params: { path: { group_id: groupId } } }),
  )
}

// ---------------------------------------------------------------- applications

export async function fetchApplications(params: { q?: string; limit?: number; offset?: number } = {}) {
  return unwrap(await client.GET('/api/applications', { params: { query: params } }))
}

export async function fetchApplication(appId: string): Promise<ApplicationDetail> {
  return unwrap(
    await client.GET('/api/applications/{app_id}', { params: { path: { app_id: appId } } }),
  )
}

// ----------------------------------------------------------------------- audit

export interface AuditListParams {
  cursor?: string
  action?: string
  outcome?: AuditEvent['outcome']
  limit?: number
}

export async function fetchAuditEvents(params: AuditListParams = {}) {
  return unwrap(await client.GET('/api/audit', { params: { query: params } }))
}

export async function verifyAuditChain(): Promise<ChainVerification> {
  return unwrap(await client.GET('/api/audit/verify'))
}

// ------------------------------------------------------------------- sessions

export async function fetchMe(): Promise<SignedInUser> {
  return unwrap(await client.GET('/api/me'))
}

// ------------------------------------------------------ identity providers

export async function fetchIdentityProviders(): Promise<IdentityProviderSummary[]> {
  return unwrap(await client.GET('/api/identity-providers'))
}

// -------------------------------------------------------- login inspector

export interface LoginListParams {
  cursor?: string
  outcome?: LoginAttempt['outcome']
  idp?: string
  limit?: number
}

export async function fetchLoginAttempts(params: LoginListParams = {}) {
  return unwrap(await client.GET('/api/saml/logins', { params: { query: params } }))
}

export async function fetchLoginAttempt(eventId: number): Promise<LoginAttemptDetail> {
  return unwrap(
    await client.GET('/api/saml/logins/{event_id}', {
      params: { path: { event_id: eventId } },
    }),
  )
}
