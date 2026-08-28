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
export type SignInOption = Schema<'SignInOption'>
export type LoginAttempt = Schema<'LoginAttempt'>
export type LoginAttemptDetail = Schema<'LoginAttemptDetail'>
export type LoginCheck = Schema<'LoginCheck'>
export type ScimClient = Schema<'ScimClientSummary'>
export type RoleGrant = Schema<'RoleGrantOut'>
export type AccessSummary = Schema<'AccessSummary'>
export type AccessRule = Schema<'AccessRuleOut'>
export type AccessRequest = Schema<'AccessRequestOut'>
export type AccessReview = Schema<'AccessReviewOut'>
export type ReviewFinding = Schema<'FindingOut'>
export type RequestState = AccessRequest['state']
export type AccessRuleCreate = Schema<'AccessRuleCreate'>
export type RuleAttribute = Schema<'RuleAttribute'>
export type RulePreview = Schema<'RulePreview'>
export type RuleRunResult = Schema<'RuleRunResult'>
export type AffectedPerson = Schema<'AffectedPerson'>
export type RuleOperator = AccessRule['operator']
export type ScimClientIssued = Schema<'ScimClientIssued'>
export type ProvisioningOverview = Schema<'ProvisioningOverview'>
export type ProvisioningActivity = Schema<'ProvisioningActivity'>
export type ProvisioningTarget = Schema<'ProvisioningTargetSummary'>
export type ProvisioningTargetCreate = Schema<'ProvisioningTargetCreate'>
export type ProvisioningLink = Schema<'ProvisioningLinkOut'>
export type LinkState = ProvisioningLink['state']
export type SyncResult = Schema<'SyncResult'>
export type ProbeResult = Schema<'ProbeResult'>

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

/**
 * Throw if the request failed, and return nothing.
 *
 * For endpoints that answer 204. unwrap cannot be used on those: a 204 has no body,
 * so `data` is undefined on success as well as on failure, and unwrap would treat
 * every success as an error.
 */
function unwrapEmpty(result: { error?: unknown; response: Response }): void {
  if (!result.response.ok) {
    throw new ApiError(result.response.status, messageFrom(result.error, result.response.status))
  }
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

/**
 * Put somebody in a group, or take them out.
 *
 * Stored as a manual membership, which is what stops the rule engine undoing it.
 * `group_members.source` is how "a person decided this" is told apart from "a rule
 * worked it out", and the engine only ever removes its own — so a hand-added member
 * survives the next run and a rule-added one does not need defending.
 *
 * Both answer 204, so there is nothing to return. Callers refetch the group.
 */
export async function addToGroup(userId: string, groupId: string): Promise<void> {
  await unwrap(
    await client.PUT('/api/users/{user_id}/groups/{group_id}', {
      params: { path: { user_id: userId, group_id: groupId } },
    }),
  )
}

export async function removeFromGroup(userId: string, groupId: string): Promise<void> {
  await unwrap(
    await client.DELETE('/api/users/{user_id}/groups/{group_id}', {
      params: { path: { user_id: userId, group_id: groupId } },
    }),
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

/**
 * The ways somebody can sign in, for the banner shown before they have.
 *
 * The only unauthenticated read in this client. A sign-in screen cannot ask for a
 * permission — whoever is reading it has no session, which is why they are reading it
 * — so the button used to be hard-coded to ?idp=authentik and pointed at a provider
 * that did not exist in production.
 */
export async function fetchSignInOptions(): Promise<SignInOption[]> {
  return unwrap(await client.GET('/api/identity-providers/sign-in-options'))
}

export async function fetchLoginAttempt(eventId: number): Promise<LoginAttemptDetail> {
  return unwrap(
    await client.GET('/api/saml/logins/{event_id}', {
      params: { path: { event_id: eventId } },
    }),
  )
}

// ------------------------------------------------------------- provisioning

export async function fetchProvisioningOverview(): Promise<ProvisioningOverview> {
  return unwrap(await client.GET('/api/provisioning/overview'))
}

export async function fetchScimClients(): Promise<ScimClient[]> {
  return unwrap(await client.GET('/api/provisioning/clients'))
}

export async function fetchProvisioningActivity(limit = 25): Promise<ProvisioningActivity[]> {
  return unwrap(await client.GET('/api/provisioning/activity', { params: { query: { limit } } }))
}

/**
 * Issue a token. The response carries it once and nothing can fetch it again,
 * so whatever calls this has to be the thing that shows it to the person.
 */
export async function issueScimClient(body: {
  name: string
  description?: string | null
}): Promise<ScimClientIssued> {
  return unwrap(await client.POST('/api/provisioning/clients', { body }))
}

export async function revokeScimClient(clientId: string, reason: string): Promise<ScimClient> {
  return unwrap(
    await client.POST('/api/provisioning/clients/{client_id}/revoke', {
      params: { path: { client_id: clientId } },
      body: { reason },
    }),
  )
}

// ------------------------------------------------- provisioning the other way

export async function fetchProvisioningTargets(): Promise<ProvisioningTarget[]> {
  return unwrap(await client.GET('/api/provisioning/targets'))
}

/**
 * Register a downstream system. The token goes one way only: nothing reads it back,
 * so whoever calls this is the last thing that ever sees the value it was given.
 */
export async function createProvisioningTarget(
  body: ProvisioningTargetCreate,
): Promise<ProvisioningTarget> {
  return unwrap(await client.POST('/api/provisioning/targets', { body }))
}

export async function updateProvisioningTarget(
  targetId: string,
  body: { base_url?: string; token?: string; enabled?: boolean },
): Promise<ProvisioningTarget> {
  return unwrap(
    await client.PATCH('/api/provisioning/targets/{target_id}', {
      params: { path: { target_id: targetId } },
      body,
    }),
  )
}

export async function deleteProvisioningTarget(targetId: string): Promise<void> {
  await unwrap(
    await client.DELETE('/api/provisioning/targets/{target_id}', {
      params: { path: { target_id: targetId } },
    }),
  )
}

/** Ask whether a target answers and accepts our token. Changes nothing. */
export async function probeProvisioningTarget(targetId: string): Promise<ProbeResult> {
  return unwrap(
    await client.POST('/api/provisioning/targets/{target_id}/probe', {
      params: { path: { target_id: targetId } },
    }),
  )
}

/**
 * Push everything that needs pushing, now.
 *
 * Slow on purpose rather than by accident: there is no background worker, so this
 * runs inside the request. A first sync against a large directory can take a while,
 * which is why the button that calls it says so.
 */
export async function syncProvisioningTarget(
  targetId: string,
  force = false,
): Promise<SyncResult> {
  return unwrap(
    await client.POST('/api/provisioning/targets/{target_id}/sync', {
      params: { path: { target_id: targetId }, query: { force } },
    }),
  )
}

export async function fetchProvisioningAccounts(
  targetId: string,
  state?: LinkState,
): Promise<ProvisioningLink[]> {
  return unwrap(
    await client.GET('/api/provisioning/targets/{target_id}/accounts', {
      params: { path: { target_id: targetId }, query: state ? { state } : {} },
    }),
  )
}

// -------------------------------------------------------------- role grants


export async function fetchAccessSummary(userId: string): Promise<AccessSummary> {
  return unwrap(
    await client.GET('/api/users/{user_id}/access', { params: { path: { user_id: userId } } }),
  )
}

export async function grantRole(
  userId: string,
  body: { role: PlatformRole; reason?: string | null; expires_at?: string | null },
): Promise<RoleGrant> {
  return unwrap(
    await client.POST('/api/users/{user_id}/role-grants', {
      params: { path: { user_id: userId } },
      body,
    }),
  )
}

export async function revokeRole(userId: string, reason: string): Promise<AccessSummary> {
  return unwrap(
    await client.DELETE('/api/users/{user_id}/role-grants', {
      params: { path: { user_id: userId } },
      body: { reason },
    }),
  )
}

// ------------------------------------------------------------- access rules

export async function fetchAccessRules(): Promise<AccessRule[]> {
  return unwrap(await client.GET('/api/access-rules'))
}

export async function fetchRuleAttributes(): Promise<RuleAttribute[]> {
  return unwrap(await client.GET('/api/access-rules/attributes'))
}

/** Try a rule without saving it. Writes nothing. */
export async function previewAccessRule(body: AccessRuleCreate): Promise<RulePreview> {
  return unwrap(await client.POST('/api/access-rules/preview', { body }))
}

export async function createAccessRule(body: AccessRuleCreate): Promise<AccessRule> {
  return unwrap(await client.POST('/api/access-rules', { body }))
}

export async function setAccessRuleEnabled(
  ruleId: string,
  enabled: boolean,
): Promise<AccessRule> {
  return unwrap(
    await client.PATCH('/api/access-rules/{rule_id}', {
      params: { path: { rule_id: ruleId } },
      body: { enabled },
    }),
  )
}

export async function deleteAccessRule(ruleId: string): Promise<RuleRunResult> {
  return unwrap(
    await client.DELETE('/api/access-rules/{rule_id}', {
      params: { path: { rule_id: ruleId } },
    }),
  )
}

/**
 * Apply a saved rule to everybody now, instead of waiting for something to trigger it.
 *
 * Rules reconcile rather than add, so a run can remove memberships as well as create
 * them — and it only ever touches the ones it made itself. That is why the result
 * counts removals: a button that quietly took access away without saying so would be
 * the worst version of this.
 */
export async function runAccessRule(ruleId: string): Promise<RuleRunResult> {
  return unwrap(
    await client.POST('/api/access-rules/{rule_id}/run', {
      params: { path: { rule_id: ruleId } },
    }),
  )
}

/**
 * Who a saved rule currently applies to.
 *
 * previewAccessRule answers the same question for a rule that has not been saved yet;
 * this one is for the rules already running, where "who does this actually catch
 * today" is the thing nobody can otherwise see.
 */
export async function fetchAffected(ruleId: string, limit = 50): Promise<AffectedPerson[]> {
  return unwrap(
    await client.GET('/api/access-rules/{rule_id}/affected', {
      params: { path: { rule_id: ruleId }, query: { limit } },
    }),
  )
}

// ---------------------------------------------------------- access requests

export async function fetchRequestQueue(): Promise<AccessRequest[]> {
  return unwrap(await client.GET('/api/access-requests'))
}

export async function fetchMyRequests(): Promise<AccessRequest[]> {
  return unwrap(await client.GET('/api/access-requests/mine'))
}

export async function raiseAccessRequest(body: {
  group_id: string
  reason: string
}): Promise<AccessRequest> {
  return unwrap(await client.POST('/api/access-requests', { body }))
}

export async function approveAccessRequest(
  requestId: string,
  body: { note?: string | null; expires_at?: string | null },
): Promise<AccessRequest> {
  return unwrap(
    await client.POST('/api/access-requests/{request_id}/approve', {
      params: { path: { request_id: requestId } },
      body,
    }),
  )
}

export async function denyAccessRequest(
  requestId: string,
  body: { note?: string | null },
): Promise<AccessRequest> {
  return unwrap(
    await client.POST('/api/access-requests/{request_id}/deny', {
      params: { path: { request_id: requestId } },
      body,
    }),
  )
}

export async function withdrawAccessRequest(requestId: string): Promise<AccessRequest> {
  return unwrap(
    await client.POST('/api/access-requests/{request_id}/withdraw', {
      params: { path: { request_id: requestId } },
    }),
  )
}

// ------------------------------------------------------------ access review

export async function fetchAccessReview(): Promise<AccessReview> {
  return unwrap(await client.GET('/api/access-review'))
}

// ------------------------------------------------------- registering apps

/**
 * Register an application by pasting its metadata. Never a form of addresses —
 * a mistyped ACS URL is a signed assertion posted somewhere it should not go.
 */
export async function registerApplication(body: {
  slug: string
  name: string
  description?: string | null
  metadata_xml: string
  enabled?: boolean
}): Promise<ApplicationDetail> {
  // enabled is spelled out because the generated type has it required — the default
  // lives on the server, and openapi-typescript reports the post-default shape.
  return unwrap(
    await client.POST('/api/applications', { body: { ...body, enabled: body.enabled ?? true } }),
  )
}

export async function grantAppAccessToUser(
  appId: string,
  userId: string,
  role?: string,
): Promise<void> {
  await unwrapEmpty(
    await client.PUT('/api/applications/{app_id}/users/{user_id}', {
      params: { path: { app_id: appId, user_id: userId }, query: role ? { role } : {} },
    }),
  )
}

export async function revokeAppAccessFromUser(appId: string, userId: string): Promise<void> {
  await unwrapEmpty(
    await client.DELETE('/api/applications/{app_id}/users/{user_id}', {
      params: { path: { app_id: appId, user_id: userId } },
    }),
  )
}

export async function grantAppAccessToGroup(
  appId: string,
  groupId: string,
  role?: string,
): Promise<void> {
  await unwrapEmpty(
    await client.PUT('/api/applications/{app_id}/groups/{group_id}', {
      params: { path: { app_id: appId, group_id: groupId }, query: role ? { role } : {} },
    }),
  )
}

export async function revokeAppAccessFromGroup(appId: string, groupId: string): Promise<void> {
  await unwrapEmpty(
    await client.DELETE('/api/applications/{app_id}/groups/{group_id}', {
      params: { path: { app_id: appId, group_id: groupId } },
    }),
  )
}
