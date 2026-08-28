/**
 * Access rules: the conditions that put people in groups automatically.
 *
 * The preview is the point of this screen, not the form.
 *
 * A rule is one line of text that quietly grants access to an unknown number of
 * people, and a mistyped value reads exactly like a correct one. So nothing can be
 * saved until it has been previewed, and the preview leads with the count. "Would
 * add 97 people" is the sentence that stops a mistake; a validation message never
 * would, because the rule is perfectly valid.
 *
 * Rules are shown as sentences rather than three fields, for the same reason they
 * are stored as a single comparison: something that can't be read out loud can't be
 * reviewed.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import {
  Empty,
  ErrorBox,
  LinkCell,
  Loading,
  Mono,
  Panel,
  Pill,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import {
  type AccessRule,
  type AccessRuleCreate,
  type RuleOperator,
  type RulePreview,
  createAccessRule,
  deleteAccessRule,
  fetchAffected,
  runAccessRule,
  fetchAccessRules,
  fetchGroups,
  fetchMe,
  fetchRuleAttributes,
  previewAccessRule,
  setAccessRuleEnabled,
} from '../lib/api'

/** Operators, with wording that matches how the rule will read back. */
const OPERATORS: { value: RuleOperator; label: string; takesValue: boolean }[] = [
  { value: 'equals', label: 'is', takesValue: true },
  { value: 'not_equals', label: 'is not', takesValue: true },
  { value: 'contains', label: 'contains', takesValue: true },
  { value: 'starts_with', label: 'starts with', takesValue: true },
  { value: 'is_set', label: 'has any value', takesValue: false },
  { value: 'is_not_set', label: 'is empty', takesValue: false },
]

function takesValue(operator: RuleOperator): boolean {
  return OPERATORS.find((entry) => entry.value === operator)?.takesValue ?? true
}

const FIELD =
  'rounded-sm border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'

function PreviewResult({ preview }: { preview: RulePreview }) {
  // The count first, and loud when it's big. Somebody skimming should be stopped
  // by the number, not by reading the sample list.
  const large = preview.would_be_added > 25

  return (
    <div
      className={`flex flex-col gap-2 rounded-sm border p-3 text-sm ${
        large
          ? 'border-amber-400 bg-amber-50 dark:border-amber-800 dark:bg-amber-950'
          : 'border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-950'
      }`}
    >
      <p className="font-medium">
        {preview.sentence} → {preview.group_name}
      </p>
      <p>
        Matches <strong className="tabular-nums">{preview.matches.toLocaleString()}</strong>{' '}
        {preview.matches === 1 ? 'person' : 'people'}. Would add{' '}
        <strong className="tabular-nums">{preview.would_be_added.toLocaleString()}</strong>;{' '}
        {preview.already_in_group.toLocaleString()} already in the group.
      </p>
      {large ? (
        <p className="text-amber-900 dark:text-amber-200">
          That is a lot of people. Worth checking the value is spelled the way the HR system
          spells it before saving.
        </p>
      ) : null}
      {preview.sample.length > 0 ? (
        <ul className="flex flex-col gap-0.5 text-xs text-slate-600 dark:text-slate-300">
          {preview.sample.map((person) => (
            <li key={person.id}>
              {person.display_name} — <Mono>{person.department ?? 'no department'}</Mono>
            </li>
          ))}
          {preview.matches > preview.sample.length ? (
            <li className="text-slate-500 dark:text-slate-400">
              …and {(preview.matches - preview.sample.length).toLocaleString()} more
            </li>
          ) : null}
        </ul>
      ) : null}
    </div>
  )
}

function NewRuleForm() {
  const queryClient = useQueryClient()
  const attributes = useQuery({ queryKey: ['rule-attributes'], queryFn: fetchRuleAttributes })
  const groups = useQuery({
    queryKey: ['groups', 'for-rules'],
    queryFn: () => fetchGroups({ limit: 200 }),
  })

  const [name, setName] = useState('')
  const [attribute, setAttribute] = useState('department')
  const [operator, setOperator] = useState<RuleOperator>('equals')
  const [value, setValue] = useState('')
  const [groupId, setGroupId] = useState('')

  const body = (): AccessRuleCreate => ({
    name: name.trim(),
    attribute,
    operator,
    value: takesValue(operator) ? value.trim() : null,
    group_id: groupId,
    // Rules are created switched on. A rule saved off would need somebody to
    // remember to come back, and the preview already showed what it will do.
    enabled: true,
  })

  const ready = Boolean(name.trim() && groupId && (!takesValue(operator) || value.trim()))

  const preview = useMutation({ mutationFn: () => previewAccessRule(body()) })
  const create = useMutation({
    mutationFn: () => createAccessRule(body()),
    onSuccess: () => {
      setName('')
      setValue('')
      preview.reset()
      void queryClient.invalidateQueries({ queryKey: ['access-rules'] })
    },
  })

  // Nothing can be saved until it has been previewed against the current
  // conditions. Changing any field clears the preview, so the count on screen
  // always belongs to the rule about to be written.
  const clearPreview = () => {
    if (preview.data) preview.reset()
  }

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault()
        if (preview.data) create.mutate()
        else if (ready) preview.mutate()
      }}
    >
      <label className="flex flex-col gap-1 text-sm">
        <span className="text-slate-500 dark:text-slate-400">Name this rule</span>
        <input
          value={name}
          onChange={(event) => {
            setName(event.target.value)
            clearPreview()
          }}
          placeholder="Engineering staff get the Engineering group"
          className={FIELD}
          required
        />
      </label>

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">When</span>
          <select
            value={attribute}
            onChange={(event) => {
              setAttribute(event.target.value)
              clearPreview()
            }}
            className={FIELD}
          >
            {(attributes.data ?? []).map((entry) => (
              <option key={entry.name} value={entry.name}>
                {entry.label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">&nbsp;</span>
          <select
            value={operator}
            onChange={(event) => {
              setOperator(event.target.value as RuleOperator)
              clearPreview()
            }}
            className={FIELD}
          >
            {OPERATORS.map((entry) => (
              <option key={entry.value} value={entry.value}>
                {entry.label}
              </option>
            ))}
          </select>
        </label>

        {takesValue(operator) ? (
          <label className="flex flex-1 flex-col gap-1 text-sm">
            <span className="text-slate-500 dark:text-slate-400">&nbsp;</span>
            <input
              value={value}
              onChange={(event) => {
                setValue(event.target.value)
                clearPreview()
              }}
              placeholder="Engineering"
              className={FIELD}
              required
            />
          </label>
        ) : null}

        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">put them in</span>
          <select
            value={groupId}
            onChange={(event) => {
              setGroupId(event.target.value)
              clearPreview()
            }}
            className={FIELD}
            required
          >
            <option value="">choose a group…</option>
            {(groups.data?.items ?? []).map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      {preview.isError ? <ErrorBox error={preview.error} /> : null}
      {create.isError ? <ErrorBox error={create.error} /> : null}
      {preview.data ? <PreviewResult preview={preview.data} /> : null}

      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={!ready || preview.isPending || create.isPending}
          className="rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
        >
          {preview.isPending
            ? 'Checking…'
            : create.isPending
              ? 'Saving…'
              : preview.data
                ? 'Save this rule'
                : 'See who this affects'}
        </button>
        {preview.data ? (
          <button
            type="button"
            onClick={() => preview.reset()}
            className="rounded-sm border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
          >
            Change it
          </button>
        ) : (
          <span className="text-xs text-slate-500 dark:text-slate-400">
            A rule is checked before it can be saved.
          </span>
        )}
      </div>
    </form>
  )
}

function RuleRow({ rule, canWrite }: { rule: AccessRule; canWrite: boolean }) {
  const queryClient = useQueryClient()
  const [confirming, setConfirming] = useState(false)

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['access-rules'] })
  }

  const toggle = useMutation({
    mutationFn: () => setAccessRuleEnabled(rule.id, !rule.enabled),
    onSuccess: refresh,
  })
  const remove = useMutation({
    mutationFn: () => deleteAccessRule(rule.id),
    onSuccess: () => {
      setConfirming(false)
      refresh()
    },
  })

  // Who this rule catches *now*, which is not the same question as who is in the
  // group. A rule that stopped matching anybody still leaves its old members behind
  // until it runs again, so "granted" and "currently matches" can disagree — and that
  // disagreement is exactly what somebody wants to see before pressing Run now.
  const [showing, setShowing] = useState(false)
  const affected = useQuery({
    queryKey: ['rule-affected', rule.id],
    queryFn: () => fetchAffected(rule.id),
    enabled: showing,
  })

  // Applying a saved rule to everybody now, instead of waiting for the next login or
  // department change to trigger it. Rules reconcile, so a run can take memberships
  // away as well as give them — only ever the ones the rule itself created — which is
  // why the line under the row reports removals rather than just additions.
  const run = useMutation({
    mutationFn: () => runAccessRule(rule.id),
    onSuccess: () => {
      refresh()
      // Membership counts move on the groups screen too.
      void queryClient.invalidateQueries({ queryKey: ['groups'] })
    },
  })

  return (
    <>
    <tr>
      <Td>
        <span className="font-medium">{rule.name}</span>
        <span className="block text-xs text-slate-500 dark:text-slate-400">{rule.sentence}</span>
        {rule.description ? (
          <span className="block text-xs text-slate-500 dark:text-slate-400">
            {rule.description}
          </span>
        ) : null}
      </Td>
      <Td>{rule.group_name}</Td>
      <Td>
        <Pill tone={rule.enabled ? 'ok' : 'muted'}>{rule.enabled ? 'on' : 'off'}</Pill>
      </Td>
      <Td right>
        <span className="tabular-nums">{rule.member_count.toLocaleString()}</span>
      </Td>
      <Td right>
        {canWrite ? (
          confirming ? (
            <span className="flex flex-col items-end gap-1">
              <span className="text-xs text-rose-700 dark:text-rose-400">
                Delete this rule? Everyone it put in {rule.group_name} loses that membership.
              </span>
              <span className="flex gap-2">
                <button
                  type="button"
                  onClick={() => remove.mutate()}
                  disabled={remove.isPending}
                  className="rounded-sm border border-rose-500 bg-rose-600 px-2 py-1 text-xs text-white disabled:opacity-40"
                >
                  {remove.isPending ? 'Deleting…' : 'Yes, delete it'}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirming(false)}
                  className="rounded-sm border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
                >
                  Cancel
                </button>
              </span>
            </span>
          ) : (
            <span className="flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowing(!showing)}
                className="rounded-sm border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
              >
                {showing ? 'Hide who' : 'Who it catches'}
              </button>
              <button
                type="button"
                onClick={() => run.mutate()}
                disabled={run.isPending || !rule.enabled}
                title={
                  rule.enabled
                    ? 'Apply this rule to everybody now'
                    : 'Turn the rule on before running it'
                }
                className="rounded-sm border border-brass-600 px-2 py-1 text-xs text-brass-700 disabled:opacity-40 dark:border-brass-400 dark:text-brass-400"
              >
                {run.isPending ? 'Running…' : 'Run now'}
              </button>
              <button
                type="button"
                onClick={() => toggle.mutate()}
                disabled={toggle.isPending}
                className="rounded-sm border border-slate-300 px-2 py-1 text-xs disabled:opacity-40 dark:border-slate-700"
              >
                {rule.enabled ? 'Turn off' : 'Turn on'}
              </button>
              <button
                type="button"
                onClick={() => setConfirming(true)}
                className="rounded-sm border border-rose-400 px-2 py-1 text-xs text-rose-700 dark:border-rose-800 dark:text-rose-400"
              >
                Delete
              </button>
            </span>
          )
        ) : null}
        {run.data ? (
          <span className="block pt-1 text-xs text-slate-500 dark:text-slate-400">
            {run.data.added} added, {run.data.removed} removed, {run.data.unchanged}{' '}
            already right
          </span>
        ) : null}
        {toggle.isError ? <ErrorBox error={toggle.error} /> : null}
        {remove.isError ? <ErrorBox error={remove.error} /> : null}
        {run.isError ? <ErrorBox error={run.error} /> : null}
      </Td>
    </tr>

    {showing ? (
      <tr>
        <Td colSpan={5}>
          {affected.isPending ? (
            <Loading />
          ) : affected.isError ? (
            <ErrorBox error={affected.error} />
          ) : affected.data.length === 0 ? (
            <Empty>
              This rule matches nobody at the moment. Anybody it put in{' '}
              {rule.group_name} stays there until it runs again.
            </Empty>
          ) : (
            <ul className="flex flex-col">
              {affected.data.map((person) => (
                <li
                  key={person.id}
                  className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 py-1 last:border-0 dark:border-slate-800/60"
                >
                  <LinkCell to={`/users/${person.id}`}>{person.display_name}</LinkCell>
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    {[person.department, person.job_title].filter(Boolean).join(' · ') || '—'}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Td>
      </tr>
    ) : null}
    </>
  )
}

export default function AccessRulesPage() {
  const rules = useQuery({ queryKey: ['access-rules'], queryFn: fetchAccessRules })
  const me = useQuery({ queryKey: ['me'], queryFn: fetchMe, retry: false })
  const canWrite = me.data?.permissions.includes('groups:write') ?? false

  return (
    <div className="flex flex-col gap-6">
      <Panel title="Access rules">
        <p className="pb-4 text-sm text-slate-600 dark:text-slate-300">
          Rules put people in groups because of who they are. Somebody who joins Engineering
          lands in the Engineering group without anybody clicking anything, and somebody who
          transfers out stops being in it.
        </p>

        {rules.isError ? (
          <ErrorBox error={rules.error} />
        ) : rules.isPending ? (
          <Loading />
        ) : rules.data.length === 0 ? (
          <Empty>No rules yet. Everything is granted by hand.</Empty>
        ) : (
          <TableWrap>
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <Th>Rule</Th>
                  <Th>Group</Th>
                  <Th>State</Th>
                  <Th right>Granted</Th>
                  <Th right>{''}</Th>
                </tr>
              </thead>
              <tbody>
                {rules.data.map((rule) => (
                  <RuleRow key={rule.id} rule={rule} canWrite={canWrite} />
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Panel>

      {canWrite ? (
        <Panel title="Write a rule">
          <NewRuleForm />
        </Panel>
      ) : null}
    </div>
  )
}
