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

import { Button } from '../components/Button'
import { cx } from '../lib/cx'
import styles from './AccessRules.module.css'
import { PageHeader } from '../components/PageHeader'
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

function PreviewResult({ preview }: { preview: RulePreview }) {
  // The count first, and loud when it's big. Somebody skimming should be stopped
  // by the number, not by reading the sample list.
  const large = preview.would_be_added > 25

  return (
    <div className={cx(styles.preview, large && styles.previewLarge)}>
      <p className={styles.previewHeadline}>
        {preview.sentence} → {preview.group_name}
      </p>
      <p>
        Matches <strong className={styles.previewCount}>{preview.matches.toLocaleString()}</strong>{' '}
        {preview.matches === 1 ? 'person' : 'people'}. Would add{' '}
        <strong className={styles.previewCount}>
          {preview.would_be_added.toLocaleString()}
        </strong>
        ; {preview.already_in_group.toLocaleString()} already in the group.
      </p>
      {large ? (
        <p className={styles.previewWarning}>
          That is a lot of people. Worth checking the value is spelled the way the HR system
          spells it before saving.
        </p>
      ) : null}
      {preview.sample.length > 0 ? (
        <ul className={styles.previewSample}>
          {preview.sample.map((person) => (
            <li key={person.id}>
              {person.display_name} — <Mono>{person.department ?? 'no department'}</Mono>
            </li>
          ))}
          {preview.matches > preview.sample.length ? (
            <li className={styles.previewMore}>
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
      className={styles.form}
      onSubmit={(event) => {
        event.preventDefault()
        if (preview.data) create.mutate()
        else if (ready) preview.mutate()
      }}
    >
      <label className={styles.label}>
        <span className={styles.labelText}>Name this rule</span>
        <input
          value={name}
          onChange={(event) => {
            setName(event.target.value)
            clearPreview()
          }}
          placeholder="Engineering staff get the Engineering group"
          className={styles.field}
          required
        />
      </label>

      <div className={styles.conditionRow}>
        <label className={styles.label}>
          <span className={styles.labelText}>When</span>
          <select
            value={attribute}
            onChange={(event) => {
              setAttribute(event.target.value)
              clearPreview()
            }}
            className={styles.field}
          >
            {(attributes.data ?? []).map((entry) => (
              <option key={entry.name} value={entry.name}>
                {entry.label}
              </option>
            ))}
          </select>
        </label>

        <label className={styles.label}>
          <span className={styles.labelText}>&nbsp;</span>
          <select
            value={operator}
            onChange={(event) => {
              setOperator(event.target.value as RuleOperator)
              clearPreview()
            }}
            className={styles.field}
          >
            {OPERATORS.map((entry) => (
              <option key={entry.value} value={entry.value}>
                {entry.label}
              </option>
            ))}
          </select>
        </label>

        {takesValue(operator) ? (
          <label className={cx(styles.label, styles.labelGrow)}>
            <span className={styles.labelText}>&nbsp;</span>
            <input
              value={value}
              onChange={(event) => {
                setValue(event.target.value)
                clearPreview()
              }}
              placeholder="Engineering"
              className={styles.field}
              required
            />
          </label>
        ) : null}

        <label className={styles.label}>
          <span className={styles.labelText}>put them in</span>
          <select
            value={groupId}
            onChange={(event) => {
              setGroupId(event.target.value)
              clearPreview()
            }}
            className={styles.field}
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

      <div className={styles.formActions}>
        <Button
          type="submit"
          variant="accent"
          disabled={!ready || preview.isPending || create.isPending}
        >
          {preview.isPending
            ? 'Checking…'
            : create.isPending
              ? 'Saving…'
              : preview.data
                ? 'Save this rule'
                : 'See who this affects'}
        </Button>
        {preview.data ? (
          <Button variant="secondary" onClick={() => preview.reset()}>
            Change it
          </Button>
        ) : (
          <span className={styles.hint}>A rule is checked before it can be saved.</span>
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
        <span className={styles.ruleName}>{rule.name}</span>
        <span className={styles.ruleDetail}>{rule.sentence}</span>
        {rule.description ? (
          <span className={styles.ruleDetail}>{rule.description}</span>
        ) : null}
      </Td>
      <Td>{rule.group_name}</Td>
      <Td>
        <Pill tone={rule.enabled ? 'ok' : 'muted'}>{rule.enabled ? 'on' : 'off'}</Pill>
      </Td>
      <Td right>
        <span className={styles.memberCount}>{rule.member_count.toLocaleString()}</span>
      </Td>
      <Td right>
        {canWrite ? (
          confirming ? (
            <span className={styles.confirm}>
              <span className={styles.confirmText}>
                Delete this rule? Everyone it put in {rule.group_name} loses that membership.
              </span>
              <span className={styles.confirmActions}>
                <Button
                  variant="danger-solid"
                  onClick={() => remove.mutate()}
                  disabled={remove.isPending}
                >
                  {remove.isPending ? 'Deleting…' : 'Yes, delete it'}
                </Button>
                <Button variant="secondary" onClick={() => setConfirming(false)}>
                  Cancel
                </Button>
              </span>
            </span>
          ) : (
            <span className={styles.rowActions}>
              <Button variant="secondary" onClick={() => setShowing(!showing)}>
                {showing ? 'Hide who' : 'Who it catches'}
              </Button>
              <Button
                variant="accent"
                onClick={() => run.mutate()}
                disabled={run.isPending || !rule.enabled}
                title={
                  rule.enabled
                    ? 'Apply this rule to everybody now'
                    : 'Turn the rule on before running it'
                }
              >
                {run.isPending ? 'Running…' : 'Run now'}
              </Button>
              <Button
                variant="secondary"
                onClick={() => toggle.mutate()}
                disabled={toggle.isPending}
              >
                {rule.enabled ? 'Turn off' : 'Turn on'}
              </Button>
              <Button variant="danger" onClick={() => setConfirming(true)}>
                Delete
              </Button>
            </span>
          )
        ) : null}
        {run.data ? (
          <span className={styles.runResult}>
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
            <ul className={styles.affectedList}>
              {affected.data.map((person) => (
                <li key={person.id} className={styles.affectedPerson}>
                  <LinkCell to={`/users/${person.id}`}>{person.display_name}</LinkCell>
                  <span className={styles.affectedMeta}>
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
    <div className={styles.page}>
      <PageHeader title="Access rules" description="Put people in groups automatically, based on who they are." />
      <Panel title="Access rules">
        <p className={styles.intro}>
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
            <table className={styles.table}>
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
