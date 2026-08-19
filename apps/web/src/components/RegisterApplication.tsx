/**
 * Registering an application by pasting its metadata.
 *
 * A textarea rather than fields for the entity ID, the login response URL and the
 * certificate — deliberately, and it is the same decision as registering an identity
 * provider. Typing those separately is how an assertion ends up posted to an address
 * the application never published, and the ACS URL is where we send a signed
 * assertion for a real person.
 *
 * We do not fetch a metadata URL either. See docs/adr/0006.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { type ApplicationDetail, registerApplication } from '../lib/api'
import { ErrorBox, Mono, Panel } from './ui'

const FIELD =
  'rounded-sm border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900'

export function RegisterApplication() {
  const [slug, setSlug] = useState('')
  const [name, setName] = useState('')
  const [metadata, setMetadata] = useState('')
  const [registered, setRegistered] = useState<ApplicationDetail | null>(null)

  const queryClient = useQueryClient()

  const register = useMutation({
    mutationFn: () =>
      registerApplication({ slug, name, metadata_xml: metadata }),
    onSuccess: (app) => {
      setRegistered(app)
      setSlug('')
      setName('')
      setMetadata('')
      void queryClient.invalidateQueries({ queryKey: ['applications'] })
    },
  })

  return (
    <Panel title="Register an application">
      {registered ? (
        <div className="mb-4 flex flex-col gap-2 rounded-sm border border-emerald-600 bg-emerald-50 p-3 text-sm dark:border-emerald-500 dark:bg-emerald-950">
          <p className="font-semibold">{registered.name} is registered.</p>
          <p>
            Read from its metadata: entity ID <Mono>{registered.entity_id}</Mono>, logins posted
            to <Mono>{registered.acs_url}</Mono>.
          </p>
          <p className="text-xs text-slate-600 dark:text-slate-300">
            Nobody can use it yet — give a group or a person access on its page first.
          </p>
        </div>
      ) : null}

      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault()
          if (slug && name && metadata.trim()) register.mutate()
        }}
      >
        <div className="flex flex-wrap gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-slate-500 dark:text-slate-400">Short name</span>
            <input
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
              placeholder="expenses"
              pattern="[a-z0-9][a-z0-9-]*"
              title="lowercase letters, digits and dashes"
              required
              className={FIELD}
            />
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Used in the sign-in link, so lowercase and dashes only.
            </span>
          </label>
          <label className="flex flex-1 flex-col gap-1 text-sm">
            <span className="text-slate-500 dark:text-slate-400">Name</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Expenses"
              required
              className={FIELD}
            />
          </label>
        </div>

        <label className="flex flex-col gap-1 text-sm">
          <span className="text-slate-500 dark:text-slate-400">
            Its SAML metadata, pasted in whole
          </span>
          <textarea
            value={metadata}
            onChange={(event) => setMetadata(event.target.value)}
            rows={6}
            placeholder="<md:EntityDescriptor …>"
            required
            className={`${FIELD} font-mono text-xs`}
          />
          <span className="text-xs text-slate-500 dark:text-slate-400">
            The entity ID, the login response URL and the certificate are read from this rather
            than typed. Get the document yourself — we never fetch a URL you give us.
          </span>
        </label>

        {register.isError ? <ErrorBox error={register.error} /> : null}

        <button
          type="submit"
          disabled={register.isPending || !slug || !name || !metadata.trim()}
          className="self-start rounded-sm border border-brass-600 px-3 py-1 text-sm text-brass-700 disabled:opacity-50 dark:border-brass-400 dark:text-brass-400"
        >
          {register.isPending ? 'Reading it…' : 'Register'}
        </button>
      </form>

      <p className="pt-4 text-xs text-slate-500 dark:text-slate-400">
        Setting up the other side? The document to give the application is at{' '}
        <Mono>{window.location.origin}/idp/metadata</Mono>.
      </p>
    </Panel>
  )
}
