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
import { Button } from './Button'
import { Field, FieldRow, Form, FormActions, controlClass } from './Form'
import styles from './RegisterApplication.module.css'
import { ErrorBox, Mono, Panel } from './ui'

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
        <div className={styles.registered}>
          <p className={styles.registeredHeadline}>{registered.name} is registered.</p>
          <p>
            Read from its metadata: entity ID <Mono>{registered.entity_id}</Mono>, logins posted
            to <Mono>{registered.acs_url}</Mono>.
          </p>
          <p className={styles.hint}>
            Nobody can use it yet — give a group or a person access on its page first.
          </p>
        </div>
      ) : null}

      <Form onSubmit={() => { if (slug && name && metadata.trim()) register.mutate() }}>
        <FieldRow>
          <Field
            label="Short name"
            required
            grow={1}
            description="Used in the sign-in link, so lowercase and dashes only."
          >
            <input
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
              placeholder="expenses"
              pattern="[a-z0-9][a-z0-9-]*"
              title="lowercase letters, digits and dashes"
              required
              className={controlClass()}
            />
          </Field>
          <Field label="Name" required grow={2}>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Expenses"
              required
              className={controlClass()}
            />
          </Field>
        </FieldRow>

        <Field
          label="Its SAML metadata, pasted in whole"
          required
          description="The entity ID, the login response URL and the certificate are read from this
            rather than typed. Get the document yourself — we never fetch a URL you give us."
        >
          <textarea
            value={metadata}
            onChange={(event) => setMetadata(event.target.value)}
            rows={6}
            placeholder="<md:EntityDescriptor …>"
            required
            className={controlClass(true)}
          />
        </Field>

        {register.isError ? <ErrorBox error={register.error} /> : null}

        <FormActions>
          <Button
            type="submit"
            variant="accent"
            disabled={register.isPending || !slug || !name || !metadata.trim()}
          >
            {register.isPending ? 'Reading it…' : 'Register'}
          </Button>
        </FormActions>
      </Form>

      <p className={styles.footnote}>
        Setting up the other side? The document to give the application is at{' '}
        <Mono>{window.location.origin}/idp/metadata</Mono>.
      </p>
    </Panel>
  )
}
