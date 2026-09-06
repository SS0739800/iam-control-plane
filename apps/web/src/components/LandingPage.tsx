/**
 * The front door. What a signed-out visitor sees at the root.
 *
 * On the deployed site that's anyone who isn't already in the tenant's directory —
 * a recruiter, a reviewer, anyone following a link. They can't sign in, since they
 * have no account here, so this page has to stand on its own and say what the thing
 * is rather than just show them a login wall.
 *
 * It's still the real sign-in page for people who do have an account, so the provider
 * links stay near the top.
 *
 * The screenshots are real console views, served from public/marketing/, not the
 * bundle. They're the demo instance, seeded data and all.
 */

import { useQuery } from '@tanstack/react-query'

import { fetchSignInOptions } from '../lib/api'
import styles from './LandingPage.module.css'

const REPO_URL = 'https://github.com/SS0739800/iam-control-plane'
const README_URL = `${REPO_URL}#readme`
const SETUP_URL = `${REPO_URL}/blob/main/docs/identity-providers.md`

/** The four things the platform does, each said in one plain sentence. */
const CAPABILITIES: { title: string; body: string }[] = [
  {
    title: 'Single sign-on, both ways',
    body: 'It accepts logins from an identity provider over SAML 2.0, and it is an identity provider itself for downstream apps. The same protocol at both ends.',
  },
  {
    title: 'Provisioning, both ways',
    body: 'A SCIM 2.0 server an identity provider pushes accounts into, and a SCIM client that pushes them onward to the systems that sit downstream.',
  },
  {
    title: 'The whole joiner-to-leaver loop',
    body: 'Someone signs in, an admin grants them access, a sync provisions them downstream, and marking them a leaver switches that account off again — end to end.',
  },
  {
    title: 'An audit log you can check',
    body: 'Every change is written to a hash-chained record. Alter one entry and the chain stops verifying, so the history cannot be quietly edited after the fact.',
  },
]

/** The walkthrough: a real screen paired with what it's for. */
const WALKTHROUGH: { src: string; alt: string; label: string; title: string; body: string }[] = [
  {
    src: '/marketing/users.png',
    alt: 'The users list, showing accounts, where each came from, and their status.',
    label: 'Directory',
    title: 'Every account, and where it came from',
    body: 'Everyone the platform knows about, whether they arrived over SCIM from the identity provider or were created here. Filter by status or role, sort any column, and open one to see their groups, their access and their history.',
  },
  {
    src: '/marketing/audit.png',
    alt: 'The audit log, a table of changes with who, what, and the outcome.',
    label: 'Audit',
    title: 'A record of every change, and a way to prove it',
    body: 'Each grant, sync and sign-in is written to a hash-chained log. The chain can be verified end to end, so a tampered entry shows up rather than passing silently — the difference between a log and a record you can trust.',
  },
]

/** How each provider stands today. The tone drives the status dot; kept honest. */
const PROVIDERS: { name: string; state: string; tone: 'live' | 'progress' | 'local' }[] = [
  { name: 'Okta', state: 'Live in production, inbound SCIM included', tone: 'live' },
  { name: 'Entra ID', state: 'Claim mapping written and tested; live tenant in progress', tone: 'progress' },
  { name: 'authentik', state: 'Proven locally — the dev IdP that ships with the stack', tone: 'local' },
]

/** Sign-in links, one per identity provider actually registered. */
function SignInLinks() {
  const options = useQuery({
    queryKey: ['sign-in-options'],
    queryFn: fetchSignInOptions,
    retry: false,
  })

  if (options.isPending) return null

  // No providers, or the request failed — either way there's no link to offer.
  if (options.isError || (options.data?.length ?? 0) === 0) {
    return (
      <span className={styles.signInEmpty}>
        No identity provider is registered yet, so there is no way to sign in.
      </span>
    )
  }

  return (
    <>
      {options.data.map((option) => (
        <a
          key={option.slug}
          href={`/saml/login?idp=${option.slug}`}
          className={styles.primaryAction}
        >
          Sign in with {option.name}
        </a>
      ))}
    </>
  )
}

export function LandingPage() {
  return (
    <div className={styles.page}>
      <header className={styles.topBar}>
        <span className={styles.brand}>IAM Control Plane</span>
        <nav className={styles.topLinks} aria-label="Project links">
          <a href={README_URL} target="_blank" rel="noreferrer">
            Source
          </a>
          <a href={SETUP_URL} target="_blank" rel="noreferrer">
            Setup guide
          </a>
        </nav>
      </header>

      <main className={styles.main}>
        <section className={styles.hero}>
          <p className={styles.kicker}>Identity platform</p>
          <h1 className={styles.title}>Single sign-on and provisioning, both directions.</h1>
          <p className={styles.lead}>
            An admin console that runs the full loop a real directory does — logins in over
            SAML, accounts synced in and back out over SCIM, access granted and reviewed,
            leavers switched off downstream — with every change written to an audit log you
            can verify. Built as a working system, not a demo, and running in production
            against a live Okta tenant.
          </p>
          <div className={styles.actions}>
            <SignInLinks />
            <a className={styles.secondaryAction} href={README_URL} target="_blank" rel="noreferrer">
              Browse the source
            </a>
          </div>
          <p className={styles.signInNote}>
            Signing in creates nothing but an ordinary employee. Console permissions are
            granted separately, by an admin, and recorded as a grant with a reason.
          </p>
        </section>

        <figure className={styles.shotFrame}>
          <img
            className={styles.shot}
            src="/marketing/overview.png"
            alt="The console overview: directory counts down the middle, platform health on the right."
            loading="lazy"
            width={1400}
            height={860}
          />
          <figcaption className={styles.shotCaption}>
            The overview — directory counts and live platform health. Demo instance with
            seeded data.
          </figcaption>
        </figure>

        <section className={styles.divided} aria-labelledby="what-it-does">
          <h2 id="what-it-does" className={styles.blockHeading}>
            What it does
          </h2>
          <div className={styles.capabilities}>
            {CAPABILITIES.map((item) => (
              <div key={item.title} className={styles.capability}>
                <h3 className={styles.capabilityTitle}>{item.title}</h3>
                <p className={styles.capabilityBody}>{item.body}</p>
              </div>
            ))}
          </div>
        </section>

        <section className={styles.divided} aria-labelledby="a-closer-look">
          <h2 id="a-closer-look" className={styles.blockHeading}>
            A closer look
          </h2>
          <div className={styles.walkthrough}>
            {WALKTHROUGH.map((item) => (
              <figure key={item.src} className={styles.walkRow}>
                <div className={styles.walkShotFrame}>
                  <img
                    className={styles.shot}
                    src={item.src}
                    alt={item.alt}
                    loading="lazy"
                    width={1400}
                    height={860}
                  />
                </div>
                <figcaption className={styles.walkText}>
                  <span className={styles.walkLabel}>{item.label}</span>
                  <h3 className={styles.walkTitle}>{item.title}</h3>
                  <p className={styles.walkBody}>{item.body}</p>
                </figcaption>
              </figure>
            ))}
          </div>
        </section>

        <div className={styles.divided}>
          <div className={styles.twoUp}>
            <section className={styles.block} aria-labelledby="how-its-built">
              <h2 id="how-its-built" className={styles.blockHeading}>
                How it's built
              </h2>
              <p className={styles.prose}>
                FastAPI and Postgres behind a React and TypeScript console, shipped as one
                Docker image. It deploys through GitHub: a push releases only once the
                tests, types, linters and the xmlsec build all pass, and{' '}
                <code>/api/health</code> reports the exact commit that's serving traffic.
              </p>
            </section>

            <section className={styles.block} aria-labelledby="providers">
              <h2 id="providers" className={styles.blockHeading}>
                Providers
              </h2>
              <dl className={styles.providers}>
                {PROVIDERS.map((provider) => (
                  <div key={provider.name} className={styles.provider}>
                    <dt className={styles.providerName}>
                      <span className={styles.dot} data-tone={provider.tone} aria-hidden="true" />
                      {provider.name}
                    </dt>
                    <dd className={styles.providerState}>{provider.state}</dd>
                  </div>
                ))}
              </dl>
            </section>
          </div>
        </div>
      </main>

      <footer className={styles.footer}>
        <a href={README_URL} target="_blank" rel="noreferrer">
          Source on GitHub
        </a>
        <a href={SETUP_URL} target="_blank" rel="noreferrer">
          Connecting an identity provider
        </a>
      </footer>
    </div>
  )
}
