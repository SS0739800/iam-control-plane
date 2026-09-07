/**
 * Public setup guide for connecting an identity provider.
 *
 * Reachable without a login, because the person standing up a fresh tenant can't
 * sign in until a provider is configured — which is exactly what this page is for.
 * It's the doc in docs/identity-providers.md, rendered as a page, with the URLs
 * filled in for wherever this happens to be hosted.
 */

import { Link } from 'react-router-dom'

import { Tabs } from './Tabs'
import styles from './SetupPage.module.css'

const REPO_URL = 'https://github.com/SS0739800/iam-control-plane'

// The address everything hangs off. On the deployed console this becomes the real
// hostname, so the tables below show the URLs a provider actually needs rather than
// a placeholder to substitute by hand.
const BASE = typeof window !== 'undefined' ? window.location.origin : 'https://your-console'

function Table({ head, rows }: { head: [string, string]; rows: [string, string][] }) {
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th scope="col">{head[0]}</th>
            <th scope="col">{head[1]}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([left, right]) => (
            <tr key={left}>
              <td>{left}</td>
              <td className={styles.valueCell}>{right}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Code({ children }: { children: string }) {
  return (
    <pre className={styles.code}>
      <code>{children}</code>
    </pre>
  )
}

function AuthentikTab() {
  return (
    <div className={styles.tabBody}>
      <p className={styles.prose}>
        The repo ships a blueprint that configures authentik for you — the fastest way to
        get the loop running locally. It declares the application, the ACS URL, the
        audience, the attributes it sends, and that the assertion is signed.
      </p>
      <Code>docker compose --profile idp up -d</Code>
      <p className={styles.prose}>Its metadata is then at:</p>
      <Code>{`${BASE.includes('localhost') ? BASE.replace(/:\d+$/, ':9000') : 'http://localhost:9000'}/application/saml/iam-console/metadata/`}</Code>
      <p className={styles.prose}>
        Register it with the snippet below, then sign in as <code>akadmin</code> with the
        password in <code>AUTHENTIK_BOOTSTRAP_PASSWORD</code>. To set it up by hand instead,
        create a SAML provider using the ACS URL, audience and signing settings from the
        table above, and add property mappings for username, email, given name and family
        name.
      </p>
    </div>
  )
}

function OktaTab() {
  return (
    <div className={styles.tabBody}>
      <p className={styles.prose}>
        Create a SAML app integration (Applications → Create App Integration → SAML 2.0),
        then fill in:
      </p>
      <Table
        head={['Okta field', 'Value']}
        rows={[
          ['Single sign-on URL', `${BASE}/saml/acs`],
          ['Audience URI (SP Entity ID)', `${BASE}/saml/metadata`],
          ['Name ID format', 'Persistent'],
          ['Application username', 'Okta username, or email'],
        ]}
      />
      <p className={styles.prose}>
        Under <strong>Attribute Statements</strong>, add the ones you want. Okta's own
        template names work as-is:
      </p>
      <Table
        head={['Name', 'Value']}
        rows={[
          ['login', 'user.login'],
          ['email', 'user.email'],
          ['firstName', 'user.firstName'],
          ['lastName', 'user.lastName'],
          ['displayName', 'user.displayName'],
        ]}
      />
      <p className={styles.prose}>
        Okta signs the assertion by default, which is what we need. For single logout,
        enable it in the app's advanced SAML settings, set the logout URL to{' '}
        <code>{BASE}/saml/sls</code>, and upload the certificate from{' '}
        <code>{BASE}/saml/metadata</code> so Okta can verify the LogoutRequests we sign.
        Without it Okta rejects our logout and the provider session stays open, so the next
        sign-in walks straight back in without a password. Then download the IdP metadata
        (the "Identity Provider metadata" link on the Sign On tab) and register it below.
      </p>

      <h3 className={styles.subHeading}>SCIM from Okta</h3>
      <p className={styles.prose}>
        Okta can push users and groups to us. In the app's <strong>Provisioning</strong>{' '}
        tab, enable API integration and give it:
      </p>
      <Table
        head={['Okta field', 'Value']}
        rows={[
          ['SCIM base URL', `${BASE}/scim/v2`],
          ['Unique identifier', 'userName'],
          ['Auth mode', 'HTTP Header, Authorization: Bearer <token>'],
        ]}
      />
      <p className={styles.prose}>
        Issue the token from the repo — it's printed once and only its hash is stored:
      </p>
      <Code>{`cd apps/api\npython -m scripts.issue_scim_token "Okta (acme.okta.com)"`}</Code>
      <p className={styles.note}>
        A provider deactivating someone over SCIM revokes their console role grants too. If
        that person is your only admin, the console locks, and the fix is running{' '}
        <code>scripts/grant_first_admin.py</code> against the database.
      </p>
    </div>
  )
}

function EntraTab() {
  return (
    <div className={styles.tabBody}>
      <p className={styles.prose}>
        Create a non-gallery enterprise application (Enterprise applications → New
        application → Create your own), then under <strong>Single sign-on</strong> choose
        SAML and set:
      </p>
      <Table
        head={['Entra field', 'Value']}
        rows={[
          ['Identifier (Entity ID)', `${BASE}/saml/metadata`],
          ['Reply URL (ACS)', `${BASE}/saml/acs`],
          ['Logout URL', `${BASE}/saml/sls`],
        ]}
      />
      <p className={styles.prose}>
        Entra sends WS-Federation claim URIs by default, all of which we already accept —
        the UPN for the username, plus email address, given name, surname, and the object
        identifier as the external id. You shouldn't need to add or rename claims. Under{' '}
        <strong>SAML Certificates</strong>, check that the signing option covers the
        assertion rather than only the response, then download the Federation Metadata XML
        and register it below.
      </p>

      <h3 className={styles.subHeading}>SCIM from Entra</h3>
      <p className={styles.prose}>
        Entra's provisioning tab takes a <strong>Tenant URL</strong> of{' '}
        <code>{BASE}/scim/v2</code> and a <strong>Secret Token</strong> from{' '}
        <code>scripts.issue_scim_token</code>, then "Test Connection" before you save.
      </p>
      <p className={styles.note}>
        Entra is the one provider not yet proven end to end here. The SAML side follows the
        same shape as the others and its claim URIs are already in the lookup tables, but
        its SCIM behaviour differs enough from Okta's that it hasn't been verified against
        this server. Expect to iterate.
      </p>
    </div>
  )
}

export default function SetupPage() {
  return (
    <div className={styles.page}>
      <header className={styles.topBar}>
        <Link to="/" className={styles.brand}>
          IAM Control Plane
        </Link>
        <nav className={styles.topLinks} aria-label="Page links">
          <Link to="/">Home</Link>
          <a href={REPO_URL} target="_blank" rel="noreferrer">
            Source
          </a>
        </nav>
      </header>

      <main className={styles.main}>
        <section className={styles.hero}>
          <p className={styles.kicker}>Setup guide</p>
          <h1 className={styles.title}>Connecting an identity provider</h1>
          <p className={styles.lead}>
            How to point authentik, Okta or Entra ID at this console — for signing in over
            SAML, and for pushing accounts to us over SCIM. The URLs below are already
            filled in for <code>{BASE}</code>.
          </p>
        </section>

        <section className={styles.divided} aria-labelledby="from-us">
          <h2 id="from-us" className={styles.blockHeading}>
            What every provider needs from us
          </h2>
          <p className={styles.prose}>These don't vary by provider.</p>
          <Table
            head={['Setting', 'Value']}
            rows={[
              ['Entity ID / Identifier / Audience', `${BASE}/saml/metadata`],
              ['ACS URL / Reply URL', `${BASE}/saml/acs`],
              ['Single logout URL', `${BASE}/saml/sls`],
              ['ACS binding', 'HTTP-POST'],
              ['Logout binding', 'HTTP-Redirect'],
              ['NameID format', 'persistent'],
            ]}
          />
          <div className={styles.callouts}>
            <div className={styles.callout}>
              <p className={styles.calloutTitle}>The audience must equal the entity ID exactly</p>
              <p className={styles.calloutBody}>
                Scheme and any trailing slash included — the check compares strings. A
                mismatch shows on the <strong>Sign-ins</strong> screen as a failed{' '}
                <code>audience</code> check, with both values printed.
              </p>
            </div>
            <div className={styles.callout}>
              <p className={styles.calloutTitle}>The assertion itself has to be signed</p>
              <p className={styles.calloutBody}>
                Not just the response envelope — an unsigned assertion inside a signed
                wrapper can still be swapped. Some providers sign only the response by
                default, so check the setting.
              </p>
            </div>
          </div>
        </section>

        <section className={styles.divided} aria-labelledby="your-provider">
          <h2 id="your-provider" className={styles.blockHeading}>
            Your provider
          </h2>
          <Tabs
            tabs={[
              { id: 'entra', label: 'Entra ID', content: <EntraTab /> },
              { id: 'okta', label: 'Okta', content: <OktaTab /> },
              { id: 'authentik', label: 'authentik', content: <AuthentikTab /> },
            ]}
          />
        </section>

        <section className={styles.divided} aria-labelledby="register">
          <h2 id="register" className={styles.blockHeading}>
            Registering it with us
          </h2>
          <p className={styles.prose}>
            The same for all three, and it's two steps because the server never fetches a
            URL you give it. Download the provider's metadata yourself, then post the
            document. This prints the login URL; the signing certificate is taken from the
            document, so there's nothing else to paste.
          </p>
          <Code>{`curl -sS https://your-provider/path/to/metadata -o idp.xml

python - <<'PY'
import json, pathlib, urllib.request
body = json.dumps({
    "slug": "okta",                     # url-safe, used in /saml/login?idp=<slug>
    "name": "Okta (acme.okta.com)",     # what the sign-in page calls it
    "metadata_xml": pathlib.Path("idp.xml").read_text(encoding="utf-8"),
}).encode()
request = urllib.request.Request(
    "${BASE}/api/identity-providers",
    data=body,
    headers={"Content-Type": "application/json"},
)
print(json.loads(urllib.request.urlopen(request).read())["login_url"])
PY`}</Code>
        </section>

        <section className={styles.divided} aria-labelledby="attributes">
          <h2 id="attributes" className={styles.blockHeading}>
            Attributes we read
          </h2>
          <p className={styles.prose}>
            We look for each fact under several names and take the first one set, so you
            usually don't have to match a specific spelling. Only a username or an email is
            required; the rest just fill in the profile.
          </p>
          <Table
            head={['What', 'Names we accept (first that is set wins)']}
            rows={[
              ['Username', 'authentik username, WS-Fed UPN, uid OID, userName, username, login, uid'],
              ['Email', 'WS-Fed emailaddress, email OID, email, emailAddress, mail'],
              ['Given name', 'WS-Fed givenname, givenName OID, givenName, firstName'],
              ['Family name', 'WS-Fed surname, surname OID, surname, familyName, lastName'],
              ['Display name', 'MS displayname, cn OID, displayName, cn'],
              ['External id', 'MS objectidentifier, authentik uid, externalId'],
            ]}
          />
        </section>

        <section className={styles.divided} aria-labelledby="checking">
          <h2 id="checking" className={styles.blockHeading}>
            Checking it worked
          </h2>
          <p className={styles.prose}>
            Start a login at <code>{BASE}/saml/login?idp=&lt;slug&gt;</code>, then open{' '}
            <strong>Sign-ins</strong> in the console. Every attempt lists all ten checks
            with the values compared, and a refused login keeps the document that arrived —
            usually enough to see what's wrong. The usual first failures:
          </p>
          <Table
            head={['Check', 'Usually means']}
            rows={[
              ['audience', `The audience at the provider isn't exactly ${BASE}/saml/metadata`],
              ['assertion_signed', 'The provider is signing only the response envelope'],
              ['signature', "The certificate in the metadata isn't the one that signed this"],
              ['timing', 'Clock skew between the provider and this server'],
              ['destination', `The ACS URL at the provider doesn't match ${BASE}/saml/acs`],
            ]}
          />
        </section>
      </main>

      <footer className={styles.footer}>
        <Link to="/">Back to home</Link>
        <a href={REPO_URL} target="_blank" rel="noreferrer">
          Source on GitHub
        </a>
      </footer>
    </div>
  )
}
