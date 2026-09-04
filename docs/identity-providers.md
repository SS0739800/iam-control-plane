# Connecting an identity provider

How to point authentik, Okta or Entra ID at your own deployment of this console,
for signing in (SAML) and for pushing accounts to us (SCIM).

Everything below assumes a base URL. Locally that's `http://localhost:8080`;
deployed it's whatever hostname you run on. Substitute it wherever you see
`BASE`.

## What every provider needs from us

These come from `iam/saml/sp.py` and don't vary by provider:

| Setting                                | Value                    |
| -------------------------------------- | ------------------------ |
| Entity ID / Identifier / Audience      | `BASE/saml/metadata`     |
| ACS URL / Reply URL / Single sign-on URL | `BASE/saml/acs`        |
| Single logout URL                      | `BASE/saml/sls`          |
| ACS binding                            | HTTP-POST                |
| Logout binding                         | HTTP-Redirect            |
| NameID format                          | `persistent`             |

Two things to get right, because both fail in ways that are hard to read:

**The audience must equal the entity ID exactly**, including scheme and any
trailing path. `https://example.com/saml/metadata` and
`https://example.com/saml/metadata/` are different strings, and the audience check
compares strings. A mismatch shows up on the **Sign-ins** screen as a failed
`audience` check with both values printed.

**The assertion itself has to be signed**, not just the response envelope. Our
metadata advertises `WantAssertionsSigned="true"` and the `assertion_signed` check
enforces it, because an unsigned assertion inside a signed wrapper can still be
swapped. Some providers sign only the response by default.

If a provider genuinely can't sign the assertion, you can register it with
`"want_signed_assertions": false` and that one check is relaxed for that provider
only. It's a real weakening, so prefer fixing the provider's settings.

We don't sign AuthnRequests (`AuthnRequestsSigned="false"`), so you don't need to
give the provider a certificate for that. We *do* sign LogoutRequests, and publish
the certificate for them in `BASE/saml/metadata` — Okta in particular refuses an
unsigned `LogoutRequest` and equally refuses a signed one it can't verify, so if
you want single logout, register that certificate at the provider.

You can fetch our metadata to hand to a provider that accepts an upload:

```bash
curl -sS BASE/saml/metadata -o sp-metadata.xml
```

## Attributes we read

We look for each fact under several names and take the first one that's set, so
you usually don't have to match a specific spelling. The lookup is
case-insensitive and lives in `iam/saml/provisioning.py`.

| What         | Names we accept                                                                                                                                              |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Username     | `http://schemas.goauthentik.io/2021/02/saml/username`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn`, `urn:oid:0.9.2342.19200300.100.1.1`, `userName`, `username`, `login`, `uid` |
| Email        | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, `urn:oid:0.9.2342.19200300.100.1.3`, `email`, `emailAddress`, `mail`                     |
| Given name   | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`, `urn:oid:2.5.4.42`, `givenName`, `firstName`, `first_name`                                  |
| Family name  | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname`, `urn:oid:2.5.4.4`, `surname`, `familyName`, `lastName`, `last_name`                           |
| Display name | `http://schemas.microsoft.com/identity/claims/displayname`, `urn:oid:2.16.840.1.113730.3.1.241`, `displayName`, `cn`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` |
| External id  | `http://schemas.microsoft.com/identity/claims/objectidentifier`, `http://schemas.goauthentik.io/2021/02/saml/uid`, `externalId`                                |

Only a username or an email is strictly required. If one is missing we fall back
to the other, and as a last resort to the NameID when it looks like an email
address. Everything else is optional and just fills in the profile.

`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` is only ever used for
a display name — authentik puts a person's full name there and Entra puts their
sign-in name, so it's too ambiguous to trust for anything that has to be exact.

## Registering the provider with us

The same for all three, and it's two steps because the server never fetches a URL
you give it ([ADR 0006](adr/0006-paste-metadata.md)). Download the provider's
metadata yourself, then post the document:

```bash
curl -sS https://your-provider/path/to/metadata -o idp.xml

python - <<'PY'
import json, pathlib, urllib.request
body = json.dumps({
    "slug": "okta",                      # url-safe, used in /saml/login?idp=<slug>
    "name": "Okta (acme.okta.com)",      # what the sign-in page calls it
    "metadata_xml": pathlib.Path("idp.xml").read_text(encoding="utf-8"),
}).encode()
request = urllib.request.Request(
    "BASE/api/identity-providers",
    data=body,
    headers={"Content-Type": "application/json"},
)
print(json.loads(urllib.request.urlopen(request).read())["login_url"])
PY
```

That prints the login URL. We take the signing certificate out of the document
itself, picking the key marked for signing, so there's no separate field to fill
in and no way to paste an encryption certificate by mistake.

If the provider rotates its certificate, post the new metadata the same way.

---

## authentik

The repo ships a blueprint that configures authentik for you, which is the fastest
route if you just want the loop working locally:

```bash
docker compose --profile idp up -d
```

[`infra/authentik/blueprints/iam-console.yaml`](../infra/authentik/blueprints/iam-console.yaml)
declares the application, the ACS URL, the audience, the attributes it sends, and
that the assertion gets signed. It reads `IAM_BASE_URL` from the environment, so
set that if you aren't on `http://localhost:8080`.

Its metadata is at:

```
http://localhost:9000/application/saml/iam-console/metadata/
```

Register it with the snippet above, then sign in as `akadmin` with
`AUTHENTIK_BOOTSTRAP_PASSWORD`.

To set it up by hand instead, create a SAML provider with the ACS URL, audience
and signing settings from the table at the top, and add property mappings for
username, email, given name and family name.

---

## Okta

Create a SAML app integration (Applications → Create App Integration → SAML 2.0),
then fill in:

| Okta field                    | Value                |
| ----------------------------- | -------------------- |
| Single sign-on URL            | `BASE/saml/acs`      |
| Audience URI (SP Entity ID)   | `BASE/saml/metadata` |
| Name ID format                | Persistent           |
| Application username          | Okta username, or email |

Under **Attribute Statements**, add the ones you want. Okta's own template names
work as-is:

| Name         | Value              |
| ------------ | ------------------ |
| `login`      | `user.login`       |
| `email`      | `user.email`       |
| `firstName`  | `user.firstName`   |
| `lastName`   | `user.lastName`    |
| `displayName`| `user.displayName` |

Okta signs the assertion by default, which is what we need.

For single logout, enable it in the app's advanced SAML settings, set the logout
URL to `BASE/saml/sls`, and upload the certificate from `BASE/saml/metadata` so
Okta can verify the LogoutRequests we sign. Without that certificate Okta rejects
our logout and the provider session stays open, so clicking sign-in again walks
straight back in without a password.

Then download the IdP metadata (the "Identity Provider metadata" link on the
Sign On tab) and register it with us.

### SCIM from Okta

Okta can push users and groups to us. In the app's **Provisioning** tab, enable
API integration and give it:

| Okta field    | Value                                     |
| ------------- | ----------------------------------------- |
| SCIM base URL | `BASE/scim/v2`                            |
| Unique identifier | `userName`                            |
| Auth mode     | HTTP Header, `Authorization: Bearer <token>` |

Issue the token from the repo — it's printed once and only its hash is stored:

```bash
cd apps/api
python -m scripts.issue_scim_token "Okta (acme.okta.com)"
```

We implement Users and Groups with GET, POST, PUT, PATCH and DELETE, plus
`/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas` for discovery. A DELETE
deactivates rather than removing the record.

One thing to know before you rely on this: a provider deactivating someone over
SCIM revokes their console role grants too. If that person is your only admin, the
console locks and the fix is running `scripts/grant_first_admin.py` against the
database. The last-admin guard can't prevent it, because it only covers changes
made through `PATCH /api/users/{id}`.

---

## Entra ID

Create a non-gallery enterprise application (Enterprise applications → New
application → Create your own), then under **Single sign-on** choose SAML and set:

| Entra field              | Value                |
| ------------------------ | -------------------- |
| Identifier (Entity ID)   | `BASE/saml/metadata` |
| Reply URL (ACS)          | `BASE/saml/acs`      |
| Logout URL               | `BASE/saml/sls`      |

Entra sends WS-Federation claim URIs by default, all of which we already accept —
`.../claims/upn` for the username, `.../claims/emailaddress`,
`.../claims/givenname`, `.../claims/surname`, and
`http://schemas.microsoft.com/identity/claims/objectidentifier` as the external
id. You shouldn't need to add or rename claims.

Under **SAML Certificates**, check that the signing option covers the assertion
rather than only the response. Then download the Federation Metadata XML and
register it with us.

### SCIM from Entra

Entra's provisioning tab takes a **Tenant URL** of `BASE/scim/v2` and a **Secret
Token** from `scripts.issue_scim_token`, then "Test Connection" before you save.

Entra is the one provider not yet integrated end to end here. The SAML side
follows the same shape as the others and its claim URIs are already in the lookup
tables, but its SCIM behaviour differs enough from Okta's that it hasn't been
proven against this server. Expect to iterate.

---

## Checking it worked

Start a login:

```
BASE/saml/login?idp=<slug>
```

Then open **Sign-ins** in the console. Every attempt lists all ten checks with the
values compared, and a refused login keeps the document that arrived, which is
normally enough to see what's wrong without turning on any logging.

The usual first failures:

| Check              | Usually means                                                  |
| ------------------ | -------------------------------------------------------------- |
| `audience`         | The audience at the provider isn't exactly `BASE/saml/metadata` |
| `assertion_signed` | The provider is signing only the response envelope              |
| `signature`        | The certificate in the metadata isn't the one that signed this  |
| `timing`           | Clock skew between the provider and this server                 |
| `destination`      | The ACS URL at the provider doesn't match `BASE/saml/acs`       |

Without a browser:

```bash
cd apps/api && python -m scripts.smoke_login
```

Signing in creates an ordinary employee with no console permissions. Granting a
role is a separate admin action on that person's page.
