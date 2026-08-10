# OIDC Module - Configuration

This guide summarizes key configuration topics for the OIDC module.
It complements the inline comments in `config/module_oidc.php`.

- Caching protocol artifacts
- Relying Party (RP) administration UI
- Cron integration
- Endpoint locations and well-known URLs
- Pushed Authorization Requests (PAR) and Request Objects
- Key rollover
- Apache Authorization header note
- Private scopes
- Attribute translation
- Auth Proc filters (OIDC)
- Client registration permissions
- OpenID Connect Dynamic Client Registration
- Token Status Lists (credential revocation)
- Running multiple OPs on one server

## Caching protocol artifacts

The configured database is the primary storage for protocol artifacts:
access tokens, authorization codes, refresh tokens, clients, and user
records. In production, you should also configure a cache in front of the
DB to improve performance during traffic spikes.

Caching uses Symfony Cache, so any compatible adapter can be used. See the
`module_oidc.php` configuration file for adapter selection and parameters.

## Relying Party (RP) administration

The module provides a UI to manage clients (create, read, update, delete).
After you create the database schema, go to the SimpleSAMLphp admin area:

- OIDC > Client Registry

Notes:

- Clients can be public or confidential.
- Public clients using Authorization Code flow must send PKCE parameters.
- Client ID and secret are generated; use the "show" button to reveal.

## Cron integration

Enable and configure the SimpleSAMLphp cron module to purge expired tokens:
[cron](https://simplesamlphp.org/docs/stable/cron/cron.html)

The configured cron tag, together with the administration UI settings, is shown in
the SimpleSAMLphp admin area:

- OIDC > General Settings

That screen also reports when cleanup can never run, for example when no cron tag is
set or when the cron module is not enabled.

If you issue Verifiable Credentials with Token Status Lists, cron does considerably
more than purge expired tokens: it is what deletes the record of who was issued which
credential once that credential expires, and what eventually retires lists nobody can
still be holding. See
[Token Status Lists](#token-status-lists-credential-revocation).

## Endpoint locations and well-known URLs

After deployment, visit the SimpleSAMLphp admin area:

- OIDC > Protocol / Federation Settings

There you can see discovery URLs. Typical discovery endpoints are:

- OpenID Connect Discovery:
[https://yourserver/simplesaml/module.php/oidc/.well-known/openid-configuration](https://yourserver/simplesaml/module.php/oidc/.well-known/openid-configuration)
- OpenID Federation configuration:
[https://yourserver/simplesaml/module.php/oidc/.well-known/openid-federation](https://yourserver/simplesaml/module.php/oidc/.well-known/openid-federation)
- OpenID for Verifiable Credential Issuance configuration:
[https://yourserver/simplesaml/module.php/oidc/.well-known/openid-credential-issuer](https://yourserver/simplesaml/module.php/oidc/.well-known/openid-credential-issuer)
- OAuth2 Authorization Server configuration:
[https://yourserver/simplesaml/module.php/oidc/.well-known/oauth-authorization-server](https://yourserver/simplesaml/module.php/oidc/.well-known/oauth-authorization-server)
- JWT VC Issuer configuration:
[https://yourserver/simplesaml/module.php/oidc/.well-known/jwt-vc-issuer](https://yourserver/simplesaml/module.php/oidc/.well-known/jwt-vc-issuer)

You may publish these as ".well-known" URLs at the web root using your
web server. For example, for `openid-configuration`:

nginx:

```nginx
location = /.well-known/openid-configuration {
    rewrite ^(.*)$ /simplesaml/module.php/oidc/.well-known/openid-configuration break;
    proxy_pass https://localhost;
}
```

Apache:

```apache
RewriteEngine On
RewriteRule ^/.well-known/openid-configuration(.*) \
  /simplesaml/module.php/oidc/.well-known/openid-configuration$1 [PT]
```

## Outbound destination policy

Most of what the OP fetches is named by somebody else. A registering client
supplies its own `jwks_uri`, `signed_jwks_uri`, `request_uri` and
`backchannel_logout_uri`; a federation entity statement says which endpoint to
fetch next. Left unrestricted, that turns the OP into a way of reaching its own
network from the outside: a URL pointing at `127.0.0.1`, `10.0.0.5` or the cloud
metadata address `169.254.169.254` would be fetched like any other, and so would
a public URL that redirects to one of them.

**Non-public destinations are refused by default.** Nothing has to be switched on.
Every redirect hop is checked in the same way, since a first hop that passes and
then redirects inward is the whole attack.

The check happens twice for a client-supplied URI: once when the client
registers, so an inward-pointing `jwks_uri` is rejected as
`invalid_client_metadata` rather than surfacing later as an unexplained
signature failure, and again at fetch time, because a host permitted at
registration can be repointed afterwards.

> Application-layer SSRF defence is leaky by nature. An egress firewall or a
> forward proxy that cannot reach internal networks remains the stronger
> control. This raises the bar; it does not make fetching arbitrary URLs safe.

### Allowing an internal destination

A deployment that legitimately fetches from a private network says so
explicitly. Prefer the narrowest range that covers the destination, so that
permitting one internal endpoint does not permit the whole private network:

```php
ModuleConfig::OPTION_OUTBOUND_ALLOWED_CIDRS => ['10.1.2.3/32'],
```

Use `OPTION_OUTBOUND_ALLOWED_HOSTS` where a range cannot describe the
destination — a name resolved outside DNS, or one whose address is not fixed.
A host listed there is permitted whatever it resolves to, which means trusting
whoever controls that name with where the request goes, so keep it to
destinations the deployment operates itself:

```php
ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS => ['rp.internal.example'],
```

Plain `http` destinations are refused as well. Add `'http'` to
`OPTION_OUTBOUND_ALLOWED_SCHEMES` only where that is knowingly wanted; the
address rules still apply.

### Address pinning

Checking a hostname and then handing the hostname to the HTTP client resolves it
twice, and whoever controls that name controls both answers: the first can be a
public address that passes the check, and the second, moments later, the
loopback address the connection actually uses. The OP therefore pins the
addresses that passed, telling the client to connect to those instead of
resolving again. The request is still made to the original hostname, so TLS
still validates the certificate against the name.

Pinning needs the cURL handler, so it cannot always be used — not without the
cURL extension, not through a proxy (which resolves the destination itself), and
not through an HTTP handler supplied by configuration.
`OPTION_OUTBOUND_ADDRESS_PINNING_MODE` decides what happens then:

- `Preferred` (default) — pin where possible, otherwise validate and proceed,
  reporting the weaker guarantee to the log once.
- `Required` — refuse the request instead. Note this refuses **every** request
  behind a proxy.
- `Disabled` — never pin, and do not report it.

The current settings are shown in the admin area under `OIDC` > `Configuration`,
in the Protocol screen's outbound HTTP section.

## Pushed Authorization Requests (PAR) and Request Objects

A client can send authorization request parameters in several ways:

- **As plain query / POST parameters** sent directly to the authorization
  endpoint (the classic flow).
- **By value**, as a Request Object (a signed or unsigned JWT) in the
  `request` parameter (OpenID Connect Core / JAR, RFC 9101).
- **By reference**, using the `request_uri` parameter:
  - **Pushed Authorization Request (PAR), RFC 9126** — the client first
    `POST`s the parameters to the PAR endpoint and receives a short-lived,
    one-time `request_uri` of the form
    `urn:ietf:params:oauth:request_uri:<id>`, which it then uses at the
    authorization endpoint.
  - **Remote `https://` request_uri** — the OP fetches the Request Object
    from the given URL (JAR by reference, or OpenID Federation by reference).

### The PAR endpoint

The PAR endpoint is published in the discovery document as
`pushed_authorization_request_endpoint` and is available at:

- [https://yourserver/simplesaml/module.php/oidc/par](https://yourserver/simplesaml/module.php/oidc/par)

It authenticates the client the same way as the token endpoint (including
`private_key_jwt`), validates the pushed parameters, stores them, and returns a
JSON response with the generated `request_uri` and an `expires_in` value. Errors
are returned as JSON (token-endpoint style); the endpoint never redirects.

### Request Object flavors

When a Request Object is provided (by value or by reference), the OP detects
its flavor and applies the matching rules:

- **OpenID Connect Core**: the Request Object may be unsigned, unless a signed
  object is required by policy (see below).
- **JAR (RFC 9101)** for plain OAuth 2.0 requests: the Request Object **must be
  signed** and must contain the `client_id` claim.
- **OpenID Federation**: the Request Object is used for automatic client
  registration (handled during client resolution).

For the OpenID Connect Core and JAR flavors, the `aud` and `iss` claims are
optional, but when present they are validated: `aud` must include this OP's
issuer identifier, and `iss` must equal the client. This prevents a Request
Object minted for a different Authorization Server (or by a different client)
from being replayed here.

### Per-client properties

The following client metadata properties can be configured per client:

- `require_pushed_authorization_requests` — require this client to use PAR.
- `require_signed_request_object` — require this client to sign its Request
  Objects.
- `request_uris` — the list of `https://` `request_uri` values registered for
  this client. A registered (non-federation) client may only use a remote
  `request_uri` that exactly matches one of these values.

### Federation `request_uri` fetch allowlist (SSRF/DoS)

For an **OpenID Federation candidate** — a client that is not (yet) registered
in storage, or is registered through OpenID Federation — the OP must fetch the
remote Request Object *before* it can establish trust. This outbound fetch is
gated by `OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES`. This allowlist does
**not** apply to registered non-federation clients — for them the `request_uri`
must match their registered `request_uris` exactly.
The `OPTION_REQUEST_URI_PARAMETER_SUPPORTED` switch still applies on top of all
of this.

### Storage and cleanup

Pushed authorization requests are stored in the `oidc_par` database table
(created by the DB migrations). Expired entries are removed by the SimpleSAMLphp
[cron](https://simplesamlphp.org/docs/stable/cron/cron.html) integration, the
same way expired tokens are purged.

## Key rollover

You can configure an additional key pair to publish via JWKS endpoints or
properties. This lets RPs pre-fetch the new public key before you switch
signing to the new private key. Once RPs have cached the new JWKS, you can
perform the key switch.

## Apache Authorization header note

Apache may strip the `Authorization` header (Bearer) from requests (a known
[issue](https://github.com/symfony/symfony/issues/19693)).

Although the module includes a fallback, it has performance implications.
Configure Apache to preserve the header using one of these snippets:

```apache
RewriteEngine On
RewriteCond %{HTTP:Authorization} .+
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
```

or

```apache
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
```

If not set, you will see warnings about this in the logs.

## Private scopes

The module supports the standard scopes: `openid`, `offline_access`, `email`,
`address`, `phone`, and `profile`. You can add private scopes in
`module_oidc.php`:

```php
<?php

$config = [
    \SimpleSAML\Module\oidc\ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES => [
        'private' => [
            'description' => 'private scope',
            'claim_name_prefix' => '',
            'are_multiple_claim_values_allowed' => false,
            'claims' => ['national_document_id'],
        ],
    ],
];
```

## Attribute translation

Default SAML-to-OIDC claim mapping follows the
[REFEDS guidance](https://wiki.refeds.org/display/GROUPS/Mapping+SAML+attributes+to+OIDC+Claims).

You can change or extend this mapping in `module_oidc.php`. Example:

```php
<?php

$config = [
    \SimpleSAML\Module\oidc\ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE => [
        // Overwrite default mapping
        'sub' => [
            'uid',
            'eduPersonPrincipalName',
            'eduPersonTargetedID',
            'eduPersonUniqueId',
        ],
        // Remove default mapping by setting an empty array
        'family_name' => [],

        // New claim created from SAML attribute
        'national_document_id' => [
            'schacPersonalUniqueId',
        ],
    ],
];
```

## Authentication Processing filters (OIDC)

Standard SAML Auth Proc Filters do not run during OIDC authN because not
all SAML entities are present (like a Service Provider). Instead, use the
`authproc.oidc` configuration option to define filters specific to OIDC.

The OIDC authN state does not include all keys present in SAML authN.
Available SAML-like keys include:

- \['Attributes'\]
- \['Authority'\]
- \['AuthnInstant'\]
- \['Expire'\]

Source and Destination entity IDs correspond to OP issuer and Client ID:

- \['Source'\]\['entityid'\]      → OP issuer ID
- \['Destination'\]\['entityid'\] → RP (client) ID

Additional OIDC data in the state:

- \['Oidc'\]\['OpenIdProviderMetadata'\]
- \['Oidc'\]\['RelyingPartyMetadata'\]
- \['Oidc'\]\['AuthorizationRequestParameters'\]

Example filter configuration:

```php
<?php

$config = [
    \SimpleSAML\Module\oidc\ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS => [
        50 => [
            'class' => 'core:AttributeAdd',
            'groups' => ['users', 'members'],
        ],
    ],
];
```

### Per-client Auth Proc filters

In addition to the global filters above, you can configure Auth Proc filters
for a **specific client (Relying Party)**. This mimics the way SAML allows
filters to be defined in Service Provider metadata.

Client filters are stored together with the client in the database (as part of
the client's extra metadata) and are managed from the client administration UI:

- OIDC > Client Registry > (edit a client) > **Authentication Processing Filters**

The value is entered as a JSON object using the same structure as the global
`authproc.oidc` option (keyed by priority; each entry is a class string or an
object with a `class` property), for example:

```json
{
    "60": {
        "class": "core:AttributeAdd",
        "groups": ["members"]
    }
}
```

During authentication for that client, its filters are merged with the global
filters by priority (the global filters run as the "IdP-side" list and the
client filters as the "SP-side" list), exactly as SAML merges IdP and SP
`authproc` filters.

> **Security note:** Auth Proc filters name a PHP class that is instantiated and
> executed on the OP during authentication. For this reason, per-client filters
> can only be set by a trusted administrator through the admin UI / API. They are
> **deliberately never accepted from client-supplied registration metadata**
> (OIDC Dynamic Client Registration or OpenID Federation registration); any such
> value present in registration metadata is ignored. This deny-list of
> administrator-only client properties is defined in
> `\SimpleSAML\Module\oidc\Entities\ClientEntity::ADMIN_ONLY_METADATA_KEYS` and
> enforced in `ClientEntityFactory::fromRegistrationData()`.

Alternatively, if you only need a global filter to run for selected clients, you
can keep using the global `authproc.oidc` option together with a
[preconditional filter](https://simplesamlphp.org/docs/stable/simplesamlphp-authproc.html#preconditional-filters),
inspecting the client ID via `$state['Destination']['entityid']`:

```php
50 => [
    'class' => 'core:AttributeAdd',
    'groups' => ['members'],
    '%precondition' => 'return $state["Destination"]["entityid"] === "https://rp.example.org/";',
],
```

## Client registration permissions

You can allow users to register their own clients. Control this via the
`permissions` setting in `module_oidc.php`.

Permissions expose functionality to specific users. In the following
example, a user's `eduPersonEntitlement` is examined. To perform an action
requiring the `client` permission (register/edit/delete a client) the user
needs one of the listed entitlements.

```php
<?php

$config = [
    \SimpleSAML\Module\oidc\ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
        'attribute' => 'eduPersonEntitlement',
        'client' => ['urn:example:oidc:manage:client'],
    ],
];
```

Users can visit the following link for administration:

- [https://example.com/simplesaml/module.php/oidc/clients/](https://example.com/simplesaml/module.php/oidc/clients/)

## OpenID Connect Dynamic Client Registration

The module can let Relying Parties register themselves dynamically, as described
by [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
(which is also compatible with RFC 7591). It exposes:

- a **Client Registration Endpoint** (`POST .../oidc/register`) that creates a
  client and returns its `client_id`, `client_secret` (for confidential
  clients), a `registration_access_token` and a `registration_client_uri`; and
- a **Client Configuration Endpoint** (`GET` / `PUT` / `DELETE`
  `.../oidc/register?client_id=...`, RFC 7592) to read, update (full replace) or
  delete a dynamically registered client, called with the
  `registration_access_token` as a bearer token. Per RFC 7592 the read and update
  responses include a `registration_access_token`; because the OP stores only its
  hash, the token is **rotated** on each successful read/update — the response
  returns a new token that the client must use for subsequent requests.

When enabled, the registration endpoint is advertised as `registration_endpoint`
in the OP discovery metadata. Dynamically registered clients are stored like any
other client and are visible in the admin UI.

The feature is **disabled by default**. It is configured through the following
options in `config/module_oidc.php` (see the inline comments there for the full
details and defaults):

- `OPTION_DCR_ENABLED` — master switch for the feature.
- `OPTION_DCR_REGISTRATION_AUTH` — access-control mode: `open` registration
  (the default) or `initial_access_token` (require a bearer Initial Access
  Token).
- `OPTION_DCR_INITIAL_ACCESS_TOKENS` — the accepted Initial Access Tokens,
  consulted only in `initial_access_token` mode.
- `OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED` — when on (the default),
  the host of `logo_uri` / `policy_uri` / `tos_uri` must match the host of one of
  the registered `redirect_uris` (spec Section 9.1).

> **Security note:** open registration lets anyone create a client, so protect
> the endpoint with rate limiting at the web-server level, or require an Initial
> Access Token.

## Token Status Lists (credential revocation)

A Verifiable Credential this module issues is, by default, valid for as long as it says it is and
there is nothing you can do about it afterwards. Token Status Lists
([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)) are
what make one revocable: each issued credential carries a `status` claim naming a list and an index
inside it, and a Relying Party checks the credential by fetching that list.

The list is one compressed bit array covering many credentials, published as a signed token. That is
the design's privacy property, and the reason lists are shared rather than per-credential: fetching
the list tells the issuer that *somebody's* credential is being verified, but not whose.

### Requirements

- **A SimpleSAMLphp providing `SimpleSAML\Database::readPrimary()`.** Deciding whether a credential is
  revoked from a lagging database secondary could publish a revoked credential as valid, so the module
  refuses to enable the feature rather than fall back to a replica read. This is available from v2.5.3
  of SimpleSAMLphp.
- **Verifiable Credential Issuance configured**, since there is nothing to give a status to otherwise.
- **The cron module running**, with a cron tag configured for this module (see
  [Cron integration](#cron-integration)). Without it, credentials are still issued, still expire on
  their own, still get served and can still be revoked — but nothing is ever cleaned up: the record of
  who was issued which credential is kept past that credential's expiry, no list is ever retired, and
  the audit trail is never pruned. See [Lifecycle and cron](#lifecycle-and-cron) below.

### Enabling

```php
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => true,

ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS => [
    'default' => [
        'credential_configurations' => [
            'UniversityDegreeCredential',
        ],
    ],
    // A pool which can also suspend, so it needs at least 2 bits per entry.
    'suspendable' => [
        'credential_configurations' => [
            'EmployeeBadgeCredential',
        ],
        'bits' => 2,
        'allowed_statuses' => [
            StatusTypeEnum::Invalid,
            StatusTypeEnum::Suspended,
        ],
    ],
],
```

Credentials of a configuration which is in no pool are issued without a `status` claim, and can never
be revoked or suspended. Turning the switch on does not change credentials which have already been
issued — they carry no `status` claim and nothing can add one.

### Pools

A pool, not a credential configuration, is the unit which shares a list, and several configurations can
map onto one pool. Splitting configurations into separate pools costs herd privacy, so it is worth
doing only when their policies genuinely differ. A configuration must appear in at most one pool.

Per-pool settings, all optional except `credential_configurations`:

| Setting                     | Default        | Notes                                                                                   |
|:----------------------------|:---------------|:----------------------------------------------------------------------------------------|
| `credential_configurations` | —              | Required. Each must be declared under `OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED`. |
| `bits`                      | `1`            | Bits per entry, one of 1, 2, 4, 8. **Cannot be changed for lists which already exist.** |
| `capacity`                  | `131072`       | Entries per list; a positive multiple of 8.                                             |
| `allowed_statuses`          | `Invalid`      | Statuses besides `Valid`, which is always allowed.                                      |
| `ttl`                       | `PT12H`        | How long a Relying Party may cache a fetched list.                                      |
| `token_validity`            | `P7D`          | Lifetime of a published Status List Token.                                              |
| `refresh_interval`          | `PT1H`         | How old a published token may get before it is re-signed.                               |
| `key_profile`               | global setting | Overrides `OPTION_VCI_STATUS_LIST_KEY_PROFILE` for this pool.                           |

Two of these deserve reading twice.

**`bits` decides what the pool can ever say.** One bit holds `Valid` and `Invalid` and nothing else, so
a pool left at the default can never suspend a credential — and the number of bits is fixed when a list
is created, so this cannot be corrected later for credentials already issued from it. A pool which may
ever suspend needs at least 2 bits *before* it issues anything. Asking for a status a list cannot carry
is refused, with `422` from the API and a message on the administration screen. Note that `bits`
affects transfer size, never herd size.

**`ttl` is the revocation latency you are offering.** It is how long a conforming Relying Party may go
on using a cached copy of the list, so with the default a credential revoked now may still be accepted
for up to 12 hours. Lower it if that is too long, bearing in mind that it is also what keeps verifiers
from fetching the list on every presentation.

### Key profile

The specification deliberately mandates no key resolution method, so how a Status List Token names the
key it was signed with is a deployment choice:

- `did_jwk` (default): `kid` is the issuer's `did:jwk:...#0` and `iss` is the same `did:jwk:...`. The
  token carries the key with it and verifies without any external lookup.
- `jwks`: `iss` is this module's issuer URL and `kid` is a JWKS key ID, so the key is resolved through
  the published JWKS. Use this for Relying Parties which will not accept a `did:jwk` key identifier.

Each list records the profile it was created under. Changing the setting therefore routes newly issued
credentials to newly created lists, while existing lists keep being served under the profile their
holders already resolved them by — so changing it never invalidates anything already in a wallet.

**A signing key has to outlive every list signed with it.** Each list records the key it was created
with and is re-signed from that key alone, never from whichever key is current. Rotating keys is
therefore safe in itself: new lists take the new key, existing lists keep theirs. Removing the old key
from the configuration is what breaks things — and it breaks them on a delay.

A published token is served from storage without the key being consulted at all, so a list whose token
is still fresh goes on answering `200` after its key is gone. The failure arrives only when that list
next needs re-signing: when its contents change, when its refresh interval comes round, or as its token
nears expiry. The module will not sign a list with a key its holders never bound to, so it answers `503`
for that list instead. **Checking the endpoint just after removing a key therefore proves nothing** —
and since a revocation is the most likely thing to force a re-sign, the breakage tends to appear exactly
when the list matters most.

Whether credentials stay verifiable in the meantime depends on the profile. A `did_jwk` token carries
its own key, so tokens already published keep verifying. Under `jwks` the key is resolved through this
module's published JWKS, which the same removal empties, so already published tokens stop verifying too
once Relying Parties refetch it. A key is only safe to discard once every list it signed has been
retired, which the lifecycle below does only after the last credential in those lists has expired.

### Credential expiry

Credentials this module issues do not expire unless you say so:

```php
ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS => [
    'UniversityDegreeCredential' => 'P1Y',
],
```

It has a consequence worth understanding before deciding. **A list holding even one credential which
never expires can never be retired**, because that credential can be presented at any point in the
future and a verifier asked about it has to be able to fetch the list. With expiry off, the module's
Status List storage grows for as long as the deployment runs and never gives anything back. The
administration screen reports how many lists are in that position.

### Serving the lists

Lists are published at `/statuslist/{id}`, unauthenticated, and the URI of the list is written into
every credential issued from it.

That URI is absolute and fixed at the moment of issuance, so **changing the deployment's base URL
strands every credential issued before the change**: the wallet resolves the URI it was given, which
still names the old origin. There is nothing to rewrite — the credential is signed, and the copy that
matters is in someone else's wallet. If the base URL has to change, keep the old origin answering, by
alias or redirect, for as long as any credential issued under it can still be presented. The same
applies to moving the module to a different path.

This endpoint keeps serving when `OPTION_VCI_STATUS_LIST_ENABLED` is switched off. Turning the switch
off stops new credentials getting an entry allocated; it does not, and must not, strand the credentials
already in wallets as unverifiable.

`OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE` puts a ceiling on how much one client can pull, and is off
by default. Before setting it, check what address actually reaches PHP: behind a reverse proxy or CDN it
is the proxy's own, identically for every request, so all clients would share one counter and the
endpoint would start refusing the verifiers that credentials depend on. It also needs a protocol cache
configured; without one, nothing is counted and no request is refused.

### Changing a status

Two ways, both of which write to the same audit trail:

- **OIDC > Credential Status** in the SimpleSAMLphp admin area. Lists issued credentials, searches by
  credential identifier or by user identifier, and changes the status of one credential at a time. The
  search is exact rather than a substring match — the user identifier is stored as a keyed hash, which
  nothing can be matched against partially.
- **The credential status API endpoint**, documented in [API](8-api.md#credential-status). This is what
  to use from an IdM / HR / helpdesk tool...

The audit trail records the credential (as a hash of its identifier), the list and index, the status
asked for, who asked, and when. It names an actor when it can: an API token's configured `name`, or the
identifier the `admin` authentication source releases. SimpleSAMLphp's admin login is a shared password
in most deployments and names nobody, in which case the trail says `admin` rather than inventing
someone — but where that source is pointed at a real one, the trail names a person, which is worth
knowing when deciding the retention below. The bearer token itself is never recorded anywhere.

### Lifecycle and cron

The module's cron hook does five things for Status Lists, all of them bounded so that no single run has
to finish the job — whatever one run leaves, the next picks up:

1. **Forgets which credential held which index, once that credential has expired.** The credential ID,
   its hash, its configuration ID and the subject reference are deleted together; the index and the
   status it ended on stay, because those are what the published list is built from and what stops the
   index being handed out to a second credential. This is why credential expiry is also a privacy
   setting: with no expiry, the record of who was issued what is kept indefinitely.
2. **Deactivates lists the current configuration would no longer allocate into**, which happens when a
   pool's settings change or the signing key is rotated. This changes nothing observable — those lists
   were already unreachable — but nothing else would ever start their clock.
3. **Retires lists nothing can still be holding**, meaning every credential issued from them expired,
   and the grace period elapsed both since the list stopped accepting allocations and since that last
   expiry. A retired list answers `404` and gives back its published token.
4. **Removes the entry rows behind retired lists** once the grace has passed again since retirement.
   This is where retirement actually recovers storage: a list at the default capacity has 131072 of
   them.
5. **Prunes the audit trail** to the configured retention.

```php
// How long to wait before retiring a list. Default P30D.
ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE => 'P30D',

// How long to keep audit rows. Not set by default, which keeps them indefinitely.
ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION => 'P1Y',
```

The retirement grace exists because retiring a list makes a URI which is written into real credentials
answer `404`. Those credentials have all expired by then, so nothing which should verify stops
verifying — but a Relying Party working from a cached response, or a wallet showing a credential it has
not noticed is expired, would see the fetch fail rather than get an answer. Lengthen it if your
verifiers cache aggressively.

**It cannot be set below one hour.** The wait counted from deactivation has a second job: outlasting an
issuance that was already under way when the list stopped accepting credentials. Nothing here can
serialise those two instead — the statement that retires a list and the one that claims an index write
different rows, so neither conflicts with the other — and a wait shorter than a request can take does
not outlast one. A credential issued into a list that has since been retired can never be verified.

The same wait passes again before a retired list's entry rows are removed, so that if that ever did
happen there is still a record the credential was issued.

Each step reports what it got through in the cron summary, and reports separately if it failed. A step
which keeps failing is worth acting on: one of them is what deletes personal data on time.

## Running multiple OPs on one server

A single module instance is designed to serve exactly one OpenID Provider
(OP): it has one issuer, one set of signing keys, and one configuration
file (`module_oidc.php`). If you need to run several independent OPs (each
with its own issuer, keys, clients, and scopes) on the same server, do not
try to fit them into one config. Instead, run multiple SimpleSAMLphp
instances side by side and select between them with the
`SIMPLESAMLPHP_CONFIG_DIR` environment variable.

The idea is to give each OP its own configuration directory (each with its
own `config.php`, `authsources.php`, `module_oidc.php`, signing keys, and
metadata) and to front each one with its own virtual host. SimpleSAMLphp
reads `SIMPLESAMLPHP_CONFIG_DIR` to decide which configuration directory to
load, so each virtual host points at the configuration for its OP:

```apache
# Virtual host for the first OP
<VirtualHost *:443>
    ServerName op1.example.org
    SetEnv SIMPLESAMLPHP_CONFIG_DIR /etc/simplesamlphp/op1/config
    # ... remaining SimpleSAMLphp / web root configuration ...
</VirtualHost>

# Virtual host for the second OP
<VirtualHost *:443>
    ServerName op2.example.org
    SetEnv SIMPLESAMLPHP_CONFIG_DIR /etc/simplesamlphp/op2/config
    # ... remaining SimpleSAMLphp / web root configuration ...
</VirtualHost>
```

With nginx + PHP-FPM, set the same variable per server block via
`fastcgi_param SIMPLESAMLPHP_CONFIG_DIR /etc/simplesamlphp/op1/config;`
(or use a separate PHP-FPM pool per OP with `env[SIMPLESAMLPHP_CONFIG_DIR]`).

In each OP's `module_oidc.php`, set a distinct `issuer` and distinct signing
key/certificate filenames so the OPs do not share identities or keys.

### Important: isolate the database (or use a table prefix)

The OIDC module keeps its protocol artifacts — clients, access tokens,
refresh tokens, authorization codes, allowed origins, and user records — in
the database, and these tables have no notion of which OP they belong to.
If two instances point at the same database tables, they will share all of
that state: a client registered on one OP will be visible to the other, and
the admin UIs will operate on the same data. That is almost certainly not
what you want.

To keep the OPs properly isolated, give each instance separate storage by
configuring its `config.php` to use **either** a separate database **or** a
distinct table prefix:

```php
// In op1/config/config.php
'database.dsn' => 'mysql:host=localhost;dbname=ssp_oidc_op1',
// ...or share a database but separate the tables with a distinct prefix:
'database.prefix' => 'op1_',
```

```php
// In op2/config/config.php
'database.dsn' => 'mysql:host=localhost;dbname=ssp_oidc_op2',
// ...or:
'database.prefix' => 'op2_',
```

Run the database schema creation (migrations) for each instance separately,
so each OP gets its own set of tables.
