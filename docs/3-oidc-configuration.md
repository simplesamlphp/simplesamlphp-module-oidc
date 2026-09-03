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
- DID document, when a `did:web` issuer identifier is configured:
[https://yourserver/simplesaml/module.php/oidc/did.json](https://yourserver/simplesaml/module.php/oidc/did.json)

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

### DID resolution has a policy of its own

Resolving a holder's `did:web` identifier is also an outbound fetch, but it is
the only one whose destination is named by whoever is being issued a credential:
the identifier arrives inside a wallet's key proof and the URL is derived from
it. It therefore gets its own settings, and **the `OPTION_OUTBOUND_*` options
above are never applied to it.** Those exemptions were granted so the deployment
could reach addresses it operates itself; sharing them here would let a wallet
name any of them.

```php
ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_HOSTS => ['wallet.internal.example'],
ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_CIDRS => ['10.1.2.3/32'],
```

Both are empty by default, so a DID may only resolve to a public `https`
destination. The usual reason to set either is a test environment in which the
DID host resolves to a container address rather than to its public one.

`OPTION_VCI_DID_ADDRESS_PINNING_MODE` works as described above with two
differences: it defaults to `Required` rather than `Preferred`, and `Preferred`
is **refused** when the configuration is read, since proceeding unpinned is
exactly what should not happen on a fetch driven from outside.

That leaves `Disabled` for the deployment that cannot pin and is not thereby
unprotected — one reaching the internet through a forward proxy. The proxy
resolves the destination itself, so there is nothing to pin, and the proxy is
doing the egress control that pinning approximates:

```php
ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE =>
    \SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum::Disabled,
```

**This is only honest while the proxy carries every DID destination.** An
exclusion list (`NO_PROXY`, or a `no` entry) sends matching hosts direct, and a
proxy configured for plain `http` alone is not used for the `https` fetch a
`did:web` identifier resolves to. Wherever a fetch goes direct, turning pinning
off removes the protection rather than delegating it. A deployment that simply
lacks the cURL extension is not this case and should install the extension.

Resolved documents are cached in the VCI cache, which is configured separately
from the protocol and federation ones:

```php
ModuleConfig::OPTION_VCI_CACHE_ADAPTER => \Symfony\Component\Cache\Adapter\FilesystemAdapter::class,
ModuleConfig::OPTION_VCI_CACHE_ADAPTER_ARGUMENTS => ['openidVci', 60 * 60 * 6, '/path/to/cache'],
```

Without an adapter, every key proof naming a `did:web` identifier is another
outbound fetch. `OPTION_VCI_DID_CACHE_MAX_DURATION` (default `PT6H`) is how long
a document is reused; a DID document states no expiry of its own, so this is the
whole of its freshness rule, and a holder rotating a key is not seen until it
runs out.

These settings are shown in the admin area under `OIDC` > `Configuration`, on
the VCI screen.

## Issuer identity and the DID document

A credential says who issued it in its `iss` claim and which key signed it in its
`kid` header, and whoever verifies it has to be able to resolve both.
`OPTION_VCI_ISSUER_IDENTIFIER_MODE` decides how:

- `did_jwk` (default): `iss` is a `did:jwk` derived from the active signing key
  and `kid` is that DID with the `#0` fragment. The credential carries the key
  with it, so it verifies with no lookup at all. Nothing ties the DID to this
  deployment, though; a verifier has to establish that by other means.
- `did_web`: `iss` is the identifier set in `OPTION_VCI_ISSUER_DID_IDENTIFIER`
  and `kid` names one verification method inside the DID document this module
  publishes. Resolvable by anyone and bound to a domain name, which is what the
  DIIP profile asks of an issuer.
- `https`: `iss` is this module's issuer URL and `kid` is the key's JWKS key ID,
  so the key is resolved through the published key set. This is what makes the
  `.well-known/jwt-vc-issuer` document meaningful, and a way out for verifiers
  which will not accept a DID. **It is not DIIP conformant**, since the profile
  requires the issuer to be identified by a DID.

The mode is read when a credential is signed, so changing it reaches newly issued
credentials only. Credentials already in wallets go on naming the identity they
were issued under — which is what the retention rules below are about.

### Keeping the `https` identity resolvable

A verifier discovers the key set by inserting `.well-known/jwt-vc-issuer` into
the `iss` value, so under this mode the issuer must resolve to an absolute
`https` URL with no query and no fragment. `OPTION_ISSUER` guarantees none of
that — left unset it is derived from the host of the current request, which is
`http://` on a development deployment or behind a proxy forwarding the wrong
scheme — so issuance is refused when it does not, rather than emitting a
credential no verifier could check.

Under `https` a credential names its signing key by its JWKS key ID, so it is
verifiable only while that key is still published. Two endpoints therefore stop
following `OPTION_VCI_ENABLED` while this mode is selected: the VCI keys stay in
the published JWKS, and `.well-known/jwt-vc-issuer` — which is how an SD-JWT VC
verifier finds that key set — keeps being served. Turning issuance off stops new
credentials being issued without making the existing ones unverifiable, the same
guarantee the Status List and DID document endpoints give.

**Moving off `https` withdraws both.** Unlike `did:web`, there is no separate
option to keep serving under: the identity is the issuer URL, which every mode
has. Credentials issued under `https` therefore stop verifying when the mode
changes, so make that change only once they have expired, or arrange to serve
their key set by other means.

### Serving the DID document

The document is served at `.../module.php/oidc/did.json`, and lists **every** key
configured under `OPTION_VCI_SIGNATURE_KEY_PAIRS` — not only the pair currently
signing — under both `verificationMethod` and `assertionMethod`. That is the same
reasoning as the JWKS document: a key which signed a credential still in
circulation has to stay resolvable, so a pair displaced by a rollover must remain
configured. Each verification method is named by its key ID, so the `kid` in a
credential stays stable across restarts and reordering.

The `did:web` method decides the document's URL from the identifier alone, which
is why the identifier is configured rather than derived. `did:web:example.org`
resolves to `https://example.org/.well-known/did.json`, at the web root, which
SimpleSAMLphp does not serve; deriving one from the module URL would instead give
`did:web:example.org:simplesaml:module.php:oidc`, which no deployment would
choose to put into its credentials. Either way, whatever URL your identifier
resolves to has to be made to reach `did.json`, the same way the well-known URLs
above are:

nginx:

```nginx
location = /.well-known/did.json {
    rewrite ^(.*)$ /simplesaml/module.php/oidc/did.json break;
    proxy_pass https://localhost;
}
```

The VCI configuration screen shows both URLs — the one the identifier resolves to
and the one this module serves — and says so when they differ.

Like the Status List endpoint, this one is **not** gated on
`OPTION_VCI_ENABLED`. Turning issuance off has to stop new credentials being
issued, not make the existing ones unverifiable.

### Changing or retiring a `did:web` identity

A credential naming a `did:web` identity can only be verified by resolving that
DID. If the document stops being served, the signature can never be checked
again — the credential is unverifiable, not merely unbound — and credentials do
not expire unless `OPTION_VCI_CREDENTIAL_TTLS` gives them a lifetime.

So the document is published **whenever `OPTION_VCI_ISSUER_DID_IDENTIFIER` is
set**, including when the mode has moved on to `did_jwk` or `https`. In that
state nothing new is issued under the DID, but what was issued under it earlier
keeps verifying. Removing the option is what retires the identity, and that is
then a decision rather than a side effect of changing the mode.

To move to a different `did:web` identity while keeping the old one resolvable,
the old document has to be served by other means: it is a static JSON file, so
fetch it from `did.json` before changing the option and park it at the URL the
old identifier resolves to.

The VCI configuration screen lists every identity this deployment has actually
issued credentials under, and warns when one of them is a `did:web` it no longer
publishes. Configuration alone cannot answer that question, which is why it is
recorded as credentials are issued.

## Holder binding and the DIIP profile

A credential configuration decides for itself whether the credentials it issues
are bound to a key the wallet proves it holds, and under which rules. The choice
is one option, because OpenID4VCI ties the metadata and the issuance together:
`proof_types_supported` must be present wherever
`cryptographic_binding_methods_supported` is, and a Credential Request must
carry `proofs` wherever `proof_types_supported` is.

```php
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;

ModuleConfig::OPTION_VCI_CREDENTIAL_BINDING_POLICIES => [
    'UniversityDegreeCredential' => VciCredentialBindingPolicyEnum::ProofBound,
    'DiipCredential' => VciCredentialBindingPolicyEnum::DiipProofBound,
    'EmployeeBadgeCredential' => VciCredentialBindingPolicyEnum::Proofless,
],
```

`ProofBound` is the default and applies the OpenID4VCI rules: a key proof is
required, its signature is verified, and the credential is issued to the holder
identifier the proof resolves to. The proof may name its key in a `kid` header,
as a DID URL of any method this deployment can resolve — `did:jwk`, `did:key`
or `did:web` — or carry the key itself in a `jwk` header.

### What `DiipProofBound` adds

`DiipProofBound` applies the DIIP profile's identifier rules on top of those. The
key proof must name its key in a `kid` header which is an **absolute `did:jwk` or
`did:web` URL**, and that verification method must appear in the
`authentication` relationship of the document the DID resolves to.

Two consequences are worth knowing before switching a configuration to it, both
about that header, since it is where this profile's holder binding lives:

- **A key proof carrying its key inline is refused.** The requirement is written
  in DID URLs, and an inline key names no verification method to point at.
- **A `did:key` holder is refused**, since the profile names the other two.

The `iss` claim is left to OpenID4VCI: the client the access token was issued to
when there is one, and absent when there is not. A wallet identified by a DID
works, but nothing requires one, and holder binding does not rest on it.

None of this affects any other configuration. DIIP's requirements are additive,
so a deployment can offer conformant configurations alongside ones which accept
inline keys or `did:key` holders.

The credential states which key it is held by in a `cnf` claim, in every format:
`cnf.kid` naming the verification method the proof named, or `cnf.jwk` carrying
the key itself when the proof sent one inline. `credentialSubject.id` is not
equivalent to it — a verifier checking holder binding reads `cnf`.

### Three interpretations this module makes

**The `iss` claim is not required to be a DID.** DIIP v5 says implementations
*"MUST support the `jwt` proof type with a `did:jwk` or `did:web` as the `iss`
value"*. Read as a rule to reject anything else, that cannot hold at the same
time as OpenID4VCI, which requires `iss` to be **absent** when the access token
was obtained through an anonymous pre-authorized code — so a DIIP configuration
could never be issued through that flow at all.

[FIDEScommunity/DIIP#83](https://github.com/FIDEScommunity/DIIP/issues/83)
proposes resolving this by dropping the requirement on `iss` and requiring an
absolute DID URL in `kid` instead. **That issue was still open and unanswered at
the time of writing, and DIIP v5 was approved without it**, so this is an
implementation choice rather than a settled profile rule. Two things make it the
right one: the requirement is worded as *"MUST support"*, a capability rather
than a rejection rule, and this module does support a DID `iss` — it accepts one,
it just does not demand it. And nothing about holder binding rests on that claim.
What proves the holder is possession of a key their DID document lists under
`authentication`, which is checked either way.

**The `assertionMethod` sentence.** DIIP §5.1.1 puts the proof's `kid` under the
`assertionMethod` relationship of the *Issuer's* DID document, while the next
requirement puts holder binding under `authentication` of the *Holder's*. In
OpenID4VCI the proof is produced by the wallet, so the two cannot both be read
literally at once. This module reads it as: the proof JWT resolves against the
**Holder's** DID under `authentication`, and the credential and Status List
signatures are made with the **Issuer's** key under `assertionMethod`. If your
conformance target reads it the other way, this is the place it differs.

**Header-JWK proofs are a documented extension, not a DIIP feature.** They stay
supported for every other configuration because they work and nothing in
OpenID4VCI forbids them, but a credential issued against one is not DIIP
conformant, which is why `DiipProofBound` refuses them.

### What one request may spend

A Credential Request may carry up to `batch_credential_issuance.batch_size`
proofs (8), name at most **4 distinct DIDs which have to be fetched**, and has
**15 seconds** in total for all of its fetches. `did:jwk` and `did:key` resolve
without leaving the process, so they do not count against the fetch limit —
under `did:jwk` every key is its own DID, and a batch of eight proofs is eight
distinct DIDs. These are fixed limits on what a request may cost this issuer,
not settings.

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

`OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS`, `OPTION_FEDERATION_SIGNATURE_KEY_PAIRS`
and `OPTION_VCI_SIGNATURE_KEY_PAIRS` each take a list. Every pair in a list is
published, so any of them can verify, but only the **first** pair in a list
signs. A rollover is therefore two deployments rather than one:

1. Append the new pair to the list and deploy. It is now published, so Relying
Parties, wallets and verifiers can pre-fetch it, while everything is still
signed with the old one.
2. Once they have had time to refetch the JWKS, move the new pair to the front
of the list and deploy again. That is the switch.

Leave the pair it displaced in the list. Removing it stops whatever it signed
from being verified, and how much that matters depends on what it signed: an ID
Token is short-lived, an Entity Statement or an issued Verifiable Credential is
not. VCI keys are the strictest case, because removing one breaks Status Lists
on a delay rather than immediately — see
[Key profile](#key-profile).

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

**A pool is not always exactly one list.** Credentials which never expire are allocated into lists of
their own, so a pool whose configurations differ in whether [credential expiry](#credential-expiry)
gives them a lifetime keeps one list for each kind. That splits its herd, but holding both kinds
could never be retired. Give every configuration in a pool a lifetime to keep it to a single list.

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
- `did_web`: `iss` is the `did:web` set under `OPTION_VCI_ISSUER_DID_IDENTIFIER` and `kid` names the
  signing key in the DID document this module publishes for it. This is the profile which makes a
  credential and the Status List Token it points at name the same issuer under the same resolvable
  identity. It requires that option to be set — a pool on this profile without one is a configuration
  error rather than something discovered when a token is signed.
- `jwks`: `iss` is this module's issuer URL and `kid` is a JWKS key ID, so the key is resolved through
  the published JWKS. Use this for Relying Parties which will not accept a `did:jwk` key identifier.

Each list records the profile it was created under. Changing the setting therefore routes newly issued
credentials to newly created lists, while existing lists keep being served under the profile their
holders already resolved them by — so changing it never invalidates anything already in a wallet.

**A `did_web` list also records the identifier, not just the profile.** It has to: unlike the other two,
that identifier is a setting of its own which can be changed or cleared while lists created under it are
still being served. Reading it afresh at signing time would silently rewrite the `iss` of every token
those lists emit, leaving a wallet holding a credential naming one issuer and a status token naming
another. Because the identifier is recorded, changing it behaves like every other policy change: new
credentials go to new lists, and the old lists go on naming the issuer they were created under.

The obligation that follows is the same one credentials carry. **Keep the DID document published for
every identifier an unretired list still names**, not only for the one currently configured — a Relying
Party checking a credential's status has to resolve the token's issuer, and a `404` there is
indistinguishable from a revoked deployment. The Verifiable Credential configuration screen lists the
identities **credentials** were issued under, which answers this too whenever credentials are issued
under the same `did:web`. It does not cover the case where they are not — a deployment naming its
credentials some other way while its Status Lists use `did:web` has to track the identifiers of its
unretired lists itself.

**Selecting `did_web` is a one-way upgrade.** Once a list has been created under it, the deployment can
no longer be rolled back to a release that predates the profile: an older process reading that row
refuses it rather than guessing an identity, which takes that list's endpoint down. Roll the code
forward everywhere before switching a pool onto it.

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
once Relying Parties refetch it. `did_web` behaves the same way as `jwks` here: the key is named in the
published DID document, which is built from the configured keys, so removing one withdraws it there
too. A key is only safe to discard once every list it signed has been
retired, which the lifecycle below does only after the last credential in those lists has expired.

### Credential expiry

Credentials this module issues do not expire unless you say so:

```php
ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS => [
    'UniversityDegreeCredential' => 'P1Y',
],
```

It has a consequence worth understanding before deciding. **A list holding a credential which never
expires can never be retired**, because that credential can be presented at any point in the future and
a verifier asked about it has to be able to fetch the list. With expiry off, the module's Status List
storage grows for as long as the deployment runs and never gives anything back. The administration
screen reports how many lists are in that position.

Such credentials do not hold up anyone else's, though: they are allocated into lists of their own, so a
configuration left without a lifetime costs its own lists and nothing more. A pool mixing the two kinds
keeps a list for each, at the price described under [Pools](#pools).

The record of who was issued what is a second reason to set a lifetime. It is deleted once a credential
expires, and a credential which never expires is one whose linkage is kept indefinitely — see step 1 of
[Lifecycle and cron](#lifecycle-and-cron).

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
   pool's settings change, the signing key is rotated, or a pool stops using one of its two lists —
   giving its last configuration a lifetime, or taking the last one away. This changes nothing
   observable — those lists were already unreachable — but nothing else would ever start their clock.
3. **Retires lists nothing can still be holding**, meaning every credential issued from them expired,
   and the grace period elapsed both since the list stopped accepting allocations and since that last
   expiry. A retired list answers `404` and gives back its published token.
4. **Removes the entry rows behind retired lists** once the grace has passed again since retirement.
   This is where retirement actually recovers storage: a list at the default capacity has 131072 of
   them.
5. **Prunes the audit trail** to the configured retention.

**Cron and issuance must read the same module configuration.** Step 2 decides which of a pool's lists are
still allocation targets from the configuration it can see, while issuance decides where to put a
credential from the lifetime it was issued with. If the server running cron and the servers issuing
credentials disagree — mid-rollout, or with a stale configuration file on one of them — cron deactivates
the list issuance keeps using, issuance creates another, and the next run deactivates that one too.
Nothing is lost or corrupted: a deactivated list refuses further allocations and retirement re-checks
what a list actually holds before retiring it. But each cycle leaves behind a list of 131072 entry rows,
and for credentials which never expire those lists are never retired. The credential status screen
reports the count of lists which can never be retired, which is what climbs if this is happening.

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
