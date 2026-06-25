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

The module supports the standard scopes: `openid`, `email`, `address`,
`phone`, and `profile`. You can add private scopes in `module_oidc.php`:

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
- a **Client Configuration Endpoint** (`GET .../oidc/register?client_id=...`)
  that returns the current registration when called with the
  `registration_access_token` as a bearer token.

When enabled, the registration endpoint is advertised as `registration_endpoint`
in the OP discovery metadata. Dynamically registered clients are stored like any
other client and are visible in the admin UI.

The feature is **disabled by default**. It is configured through the following
options in `config/module_oidc.php` (see the inline comments there for the full
details and defaults):

- `OPTION_OIDC_DCR_ENABLED` — master switch for the feature.
- `OPTION_OIDC_DCR_REGISTRATION_AUTH` — access-control mode: `open` registration
  (the default) or `initial_access_token` (require a bearer Initial Access
  Token).
- `OPTION_OIDC_DCR_INITIAL_ACCESS_TOKENS` — the accepted Initial Access Tokens,
  consulted only in `initial_access_token` mode.
- `OPTION_OIDC_DCR_IMPERSONATION_PROTECTION_ENABLED` — when on (the default),
  the host of `logo_uri` / `policy_uri` / `tos_uri` must match the host of one of
  the registered `redirect_uris` (spec Section 9.1).

> **Security note:** open registration lets anyone create a client, so protect
> the endpoint with rate limiting at the web-server level, or require an Initial
> Access Token.

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
