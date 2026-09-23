# API

## Enabling API

To enable API capabilities, in module config file `config/module_oidc.php`, find option
`ModuleConfig::OPTION_API_ENABLED` and set it to `true`.

```php
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_ENABLED => true,
```

This is the master switch, and on its own it exposes nothing. Every endpoint
also has its own switch, and some additionally depend on the feature they belong
to being enabled. All of these default to `false`, so an endpoint answers only
once this option and the ones listed with that endpoint below are all `true`.

## API Authentication and Authorization

API access tokens are defined in file `config/module_oidc.php`, under option `ModuleConfig::OPTION_API_TOKENS`.
This option is an associative array, where keys are the API access tokens, and values are arrays of scopes.

```php
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_TOKENS => [
    'strong-random-token-string' => [
        ApiScopesEnum::All,
    ],
],
```

Scopes determine which endpoints are accessible by the API access token. The following scopes are available:

* `\SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::All`: Access to all endpoints.
* `\SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::VciAll`: Access to all VCI-related endpoints.
* `\SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::VciCredentialOffer`: Access to credential offer endpoint.
* `\SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::VciCredentialStatus`: Access to the credential status endpoint.
* `\SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::OAuth2All`: Access to all OAuth2-related endpoints.
* `\SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::OAuth2TokenIntrospection`: Access to the OAuth2 token introspection endpoint.

### Naming a token

A token may instead be configured as an array with a `name` and a `scopes` key:

```php
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_TOKENS => [
    'strong-random-token-string' => [
        'name' => 'HR system',
        'scopes' => [
            ApiScopesEnum::VciCredentialStatus,
        ],
    ],
],
```

The name is what gets recorded in the status change audit trail when this token revokes or suspends a
credential, so the trail says which system asked rather than only that something did. Without a name,
an audit row records a fingerprint of the token instead (`token:` and 16 hex characters, keyed with a key
derived from the module's encryption key or the SimpleSAMLphp secret salt), which keeps separate callers
apart but says nothing about who they are — the
token itself is never written anywhere, since that would put a bearer secret in the database.

Both shapes work, and a token configured as a plain list of scopes keeps working unchanged.

## API Endpoints

Note that all endpoints will have a path prefix based on the SimpleSAMLphp base path and `oidc` module path.
For example, if you serve SimpleSAMLphp using base URL path `simplesaml/`, the path prefix for each API endpoint
will be

`/simplesaml/module.php/oidc/api/`

Check the SimpleSAMLphp config file `config/config.php`, option `baseurlpath` to find the base URL path of the
SimpleSAMLphp installation.

### Credential Offer

Enables fetching a credential offer as per OpenID4VCI specification.

Enable it in `config/module_oidc.php`, together with the VCI feature itself,
which this endpoint depends on:

```php
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_VCI_ENABLED => true,
ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,
```

#### Path

`/api/vci/credential-offer`

#### Method

`POST`

#### Authorization

`Bearer Token`

#### Request

The request is sent as a JSON object in the body with the following parameters:

* __grant_type__ (string, mandatory): Specifies the type of grant (issuance flow) being requested. Allowed values are:
  * `urn:ietf:params:oauth:grant-type:pre-authorized_code`: Pre-authorized code grant.
  * `authorization_code`: Authorization code grant.
* __credential_configuration_id__ (string, mandatory): The identifier for the credential configuration being requested.
This must correspond to a predefined configuration ID for the VCI Issuer. Check the Credential Issuer Configuration URL
`/.well-known/openid-credential-issuer`, under the `credential_configurations_supported` field.
* __use_tx_code__ (boolean, optional, default being `false`): Indicates whether to use transaction code protection for
pre-authorized code grant.
* __users_email_attribute_name__ (string, optional, no default): The name of the attribute that holds the
user's email address. Used when transaction code protection is enabled to send the transaction code to the user's email
address.
* __authentication_source_id__ (string, optional, no default): The identifier for the SimpleSAMLphp authentication
source, that should be used to determine the user's email address attribute. Used if `users_email_attribute_name` is
not specified, and transaction code protection is enabled.
* __user_attributes__ (object, optional, no default): An object containing various user attributes. Used in
pre-authorized code grant to populate credential data.

#### Response

The response is a JSON object with the `credential_offer_uri` field containing the credential offer URI string value.

#### Sample 1

Request a credential offer to issue a credential with the ID `ResearchAndScholarshipCredentialDcSdJwt` using the
authorization code grant.

Request:

```shell
curl --location 'https://idp.mivanci.incubator.hexaa.eu/ssp/module.php/oidc/api/vci/credential-offer' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer ***' \
--data '{
    "grant_type": "authorization_code",
    "credential_configuration_id": "ResearchAndScholarshipCredentialDcSdJwt"
}'
```

Response:

```json
{
    "credential_offer_uri": "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fidp.mivanci.incubator.hexaa.eu%22%2C%22credential_configuration_ids%22%3A%5B%22ResearchAndScholarshipCredentialDcSdJwt%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%2230616b68fa26b00c5a6391faffc02e4e4fd9b0023fd6a3aa29ec754e2f5e2871%22%7D%7D%7D"
}

```

#### Sample 2

Request a credential offer to issue a credential with the ID `ResearchAndScholarshipCredentialDcSdJwt` using the
pre-authorized code grant with transaction code protection. The user's email address is retrieved from the attribute
`mail`.

Request:

```shell
curl --location 'https://idp.mivanci.incubator.hexaa.eu/ssp/module.php/oidc/api/vci/credential-offer' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer ***' \
--data-raw '{
    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "credential_configuration_id": "ResearchAndScholarshipCredentialDcSdJwt",
    "use_tx_code": true,
    "users_email_attribute_name": "mail",
    "user_attributes": {
        "uid": ["testuseruid"],
        "mail": ["testuser@example.com"],
        "...": ["..."]
    }
}'
```

Response:

```json
{
    "credential_offer_uri": "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fidp.mivanci.incubator.hexaa.eu%22%2C%22credential_configuration_ids%22%3A%5B%22ResearchAndScholarshipCredentialDcSdJwt%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22_ffcdf6d86cd564c300346351dce0b4ccb2fde304e2%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22numeric%22%2C%22length%22%3A4%2C%22description%22%3A%22Please%20provide%20the%20one-time%20code%20that%20was%20sent%20to%20e-mail%20testuser%40example.com%22%7D%7D%7D%7D"
}
```

### Credential Status

Withdraws, suspends or reinstates a Verifiable Credential which has already been issued, by moving its
Token Status List entry to a new status. See
[Token Status Lists](3-oidc-configuration.md#token-status-lists-credential-revocation) for what has to
be configured before a credential has an entry to move.

Enable it in `config/module_oidc.php`:

```php
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => true,
```

#### Path

`/api/vci/credential-status`

#### Method

`POST`

#### Authorization

`Bearer Token`, and only from the `Authorization` header.

This endpoint deliberately does not accept the two other ways the rest of this API can be authorized. A
token passed as a request parameter would end up in web server access logs and browser history, which
for a token that can revoke credentials is worse than for one that reads them. An administrator's
SimpleSAMLphp session is not accepted either, because a request authorized by a session cookie can be
made by any page the administrator happens to be visiting. Use the administration screens for
session-authenticated changes; they carry their own protection against that.

#### Request

The request is sent as a JSON object in the body with the following parameters:

* __credential_id__ (string, mandatory): The credential identifier, being the `jti` (or `id`) of the
issued credential.
* __status__ (string, mandatory): The status to set. Matched case insensitively. Allowed values are:
  * `valid`: the credential is in force. Use this to reinstate a suspended one.
  * `invalid`: the credential is revoked. This is permanent in practice; a wallet holding it should
    stop presenting it.
  * `suspended`: the credential is temporarily out of force and can be reinstated.

#### Response

The response is a JSON object with the following fields:

* __status__ (string): The status the credential now holds.
* __changed__ (boolean): Whether this request is what changed it. `false` means the credential already
held that status, so a caller retrying a request it never saw the answer to can tell which happened.

Errors:

* `400 invalid_request`: the body could not be read, the credential identifier was missing, or the
status was not one of the three.
* `401 unauthorized`: no bearer token, or one which is not configured.
* `403 insufficient_scope`: the token is configured but has none of the scopes this endpoint accepts.
* `404 not_found`: no credential with that identifier can have its status changed. A credential which
was never issued here, one issued without a `status` claim, and one which has expired are all answered
the same way, so that the endpoint can not be used to find out which identifiers exist.
* `409 conflict`: another change landed at the same moment and the credential ended up holding
something other than what was asked for. Read the current status and decide again.
* `422 unsupported_status`: the Status List this credential belongs to was created without room for
that status. Bits per entry are fixed when a list is created, so this will not succeed on retry — a
pool which may suspend has to be configured with at least 2 bits before its credentials are issued.

#### Sample 1

Revoke a credential.

Request:

```shell
curl --location 'https://idp.example.org/ssp/module.php/oidc/api/vci/credential-status' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer ***' \
--data-raw '{
    "credential_id": "https://idp.example.org/vc/mBS4Zt9wDRe-8sYcJUEBiZ4bGDsYY3rMHOB2Xdw4t1c",
    "status": "invalid"
}'
```

Response:

```json
{
    "status": "invalid",
    "changed": true
}
```

#### Sample 2

Reinstate a suspended credential which somebody else has already reinstated.

Request:

```shell
curl --location 'https://idp.example.org/ssp/module.php/oidc/api/vci/credential-status' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer ***' \
--data-raw '{
    "credential_id": "https://idp.example.org/vc/mBS4Zt9wDRe-8sYcJUEBiZ4bGDsYY3rMHOB2Xdw4t1c",
    "status": "valid"
}'
```

Response:

```json
{
    "status": "valid",
    "changed": false
}
```

### Token Introspection

Enables token introspection for OAuth2 access tokens and refresh tokens as per
[RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662).

Enable it in `config/module_oidc.php`:

```php
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED => true,
```

#### Path

`/api/oauth2/token-introspection`

While enabled, the endpoint is advertised as `introspection_endpoint` in the
OpenID Connect discovery document (`/.well-known/openid-configuration`), the
OAuth 2.0 Authorization Server Metadata document
(`/.well-known/oauth-authorization-server`) and, when OpenID Federation is
enabled, the `openid_provider` metadata of the entity configuration
(`/.well-known/openid-federation`), together with
`introspection_endpoint_auth_methods_supported` and
`introspection_endpoint_auth_signing_alg_values_supported` (RFC 8414). The
advertised methods are the OAuth2 client authentication methods below plus
`Bearer`, which stands for the API Bearer Token (RFC 8414 admits IANA access
token types in that list, as RFC 7662 lets a protected resource authenticate
with a token of its own).

#### Method

`POST`

#### Authorization

Access is granted if:

* The client is authenticated using one of the supported OAuth2 client
authentication methods (`client_secret_basic`, `client_secret_post`,
`private_key_jwt`). A bare `client_id` does not count.
* Or, if the request is authorized using an API Bearer Token with
the appropriate scope.
* Or, if the request is made by a logged in SimpleSAMLphp administrator.

Authenticating is not on its own permission to introspect any given token.
A client which authenticates as itself is told about tokens issued to it, and
answered with `active: false` for tokens issued to anyone else. It already
holds its own tokens, so it learns nothing new about them, while another
client's token would answer with that token's subject, scopes and lifetime.

A deployment which runs a resource server as a client of its own names it in
`config/module_oidc.php`, and that client may then introspect any token:

```php
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS => [
    'resource-server-client-id',
],
```

This is configuration rather than client metadata on purpose: a client
registering itself through Dynamic Client Registration must not be able to ask
for the ability to read every other party's tokens. Naming a client there is a
decision to trust it with personal data: a client on that list is trusted with
the user claims of every token it can present (see the response below).

A deployment whose tokens are introspected by an upstream hub on behalf of
resource servers elsewhere -- the AS performing
[AARC-G052](https://aarc-community.org/guidelines/aarc-g052/) proxied token
introspection towards this OP; for an EOSC Node, the EOSC AAI Federation hub --
names the client registered for the hub separately:

```php
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_UPSTREAM_HUB_CLIENT_IDS => [
    'hub-client-id',
],
```

The hub may introspect any token this OP issued, as a resource server may, since
introspecting tokens it did not receive itself is its whole function; it is the
same trust decision. A client named in both lists is a configuration error, and
until it is resolved the endpoint answers every request authenticated with OAuth2
client credentials with a `server_error` (API Bearer Tokens and administrators
are not affected).

Requests authorized with an API Bearer Token holding an introspection scope,
and those made by a logged in SimpleSAMLphp administrator, may introspect any
token and are unaffected by those options. Such a request is attributed to the
token's configured name, or to a fingerprint of the token where it has none (two
tokens configured under one name are therefore one caller), and to
`simplesamlphp-admin` for an administrator.

#### Request

The request is sent with `application/x-www-form-urlencoded` encoding with the
following parameters:

* __token__ (string, mandatory): The string value of the token.
* __token_type_hint__ (string, optional): A hint about the type of the
token submitted for introspection. Allowed values:
  * `access_token`
  * `refresh_token`

#### Response

The response is a JSON object with the following fields:

* __active__ (boolean, mandatory): Indicator of whether or not the presented
token is currently active.
* __scope__ (string, optional): A JSON string containing a space-separated
list of scopes associated with this token.
* __client_id__ (string, optional): Client identifier for the OAuth 2.0 client
that requested this token.
* __token_type__ (string, optional): Type of the token as defined in OAuth 2.0.
* __exp__ (integer, optional): Expiration time.
* __iat__ (integer, optional): Issued at time.
* __nbf__ (integer, optional): Not before time.
* __sub__ (string, optional): Subject identifier for the user who
authorized the token.
* __aud__ (string/array, optional): Audience for the token.
* __iss__ (string, optional): Issuer of the token.
* __jti__ (string, optional): Identifier for the token.
* The __user claims__ the token's scopes release (access tokens issued to a
user only), as further top-level members, see below.

For an access token issued to a user, the response also carries the user
claims the token's scopes release -- those of the `openid` scope (`sub`, the
[identity claims](3-oidc-configuration.md#identity-claims-and-access-token-claims)),
the standard scopes and the private scopes the token was granted -- read from
the user record as it is now: the same claims, from the same record, the
UserInfo endpoint releases for that token, so a resource server which enforces
its policy on the introspection response (RFC 7662 section 2.2 lets an
implementation extend it with members of its own) sees what it would see at the
UserInfo endpoint. Nothing is read from the token itself, which is a snapshot
taken when it was minted, and the `claims` request parameter plays no part. The
`sub` reported is the token's own, the subject it was minted with (see [the
subject](3-oidc-configuration.md#the-subject)); a user claim of the same name
as a token member does not displace it. (For an access token issued before the
module wrote a `typ` header, whose `sub` is the internal user identifier, the
`sub` the `openid` scope releases stands instead, as it does at the UserInfo
endpoint.) An access token issued without a user
(a client credentials token, a pre-authorized code with no holder) carries the
token members only, and so does a refresh token, which is never shown to a
resource server.

If the token is not active, only the `active` field with a value of
`false` is returned. The same answer is given when the caller is not entitled
to be told about the token, so an inactive answer does not distinguish a token
which does not exist from one the caller may not see. A token whose user or
client no longer exists is not active either: deleting a user or a client
deletes the tokens issued to or for them, so the token was revoked with the
record, and the answer is the same whether the token's own record is already
gone or a cached copy of it is still around.

If the endpoint can not read the records it answers from (the token's, the
user's), it responds with `server_error` (HTTP 500) rather than with an
inactive token: the failure is the OP's, not a verdict on the token, and a
resource server may cache the verdict.

#### Release policy

By default every caller entitled to ask about a token is told the whole
answer. A deployment which wants to tell some callers less configures a
release policy: a class implementing
`\SimpleSAML\Module\oidc\Services\Introspection\IntrospectionReleasePolicyInterface`,
constructed with the arguments configured next to it (a list is passed by
position, string keys by name). RFC 7662 section 2.2 lets an authorization
server "respond differently to different protected resources making the same
request", for instance by limiting which scopes are returned to each.

The policy is asked once per answer, only about a token which is active and
which the caller may ask about. It is given the caller (its identifier and its
role: `client`, `resource_server`, `upstream_hub` or `administrative`), where
the token comes from, the scopes the token was granted and the token's members
without the user claims, and returns a decision
(`\SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision`):

* `releaseAll()` -- the whole answer;
* `deny()` -- the token is answered as `active: false`, exactly as an unknown
  token is, and nothing says why (the refusal is logged);
* `release($scopes, $withheldMembers)` -- only the granted scopes named in
  `$scopes` (null for all of them) are released: the `scope` member names only
  those, and the user claims are read for those scopes only, so a scope taken
  away takes its claims with it. The members named in `$withheldMembers` are
  then removed from the assembled answer, last, so none of them comes back --
  `sub` included, which is a token member as well as a user claim.

A decision can only take away: naming a scope the token was not granted does
not release it. The members describing the token itself -- `active`, `iss`,
`exp`, `iat`, `nbf`, `token_type`, `client_id`, `jti` (those AARC-G052 section
3 forbids a proxy to change) and `aud` -- can not be withheld; a decision naming
one is a configuration error. A policy which throws, which returns such a
decision, or which can not be built is answered with a `server_error`, never
with an inactive token.

For a token this OP issued, whoever holds the token can read the same user
claims at the UserInfo endpoint, so a policy limits what the introspection
endpoint hands over, not what a caller holding the token can learn.

For example, releasing only the `openid` scope (and so only its claims) to one
resource server, and the whole answer to every other caller:

```php
use SimpleSAML\Module\oidc\Codebooks\IntrospectionCallerRoleEnum;
use SimpleSAML\Module\oidc\Services\Introspection\IntrospectionReleasePolicyInterface;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision;

class ScopesPerResourceServer implements IntrospectionReleasePolicyInterface
{
    /** @param array<string, string[]> $scopesByResourceServer */
    public function __construct(protected readonly array $scopesByResourceServer)
    {
    }

    public function decide(
        IntrospectionAuthorization $caller,
        IntrospectedTokenOrigin $origin,
        array $grantedScopes,
        array $tokenMembers,
    ): IntrospectionReleaseDecision {
        // Keyed by role as well as identifier: an API token's name could equal a client identifier.
        if ($caller->getRole() !== IntrospectionCallerRoleEnum::ResourceServer) {
            return IntrospectionReleaseDecision::releaseAll();
        }

        $scopes = $this->scopesByResourceServer[$caller->getCallerId()] ?? null;

        return IntrospectionReleaseDecision::release($scopes);
    }
}
```

```php
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RELEASE_POLICY => \Acme\ScopesPerResourceServer::class,
ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RELEASE_POLICY_ARGUMENTS => [
    'scopesByResourceServer' => ['analytics-rs' => ['openid']],
],
```

#### Sample 1

Introspect an active access token using an API Bearer Token.

Request:

```shell
curl --location 'https://idp.mivanci.incubator.hexaa.eu/ssp/module.php/oidc/api/oauth2/token-introspection' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Bearer ***' \
--data-urlencode 'token=access-token-string'
```

Response:

```json
{
    "active": true,
    "scope": "openid profile email",
    "client_id": "test-client",
    "token_type": "Bearer",
    "exp": 1712662800,
    "iat": 1712659200,
    "sub": "user-id",
    "aud": "test-client",
    "iss": "https://idp.mivanci.incubator.hexaa.eu",
    "jti": "token-id",
    "name": "Ada Lovelace",
    "email": "ada@example.org"
}
```

#### Sample 2

Introspect a refresh token using an API Bearer Token.

Request:

```shell
curl --location 'https://idp.mivanci.incubator.hexaa.eu/ssp/module.php/oidc/api/oauth2/token-introspection' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Bearer ***' \
--data-urlencode 'token=refresh-token-string' \
--data-urlencode 'token_type_hint=refresh_token'
```

Response:

```json
{
    "active": true,
    "scope": "openid profile",
    "client_id": "test-client",
    "exp": 1715251200,
    "sub": "user-id",
    "aud": "test-client",
    "jti": "refresh-token-id"
}
```
