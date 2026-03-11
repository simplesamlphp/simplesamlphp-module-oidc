# API

## Enabling API

To enable API capabilities, in module config file `config/module_oidc.php`, find option
`ModuleConfig::OPTION_API_ENABLED` and set it to `true`.

```php
use SimpleSAML\Module\oidc\ModuleConfig;

ModuleConfig::OPTION_API_ENABLED => true,
```


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
* `\SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::OAuth2All`: Access to all OAuth2-related endpoints.
* `\SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::OAuth2TokenIntrospection`: Access to the OAuth2 token introspection endpoint.

## API Endpoints

Note that all endpoints will have a path prefix based on the SimpleSAMLphp base path and `oidc` module path.
For example, if you serve SimpleSAMLphp using base URL path `simplesaml/`, the path prefix for each API endpoint
will be 

`/simplesaml/module.php/oidc/api/`

Check the SimpleSAMLphp config file `config/config.php`, option `baseurlpath` to find the base URL path of the
SimpleSAMLphp installation.

### Credential Offer

Enables fetching a credential offer as per OpenID4VCI specification.

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
    "credential_offer_uri": "openid-credential-offer://?credential_offer={\"credential_issuer\":\"https:\\/\\/idp.mivanci.incubator.hexaa.eu\",\"credential_configuration_ids\":[\"ResearchAndScholarshipCredentialDcSdJwt\"],\"grants\":{\"authorization_code\":{\"issuer_state\":\"30616b68fa26b00c5a6391faffc02e4e4fd9b0023fd6a3aa29ec754e2f5e2871\"}}}"
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
        "uid": [“testuseruid"],
        "mail": ["testuser@example.com"],
        "...": [“..."]
    }
}'
```

Response:

```json
{
    "credential_offer_uri": "openid-credential-offer://?credential_offer={\"credential_issuer\":\"https:\\/\\/idp.mivanci.incubator.hexaa.eu\",\"credential_configuration_ids\":[\"ResearchAndScholarshipCredentialDcSdJwt\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"_ffcdf6d86cd564c300346351dce0b4ccb2fde304e2\",\"tx_code\":{\"input_mode\":\"numeric\",\"length\":4,\"description\":\"Please provide the one-time code that was sent to e-mail testuser@example.com\"}}}}"
}
```

### Token Introspection

Enables token introspection for OAuth2 access tokens and refresh tokens as per
[RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662).

#### Path

`/api/oauth2/token-introspection`

#### Method

`POST`

#### Authorization

Access is granted if:
* The client is authenticated using one of the supported OAuth2 client
authentication methods (Basic, Post, Private Key JWT, Bearer).
* Or, if the request is authorized using an API Bearer Token with
the appropriate scope.

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

If the token is not active, only the `active` field with a value of
`false` is returned.

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
    "jti": "token-id"
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
