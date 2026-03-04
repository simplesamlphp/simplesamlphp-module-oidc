# OIDC Module - Configuration

This guide summarizes key configuration topics for the OIDC module.
It complements the inline comments in `config/module_oidc.php`.

- Caching protocol artifacts
- Relying Party (RP) administration UI
- Cron integration
- Endpoint locations and well-known URLs
- Key rollover
- Apache Authorization header note
- Private scopes
- Attribute translation
- Auth Proc filters (OIDC)
- Client registration permissions

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
            'attributes' => ['national_document_id'],
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

## Auth Proc filters (OIDC)

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
