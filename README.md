# simplesamlphp-module-oidc
> A SimpleSAMLphp module adding support for the OpenID Connect protocol.

This module adds support for the OpenID Connect protocol through a SimpleSAMLphp module installable through Composer.

[![Build Status](https://travis-ci.org/rediris-es/simplesamlphp-module-oidc.svg?branch=master)](https://travis-ci.org/rediris-es/simplesamlphp-module-oidc) 
[![Coverage Status](https://coveralls.io/repos/github/rediris-es/simplesamlphp-module-oidc/badge.svg?branch=master)](https://coveralls.io/github/rediris-es/simplesamlphp-module-oidc?branch=master)
[![SimpleSAMLphp](https://img.shields.io/badge/simplesamlphp-1.18-red.svg)](https://simplesamlphp.org/)

![Main screen capture](docs/oidc.png)

## Installation

Installation can be as easy as executing:

    composer require rediris-es/simplesamlphp-module-oidc
    
## Configuration

### Configure the database

Edit your `config/config.php` and check you configured at least the next parameters from the _database_ section:

    'database.dsn' => 'mysql:host=server;dbname=simplesamlphp',
    'database.username' => 'user',
    'database.password' => 'password',

### Configure the template

This module used the new twig template system, so you need to configure the next option in `config/config.php`:

    'language.i18n.backend' => 'gettext/gettext',

### Configure the module

Copy the template file to the config directory:

    cp modules/oidc/config-template/module_oidc.php config/

and edit it. The options are self explained.

#### Private scopes

This module support the basic OIDC scopes: openid, email, address, phone and profile. You can add your own private scopes in the `module_oidc.php` config file:

```php
<?php

$config = [
    'scopes' => [
        'private' => [
            'description' => 'private scope',
            'claim_name_prefix' => '', // Optional prefix for claim names
            'are_multiple_claim_values_allowed' => false, // Allow or disallow multiple values for claims
            'attributes' => ['national_document_id']
        ],
    ],
];
```

#### Attribute translation

We have a default translation table from SAML attributes to OIDC claims, based on this [REFEDS wiki article: "Mapping SAML attributes to OIDC Claims"](https://wiki.refeds.org/display/GROUPS/Mapping+SAML+attributes+to+OIDC+Claims).

You can change or extend this table from `module_oidc.php` config file:

```php
<?php

$config = [
    'translate' => [
        // Overwrite default translation
        'sub' => [
            'uid', // added
            'eduPersonPrincipalName',
            'eduPersonTargetedID',
            'eduPersonUniqueId',
        ],
        // Remove default translation
        'family_name' => [
        ],

        // New claim created from SAML attribute
        // Used in previus private scope
        'national_document_id' => [
            'schacPersonalUniqueId',
        ],
    ],
];
```

#### Auth Proc Filters
This module will not execute standard Auth Proc Filters which are used during regular SAML authN, reason being that 
not all expected entities are participating in the authN process (most notably the Service Provider - SP). 
Because of that, OIDC module provides its own 'authproc.oidc' configuration option which can be used to designate 
specific Auth Proc Filters which will run only during OIDC authN. 

However, there are some considerations. OIDC authN state array will not contain all the keys which are 
available during SAML authN, like Service Provider metadata. If you are using an existing filter, make sure it does 
not rely on some non-existent state data. At the moment, only the following SAML authN data will be available:
* 'Attributes'
* 'Authority'
* 'AuthnInstant'
* 'Expire'
* 'IdPMetadata'
* 'Source'

In addition to that, the following OIDC related data will be available in the state array:
* 'OidcProviderMetadata' - contains information otherwise available from the OIDC configuration URL.
* 'OidcRelyingPartyMetadata' - contains information about the OIDC client making the authN request.
* 'OidcAuthorizationRequestParameters' - contains relevant authorization request query parameters.

Note: at the moment there is no support for showing a page to the user in a filter, and then resuming the filtering.
Only the common filter use cases are supported like attribute handling, logging, or similar. 

You can add Auth Proc filters in the 'authproc.oidc' config option in the same manner as described in the [Auth Proc 
documentation](https://simplesamlphp.org/docs/stable/simplesamlphp-authproc).

```php
<?php

$config = [
    'authproc.oidc' => [
        50 => [
            'class' => 'core:AttributeAdd',
            'groups' => ['users', 'members'],
        ],
    ],
];
```

#### Cron hook

This module requires [cron module](https://simplesamlphp.org/docs/stable/cron:cron) is active to remove old tokens.

### Create the OpenID Connect keys

The oidc library used generates Json Web Tokens to create the Access Tokens, so you need to create a public and private cert keys.

To generate the private key run this command on the terminal:

    openssl genrsa -out cert/oidc_module.pem 1024

If you want to provide a passphrase for your private key run this command instead:

    openssl genrsa -passout pass:myPassPhrase -out cert/oidc_module.pem 1024

Now you need to extract the public key from the private key:

    openssl rsa -in cert/oidc_module.pem -pubout -out cert/oidc_module.crt

or use your passphrase if provided on private key generation:

    openssl rsa -in cert/oidc_module.pem -passin pass:myPassPhrase -pubout -out cert/oidc_module.crt

If you use a passphrase remember to configure it in the module_oidc.php config file.

## Installation

First, you need to create the database schema. The module detects if the schema is not created or updated.

Open the _Federation_ tab from your _SimpleSAMLphp_ installation and select the option _OpenID Connect Installation_ inside the _Tools_ section.

All you need to do is press the _Install_ button and the schema will be created. If you have a legacy oauth2 module installed, the installation page will ask if you want to migrate the date.

## OpenID Connect Autodiscovery

This module offers a OpenID Connect Autodiscovery endpoint in the next url:

    https://yourserver/simplesaml/module.php/oidc/openid-configuration.php

If you want to know all the module endpoints, check that url.

### Nginx configuration

If you want to have a canonical `https://yourserver/.well-known/openid-configuration` url for this service you can add this to your _nginx_ server configuration:

    location = /.well-known/openid-configuration {
        rewrite ^(.*)$ /simplesaml/module.php/oidc/openid-configuration.php break;
        proxy_pass https://localhost;
    }

### OAuth2 authentication

This module is based on [Oauth2 Server from the PHP League](https://oauth2.thephpleague.com/) and only supports implicit and explicit tokens.

## Administration

Once the database schema has been created, you can open the _Federation_ tab from your _SimpleSAMLphp_ installation and select the option _OpenID Connect Client Registry_ inside the _Tools_ section.

The module lets you create, read, update and delete all the RP you want. To see the client id and the client secret press the show button.

### Create client options

* Enabled: You can enable or disable a client. Disabled by default.
* Secure client: The client is secure if it is capable of securely storing a secret. Unsecure clients
must provide a PCKS token (code_challenge parameter during authorization phase). Disabled by default. 
