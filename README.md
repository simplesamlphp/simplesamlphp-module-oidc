# simplesamlphp-module-oidc
> A SimpleSAMLphp module for OIDC OP support.

This module adds support for OpenID Provider role from the OpenID Connect protocol
through a SimpleSAMLphp module installable through Composer. It is based on 
[Oauth2 Server from the PHP League](https://oauth2.thephpleague.com/) 

Currently supported flows are:
* Authorization Code flow, with PKCE support (response_type 'code')
* Implicit flow (response_type 'id_token token' or 'id_token')
* Plain OAuth2 Implicit flow (response_type 'token')
* Refresh Token flow

[![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-oidc/actions/workflows/test.yaml/badge.svg)](https://github.com/simplesamlphp/simplesamlphp-module-oidc/actions/workflows/test.yaml) 
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-oidc/branch/master/graph/badge.svg)](https://app.codecov.io/gh/simplesamlphp/simplesamlphp-module-oidc)
[![SimpleSAMLphp](https://img.shields.io/badge/simplesamlphp-1.19-brightgreen)](https://simplesamlphp.org/)

![Main screen capture](docs/oidc.png)

## Version compatibility

| OIDC module | SimpleSAMLphp |  PHP   | Note                        |
|:------------|:--------------|:------:|-----------------------------|
| v5.\*       | v2.1.\*       | \>=8.1 | Recommended                 |
| v4.\*       | v2.0.\*       | \>=8.0 |                             |
| v3.\*       | v2.0.\*       | \>=7.4 | Abandoned from August 2023. |
| v2.\*       | v1.19.\*      | \>=7.4 |                             |

### Upgrading?

If you are upgrading from a previous version, checkout the [upgrade guide](UPGRADE.md).

## Installation

Installation can be as easy as executing:

    composer require simplesamlphp/simplesamlphp-module-oidc

### Configure the module

Copy the module config template file to the SimpleSAMLphp config directory:

    cp modules/oidc/config-templates/module_oidc.php config/

The options are self-explanatory, so make sure to go through the file and edit them as appropriate.

### Configure the database

This module uses a default SimpleSAMLphp database feature to store access/refresh tokens, user data, etc.
In order for this to work, edit your `config/config.php` and check 'database' related configuration. Make sure
you have at least the following parameters set:

    'database.dsn' => 'mysql:host=server;dbname=simplesamlphp;charset=utf8',
    'database.username' => 'user',
    'database.password' => 'password',

### Run database migrations

The module comes with some default SQL migrations which set up needed tables in the configured database. To run them,
open the _Federation_ tab from your _SimpleSAMLphp_ installation and select the option _OpenID Connect Installation_
inside the _Tools_ section. Once there, all you need to do is press the _Install_ button and the schema will be created.

### Relying Party (RP) Administration

The module lets you manage (create, read, update and delete) approved RPs from the module user interface itself.

Once the database schema has been created, you can open the _Federation_ tab from your _SimpleSAMLphp_ installation
and select the option _OpenID Connect Client Registry_ inside the _Tools_ section.

Note that clients can be marked as confidential or public. If the client is not marked as confidential (it is public),
and is using Authorization Code flow, it will have to provide PKCE parameters during the flow.

Client ID and secret will be generated, and can be seen after the client creation by clicking on the 'show' button.

### Create RSA key pair

During the authentication flow, generated ID Token and Access Token will be in a form of signed JSON Web token (JWS).
Because of the signing part, you need to create a public/private RSA key pair.

To generate the private key, you can run this command in the terminal:

    openssl genrsa -out cert/oidc_module.key 2048

If you want to provide a passphrase for your private key, run this command instead:

    openssl genrsa -passout pass:myPassPhrase -out cert/oidc_module.key 2048

Now you need to extract the public key from the private key:

    openssl rsa -in cert/oidc_module.key -pubout -out cert/oidc_module.crt

or use your passphrase if provided on private key generation:

    openssl rsa -in cert/oidc_module.key -passin pass:myPassPhrase -pubout -out cert/oidc_module.crt

If you use a passphrase, make sure to also configure it in the `module_oidc.php` config file.

### Cron hook

In order to purge expired tokens, this module requires [cron module](https://simplesamlphp.org/docs/stable/cron:cron)
to be enabled and configured.

## Additional considerations
### Private scopes

This module support the basic OIDC scopes: openid, email, address, phone and profile.
However, you can add your own private scopes in the `module_oidc.php` config file, for example:

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

### Attribute translation

Default translation table from SAML attributes to OIDC claims is based on
[REFEDS wiki article: "Mapping SAML attributes to OIDC Claims"](https://wiki.refeds.org/display/GROUPS/Mapping+SAML+attributes+to+OIDC+Claims).

You can change or extend this table in the `module_oidc.php` config file, for example:

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

### Auth Proc Filters
This module will not execute standard Auth Proc Filters which are used during regular SAML authN, reason being that 
not all expected entities are participating in the authN process (most notably the Service Provider - SP). 
Because of that, OIDC module provides its own 'authproc.oidc' configuration option which can be used to designate 
specific Auth Proc Filters which will run only during OIDC authN. 

However, there are some considerations. OIDC authN state array will not contain all the keys which are 
available during SAML authN, like Service Provider metadata. If you are using an existing filter, make sure it does 
not rely on some non-existent state data. At the moment, only the following SAML authN data will be available:
* \['Attributes'\]
* \['Authority'\]
* \['AuthnInstant'\]
* \['Expire'\]

Source and destination will have entity IDs corresponding to the OP issuer ID and Client ID respectively.
* \['Source'\]\['entityid'\] - contains OpenId Provider issuer ID
* \['Destination'\]\['entityid'\] - contains Relying Party (OIDC Client) ID

In addition to that, the following OIDC related data will be available in the state array:
* \['Oidc'\]\['OpenIdProviderMetadata'\] - contains information otherwise available from the OIDC configuration URL.
* \['Oidc'\]\['RelyingPartyMetadata'\] - contains information about the OIDC client making the authN request.
* \['Oidc'\]\['AuthorizationRequestParameters'\] - contains relevant authorization request query parameters.

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
### Client registration permissions

You can allow users to register their own clients.
This is controlled through the `permissions` setting in `module_oidc.php`

Permissions let the module expose functionality to specific users. In the
below configuration, a user's eduPersonEntitlement attribute is examined.
If the user tries to do something that requires the `client` permission
(such as registering their own client) then they will need one of the
eduPersonEntitlements from the `client` permission array.

A permission can be disabled by commenting it out.

```bash
    'permissions' => [
        // Attribute to inspect to determine user's permissions
        'attribute' => 'eduPersonEntitlement',
        // Which entitlements allow for registering, editing, delete a client. OIDC clients are owned by the creator
        'client' => ['urn:example:oidc:manage:client'],
    ],
```

Users can visit the `https://example.com/simplesaml/module.php/oidc/clients/` to create and view their clients.

## OIDC Discovery

The module offers an OpenID Connect Discovery endpoint at URL:

    https://yourserver/simplesaml/module.php/oidc/openid-configuration.php

### .well-known URL

You can configure you web server (Apache, Nginx) in a way to serve the mentioned autodiscovery URL in a '.well-known'
form. Here are some sample configurations:

#### nginx 
    location = /.well-known/openid-configuration {
        rewrite ^(.*)$ /simplesaml/module.php/oidc/openid-configuration.php break;
        proxy_pass https://localhost;
    }

#### Apache

    Alias /.well-known/openid-configuration "/path/to/simplesamlphp/module.php/oidc/openid-configuration.php"

## Using Docker

### With current git branch.

To explore the module using docker run the below command. This will run an SSP image, with the current oidc module mounted
in the container, along with some configuration files. Any code changes you make to your git checkout are "live" in
the container, allowing you to test and iterate different things.

```
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
docker run --name ssp-oidc-dev \
   --mount type=bind,source="$(pwd)",target=/var/simplesamlphp/staging-modules/oidc,readonly \
  -e STAGINGCOMPOSERREPOS=oidc \
  -e COMPOSER_REQUIRE="simplesamlphp/simplesamlphp-module-oidc:dev-$GIT_BRANCH" \
  -e SSP_ADMIN_PASSWORD=secret1 \
  --mount type=bind,source="$(pwd)/docker/ssp/module_oidc.php",target=/var/simplesamlphp/config/module_oidc.php,readonly \
  --mount type=bind,source="$(pwd)/docker/ssp/authsources.php",target=/var/simplesamlphp/config/authsources.php,readonly \
  --mount type=bind,source="$(pwd)/docker/ssp/config-override.php",target=/var/simplesamlphp/config/config-override.php,readonly \
  --mount type=bind,source="$(pwd)/docker/ssp/oidc_module.crt",target=/var/simplesamlphp/cert/oidc_module.crt,readonly \
  --mount type=bind,source="$(pwd)/docker/ssp/oidc_module.key",target=/var/simplesamlphp/cert/oidc_module.key,readonly \
  --mount type=bind,source="$(pwd)/docker/apache-override.cf",target=/etc/apache2/sites-enabled/ssp-override.cf,readonly \
   -p 443:443 cirrusid/simplesamlphp:1.19.0
```

Visit https://localhost/simplesaml/ and confirm you get the default page.
Then navigate to [OIDC screen](https://localhost/simplesaml/module.php/oidc/install.php)
and you can add a client.

You may view the OIDC configuration endpoint at `https://localhost/.well-known/openid-configuration`

### Build Image to Deploy for Conformance Tests

Build an image that contains a pre-configured sqlite database.

```bash
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
# Replace invalid tag characters when doing build
IMAGE_TAG=$(tr '/' '_' <<< $GIT_BRANCH)
docker build -t "simplesamlphp/simplesamlphp-oidc:dev-$IMAGE_TAG" \
  --build-arg OIDC_VERSION=dev-${GIT_BRANCH} \
  -f docker/Dockerfile .

docker run --name ssp-oidc-dev-image \
  -e SSP_ADMIN_PASSWORD=secret1 \
  -p 443:443 simplesamlphp/simplesamlphp-oidc:dev-$IMAGE_TAG

```

Publish the image somewhere you can retrieve it.
Temporarily, this will occasionally get published into the cirrusid Docker namespace.

```
docker tag "simplesamlphp/simplesamlphp-oidc:dev-$IMAGE_TAG" "cirrusid/simplesamlphp-oidc:dev-$IMAGE_TAG"
docker push "cirrusid/simplesamlphp-oidc:dev-$IMAGE_TAG"
```

The database is not currently on a share volume, so any changes will get lost if the container restarts.
You may want to back it up.
To dump the database
```bash
docker exec ssp-oidc-dev-image sqlite3  /var/simplesamlphp/data/mydb.sq3 '.dump' > docker/conformance.sql
```

Conformance tests are easier to run locally, see the `Docker compose` section and [CONFORMANCE_TEST.md](CONFORMANCE_TEST.md)

### Docker compose

Docker compose will run several containers to make it easier to test scenarios. It will build an image
that contains OIDC module. You may remove the ``--build`` argument if you want docker-compose to reuse
previously running container.

```
# Use the current branch/git checkout. Composer installs local checkout
OIDC_VERSION=@dev docker-compose -f docker/docker-compose.yml --project-directory . up --build

# Set OIDC_VERSION to a version that composer can install to use a different version of the module.
OIDC_VERSION=dev-master docker-compose -f docker/docker-compose.yml --project-directory . up --build
```

Visit the [OP](https://op.local.stack-dev.cirrusidentity.com/simplesaml/) and confirm a few clients already exist.

Conformance tests are easier to run locally, see [CONFORMANCE_TEST.md](CONFORMANCE_TEST.md)

## Running Conformance Tests

See [CONFORMANCE_TEST.md](CONFORMANCE_TEST.md)

## Have more questions?

Check the [FAQ](FAQ.md).