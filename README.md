# simplesamlphp-module-oidc
> A SimpleSAMLphp module adding support for the OpenID Connect protocol.

This module adds support for the OpenID Connect protocol through a SimpleSAMLphp module installable through Composer.

[![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-oidc/actions/workflows/test.yaml/badge.svg)](https://github.com/simplesamlphp/simplesamlphp-module-oidc/actions/workflows/test.yaml) 
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-oidc/branch/master/graph/badge.svg)](https://app.codecov.io/gh/simplesamlphp/simplesamlphp-module-oidc)
[![SimpleSAMLphp](https://img.shields.io/badge/simplesamlphp-1.19-brightgreen)](https://simplesamlphp.org/)

![Main screen capture](docs/oidc.png)

## Installation

Installation can be as easy as executing:

    composer require simplesamlphp/simplesamlphp-module-oidc
    
## Configuration

Once you install and configure the module checkout the [FAQ](FAQ.md)

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

#### Cron hook

This module requires [cron module](https://simplesamlphp.org/docs/stable/cron:cron) is active to remove old tokens.

### Create the OpenID Connect keys

The oidc library used generates Json Web Tokens to create the Access Tokens, so you need to create a public and private cert keys.

To generate the private key run this command on the terminal:

    openssl genrsa -out cert/oidc_module.pem 2048

If you want to provide a passphrase for your private key run this command instead:

    openssl genrsa -passout pass:myPassPhrase -out cert/oidc_module.pem 2048

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

### Client self registration

You can allow users to register their own clients.
This is controlled through the `permissions` setting in `module_oidc.php`

Permissions let the module expose functionality to specific users. In the
below configuration, a user's eduPersonEntitlement attribute is examined.
If the user tries to do something that requires the `client` permission
(such as registering their own client) then they will need one of the
eduPersonEntitlements from the `client` permission array.

A permission can be disable by commenting it out.

```bash
    'permissions' => [
        // Attribute to inspect to determine user's permissions
        'attribute' => 'eduPersonEntitlement',
        // Which entitlements allow for registering, editing, delete a client. OIDC clients are owned by the creator
        'client' => ['urn:example:oidc:manage:client'],
    ],
```

Users can visit the `https://example.com/simplesaml/module.php/oidc/clients/` to create and view their clients.

### Create client options

* Enabled: You can enable or disable a client. Disabled by default.
* Secure client: The client is secure if it is capable of securely storing a secret. Unsecure clients
must provide a PCKS token (code_challenge parameter during authorization phase). Disabled by default. 

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
  --mount type=bind,source="$(pwd)/docker/ssp/oidc_module.pem",target=/var/simplesamlphp/cert/oidc_module.pem,readonly \
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

Work in Progress:
  * Adding RPs to docker compose. Issue: the RP container refuses to connect to the OP's .well-known endpoint because
  it uses self-signed certificates. This makes local testing difficult.
  * Allow testing with different databases

## Running Conformance Tests

See [CONFORMANCE_TEST.md](CONFORMANCE_TEST.md)
