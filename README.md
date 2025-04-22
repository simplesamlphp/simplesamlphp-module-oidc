# simplesamlphp-module-oidc
> A SimpleSAMLphp module for OIDC OP support.

This module adds support for the OpenID Provider role from the OpenID Connect protocol
through a SimpleSAMLphp module installable via Composer. It is based on 
[OAuth2 Server from the PHP League](https://oauth2.thephpleague.com/).

Currently supported flows are:
* Authorization Code flow, with PKCE support (response_type 'code')
* Implicit flow (response_type 'id_token token' or 'id_token')
* Refresh Token flow

[![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-oidc/actions/workflows/test.yaml/badge.svg)](https://github.com/simplesamlphp/simplesamlphp-module-oidc/actions/workflows/test.yaml) 
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-oidc/branch/master/graph/badge.svg)](https://app.codecov.io/gh/simplesamlphp/simplesamlphp-module-oidc)
[![SimpleSAMLphp](https://img.shields.io/badge/simplesamlphp-2.3-brightgreen)](https://simplesamlphp.org/)

![Main screen capture](docs/oidc.png)

### Note on OpenID Federation (OIDFed) support

OpenID Federation support is in "draft" phase, as is the
[specification](https://openid.net/specs/openid-federation-1_0) itself. This means that you can expect breaking changes
in future releases related to OIDFed capabilities. You can enable / disable OIDFed support at any time in the module
configuration.

Currently, the following OIDFed features are supported:
* automatic client registration using a Request Object (passing it by value)
* federation participation limiting based on Trust Marks
* endpoint for issuing configuration entity statement (statement about itself)
* fetch endpoint for issuing statements about subordinates (registered clients)
* subordinate listing endpoint

OIDFed support is implemented using the underlying [SimpleSAMLphp OpenID library](https://github.com/simplesamlphp/openid).

## Version compatibility

The minor versions of SimpleSAMLphp listed below indicate which versions of SimpleSAMLphp were used for testing
during module development. SimpleSAMLphp has followed semantic versioning for its API since version 2.0. This means,
for example, that v5.* of the OIDC module should work with any v2.* of SimpleSAMLphp. However, please note that
PHP version requirements have changed in minor SimpleSAMLphp releases.

| OIDC module | Tested SimpleSAMLphp |  PHP   | Note                        |
|:------------|:---------------------|:------:|-----------------------------|
| v6.\*       | v2.3.\*              | \>=8.2 | Recommended                 |
| v5.\*       | v2.1.\*              | \>=8.1 |                             |
| v4.\*       | v2.0.\*              | \>=8.0 |                             |
| v3.\*       | v2.0.\*              | \>=7.4 | Abandoned from August 2023. |
| v2.\*       | v1.19.\*             | \>=7.4 |                             |

### Upgrading?

If you are upgrading from a previous version, make sure to check the [upgrade guide](UPGRADE.md).

## Installation

Installation is as simple as executing:

    composer require simplesamlphp/simplesamlphp-module-oidc

### Configure the module

Copy the module configuration template file to the SimpleSAMLphp config directory:

    cp modules/oidc/config/module_oidc.php.dist config/module_oidc.php

Review all options in the file and edit them as needed for your environment.

### Configure the database

This module uses SimpleSAMLphp's database feature to store access/refresh tokens, user data, and other information.
To set this up, edit your `config/config.php` and configure the database-related settings. Ensure you have at least
the following parameters configured:

    'database.dsn' => 'mysql:host=server;dbname=simplesamlphp;charset=utf8',
    'database.username' => 'user',
    'database.password' => 'password',

> [!NOTE]  
> The module has been tested with and supports SQLite, PostgreSQL, and MySQL databases.

### Create Protocol / Federation RSA key pairs

During the authentication flow, the generated ID Token and Access Token will be in the form of signed JSON Web Tokens (JWS).
For signing these tokens, you need to create a public/private RSA key pair, referred to as "OIDC protocol" keys.

If you plan to use OpenID Federation capabilities, you should create a separate key pair dedicated to OpenID Federation
operations, such as signing Entity Statement JWS.

Below are sample commands to create key pairs with default file names for both "protocol" and "federation" purposes:

To generate the private keys without a passphrase:

    openssl genrsa -out cert/oidc_module.key 3072
    openssl genrsa -out cert/oidc_module_federation.key 3072

To generate the private keys with a passphrase:

    openssl genrsa -passout pass:myPassPhrase -out cert/oidc_module.key 3072
    openssl genrsa -passout pass:myPassPhrase -out cert/oidc_module_federation.key 3072

Next, extract the public key from each private key:

Without passphrase:

    openssl rsa -in cert/oidc_module.key -pubout -out cert/oidc_module.crt
    openssl rsa -in cert/oidc_module_federation.key -pubout -out cert/oidc_module_federation.crt

With passphrase:

    openssl rsa -in cert/oidc_module.key -passin pass:myPassPhrase -pubout -out cert/oidc_module.crt
    openssl rsa -in cert/oidc_module_federation.key -passin pass:myPassPhrase -pubout -out cert/oidc_module_federation.crt

If you use different file names or a passphrase, be sure to update these settings in the `module_oidc.php` configuration file.

### Enabling the module

To enable the module, add `'oidc' => true` to the list of enabled modules in the main SimpleSAMLphp 
configuration file, `config/config.php`:

    'module.enable' => [
        'exampleauth' => false,
        'core' => true,
        'admin' => true,
        'saml' => true,
        // enable oidc module
        'oidc' => true,
    ],

After enabling the module, you must run the database migrations.

### Run database migrations

The module includes default SQL migrations that set up the necessary tables in your configured database. 
To run these migrations:

Option 1: Through the web interface - Navigate to the SimpleSAMLphp administration area, go to 
`OIDC` > `Database Migrations`, and click the available button.

Option 2: Through the command line (recommended for automated/scripted deployments):

    php modules/oidc/bin/install.php

### Protocol Artifacts Caching

The configured database serves as the primary storage for protocol artifacts, such as access tokens, authorization
codes, refresh tokens, clients, and user data. In production environments, it is recommended to also set up caching
for these artifacts. The cache layer operates in front of the database, improving performance, particularly during
sudden surges of users attempting to authenticate. The implementation leverages the Symfony Cache component, allowing
the use of any compatible Symfony cache adapter. For more details on configuring the protocol cache, refer to the
module configuration file.

### Relying Party (RP) Administration

The module lets you manage (create, read, update and delete) approved RPs from the module user interface itself.

Once the database schema has been created, in the SimpleSAMLphp administration area go to `OIDC` >
`Client Registry`. 

Note that clients can be marked as confidential or public. If the client is not marked as confidential (it is public),
and is using Authorization Code flow, it will have to provide PKCE parameters during the flow.

Client ID and secret will be generated, and can be seen after the client creation by clicking on the 'show' button.

### Cron hook

In order to purge expired tokens, this module requires [cron module](https://simplesamlphp.org/docs/stable/cron:cron)
to be enabled and configured.

### Endpoint locations

Once you deploy the module, in the SimpleSAMLphp administration area go to `OIDC` and then select the
Protocol / Federation Settings page to see the available discovery URLs. These URLs can then be used to set up a
`.well-known` URLs (see below).

### Key rollover

The module supports defining additional (new) private / public key pair to be published on relevant JWKS endpoint
or contained in relevant JWKS property. In this way, you can "announce" new public key which can then be fetched
by RPs in order to prepare for the switch of the keys (until the switch of keys, all artifacts continue to be
signed with the "old" private key).

In this way, after RPs fetch new JWKS (JWKS with "old" and "new" key), you can do the switch of keys when you find
appropriate.

### Note when using Apache web server

If you are using Apache web server, you might encounter situations in which Apache strips of Authorization header
with Bearer scheme in HTTP requests, which is a known 'issue' (https://github.com/symfony/symfony/issues/19693). 
Although we handle this special situation, it has performance implications, so you should add one of the following
Apache configuration snippets to preserve Authorization header in requests:

```apacheconf
RewriteEngine On
RewriteCond %{HTTP:Authorization} .+
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
```
or
```apacheconf
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
```
Choose the one which works for you. If you don't set it, you'll get a warnings about this situation in your logs.

## Additional considerations
### Private scopes

This module support the basic OIDC scopes: openid, email, address, phone and profile.
However, you can add your own private scopes in the `module_oidc.php` config file, for example:

```php
<?php

$config = [
    \SimpleSAML\Module\oidc\ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES => [
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

You can change or extend this table in the `module_oidc.php` config file, like in example below. Note that translation
examples use friendly attribute names. If other attribute name format is used, adjust configuration accordingly. 

```php
<?php

$config = [
    \SimpleSAML\Module\oidc\ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE => [
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

Auth Proc processing has been tested with a variety of modules including ones that adjust attributes, log
and redirect for user interaction.

You can add Auth Proc filters in the 'authproc.oidc' config option in the same manner as described in the [Auth Proc 
documentation](https://simplesamlphp.org/docs/stable/simplesamlphp-authproc).

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
### Client registration permissions

You can allow users to register their own clients.
This is controlled through the `permissions` setting in `module_oidc.php`

Permissions let the module expose functionality to specific users. In the
below configuration, a user's eduPersonEntitlement attribute is examined.
If the user tries to do something that requires the `client` permission
(such as registering their own client) then they will need one of the
eduPersonEntitlements from the `client` permission array.

A permission can be disabled by commenting it out.

```php
     \SimpleSAML\Module\oidc\ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
        // Attribute to inspect to determine user's permissions
        'attribute' => 'eduPersonEntitlement',
        // Which entitlements allow for registering, editing, delete a client. OIDC clients are owned by the creator
        'client' => ['urn:example:oidc:manage:client'],
    ],
```

Users can visit the `https://example.com/simplesaml/module.php/oidc/clients/` to create and view their clients.

## OIDC Discovery Endpoint

The module offers an OpenID Connect Discovery endpoint at URL:

    https://yourserver/simplesaml/module.php/oidc/.well-known/openid-configuration

## OpenID Federation Configuration Endpoint

The module offers an OpenID Federation configuration endpoint at URL:

    https://yourserver/simplesaml/module.php/oidc/.well-known/openid-federation

### .well-known URLs

You can configure your web server (Apache, Nginx) in a way to serve the mentioned URLs in a '.well-known'
format. Below are some sample configurations for `openid-configuration`, but you can take the same approach for 
`openid-federation`.

#### nginx 
    location = /.well-known/openid-configuration {
        rewrite ^(.*)$ /simplesaml/module.php/oidc/.well-known/openid-configuration break;
        proxy_pass https://localhost;
    }

#### Apache

    RewriteEngine On
    RewriteRule ^/.well-known/openid-configuration(.*) /simplesaml/module.php/oidc/.well-known/openid-configuration$1 [PT]

## Using Docker

### With current git branch.

To explore the module using docker run the below command. This will run an SSP image, with the current oidc module
mounted in the container, along with some configuration files. Any code changes you make to your git checkout are
"live" in the container, allowing you to test and iterate different things.

```
docker run --name ssp-oidc-dev \
   --mount type=bind,source="$(pwd)",target=/var/simplesamlphp/staging-modules/oidc,readonly \
  -e STAGINGCOMPOSERREPOS=oidc \
  -e COMPOSER_REQUIRE="simplesamlphp/simplesamlphp-module-oidc:@dev" \
  -e SSP_ADMIN_PASSWORD=secret1 \
  --mount type=bind,source="$(pwd)/docker/ssp/module_oidc.php",target=/var/simplesamlphp/config/module_oidc.php,readonly \
  --mount type=bind,source="$(pwd)/docker/ssp/authsources.php",target=/var/simplesamlphp/config/authsources.php,readonly \
  --mount type=bind,source="$(pwd)/docker/ssp/config-override.php",target=/var/simplesamlphp/config/config-override.php,readonly \
  --mount type=bind,source="$(pwd)/docker/ssp/oidc_module.crt",target=/var/simplesamlphp/cert/oidc_module.crt,readonly \
  --mount type=bind,source="$(pwd)/docker/ssp/oidc_module.key",target=/var/simplesamlphp/cert/oidc_module.key,readonly \
  --mount type=bind,source="$(pwd)/docker/apache-override.cf",target=/etc/apache2/sites-enabled/ssp-override.cf,readonly \
   -p 443:443 cirrusid/simplesamlphp:v2.3.5
```

Visit https://localhost/simplesaml/ and confirm you get the default page.
Then navigate to [OIDC screen](https://localhost/simplesaml/module.php/oidc/install.php)
and you can add a client.

You may view the OIDC configuration endpoint at `https://localhost/.well-known/openid-configuration`

#### Local Testing with other DBs

To test local changes against another DB, such as Postgres, we need to:

* Create a docker network layer
* Run a DB container (and create a DB if one doesn't exist)
* Run SSP and use the DB container

```
# Create the network
docker network create ssp-oidc-test
```

```
# Run the db container
    docker run --name oidc-db \
      --network ssp-oidc-test \
      -e POSTGRES_PASSWORD=oidcpass \
      -p 25432:5432 \
      -d  postgres:15
```

And then use the `docker run` command from  `With current git branch` with the following additions

```
    -e DB.DSN="pgsql:host=oidc-db;dbname=postgres" \
    -e DB.USERNAME="postgres" \
    -e DB.PASSWORD="oidcpass" \
   --network ssp-oidc-test \

```

#### Testing AuthProc filters

To perform manual testing of authproc filters, enable the authprocs in `module_oidc.php` that set firstname, sn and performs
a redirect for preprod warning. This setup shows that an authproc can do a redirect and then processing resumes.
Once adjusted, run docker while change the `COMPOSER_REQUIRE` line to

    `-e COMPOSER_REQUIRE="simplesamlphp/simplesamlphp-module-oidc:@dev simplesamlphp/simplesamlphp-module-preprodwarning" \`

You can register a client from https://oidcdebugger.com/ to test.

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
