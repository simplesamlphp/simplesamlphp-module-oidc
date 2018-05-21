# simplesamlphp-module-oidc
> A SimpleSAMLphp module adding support for the OpenID Connect protocol.

This module adds support for the OpenID Connect protocol through a SimpleSAMLphp module installable through Composer.

[![Build Status](https://travis-ci.org/rediris-es/simplesamlphp-module-oidc.svg?branch=master)](https://travis-ci.org/rediris-es/simplesamlphp-module-oidc) 
[![Coverage Status](https://coveralls.io/repos/github/rediris-es/simplesamlphp-module-oidc/badge.svg?branch=master)](https://coveralls.io/github/rediris-es/simplesamlphp-module-oidc?branch=master)
[![SimpleSAMLphp](https://img.shields.io/badge/simplesamlphp-1.15-red.svg)](https://simplesamlphp.org/)

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