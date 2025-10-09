# Installation

This guide walks you through installing, enabling, and preparing the OIDC
module in SimpleSAMLphp.

## 1. Install the module

Run:

```bash
composer require simplesamlphp/simplesamlphp-module-oidc
```

## 2. Configure the module

Copy the configuration template into your SimpleSAMLphp config directory
and review all options:

```bash
cp modules/oidc/config/module_oidc.php.dist config/module_oidc.php
```

## 3. Configure the database

The module uses SimpleSAMLphp's database feature to store access and
refresh tokens, user data, and other artifacts. Edit `config/config.php`
and ensure at least the following parameters are set:

```php
'database.dsn' => 'mysql:host=server;dbname=simplesamlphp;charset=utf8',
'database.username' => 'user',
'database.password' => 'password',
```

Note: SQLite, PostgreSQL, and MySQL are supported.

## 4. Create RSA key pairs

ID and Access tokens are signed JWTs. Create a public/private RSA key
pair for OIDC protocol operations. If you plan to use OpenID Federation,
create a separate key pair for federation operations.

Generate private keys without a passphrase:

```bash
openssl genrsa -out cert/oidc_module.key 3072
openssl genrsa -out cert/oidc_module_federation.key 3072
```

Generate private keys with a passphrase:

```bash
openssl genrsa -passout pass:myPassPhrase -out cert/oidc_module.key 3072
openssl genrsa -passout pass:myPassPhrase -out cert/oidc_module_federation.key 3072
```

Extract public keys:

Without passphrase:

```bash
openssl rsa -in cert/oidc_module.key -pubout -out cert/oidc_module.crt
openssl rsa -in cert/oidc_module_federation.key -pubout -out cert/oidc_module_federation.crt
```

With a passphrase:

```bash
openssl rsa -in cert/oidc_module.key -passin pass:myPassPhrase -pubout -out cert/oidc_module.crt
openssl rsa -in cert/oidc_module_federation.key -passin pass:myPassPhrase -pubout -out cert/oidc_module_federation.crt
```

If you use different file names or a passphrase, update
`config/module_oidc.php` accordingly.

## 5. Enable the module

Edit `config/config.php` and enable `oidc`:

```php
'module.enable' => [
    'exampleauth' => false,
    'core' => true,
    'admin' => true,
    'saml' => true,
    // enable oidc module
    'oidc' => true,
],
```

## 6. Run database migrations

Run the built-in migrations to create required tables.

Option A: Web UI

- Go to the admin area, then `OIDC` > `Database Migrations` and click the
  available button.

Option B: Command line

```bash
php modules/oidc/bin/install.php
```

## 7. Next steps

- Configure caches, endpoints, and other options:
  see [Configuration](configuration.md)
- Administer clients from the UI:
  see [Relying Party (RP) Administration](configuration.md#relying-party-rp-administration)
