# OIDC Module - Installation

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

The module uses SimpleSAMLphp's database feature to store Access and
Refresh tokens, user data, and other artifacts. Edit `config/config.php`
and ensure at least the following parameters are set:

```php
'database.dsn' => 'mysql:host=server;dbname=simplesamlphp;charset=utf8',
'database.username' => 'user',
'database.password' => 'password',
```

Note: SQLite, PostgreSQL, and MySQL are supported.

## 4. Create signature key pairs

In order to sign JWS artifacts (ID Tokens, Entity Statements, Verifiable
Credentials, etc.), you must create a public / private key pair for each
signature algorithm that you want to support. You should use different
keys for protocol (Connect), Federation and Verifiable Credential (VCI)
operations. You must have at least one algorithm / key-pair for protocol
(Connect), and for Federation and VCI if you use those features.

### RSA key pair generation, for `RS256/384/512` and `PS256/384/512` algorithms

Generate private keys without a password:

```bash
openssl genrsa -out cert/oidc_module_connect_rsa_01.key 3072
openssl genrsa -out cert/oidc_module_federation_rsa_01.key 3072
openssl genrsa -out cert/oidc_module_vci_rsa_01.key 3072
```

Generate private keys with a password:

```bash
openssl genrsa -passout pass:somePassword -out cert/oidc_module_connect_rsa_01.key 3072
openssl genrsa -passout pass:somePassword -out cert/oidc_module_federation_rsa_01.key 3072
openssl genrsa -passout pass:somePassword -out cert/oidc_module_vci_rsa_01.key 3072
```

Extract public keys:

Without password:

```bash
openssl rsa -in cert/oidc_module_connect_rsa_01.key -pubout -out cert/oidc_module_connect_rsa_01.pub
openssl rsa -in cert/oidc_module_federation_rsa_01.key -pubout -out cert/oidc_module_federation_rsa_01.pub
openssl rsa -in cert/oidc_module_vci_rsa_01.key -pubout -out cert/oidc_module_vci_rsa_01.pub
```

With a password:

```bash
openssl rsa -in cert/oidc_module_connect_rsa_01.key -passin pass:somePassword -pubout -out cert/oidc_module_connect_rsa_01.pub
openssl rsa -in cert/oidc_module_federation_rsa_01.key -passin pass:somePassword -pubout -out cert/oidc_module_federation_rsa_01.pub
openssl rsa -in cert/oidc_module_vci_rsa_01.key -passin pass:somePassword -pubout -out cert/oidc_module_vci_rsa_01.pub
```

Enter algorithm, key file names, and a password (if used) in `config/module_oidc.php` accordingly.

### EC key pair generation, per curve for different algorithms

If you prefer to use Elliptic Curve Cryptography (ECC) instead of RSA.

Generate private EC P‑256 keys without a password, usable for `ES256` algorithm:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out cert/oidc_module_connect_ec_p256_01.key
openssl ecparam -genkey -name prime256v1 -noout -out cert/oidc_module_federation_ec_p256_01.key
openssl ecparam -genkey -name prime256v1 -noout -out cert/oidc_module_vci_ec_p256_01.key
```

Generate private EC P‑256 keys with a password, usable for `ES256` algorithm:

```bash
openssl ecparam -genkey -name prime256v1 | openssl ec -AES-128-CBC -passout pass:somePassword -out cert/oidc_module_connect_ec_p256_01.key
openssl ecparam -genkey -name prime256v1 | openssl ec -AES-128-CBC -passout pass:somePassword -out cert/oidc_module_federation_ec_p256_01.key
openssl ecparam -genkey -name prime256v1 | openssl ec -AES-128-CBC -passout pass:somePassword -out cert/oidc_module_vci_ec_p256_01.key
```

Extract public keys:

Without password:

```bash
openssl ec -in cert/oidc_module_connect_ec_p256_01.key -pubout -out cert/oidc_module_connect_ec_p256_01.pub
openssl ec -in cert/oidc_module_federation_ec_p256_01.key -pubout -out cert/oidc_module_federation_ec_p256_01.pub
openssl ec -in cert/oidc_module_vci_ec_p256_01.key -pubout -out cert/oidc_module_vci_ec_p256_01.pub
```

With a password:

```bash
openssl ec -in cert/oidc_module_connect_ec_p256_01.key -passin pass:somePassword -pubout -out cert/oidc_module_connect_ec_p256_01.pub
openssl ec -in cert/oidc_module_federation_ec_p256_01.key -passin pass:somePassword -pubout -out cert/oidc_module_federation_ec_p256_01.pub
openssl ec -in cert/oidc_module_vci_ec_p256_01.key -passin pass:somePassword -pubout -out cert/oidc_module_vci_ec_p256_01.pub
```

For other curves, replace the `-name` option value depending on which
algorithm you want to support:
- `-name secp384r1`: usable for `ES384` algorithm
- `-name secp521r1`: usable for `ES512` algorithm

Enter algorithm, key file names, and a password (if used) in `config/module_oidc.php` accordingly.

### Ed25519 key pair generation, for `EdDSA` algorithm

Generate private keys without a password:

```bash
openssl genpkey -algorithm ED25519 -out cert/oidc_module_connect_ed25519_01.key
openssl genpkey -algorithm ED25519 -out cert/oidc_module_federation_ed25519_01.key
openssl genpkey -algorithm ED25519 -out cert/oidc_module_vci_ed25519_01.key
```

Generate private keys with a password:

```bash
openssl genpkey -algorithm ED25519 -AES-128-CBC -pass pass:somePassword -out cert/oidc_module_connect_ed25519_01.key
openssl genpkey -algorithm ED25519 -AES-128-CBC -pass pass:somePassword -out cert/oidc_module_federation_ed25519_01.key
openssl genpkey -algorithm ED25519 -AES-128-CBC -pass pass:somePassword -out cert/oidc_module_vci_ed25519_01.key
```

Extract public keys:

Without password:

```bash
openssl pkey -in cert/oidc_module_connect_ed25519_01.key -pubout -out cert/oidc_module_connect_ed25519_01.pub
openssl pkey -in cert/oidc_module_federation_ed25519_01.key -pubout -out cert/oidc_module_federation_ed25519_01.pub
openssl pkey -in cert/oidc_module_vci_ed25519_01.key -pubout -out cert/oidc_module_vci_ed25519_01.pub
```

With a password:

```bash
openssl pkey -in cert/oidc_module_connect_ed25519_01.key -passin pass:somePassword -pubout -out cert/oidc_module_connect_ed25519_01.pub
openssl pkey -in cert/oidc_module_federation_ed25519_01.key -passin pass:somePassword -pubout -out cert/oidc_module_federation_ed25519_01.pub
openssl pkey -in cert/oidc_module_vci_ed25519_01.key -passin pass:somePassword -pubout -out cert/oidc_module_vci_ed25519_01.pub
```

Enter algorithm, key file names, and a password (if used) in `config/module_oidc.php` accordingly.

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
  see [Configuration](3-oidc-configuration.md)
- Administer clients from the UI:
  see [Relying Party (RP) Administration](3-oidc-configuration.md#relying-party-rp-administration)
