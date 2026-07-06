# OIDC Module - Using Docker

This document shows how to run and test the module with Docker.

- Run with the current git branch (live mount)
- Local testing with other DBs
- Testing AuthProc filters
- Build image for conformance tests
- Build against an unreleased SimpleSAMLphp version
- Docker Compose

## Run with the current git branch (live mount)

Run an SSP image with the current OIDC module mounted read-only. Changes
in your checkout are reflected live in the container.

```bash
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
  -p 443:443 cirrusid/simplesamlphp:v2.4.4
```

Then visit:

- [https://localhost/simplesaml/](https://localhost/simplesaml/)

The OIDC configuration endpoint is available at:

- [https://localhost/.well-known/openid-configuration](https://localhost/.well-known/openid-configuration)

## Local testing with other DBs

You can test it against another database such as PostgreSQL.

1 - Create a Docker network:

```bash
docker network create ssp-oidc-test
```

2 - Run a DB container:

```bash
docker run --name oidc-db \
  --network ssp-oidc-test \
  -e POSTGRES_PASSWORD=oidcpass \
  -p 25432:5432 \
  -d postgres:15
```

3 - Run SSP (from the prior command) with these additions:

```bash
-e DB.DSN="pgsql:host=oidc-db;dbname=postgres" \
-e DB.USERNAME="postgres" \
-e DB.PASSWORD="oidcpass" \
--network ssp-oidc-test \
```

## Testing AuthProc filters

Enable the example AuthProc filters in `module_oidc.php` that set
`firstname` and `sn` and configure the preprod warning filter. This shows
that an authproc can redirect and processing resumes.

When running Docker, adjust `COMPOSER_REQUIRE` to include the module:

```text
-e "COMPOSER_REQUIRE=simplesamlphp/simplesamlphp-module-oidc:@dev \
 simplesamlphp/simplesamlphp-module-preprodwarning"
```

You can register a client from
[https://oidcdebugger.com/](https://oidcdebugger.com/) to test.

## Build image for conformance tests

Build an image that contains a pre-configured sqlite database.

```bash
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
IMAGE_TAG=$(tr '/' '_' <<< "$GIT_BRANCH")

docker build -t "simplesamlphp/simplesamlphp-oidc:dev-$IMAGE_TAG" \
  --build-arg OIDC_VERSION=dev-${GIT_BRANCH} \
  -f docker/Dockerfile .

docker run --name ssp-oidc-dev-image \
  -e SSP_ADMIN_PASSWORD=secret1 \
  -p 443:443 simplesamlphp/simplesamlphp-oidc:dev-$IMAGE_TAG
```

Publish the image where you can retrieve it. Example:

```bash
docker tag "simplesamlphp/simplesamlphp-oidc:dev-$IMAGE_TAG" \
  "cirrusid/simplesamlphp-oidc:dev-$IMAGE_TAG"

docker push "cirrusid/simplesamlphp-oidc:dev-$IMAGE_TAG"
```

The DB is not on a shared volume. Changes are lost if the container
restarts. Backup example:

```bash
docker exec ssp-oidc-dev-image sqlite3 /var/simplesamlphp/data/mydb.sq3 '.dump' \
  > docker/conformance.sql
```

Conformance tests are easier to run locally. See [Conformance](5-oidc-conformance.md).

## Build against an unreleased SimpleSAMLphp version

The OP image is built `FROM` a SimpleSAMLphp base image, selected with the
`SSP_IMAGE` build argument (default: a published `cirrusid/simplesamlphp`
release tag). Published tags only exist for SimpleSAMLphp *releases*, so to run
against an unreleased SimpleSAMLphp branch (or any specific ref) you first build
a base image from that ref and then point `SSP_IMAGE` at it.

> During v7 development the module depends on the unreleased `simplesamlphp-2.5`
> branch (it uses `\SimpleSAML\Locale\Language::getAvailableLanguages()`, added
> there for the `ui_locales` support). Until a SimpleSAMLphp release contains it,
> the OP image must be built from that branch, otherwise the discovery endpoint
> fails.

The [cirrusid/simplesamlphp image](https://github.com/cirrusidentity/docker-simplesamlphp)
installs SimpleSAMLphp with Composer when given an `SSP_COMPOSER_VERSION` build
argument, which accepts any Composer version — a branch (`dev-<branch>`) or a
tag (`v2.5.2`):

```bash
# 1. Build a SimpleSAMLphp base image from the desired ref (branch or tag).
git clone https://github.com/cirrusidentity/docker-simplesamlphp.git
docker build docker-simplesamlphp/docker \
  --build-arg SSP_COMPOSER_VERSION=dev-simplesamlphp-2.5 \
  -t ssp-base:dev-simplesamlphp-2.5

# 2. Build and run the OP on top of it. For the docker/Dockerfile-based builds
#    (Docker Compose below and the conformance image above) set SSP_IMAGE:
SSP_IMAGE=ssp-base:dev-simplesamlphp-2.5 OIDC_VERSION=@dev \
  docker compose -f docker/docker-compose.yml --project-directory . up --build
```

For the live-mount `docker run` example above, use the built base image name
(`ssp-base:dev-simplesamlphp-2.5`) directly in place of
`cirrusid/simplesamlphp:...`. This is exactly what the GitHub Actions conformance
job does: it builds the base image from `matrix.ssp-composer-version` and passes
it as `SSP_IMAGE`.

## Docker Compose

Docker Compose runs multiple containers to ease testing. It builds an
image containing the OIDC module. You can remove `--build` to reuse an
existing container. The SimpleSAMLphp base image defaults to a published
`cirrusid/simplesamlphp` release tag; override it with `SSP_IMAGE` to run
against a different base (see "Build against an unreleased SimpleSAMLphp
version" above).

```bash
# Use current branch/git checkout. Composer installs local checkout
OIDC_VERSION=@dev docker compose -f docker/docker-compose.yml --project-directory . up --build

# Use a specific module version
OIDC_VERSION=dev-master docker compose -f docker/docker-compose.yml --project-directory . up --build
```

Visit the OP and verify a few clients exist:

- [https://op.local.stack-dev.cirrusidentity.com/simplesaml/](https://op.local.stack-dev.cirrusidentity.com/simplesaml/)
