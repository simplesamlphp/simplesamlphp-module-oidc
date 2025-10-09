# Using Docker

This document shows how to run and test the module with Docker.

- Run with the current git branch (live mount)
- Local testing with other DBs
- Testing AuthProc filters
- Build image for conformance tests
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
  -p 443:443 cirrusid/simplesamlphp:v2.3.5
```

Then visit:

- https://localhost/simplesaml/

The OIDC configuration endpoint is available at:

- https://localhost/.well-known/openid-configuration

## Local testing with other DBs

You can test it against another database such as PostgreSQL.

1) Create a Docker network:

```bash
docker network create ssp-oidc-test
```

2) Run a DB container:

```bash
docker run --name oidc-db \
  --network ssp-oidc-test \
  -e POSTGRES_PASSWORD=oidcpass \
  -p 25432:5432 \
  -d postgres:15
```

3) Run SSP (from the prior command) with these additions:

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

You can register a client from https://oidcdebugger.com/ to test.

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

Conformance tests are easier to run locally. See [Conformance](conformance.md).

## Docker Compose

Docker Compose runs multiple containers to ease testing. It builds an
image containing the OIDC module. You can remove `--build` to reuse an
existing container.

```bash
# Use current branch/git checkout. Composer installs local checkout
OIDC_VERSION=@dev docker-compose -f docker/docker-compose.yml --project-directory . up --build

# Use a specific module version
OIDC_VERSION=dev-master docker-compose -f docker/docker-compose.yml --project-directory . up --build
```

Visit the OP and verify a few clients exist:

- https://op.local.stack-dev.cirrusidentity.com/simplesaml/
