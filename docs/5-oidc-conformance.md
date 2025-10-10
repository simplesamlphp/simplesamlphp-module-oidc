# OIDC Module - OpenID Conformance

This guide summarizes how to run the OpenID Foundation conformance tests
against this module, both locally and using the hosted service.

- Run conformance tests locally
- Run hosted tests

## Run conformance tests locally

This approach is best when you want to test changes without deploying.

### Run conformance images

Clone, build, and run the conformance test suite:

```bash
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
git checkout release-v5.1.35
MAVEN_CACHE=./m2 docker-compose -f builder-compose.yml run builder
docker-compose up
```

This starts the Java conformance app and a MongoDB server. Then:

- Visit [https://localhost:8443/](https://localhost:8443/)
- Create a new plan:
  "OpenID Connect Core: Basic Certification Profile Authorization server test"
- Click the JSON tab and paste
  `conformance-tests/conformance-basic-local.json` from this repo.

Next, run your SSP OIDC image.

### Run SSP

Run SSP with OIDC on the same Docker network as the conformance tests so
containers can communicate. See the "Docker Compose" section in the
README for details.

### Run conformance tests (interactive)

The tests are interactive and will ask you to authenticate. Some tests
require clearing cookies to confirm a scenario; others require existing
session cookies. You may be redirected to
`https://localhost.emobix.co.uk:8443/` (the Java app). Accept SSL
warnings as needed.

### Run automated tests

Once manual tests pass, you can
[automate the browser portion](https://gitlab.com/openid/conformance-suite/-/wikis/Design/BrowserControl).

From the `simplesamlphp-module-oidc` directory:

```bash
# Adjust to your conformance-suite installation path
OIDC_MODULE_FOLDER=.

# Basic profile
conformance-suite/scripts/run-test-plan.py \
  --expected-failures-file ${OIDC_MODULE_FOLDER}/conformance-tests/basic-warnings.json \
  --expected-skips-file ${OIDC_MODULE_FOLDER}/conformance-tests/basic-skips.json \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-basic-ci.json

# Implicit profile
conformance-suite/scripts/run-test-plan.py \
  --expected-failures-file ${OIDC_MODULE_FOLDER}/conformance-tests/implicit-warnings.json \
  --expected-skips-file ${OIDC_MODULE_FOLDER}/conformance-tests/implicit-skips.json \
  "oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-implicit-ci.json

# RP initiated back-channel logout
conformance-suite/scripts/run-test-plan.py \
  "oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-back-channel-logout-ci.json

# RP initiated logout
conformance-suite/scripts/run-test-plan.py \
  "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-rp-initiated-logout-ci.json
```

Prerequisites: run the docker deploy image for conformance tests (see
README) and the conformance test image first.

## Run hosted tests

The OpenID Foundation hosts the conformance testing software. Your OIDC
OP must be publicly accessible on the internet.

### Deploy SSP OIDC image

Use the docker image described in the README. It contains a SQLite DB
pre-populated with data for the tests. Build and run the image.

### Register and create conformance tests

Visit [https://openid.net/certification/instructions/](https://openid.net/certification/instructions/).

Use the `json` configs under `conformance-tests` to configure your cloud
instances. Update `discoveryUrl` to the deployed location. Adjust `alias`
if it conflicts with existing test suites (it is used in redirect URIs).
