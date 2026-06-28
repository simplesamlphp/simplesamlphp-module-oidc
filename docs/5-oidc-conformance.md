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
git checkout release-v5.1.45
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

# Dynamic Client Registration (DCR)
conformance-suite/scripts/run-test-plan.py \
  --expected-failures-file ${OIDC_MODULE_FOLDER}/conformance-tests/dynamic-warnings.json \
  --expected-skips-file ${OIDC_MODULE_FOLDER}/conformance-tests/dynamic-skips.json \
  "oidcc-dynamic-certification-test-plan[response_type=code]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-dynamic-ci.json
```

### Dynamic Client Registration notes

In `dynamic_client` mode the
conformance suite registers its own clients by POSTing client metadata to the
`registration_endpoint` advertised in discovery — and updates/deletes them via
the Client Configuration Endpoint — so it exercises the module's DCR endpoint
(`RegistrationController`) directly. No static `client` blocks are needed in
`conformance-dynamic-ci.json`.

The module also supports Initial Access Token registration
(`DcrRegistrationAuthEnum::InitialAccessToken` plus `OPTION_DCR_INITIAL_ACCESS_TOKENS`),
but the official dynamic certification profile does not exercise that mode. To
test it manually, switch the OP to that mode and POST to the registration
endpoint with a configured token as an HTTP Bearer token.

#### Default scopes for scope-less DCR clients

`scope` is OPTIONAL in a registration request. When a **Dynamic** registration
omits it, the client is assigned the set configured by
`OPTION_DCR_DEFAULT_SCOPES`, which **defaults to all scopes the OP supports**
(including `offline_access`). This lets a scope-less dynamic client request any
supported scope, e.g. obtain a refresh token via `offline_access`. To restrict
this, set an explicit list in config. This applies to Dynamic registrations
only: manual (admin) and OpenID Federation automatic registrations still default
to `openid` only. An explicit but *unsupported* `scope` is not treated as
"omitted" — the unsupported values are dropped and the client ends up with
`openid` only (it does not receive the default set).

### Known non-passing tests in the dynamic plan

The DCR functionality passes. With the conformance image configuration, the whole
plan runs to a clean (exit 0) result: the only two non-passing tests are OP-wide
gaps unrelated to Dynamic Client Registration, recorded as expected failures in
`conformance-tests/dynamic-warnings.json` (condition-by-condition, so the runner
reports them as *expected*):

- **OP-wide gaps (not DCR):** `oidcc-userinfo-rs256` (signed/JWT UserInfo responses
  are not supported) and `oidcc-server-rotate-keys` (the OP does not rotate its
  signing keys on demand).

`conformance-tests/dynamic-skips.json` holds the genuinely optional tests the suite
itself skips: `oidcc-idtoken-unsigned` (needs `id_token_signed_response_alg=none`)
and the two `*-sector-*` tests (need `sector_identifier_uri`).

Tests that previously failed only because of the conformance suite's self-signed
TLS certificate — `oidcc-registration-jwks-uri`, `oidcc-request-uri-unsigned`,
`oidcc-request-uri-signed-rs256` and `oidcc-refresh-token-rp-key-rotation` — now
pass because the conformance image sets `OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS` to
disable TLS verification for the `openid` library's outbound fetches (see "HTTP
client options" in `config/module_oidc.php.dist`). `oidcc-refresh-token` passes
because scope-less dynamic clients are granted `offline_access` by default (see
"Default scopes for scope-less DCR clients") and the `refresh_token` grant
authenticates `private_key_jwt` clients the same way the `authorization_code` grant
does. `request_uri` by reference works because dynamically-registered `request_uris`
are now persisted and exact-matched at the authorization endpoint.

Because the plan is deterministic, the GitHub Actions step is a blocking gate (no
`continue-on-error`).

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

## Pushed Authorization Requests (PAR) and `request_uri`

The OpenID Foundation certification profiles run above only exercise PAR as
part of the FAPI 2.0 profile, which imposes many unrelated requirements and is
not a practical fit for validating PAR on this general-purpose OP. Instead, the
RFC 9126 (PAR) and related `request` / `request_uri` MUST-level requirements are
tracked, and mapped to the unit tests that cover them, in
`conformance-tests/rfc9126-par-compliance.md`. Keep that checklist in sync when
changing PAR or request-object behaviour.
