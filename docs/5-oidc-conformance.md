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
git checkout release-v5.3.1
MAVEN_CACHE=./m2 docker compose -f builder-compose.yml run builder
docker compose up
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
containers can communicate. See the "Docker Compose" section in
[Using Docker](4-oidc-docker.md) for details.

The OP image is built on a SimpleSAMLphp base image, which has to be built
locally first with `./docker/build-ssp-base.sh` — no published base image
carries a SimpleSAMLphp new enough for this module. See "Build the SimpleSAMLphp
base image" in [Using Docker](4-oidc-docker.md). The GitHub Actions conformance
job does this automatically: it runs the same script for the SimpleSAMLphp ref
in its matrix (`ssp-composer-version`) and passes the result to the OP build as
`SSP_IMAGE`.

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

# Implicit profile (only with the implicit grant enabled, which is the default;
# see enabled_grant_types in the configuration guide)
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

# OpenID4VCI issuer (see "OpenID4VCI issuer plan" below)
conformance-suite/scripts/run-test-plan.py \
  --expected-failures-file ${OIDC_MODULE_FOLDER}/conformance-tests/vci-issuer-warnings.json \
  --expected-skips-file ${OIDC_MODULE_FOLDER}/conformance-tests/vci-issuer-skips.json \
  "oid4vci-1_0-issuer-test-plan[sender_constrain=dpop][client_auth_type=private_key_jwt][credential_format=sd_jwt_vc][vci_authorization_code_flow_variant=wallet_initiated][authorization_request_type=simple][openid=plain_oauth][fapi_request_method=unsigned][vci_grant_type=authorization_code][vci_credential_encryption=plain][fapi_profile=vci][fapi_response_mode=plain_response]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-vci-issuer.json

# OpenID4VCI issuer, flows started by a Credential Offer: keep the offer driver
# running in the background for the length of each run (it gives up after an hour)
python3 ${OIDC_MODULE_FOLDER}/conformance-tests/vci-offer-driver.py &
conformance-suite/scripts/run-test-plan.py \
  --expected-failures-file "${OIDC_MODULE_FOLDER}/conformance-tests/vci-issuer-warnings.json|${OIDC_MODULE_FOLDER}/conformance-tests/vci-issuer-offer-warnings.json" \
  --expected-skips-file ${OIDC_MODULE_FOLDER}/conformance-tests/vci-issuer-skips.json \
  "oid4vci-1_0-issuer-test-plan[sender_constrain=dpop][client_auth_type=private_key_jwt][credential_format=sd_jwt_vc][vci_authorization_code_flow_variant=issuer_initiated][authorization_request_type=rar][openid=plain_oauth][fapi_request_method=signed_non_repudiation][vci_grant_type=authorization_code][vci_credential_encryption=plain][fapi_profile=vci][fapi_response_mode=plain_response]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-vci-issuer.json
kill %1

python3 ${OIDC_MODULE_FOLDER}/conformance-tests/vci-offer-driver.py --use-tx-code &
conformance-suite/scripts/run-test-plan.py \
  --expected-failures-file ${OIDC_MODULE_FOLDER}/conformance-tests/vci-issuer-warnings.json \
  --expected-skips-file ${OIDC_MODULE_FOLDER}/conformance-tests/vci-issuer-skips.json \
  "oid4vci-1_0-issuer-test-plan[sender_constrain=dpop][client_auth_type=private_key_jwt][credential_format=sd_jwt_vc][vci_authorization_code_flow_variant=issuer_initiated][authorization_request_type=simple][openid=plain_oauth][fapi_request_method=unsigned][vci_grant_type=pre_authorization_code][vci_credential_encryption=plain][fapi_profile=vci][fapi_response_mode=plain_response]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-vci-issuer.json
kill %1
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
(including `offline_access`, while the `refresh_token` grant is enabled). This
lets a scope-less dynamic client request any supported scope, e.g. obtain a
refresh token via `offline_access`. To restrict
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
[Using Docker](4-oidc-docker.md)) and the conformance test image first.

## Run hosted tests

The OpenID Foundation hosts the conformance testing software. Your OIDC
OP must be publicly accessible on the internet.

### Deploy SSP OIDC image

Use the docker image described in [Using Docker](4-oidc-docker.md). It contains
a SQLite DB pre-populated with data for the tests. Build and run the image.

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
changing PAR or request-object behaviour. The OpenID4VCI issuer plan below sends
its authorization requests through PAR, so CI exercises the endpoint on that
flow, but the plan is no substitute for the checklist.

## OpenID4VCI issuer plan

CI also runs the OpenID Foundation's OpenID4VCI 1.0 issuer test plan,
`oid4vci-1_0-issuer-test-plan`. At the suite release CI uses (`release-v5.3.1`)
the suite labels this plan alpha and outside its certification programme:
certification goes through the HAIP issuer plan, which needs client
attestation, and this module does not support client attestation. A passing run
is a test result, not a certification.

The runs use the two clients seeded by `docker/conformance-vci.sql` and the suite
configuration in `conformance-tests/conformance-vci-issuer.json`. CI runs the plan
three times, over these flows:

- `vci_grant_type=authorization_code`,
  `vci_authorization_code_flow_variant=wallet_initiated`,
  `authorization_request_type=simple` and `fapi_request_method=unsigned`: the
  wallet starts the flow itself and asks for the credential by its scope,
  through PAR.
- `vci_grant_type=authorization_code`,
  `vci_authorization_code_flow_variant=issuer_initiated`,
  `authorization_request_type=rar` and
  `fapi_request_method=signed_non_repudiation`: the flow starts from a
  Credential Offer, the wallet asks for the credential through
  `authorization_details`, and the authorization request is a signed Request
  Object, pushed through PAR.
- `vci_grant_type=pre_authorization_code` with
  `vci_authorization_code_flow_variant=issuer_initiated`: a Credential Offer
  carrying a pre-authorized code and a transaction code.

In an offer flow each test waits for the issuer to hand it a Credential Offer,
and for a pre-authorized code also the transaction code, which the suite's plan
runner does not do. `conformance-tests/vci-offer-driver.py` stands in for that:
run in the background for the length of the run, it gets each offer from the
OP's [credential offer API](8-api.md#credential-offer) and hands it to the
waiting test. The OP mails the transaction code to the user, and the driver reads
it from the Mailpit container of the Docker stack, which catches the OP's mail.

All three runs share these variants:

- `credential_format=sd_jwt_vc`: the conformance image's `dc+sd-jwt` credential
  configuration, `ResearchAndScholarshipCredentialDcSdJwt`.
- `client_auth_type=private_key_jwt`: the only one of the plan's client
  authentication methods this module supports.
- `sender_constrain=dpop`: the plan offers only DPoP and mTLS, and the module
  supports DPoP (RFC 9449). The suite sends a DPoP proof to the token endpoint,
  gets a DPoP-bound access token (`token_type` `DPoP`), and calls the credential
  endpoint under the `DPoP` scheme with a proof carrying the token's hash. The
  conformance image requires a proof for credential issuance
  (`vci_require_dpop`), so every token request the plan makes has to carry one.
  The plan's one DPoP refusal check, in the multiple-clients test, presents the
  second client's access token with a proof by the first client's key and
  expects a 4xx answer (the module answers 401 `invalid_token`); in the offer
  run the test stops before reaching it, as described below. The plan sends no
  `dpop_jkt`, so code binding and the module's other DPoP refusals rest on its
  own unit tests.
- `fapi_profile=vci` (not `vci_haip`) and `vci_credential_encryption=plain`.
  The `openid` and `fapi_response_mode` variants do not apply to this profile.

Every test which runs passes, apart from the checks
`conformance-tests/vci-issuer-warnings.json` records as expected failures. One
applies to every run: the signature of the Status List Token. The conformance image turns Token Status
Lists on, so each credential carries a `status` claim, and the suite fetches the
token it points at, parses it, reads the credential's status from it and checks
its content type. In the batch test it also checks that the credentials of a
batch do not each point at a list of their own, and that their indices are
unpredictable. The signature is what it can not check. The token names its key
the way the credential does, by the same `did:jwk` `kid`, which is what the
Token Status List draft recommends when the credential issuer also issues the
status (draft 21, section 11.3). Outside HAIP, however, the suite verifies a
Status List Token only against a `jwk` embedded in its header or the server's
JWKS, and it fetches that key set only for OpenID Connect or JARM, so here it
has no key to verify with.

Two more apply to the offer run only, and are recorded apart from the others, in
`conformance-tests/vci-issuer-offer-warnings.json`, since the runner fails on an
expected failure which no test of its run produced:

- The multiple-clients test. At `release-v5.3.1` the suite sends the second
  client to PAR with the issuer state of the first client's offer. The module
  redeems an offer once, when its code is exchanged for an access token, so the
  second client's request is refused. The suite's `master` has the second client
  wait for an offer of its own; the entry goes once a release CI uses carries
  that.
- The unknown credential configuration test, under
  `authorization_request_type=rar`. With `authorization_details` the token
  response returns `credential_identifiers`, and OpenID4VCI 1.0 section 8.2 then
  requires `credential_identifier` and does not allow
  `credential_configuration_id`. The test sends an unknown
  `credential_configuration_id` alone and expects
  `unknown_credential_configuration`; the module answers
  `invalid_credential_request`, the code section 8.3.1.2 gives a request missing
  a required parameter or carrying one it may not.

The suite skips three tests, each for an optional feature the module does not
offer, and `conformance-tests/vci-issuer-skips.json` lists them: signed
credential issuer metadata, key attestations, and credential response
encryption. The GitHub Actions step is a blocking gate.

The plan's additional-requests test also checks the OP's TLS configuration. The
conformance image restricts TLS 1.2 to the four cipher suites RFC 9325 (BCP 195)
section 4.2 recommends, in `docker/apache-override.cf`; Apache's default list
also offers CBC suites, which the suite warns about.

What the run leaves out:

- Combinations of the variants beyond the three runs, such as
  `authorization_details` in a wallet-initiated flow or an unsigned request
  with an offer.
- The W3C credential formats (`jwt_vc_json`, `vc+sd-jwt`). The plan tests only
  `dc+sd-jwt` and `mso_mdoc`.
- Revocation and suspension. The plan reads only the status of credentials it
  has just been issued, so it never sees one which is not valid.
- The DIIP profile, for which no conformance suite exists. What the module claims
  there is a self-assessment against the specification text rather than a test
  result, and it is backed by unit tests instead. The claim and the roles it
  covers are in [OIDC Module](1-oidc.md#note-on-the-diip-profile); the readings
  this module makes of individual profile requirements are in
  [Configuration](3-oidc-configuration.md#three-interpretations-this-module-makes).
