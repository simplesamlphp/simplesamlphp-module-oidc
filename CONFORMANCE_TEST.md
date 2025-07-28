# Overview

The OpenID foundation provides conformance tests. This is a guide to setting up and running
them against this SSP module.

# Running Conformance Tests Locally

This approach is best when you want to test changes without having to deploy your project

## Run Conformance Images

Clone the conformance test git repo, build the software and run it.

```bash
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
git checkout release-v5.1.35
MAVEN_CACHE=./m2 docker-compose -f builder-compose.yml run builder
docker-compose up
```

This will start up the Java conformance app and a MongoDB server. You'll need to configure a test.

Visit https://localhost:8443/ and "Create a new plan".
The Test Plan should be "OpenID Connect Core: Basic Certification Profile Authorization server test"
which is under "Test an OpenID Provider / Authorization Server".

Then click on the JSON tab and enter the JSON from file `conformance-tests/conformance-basic-local.json`.
This file contains several clients and a OIDC discovery config for running against a local SSP OIDC

You'll need to get your OIDC SSP image running next

## Run SSP

You'll need to run SSP with OIDC on the same docker network as the compliance tests, so they are able to communicate.

See "Docker Compose" section of the main README.

## Run Conformance Tests

The conformance tests are interactive to make you authenticate. Some of the tests require you to clear cookies to
confirm certain test scenarios, while others require you to have session cookies to test the RP signaling to the
OP that the user should reauthenticate. The tests may also redirect you to https://localhost.emobix.co.uk:8443/
which will resolve to the conformance Java container. You'll need to accept any SSL connection warnings.

## Run automated tests

Eventually these test can have
[the browser portion automated](https://gitlab.com/openid/conformance-suite/-/wikis/Design/BrowserControl)
though the Conformance tests authors recommend getting them all to pass first.

To run basic profile test, launch this command in console inside `simplesamlphp-module-oidc` directory:

```shell
# Run run-test-plan.py script inside conformance-suite/scripts
# Change the relative path to your conformance-suite installation
# conformance-basic-ci.json contains clients, and browser interactions for automating various tests
# Lines like "oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
#    indicate the conformance plan to run, and any variants (parameters) are passed in []

OIDC_MODULE_FOLDER=.  # path to your checkout of the OIDC module
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

# RP Initiated back channel
conformance-suite/scripts/run-test-plan.py \
  "oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-back-channel-logout-ci.json

conformance-suite/scripts/run-test-plan.py \
  "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" \
  ${OIDC_MODULE_FOLDER}/conformance-tests/conformance-rp-initiated-logout-ci.json
```



As prerequisites, you need to run first the docker deploy image for conformance test described in [README.md](README.md)
and the conformance test image.

# Running Hosted Tests

OpenID foundation hosts the conformance testing software and allows you to test it against your server.
In this situation your OIDC OP must be accessible to the public internet.

## Deploy SSP OIDC Image

The docker image created in the README.md is designed to be used for running the conformance tests.
It contains a sqlite database pre-populated with data that can be used for these tests.
Build and run the image somewhere.

## Register and Create Conformance Tests

Visit https://openid.net/certification/instructions/
You can use the `json` deployment configurations under `conformance-tests` to configure your cloud instances. Update
your `discoveryUrl` to reflect the location you deployed SSP. You may also need to adjust `alias` since that is used
in all client redirect URIs and may conflict with existing test suites.

