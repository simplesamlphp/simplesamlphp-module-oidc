# Overview

The OpenID foundation provides conformance tests. This is a guide to setting up and running
them against this SSP module.

# Running Hosted Tests

OpenID foundation hosts the conformance testing software and allows you to test it against your server.
In this situation your OIDC OP must be accessible to the public internet.

## Deploy SSP OIDC Image

The docker image created in the README.md is designed to be used for running the conformance tests.
It contains an sqlite database pre-populated with data that can be used for these tests.
Build and run the image some where.

