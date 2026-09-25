#!/usr/bin/env bash
#
# Runs the proxied introspection harness: builds its image, starts its nodes, runs the tests in
# tests/ProxiedIntrospectionHarness against them, and removes everything again, the harness PKI included. On a
# failure, the containers' logs are printed.
#
# Usage: docker/proxied-introspection-harness/run.sh [--keep] [PHPUnit arguments ...]
#
#   --keep  Leaves the nodes running afterwards, to look at or to run the tests again with
#           docker compose -f docker/proxied-introspection-harness/docker-compose.yml --project-directory . \
#             run --rm runner
#
# Needs the SimpleSAMLphp base image (docker/build-ssp-base.sh) and the checkout's own dependencies (composer install):
# the tests run from the checkout. See "Proxied introspection harness" in docs/4-oidc-docker.md.

set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")/../.."

compose=(docker compose -f docker/proxied-introspection-harness/docker-compose.yml --project-directory .)

keep=false
if [ "${1:-}" = --keep ]; then
    keep=true
    shift
fi

if [ ! -f vendor/autoload.php ]; then
    echo 'The tests run from the checkout: run "composer install" first.' >&2
    exit 1
fi

# Whatever failed - the PKI, a node's start, a healthcheck, the tests - the logs are printed before anything is
# removed, and the exit status is the one of the failure.
finish() {
    local status=$?

    if [ "$status" -ne 0 ]; then
        echo "The harness failed (exit status $status); its containers logged:" >&2
        "${compose[@]}" logs --no-color >&2 || true
    fi

    if [ "$keep" = false ]; then
        "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi

    exit "$status"
}
trap finish EXIT

"${compose[@]}" up --build --detach --wait
"${compose[@]}" run --rm runner "$@"
