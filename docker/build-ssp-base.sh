#!/usr/bin/env bash
#
# Builds the SimpleSAMLphp base image the OP image is built FROM.
#
# Published cirrusid/simplesamlphp tags exist only for the SimpleSAMLphp releases someone built an
# image for, and the newest of those is older than the release this module requires, so the base
# image has to be built locally. The recipe installs SimpleSAMLphp with Composer, so any Composer
# version works: a released tag (v2.5.3.1) or a branch (dev-simplesamlphp-2.5).
#
# Usage: docker/build-ssp-base.sh [ssp-composer-version]
#
# The result is tagged ssp-base:<ssp-composer-version>, which is what docker/Dockerfile and
# docker/docker-compose.yml expect in SSP_IMAGE. See docs/4-oidc-docker.md.

set -euo pipefail

# Keep in step with the requirement in composer.json.
ssp_composer_version="${1:-v2.5.3.1}"

recipe_repository='https://github.com/cirrusidentity/docker-simplesamlphp.git'
# Pinned so the image is reproducible; bump deliberately.
recipe_commit='0bf3ae9df5c0'

# A Composer version is not always a usable Docker tag: a branch ref carries the branch name, and a
# branch name may contain a '/', which Docker reads as a registry path separator. Everything a tag
# may not hold becomes an underscore, so ssp-base:dev-feature_foo comes out of dev-feature/foo. The
# unsanitized value is what gets installed; only the tag is rewritten.
image="ssp-base:$(printf '%s' "$ssp_composer_version" | tr -c 'A-Za-z0-9_.-' '_')"

for command in docker git; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "$command is required but was not found on PATH." >&2
        exit 1
    fi
done

recipe_directory="$(mktemp -d)"
trap 'rm -rf "$recipe_directory"' EXIT

echo "Cloning the SimpleSAMLphp image recipe at $recipe_commit ..."
git clone --quiet "$recipe_repository" "$recipe_directory"
git -C "$recipe_directory" checkout --quiet "$recipe_commit"

echo "Building $image with SimpleSAMLphp $ssp_composer_version ..."
docker build "$recipe_directory/docker" \
    --build-arg "SSP_COMPOSER_VERSION=$ssp_composer_version" \
    -t "$image"

# Named rather than only implied, since a ref which had to be sanitized does not appear verbatim.
echo "Built $image. Pass it as SSP_IMAGE to build the OP on top of it."
