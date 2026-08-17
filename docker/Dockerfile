# Base SimpleSAMLphp image, built locally by docker/build-ssp-base.sh. No published
# cirrusid/simplesamlphp tag carries a SimpleSAMLphp new enough for this module, so there is nothing
# to default to: run that script first, or override this to point at another base image. See
# "Build the SimpleSAMLphp base image" in docs/4-oidc-docker.md.
ARG SSP_IMAGE="ssp-base:v2.5.3.1"
FROM ${SSP_IMAGE}

RUN apt-get update && apt-get --no-install-recommends install -y sqlite3
# Prepopulate the DB with items needed for testing
ADD docker/conformance.sql /tmp/
# Preload some clients
RUN sqlite3 /var/simplesamlphp/data/mydb.sq3  < /tmp/conformance.sql \
    && chown www-data /var/simplesamlphp/data/mydb.sq3 

# --build-arg OIDC_VERSION
ARG OIDC_VERSION="@dev"

ENV STAGINGCOMPOSERREPOS=oidc \
    COMPOSER_REQUIRE="simplesamlphp/simplesamlphp-module-oidc:$OIDC_VERSION"
ADD . /var/simplesamlphp/staging-modules/oidc

RUN /opt/simplesaml/staging-install.sh
RUN /opt/simplesaml/module-setup.sh
ADD docker/ssp/module_oidc.php /var/simplesamlphp/config/module_oidc.php
ADD docker/ssp/authsources.php /var/simplesamlphp/config/authsources.php
ADD docker/ssp/config-override.php /var/simplesamlphp/config/config-override.php
ADD docker/ssp/oidc_module.crt /var/simplesamlphp/cert/oidc_module.crt
ADD docker/ssp/oidc_module.key /var/simplesamlphp/cert/oidc_module.key
ADD docker/apache-override.cf /etc/apache2/sites-enabled/ssp-override.cf

RUN chown www-data /var/simplesamlphp/cert/oidc* \
    && chmod 660 /var/simplesamlphp/cert/oidc*
