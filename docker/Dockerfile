# Base SimpleSAMLphp image, built locally by docker/build-ssp-base.sh. No published
# cirrusid/simplesamlphp tag carries a SimpleSAMLphp new enough for this module, so there is nothing
# to default to: run that script first, or override this to point at another base image. See
# "Build the SimpleSAMLphp base image" in docs/4-oidc-docker.md.
ARG SSP_IMAGE="ssp-base:v2.5.3.1"
FROM ${SSP_IMAGE}

RUN apt-get update && apt-get --no-install-recommends install -y sqlite3
# Prepopulate the DB with items needed for testing
ADD docker/conformance.sql /tmp/
ADD docker/conformance-vci.sql /tmp/
# Preload some clients
RUN sqlite3 /var/simplesamlphp/data/mydb.sq3  < /tmp/conformance.sql \
    && sqlite3 /var/simplesamlphp/data/mydb.sq3 < /tmp/conformance-vci.sql \
    && chown www-data /var/simplesamlphp/data/mydb.sq3

# --build-arg OIDC_VERSION
ARG OIDC_VERSION="@dev"

ENV STAGINGCOMPOSERREPOS=oidc \
    COMPOSER_REQUIRE="simplesamlphp/simplesamlphp-module-oidc:$OIDC_VERSION"
ADD . /var/simplesamlphp/staging-modules/oidc

RUN git config --global --add safe.directory '*'
RUN /opt/simplesaml/staging-install.sh
RUN /opt/simplesaml/module-setup.sh
ADD docker/ssp/module_oidc.php /var/simplesamlphp/config/module_oidc.php
ADD docker/ssp/authsources.php /var/simplesamlphp/config/authsources.php
ADD docker/ssp/config-override.php /var/simplesamlphp/config/config-override.php
# Bring the seeded database up to the schema of the module being built. docker/conformance.sql is a dump
# taken at some earlier schema, so the migrations it has not seen run here and a new migration needs no new
# dump. The script exits 0 whatever happens, so its output decides whether the build goes on.
RUN php /var/simplesamlphp/modules/oidc/bin/install.php | tee /tmp/oidc-install.log \
    && ! grep -q 'There was an error' /tmp/oidc-install.log
ADD docker/ssp/oidc_module.crt /var/simplesamlphp/cert/oidc_module.crt
ADD docker/ssp/oidc_module.key /var/simplesamlphp/cert/oidc_module.key
ADD docker/ssp/oidc_module_vci_ec_p256_01.pub /var/simplesamlphp/cert/oidc_module_vci_ec_p256_01.pub
ADD docker/ssp/oidc_module_vci_ec_p256_01.key /var/simplesamlphp/cert/oidc_module_vci_ec_p256_01.key
ADD docker/apache-override.cf /etc/apache2/sites-enabled/ssp-override.cf

RUN chown www-data /var/simplesamlphp/cert/oidc* \
    && chmod 660 /var/simplesamlphp/cert/oidc*
