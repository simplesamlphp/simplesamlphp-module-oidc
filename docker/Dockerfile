FROM cirrusid/simplesamlphp:1.19.1

RUN apt-get update && apt-get install -y sqlite3
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
ADD docker/ssp/oidc_module.pem /var/simplesamlphp/cert/oidc_module.pem
ADD docker/apache-override.cf /etc/apache2/sites-enabled/ssp-override.cf

RUN chown www-data /var/simplesamlphp/cert/oidc* \
    && chmod 660 /var/simplesamlphp/cert/oidc*