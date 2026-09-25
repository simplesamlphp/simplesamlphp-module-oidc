#!/usr/bin/env bash
#
# Run by the SimpleSAMLphp image as root, before Apache starts (/opt/simplesaml/run-on-start.sh). Puts the host's
# TLS certificate where Apache reads it (APACHE_CERT_NAME=harness), and on an OP node, the node's token signing key
# pair where the module reads it, then its database and clients (seed.php).

set -euo pipefail

pki=/harness/pki
host="${HARNESS_HOST:?HARNESS_HOST names the host this container serves}"

install -m 644 "$pki/tls/$host.crt" /etc/ssl/certs/harness.pem
install -m 600 "$pki/tls/$host.key" /etc/ssl/private/harness.key

if [ -z "${HARNESS_NODE:-}" ]; then
    exit 0
fi

install -o www-data -g www-data -m 600 "$pki/signing/$HARNESS_NODE.key" /var/simplesamlphp/cert/oidc_module.key
install -o www-data -g www-data -m 644 "$pki/signing/$HARNESS_NODE.pub" /var/simplesamlphp/cert/oidc_module.crt

su www-data -s /bin/bash -c 'php /harness/seed.php'
