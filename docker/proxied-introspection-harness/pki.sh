#!/usr/bin/env bash
#
# Creates what the proxied introspection harness needs to run over verified TLS, in the volume every harness
# container shares (/harness/pki): a CA of its own, a TLS certificate from it for each host, and a token signing key
# pair for each OP node. Run by the one-shot "pki" service before any other container starts. What exists is kept,
# so a node keeps its signing key from one "up" to the next; "docker compose down --volumes" starts afresh.

set -euo pipefail

pki=/harness/pki
hosts=(a.oidc.test h.oidc.test b.oidc.test b-literal.oidc.test b-loop.oidc.test upstream-mock.oidc.test)
nodes=(a h b b-literal b-loop)

mkdir -p "$pki/tls" "$pki/signing"

if [ ! -f "$pki/ca.pem" ] || [ ! -f "$pki/ca.key" ]; then
    echo 'Creating the harness CA ...'
    openssl req -x509 -sha256 -days 825 -nodes -newkey rsa:2048 \
        -keyout "$pki/ca.key" -out "$pki/ca.pem" \
        -subj '/CN=OIDC module proxied introspection harness CA' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
fi

for host in "${hosts[@]}"; do
    if [ -f "$pki/tls/$host.crt" ] && [ -f "$pki/tls/$host.key" ]; then
        continue
    fi

    echo "Issuing a TLS certificate for $host ..."
    openssl req -new -sha256 -nodes -newkey rsa:2048 \
        -keyout "$pki/tls/$host.key" -out "$pki/tls/$host.csr" \
        -subj "/CN=$host" >/dev/null 2>&1
    openssl x509 -req -sha256 -days 825 \
        -in "$pki/tls/$host.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial \
        -out "$pki/tls/$host.crt" \
        -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host") >/dev/null 2>&1
    rm "$pki/tls/$host.csr"
done

for node in "${nodes[@]}"; do
    if [ -f "$pki/signing/$node.key" ] && [ -f "$pki/signing/$node.pub" ]; then
        continue
    fi

    echo "Creating the token signing key pair of node $node ..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$pki/signing/$node.key" >/dev/null 2>&1
    openssl rsa -in "$pki/signing/$node.key" -pubout -out "$pki/signing/$node.pub" >/dev/null 2>&1
done

# Readable by every container; each copies what it needs and sets its own ownership. The CA key is the one secret
# that stays behind.
chmod 755 "$pki" "$pki/tls" "$pki/signing"
chmod 644 "$pki/ca.pem" "$pki"/tls/*.crt "$pki"/tls/*.key "$pki"/signing/*
chmod 600 "$pki/ca.key"

echo 'Harness PKI is in place.'
