#!/usr/bin/env bash
#
# Generates the throwaway keys and certificates the local Docker stack needs.
#
# None of the generated files are kept in Git, so a release tree never ships a
# private key. Run this once before "docker compose up"; see
# docs/4-oidc-docker.md. Existing files are left alone, and an existing private
# key is never replaced, unless --force is given.

set -euo pipefail

force=false
case "${1:-}" in
    '') ;;
    --force) force=true ;;
    *)
        echo "Usage: ${0##*/} [--force]" >&2
        exit 1
        ;;
esac

docker_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

tls_key="$docker_dir/nginx-certs/default.key"
tls_certificate="$docker_dir/nginx-certs/default.crt"
module_key="$docker_dir/ssp/oidc_module.key"
module_public_key="$docker_dir/ssp/oidc_module.crt"

# docker-compose.yml publishes the OP as op.local.stack-dev.cirrusidentity.com
# with CERT_NAME=default, so the certificate has to cover that name.
tls_wildcard_host='*.local.stack-dev.cirrusidentity.com'

if ! command -v openssl >/dev/null 2>&1; then
    echo 'openssl is required but was not found on PATH.' >&2
    exit 1
fi

# Succeeds while $1 still has to be generated.
needs_generating() {
    [ "$force" = true ] || [ ! -f "$1" ]
}

issue_tls_certificate() {
    local key_arguments

    # A certificate can go missing while its key survives, for instance after a
    # partial clean. Reissue from the surviving key rather than replacing it:
    # replacing it would discard a key the operator may have put here
    # deliberately, such as one issued by mkcert.
    if [ -f "$tls_key" ] && [ "$force" = false ]; then
        echo "Issuing self-signed TLS certificate for $tls_wildcard_host from the existing key ..."
        key_arguments=(-key "$tls_key")
    else
        echo "Generating self-signed TLS certificate and key for $tls_wildcard_host ..."
        key_arguments=(-nodes -newkey rsa:2048 -keyout "$tls_key")
    fi

    # -addext needs OpenSSL 1.1.1 or newer.
    openssl req -x509 -sha256 -days 825 \
        "${key_arguments[@]}" \
        -out "$tls_certificate" \
        -subj "/CN=$tls_wildcard_host" \
        -addext "subjectAltName=DNS:$tls_wildcard_host,DNS:localhost" >/dev/null 2>&1

    # Read by the nginx-proxy container, which runs as root.
    chmod 600 "$tls_key"
    chmod 644 "$tls_certificate"
}

generate_module_key_pair() {
    if [ ! -f "$module_key" ] || [ "$force" = true ]; then
        echo 'Generating OIDC module signing key ...'

        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
            -out "$module_key" >/dev/null 2>&1

        # World readable on purpose: the live-mount example in
        # docs/4-oidc-docker.md mounts this key straight into a container, where
        # www-data reads a file it does not own. The key is a local throwaway.
        chmod 644 "$module_key"
    else
        # Only the public key is missing, and it is a pure function of the
        # private key. Deriving it keeps the signing key the OP has already
        # issued tokens with, which regenerating the pair would silently rotate.
        echo 'Deriving OIDC module public key from the existing private key ...'
    fi

    # Despite the .crt name this is a bare public key rather than a
    # certificate, which is what the module's public key option expects.
    openssl rsa -in "$module_key" -pubout -out "$module_public_key" >/dev/null 2>&1
    chmod 644 "$module_public_key"
}

generated=false

if needs_generating "$tls_key" || needs_generating "$tls_certificate"; then
    issue_tls_certificate
    generated=true
fi

if needs_generating "$module_key" || needs_generating "$module_public_key"; then
    generate_module_key_pair
    generated=true
fi

if [ "$generated" = false ]; then
    echo 'Development certificates are already in place; pass --force to replace them.'
fi
