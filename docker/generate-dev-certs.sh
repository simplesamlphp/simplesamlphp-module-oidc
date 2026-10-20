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
# The key pair docker/ssp/module_oidc.php signs verifiable credentials with.
vci_key="$docker_dir/ssp/oidc_module_vci_ec_p256_01.key"
vci_public_key="$docker_dir/ssp/oidc_module_vci_ec_p256_01.pub"
# Its certificate chain (HAIP 1.0 sections 6.1 and 6.1.1): a certificate for the key from an issuing CA, which a
# root CA issued. docker/ssp/module_oidc.php names the chain (the key's certificate and the issuing CA's) and the
# root as the trust anchor. The CAs' keys stay in vci-pki/, out of the image.
vci_pki_dir="$docker_dir/vci-pki"
vci_root_key="$vci_pki_dir/root-ca.key"
vci_root_certificate="$vci_pki_dir/root-ca.crt"
vci_issuing_key="$vci_pki_dir/issuing-ca.key"
vci_issuing_certificate="$vci_pki_dir/issuing-ca.crt"
vci_certificate_chain="$docker_dir/ssp/oidc_module_vci_ec_p256_01.chain.pem"
vci_trust_anchors="$docker_dir/ssp/oidc_module_vci_trust_anchors.pem"
# The OP's issuer, which docker/ssp/module_oidc.php leaves to be derived from the host docker-compose.yml publishes
# it as. The key's certificate names it, as a URI and by its host.
vci_issuer_host='op.local.stack-dev.cirrusidentity.com'

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

generate_vci_key_pair() {
    if [ ! -f "$vci_key" ] || [ "$force" = true ]; then
        echo 'Generating verifiable credential signing key (EC P-256) ...'
        # A new key needs a certificate of its own.
        vci_key_replaced=true

        # Same commands as docs/2-oidc-installation.md gives for this key.
        openssl ecparam -genkey -name prime256v1 -noout -out "$vci_key" >/dev/null 2>&1

        # World readable for the same reason as the module signing key.
        chmod 644 "$vci_key"
    else
        # As with the module signing key: derive the missing public half instead
        # of rotating a key credentials may already have been signed with.
        echo 'Deriving verifiable credential public key from the existing private key ...'
    fi

    openssl ec -in "$vci_key" -pubout -out "$vci_public_key" >/dev/null 2>&1
    chmod 644 "$vci_public_key"
}

# Issues a certificate for a key from a CA. The extensions are one per line, separated by \n escapes.
issue_certificate() {
    local key="$1" subject="$2" ca_certificate="$3" ca_key="$4" extensions="$5" days="$6" out="$7"

    openssl req -new -sha256 -key "$key" -subj "$subject" |
        openssl x509 -req -sha256 -days "$days" -CA "$ca_certificate" -CAkey "$ca_key" \
            -set_serial "0x$(openssl rand -hex 16)" -extfile <(printf '%b\n' "$extensions") \
            -out "$out" >/dev/null 2>&1
}

issue_vci_certificate_chain() {
    mkdir -p "$vci_pki_dir"

    if [ ! -f "$vci_root_key" ] || [ ! -f "$vci_root_certificate" ] || [ "$force" = true ]; then
        echo 'Creating the verifiable credential root CA ...'
        openssl ecparam -genkey -name prime256v1 -noout -out "$vci_root_key" >/dev/null 2>&1
        openssl req -x509 -new -sha256 -days 3650 -key "$vci_root_key" -out "$vci_root_certificate" \
            -subj '/CN=OIDC module development credential root CA' \
            -addext 'basicConstraints=critical,CA:TRUE' \
            -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
        # A new root issues the issuing CA anew.
        rm -f "$vci_issuing_certificate"
    fi

    if [ ! -f "$vci_issuing_key" ] || [ "$force" = true ]; then
        openssl ecparam -genkey -name prime256v1 -noout -out "$vci_issuing_key" >/dev/null 2>&1
        rm -f "$vci_issuing_certificate"
    fi

    if [ ! -f "$vci_issuing_certificate" ]; then
        echo 'Issuing the verifiable credential issuing CA ...'
        issue_certificate "$vci_issuing_key" '/CN=OIDC module development credential issuing CA' \
            "$vci_root_certificate" "$vci_root_key" \
            'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always' \
            1825 "$vci_issuing_certificate"
    fi

    echo "Issuing the verifiable credential signing key's certificate for $vci_issuer_host ..."
    issue_certificate "$vci_key" "/CN=$vci_issuer_host" \
        "$vci_issuing_certificate" "$vci_issuing_key" \
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:$vci_issuer_host,URI:https://$vci_issuer_host\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always" \
        825 "$vci_pki_dir/signing.crt"

    # The leaf first, then the issuing CA; never the trust anchor.
    cat "$vci_pki_dir/signing.crt" "$vci_issuing_certificate" > "$vci_certificate_chain"
    cp "$vci_root_certificate" "$vci_trust_anchors"

    chmod 600 "$vci_root_key" "$vci_issuing_key"
    chmod 644 "$vci_root_certificate" "$vci_issuing_certificate" "$vci_pki_dir/signing.crt" \
        "$vci_certificate_chain" "$vci_trust_anchors"
}

generated=false
vci_key_replaced=false

if needs_generating "$tls_key" || needs_generating "$tls_certificate"; then
    issue_tls_certificate
    generated=true
fi

if needs_generating "$module_key" || needs_generating "$module_public_key"; then
    generate_module_key_pair
    generated=true
fi

if needs_generating "$vci_key" || needs_generating "$vci_public_key"; then
    generate_vci_key_pair
    generated=true
fi

if needs_generating "$vci_certificate_chain" || needs_generating "$vci_trust_anchors" ||
    [ "$vci_key_replaced" = true ]; then
    issue_vci_certificate_chain
    generated=true
fi

if [ "$generated" = false ]; then
    echo 'Development certificates are already in place; pass --force to replace them.'
fi
