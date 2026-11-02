#!/usr/bin/env python3
"""Write the suite configurations of the OpenID4VCI issuer HAIP test plan.

conformance-tests/conformance-vci-issuer-haip.template.json is the configuration of
oid4vci-1_0-issuer-haip-test-plan but for what docker/generate-dev-certs.sh issues anew for each
checkout: the key and certificate chain the suite attests its two wallets with, as the wallet
provider's attester; the key and chain it signs key attestations with, as the wallet provider's key
attester; and the trust anchor of the issuer's certificates, which the suite validates the x5c
chains of credentials and Status List Tokens against. This script fills them in from
docker/vci-pki/ and docker/ssp/ and writes, into conformance-tests/, one configuration for each
run of the plan (RUNS):

    ./docker/generate-dev-certs.sh
    python3 conformance-tests/vci-haip-config.py

Run it again whenever generate-dev-certs.sh has issued new keys or certificates. It needs only the
standard library.
"""

import argparse
import base64
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The DER encoding of the named curve P-256 (prime256v1, 1.2.840.10045.3.1.7).
P256_OID = bytes.fromhex("06082a8648ce3d030107")

# The configuration of each run of the plan, by file name: the template's, with the credential
# configuration of docker/ssp/module_oidc.php the run selects and the proof type it prefers, where
# not the template's. The plan tests the configuration it is given only, and its key attestation
# test prefers the attestation proof type wherever it is offered, so each way of taking key
# attestations needs a run of its own: a jwt proof carrying one in its key_attestation header, of a
# configuration offering jwt alone, and an attestation proof.
RUNS = {
    "conformance-vci-issuer-haip.json": None,
    "conformance-vci-issuer-haip-key-attestation.json": (
        "ResearchAndScholarshipCredentialDcSdJwtKeyAttested", "jwt"),
    "conformance-vci-issuer-haip-attestation.json": (
        "ResearchAndScholarshipCredentialDcSdJwtAttestation", "attestation"),
}


def read_pem(path, label):
    """The DER bytes of the first PEM block with this label in the file."""
    with open(path, encoding="ascii") as f:
        text = f.read()
    match = re.search(r"-----BEGIN {0}-----(.*?)-----END {0}-----".format(label), text, re.S)
    if match is None:
        sys.exit("{}: no {} PEM block".format(path, label))
    return base64.b64decode("".join(match.group(1).split()), validate=True)


def der_element(data, position):
    """The tag, the content and the position after one DER element."""
    tag = data[position]
    length = data[position + 1]
    position += 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[position:position + size], "big")
        position += size
    if position + length > len(data):
        raise ValueError("a DER element runs past the end of its data")
    return tag, data[position:position + length], position + length


def der_elements(data):
    """The tag and content of each DER element in data, which they must fill exactly."""
    elements = []
    position = 0
    while position < len(data):
        tag, content, position = der_element(data, position)
        elements.append((tag, content))
    return elements


def der_only_element(data):
    """The tag and content of the one DER element which data must hold, and nothing after it."""
    elements = der_elements(data)
    if len(elements) != 1:
        raise ValueError("expected exactly one DER element")
    return elements[0]


def base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def p256_private_jwk(path):
    """The private JWK of an EC P-256 key in a SEC1 PEM file (EC PRIVATE KEY, RFC 5915), the form
    `openssl ecparam -genkey -noout` writes: exactly its version 1, the private key, the curve and the
    public key, in that order, and nothing else."""
    try:
        tag, key = der_only_element(read_pem(path, "EC PRIVATE KEY"))
        members = der_elements(key) if tag == 0x30 else []
        if [member_tag for member_tag, _ in members] != [0x02, 0x04, 0xA0, 0xA1]:
            raise ValueError("not version, private key, curve and public key")
        (_, version), (_, private_key), (_, curve), (_, public_key) = members
        public_key_tag, point = der_only_element(public_key)
    except (ValueError, IndexError) as error:
        sys.exit("{}: not an EC private key in the expected form ({})".format(path, error))
    # A BIT STRING without unused bits, holding the uncompressed point (SEC1 section 2.3.3).
    if (version != b"\x01" or curve != P256_OID or len(private_key) != 32 or public_key_tag != 0x03
            or len(point) != 66 or point[:2] != b"\x00\x04"):
        sys.exit("{}: not an EC P-256 private key with its public key".format(path))
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url(point[2:34]),
        "y": base64url(point[34:66]),
        "d": base64url(private_key),
    }


def certificate_base64(path):
    """A certificate as an x5c member carries it: the standard base64 of its DER."""
    return base64.b64encode(read_pem(path, "CERTIFICATE")).decode("ascii")


def signing_jwk(pki, name, kid):
    """The private JWK the suite signs with as one of the wallet provider's attesters, with its x5c: its
    certificate, then the issuing CA's, never the root (HAIP 1.0 sections 4.3.1 and 4.5.1)."""
    jwk = p256_private_jwk(os.path.join(pki, name + ".key"))
    jwk.update({
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
        "x5c": [
            certificate_base64(os.path.join(pki, name + ".crt")),
            certificate_base64(os.path.join(pki, "wallet-provider-issuing-ca.crt")),
        ],
    })
    return jwk


def write_private(path, config):
    """Write the configuration so that only its owner can read it: it holds the attesters' private keys,
    which are kept so as the key files are."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    # The mode above applies only to a file created here, not to one written over.
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)
        f.write("\n")
    print("wrote " + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--template", default=os.path.join(ROOT, "conformance-tests", "conformance-vci-issuer-haip.template.json"))
    parser.add_argument(
        "--output-dir", default=os.path.join(ROOT, "conformance-tests"), help="where the configurations go")
    parser.add_argument("--pki", default=os.path.join(ROOT, "docker", "vci-pki"), help="where the wallet provider PKI is")
    parser.add_argument(
        "--issuer-trust-anchors", default=os.path.join(ROOT, "docker", "ssp", "oidc_module_vci_trust_anchors.pem"))
    args = parser.parse_args()

    with open(args.template, encoding="utf-8") as f:
        config = json.load(f)

    attester = signing_jwk(args.pki, "wallet-attester", "wallet-attester")
    key_attester = signing_jwk(args.pki, "key-attester", "key-attester")

    with open(args.issuer_trust_anchors, encoding="ascii") as f:
        issuer_trust_anchors = f.read()
    # The suite takes one certificate as each anchor.
    if issuer_trust_anchors.count("-----BEGIN CERTIFICATE-----") != 1:
        sys.exit("{}: expected exactly one certificate".format(args.issuer_trust_anchors))

    config["client_attestation"]["attester_jwks"] = {"keys": [attester]}
    config["client_attestation"]["key_attestation_jwks"] = {"keys": [key_attester]}
    config["credential"]["trust_anchor_pem"] = issuer_trust_anchors
    config["credential"]["status_list_trust_anchor_pem"] = issuer_trust_anchors

    for filename, selection in RUNS.items():
        run_config = json.loads(json.dumps(config))
        if selection is not None:
            credential_configuration_id, proof_type = selection
            run_config["vci"]["credential_configuration_id"] = credential_configuration_id
            run_config["vci"]["credential_proof_type_hint"] = proof_type
            run_config["description"] += (" This run selects the credential configuration {}, which takes key"
                                           " attestations, and prefers the {} proof type.").format(
                credential_configuration_id, proof_type)
        write_private(os.path.join(args.output_dir, filename), run_config)


if __name__ == "__main__":
    main()
