<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * How a Status List Token identifies the key it was signed with.
 *
 * The Token Status List specification deliberately mandates no key resolution method
 * (draft-ietf-oauth-status-list, Key Resolution), so which identifier a Relying Party can actually
 * resolve is a property of a deployment's profile rather than of the specification. This enum names
 * the profiles this module can emit.
 *
 * The profile is recorded on each Status List row when the list is created, and is part of the
 * policy fingerprint allocation filters on. Changing the configured profile therefore routes new
 * credentials to newly created lists while existing lists keep being served under the profile they
 * were issued with, so a change never invalidates credentials which are already in wallets.
 */
enum StatusListKeyProfileEnum: string
{
    /**
     * `kid` is the issuer's `did:jwk:...#0` and `iss` is the same `did:jwk:...`, matching how the
     * module already signs Verifiable Credentials. The token carries the key with it, so it is
     * self-verifiable without any external lookup. Note that this establishes integrity only: a
     * Relying Party must still bind the DID to the issuer it expects by its own means.
     */
    case DidJwk = 'did_jwk';

    /**
     * `iss` is the deployment's configured `did:web`, and `kid` the verification method that DID's
     * published document names for the signing key, matching how Verifiable Credentials are identified
     * under the same issuer identity. Unlike `did_jwk`, the token does not carry its key: a Relying
     * Party resolves the document over HTTPS, which is what lets the same issuer name outlive any one
     * key. Requires a configured issuer `did:web` identifier, whose document this module publishes.
     *
     * The identifier is recorded on each list at creation, so a list keeps naming the issuer it was
     * created under even after the configured one changes -- and that document therefore has to stay
     * resolvable for as long as any credential pointing at the list is still being verified.
     */
    case DidWeb = 'did_web';

    /**
     * `iss` is the module's issuer URL and `kid` is the JWKS key ID, so a Relying Party resolves the
     * key through the issuer's published JWKS. Use this for Relying Parties which will not accept a
     * `did:jwk` key identifier.
     */
    case Jwks = 'jwks';

    /**
     * `iss` is the module's issuer URL and `x5c` the certificate chain of the signing key, without its trust
     * anchor, as HAIP 1.0 section 6.1 has it; there is no `kid`. A Relying Party validates the chain against the
     * trust anchor it holds for this issuer and verifies with the leaf's key, so the token is self-verifiable, and
     * the certificate is what binds the key to the issuer. Requires a certificate chain on the signing key
     * (ModuleConfig::KEY_CERTIFICATE_CHAIN_FILENAME), the same one credentials carry.
     *
     * A list keeps its key, not its chain: a token carries the chain its key has when it is signed, so a renewed
     * certificate reaches the lists signed with that key at their next token, and a token never outlives a
     * certificate of the chain it carries.
     */
    case X509 = 'x509';
}
