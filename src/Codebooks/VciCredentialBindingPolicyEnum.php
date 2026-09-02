<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * Whether a credential configuration binds the credentials it issues to a key the wallet proves it holds.
 *
 * OpenID4VCI chains the two halves of this together: `proof_types_supported` must be present in a
 * credential configuration whenever `cryptographic_binding_methods_supported` is, and a Credential
 * Request must carry `proofs` whenever the configuration advertises `proof_types_supported`. So the
 * choice cannot be made per metadata field, and it cannot be made per request either -- it belongs to
 * the configuration, and it governs what is advertised and what is accepted at the same time.
 *
 * Advertising binding and then issuing without it, which is what this module did before, tells a wallet
 * the credential it received is held to its key when nothing of the sort was checked.
 */
enum VciCredentialBindingPolicyEnum: string
{
    /**
     * The default. A Key Proof is required, verified, and the credential is issued to the holder
     * identifier that proof resolves to. Both binding metadata fields are advertised.
     */
    case ProofBound = 'proof_bound';

    /**
     * Everything ProofBound requires, plus the identifier rules the DIIP profile writes on top of
     * OpenID4VCI. The proof's `kid` header must be an absolute DID URL of a `did:jwk` or a `did:web`,
     * and the verification method it names must appear in that document's `authentication`
     * relationship.
     *
     * Two consequences, both about the `kid` header, since that is where this profile's holder binding
     * lives:
     *
     * - A key proof carrying its key inline in a `jwk` header is refused. The requirement is written in
     *   DID URLs, and an inline key names no verification method to point at.
     * - A `did:key` holder is refused, since the profile names the other two. Every other configuration
     *   keeps accepting one.
     *
     * The `iss` claim is left to OpenID4VCI: the client the access token was issued to when there is
     * one, absent when there is not. The profile's own text asks for the holder's DID there, which
     * cannot hold at the same time as OpenID4VCI's rule for an anonymous pre-authorized code;
     * FIDEScommunity/DIIP#83 proposes dropping it in favour of the `kid` rule above, and that is what
     * this implements. A wallet identified by a DID still works - it is accepted, not required, and no
     * part of holder binding rests on it.
     *
     * Every other credential configuration is unaffected: DIIP's requirements are additive, so a
     * deployment can offer conformant configurations alongside ones which accept inline keys or
     * `did:key` holders.
     */
    case DiipProofBound = 'diip_proof_bound';

    /**
     * Credentials are issued unbound, to a subject identifier this issuer derives from the
     * authenticated user. Neither binding metadata field is advertised, and a Key Proof sent anyway is
     * refused: nothing told the wallet which proof type or signing algorithm to produce one with, so
     * accepting it would mean honouring a proof this configuration never asked for.
     */
    case Proofless = 'proofless';


    /**
     * Whether this policy requires a Key Proof at all, which is what decides both halves of the binding
     * metadata and whether a Credential Request has to carry `proofs`.
     *
     * Asked as a question rather than compared against a case, so that a policy added later has to
     * answer it here instead of falling into whichever branch an `if` happened to leave open.
     */
    public function requiresKeyProof(): bool
    {
        return match ($this) {
            self::ProofBound, self::DiipProofBound => true,
            self::Proofless => false,
        };
    }


    /**
     * Whether the DIIP profile's identifier rules apply on top of the OpenID4VCI ones.
     */
    public function requiresDiipIdentifiers(): bool
    {
        return $this === self::DiipProofBound;
    }
}
