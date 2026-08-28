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
     * Credentials are issued unbound, to a subject identifier this issuer derives from the
     * authenticated user. Neither binding metadata field is advertised, and a Key Proof sent anyway is
     * refused: nothing told the wallet which proof type or signing algorithm to produce one with, so
     * accepting it would mean honouring a proof this configuration never asked for.
     */
    case Proofless = 'proofless';
}
