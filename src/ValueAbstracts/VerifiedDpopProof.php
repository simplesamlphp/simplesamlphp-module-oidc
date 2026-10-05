<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\OpenID\OAuth2\DpopProof;

/**
 * A DPoP proof which passed every check of DpopProofVerifier, and the JWK SHA-256 Thumbprint (RFC 7638) of the key
 * which signed it: what an access token is bound to (RFC 9449 section 6.1, `cnf.jkt`).
 */
class VerifiedDpopProof
{
    /**
     * @param non-empty-string $jwkThumbprint
     */
    public function __construct(
        protected readonly DpopProof $proof,
        protected readonly string $jwkThumbprint,
    ) {
    }


    public function getProof(): DpopProof
    {
        return $this->proof;
    }


    /**
     * @return non-empty-string
     */
    public function getJwkThumbprint(): string
    {
        return $this->jwkThumbprint;
    }
}
