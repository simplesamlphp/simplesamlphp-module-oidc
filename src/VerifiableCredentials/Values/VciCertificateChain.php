<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use SimpleSAML\OpenID\X509\Certificate;
use SimpleSAML\OpenID\X509\CertificateChain;

/**
 * The certificate chain of a Verifiable Credential Issuance signing key, validated against the issuer's trust anchors.
 *
 * Two chains travel together. The chain as configured is what a signed artifact carries in its `x5c` header, the
 * trust anchor left out, as HAIP 1.0 has it for credentials (section 6.1.1) and Status List Tokens (section 6.1). The
 * path it was validated as ends with the trust anchor, so it is the one which says until when the chain validates.
 *
 * @see \SimpleSAML\Module\oidc\VerifiableCredentials\VciCertificateChainResolver
 */
class VciCertificateChain
{
    public function __construct(
        protected readonly CertificateChain $chain,
        protected readonly CertificateChain $validatedPath,
    ) {
    }


    /**
     * The chain as configured: the leaf first, then the intermediates.
     */
    public function getChain(): CertificateChain
    {
        return $this->chain;
    }


    /**
     * The chain followed by the trust anchor it was validated with.
     */
    public function getValidatedPath(): CertificateChain
    {
        return $this->validatedPath;
    }


    /**
     * The value of the `x5c` header parameter: the chain as configured, without the trust anchor.
     *
     * @return non-empty-list<non-empty-string>
     */
    public function getX5c(): array
    {
        return $this->chain->getX5c();
    }


    public function getLeaf(): Certificate
    {
        return $this->chain->getLeaf();
    }


    public function getTrustAnchor(): Certificate
    {
        return $this->validatedPath->getLast();
    }


    /**
     * The moment the chain stops validating, as a Unix timestamp: the earliest end of validity in the validated
     * path, which may be an intermediate's or the trust anchor's rather than the leaf's.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\X509Exception
     */
    public function getEarliestNotAfter(): int
    {
        return $this->validatedPath->getEarliestNotAfter();
    }
}
