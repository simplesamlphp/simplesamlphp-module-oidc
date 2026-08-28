<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;

/**
 * A Key Proof which passed every check, together with what issuance is to bind the credential to.
 *
 * The holder identifier is resolved once, while the proof is being validated, rather than derived again
 * at signing time. The credential's subject and its `cnf` claim have to name the key whose signature was
 * actually verified, and deriving them a second time from the same proof is how those come apart.
 */
class ValidatedOpenId4VciProof
{
    /**
     * @param string $subject The holder identifier the credential is issued to.
     * @param ?string $keyId The verification method the proof named, or null when the proof carried its
     * key inline in a `jwk` header and so named no verification method at all.
     */
    public function __construct(
        protected readonly OpenId4VciProof $proof,
        protected readonly string $subject,
        protected readonly ?string $keyId,
    ) {
    }


    public function getProof(): OpenId4VciProof
    {
        return $this->proof;
    }


    public function getSubject(): string
    {
        return $this->subject;
    }


    public function getKeyId(): ?string
    {
        return $this->keyId;
    }
}
