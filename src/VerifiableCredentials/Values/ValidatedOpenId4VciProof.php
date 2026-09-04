<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
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
     * @param ?array<array-key,mixed> $holderJwk The key the proof carried inline, or null when it named
     * a verification method instead.
     */
    public function __construct(
        protected readonly OpenId4VciProof $proof,
        protected readonly string $subject,
        protected readonly ?string $keyId,
        protected readonly ?array $holderJwk = null,
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


    /**
     * @return ?array<array-key,mixed>
     */
    public function getHolderJwk(): ?array
    {
        return $this->holderJwk;
    }


    /**
     * The `cnf` claim stating which key this credential is held by, in whichever way the proof stated
     * it.
     *
     * Built here rather than in each of the three format branches which emit it. All three have to say
     * the same thing about the same proof, and the way that goes wrong is one branch being written
     * before a second way of naming a key exists and never learning about it - which is exactly what
     * happened to the inline-key case, whose credentials carried no `cnf` at all and so looked unbound
     * to any verifier which checks holder binding there rather than at `sub`.
     *
     * @return ?array<string,mixed>
     */
    public function getConfirmation(): ?array
    {
        if (is_string($this->keyId)) {
            return [ClaimsEnum::Kid->value => $this->keyId];
        }

        if (is_array($this->holderJwk)) {
            // RFC 7800 names the key itself, which is all an inline proof gave us to name. There is no
            // verification method to point at, and manufacturing one would be inventing an identifier
            // the wallet never published.
            return [ClaimsEnum::Jwk->value => $this->holderJwk];
        }

        return null;
    }
}
