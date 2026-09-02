<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;

/**
 * How a signed artifact says who issued it and with which key.
 *
 * The pair travels together because it has to agree: `kid` names a key inside whatever `iss` resolves
 * to, so an issuer taken from one mode and a key identifier taken from another names a key which is
 * not there. Resolving both in one place is what keeps that from happening.
 *
 * The mode is carried alongside so that a caller recording what it issued under can say which kind of
 * identity the value is, without having to re-derive it from the string's shape.
 */
class VciIssuerIdentity
{
    /**
     * @param string $issuer The `iss` claim value.
     * @param string $keyId The `kid` header value, naming the key within that issuer.
     */
    public function __construct(
        protected readonly VciIssuerIdentifierModeEnum $mode,
        protected readonly string $issuer,
        protected readonly string $keyId,
    ) {
    }


    public function getMode(): VciIssuerIdentifierModeEnum
    {
        return $this->mode;
    }


    public function getIssuer(): string
    {
        return $this->issuer;
    }


    public function getKeyId(): string
    {
        return $this->keyId;
    }
}
