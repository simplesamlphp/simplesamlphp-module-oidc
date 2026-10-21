<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\OpenID\OAuth2\ClientAttestation;
use SimpleSAML\OpenID\OAuth2\ClientAttestationPop;

/**
 * A Client Attestation and its PoP as a request presented them, parsed and held to the checks which need nothing
 * but the two JWTs (ClientAttestationVerifier::parse()), with the values the remaining checks need read once, at
 * parsing: the library's time accessors check the clock again on every call, and would throw at a later check
 * as if the OP had failed. Not yet trusted: ClientAttestationVerifier::verify() decides that, for the client the
 * attestation names.
 */
class PresentedClientAttestation
{
    /**
     * @param non-empty-string $clientId The attestation's `sub`, the client it names.
     * @param non-empty-string $instanceKeyThumbprint The JWK SHA-256 Thumbprint of the Client Instance Key.
     * @param non-empty-string $popJwtId
     */
    public function __construct(
        protected readonly ClientAttestation $attestation,
        protected readonly ClientAttestationPop $pop,
        protected readonly string $clientId,
        protected readonly int|float $attestationExpiresAt,
        protected readonly int|float $popIssuedAt,
        protected readonly int|float|null $popExpiresAt,
        protected readonly string $popJwtId,
        protected readonly string $instanceKeyThumbprint,
    ) {
    }


    public function getAttestation(): ClientAttestation
    {
        return $this->attestation;
    }


    public function getPop(): ClientAttestationPop
    {
        return $this->pop;
    }


    /**
     * @return non-empty-string
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }


    public function getAttestationExpiresAt(): int|float
    {
        return $this->attestationExpiresAt;
    }


    public function getPopIssuedAt(): int|float
    {
        return $this->popIssuedAt;
    }


    public function getPopExpiresAt(): int|float|null
    {
        return $this->popExpiresAt;
    }


    /**
     * @return non-empty-string
     */
    public function getPopJwtId(): string
    {
        return $this->popJwtId;
    }


    /**
     * @return non-empty-string
     */
    public function getInstanceKeyThumbprint(): string
    {
        return $this->instanceKeyThumbprint;
    }
}
