<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Associations\Interfaces;

interface RelyingPartyAssociationInterface
{
    public function getClientId(): string;
    public function setClientId(string $clientId): void;
    public function getUserId(): string;
    public function setUserId(string $userId): void;
    public function getSessionId(): ?string;
    public function setSessionId(?string $sessionId): void;
    public function getBackChannelLogoutUri(): ?string;
    public function setBackChannelLogoutUri(?string $backChannelLogoutUri): void;

    /**
     * Get id_token_signed_response_alg metadata parameter used by the client.
     *
     * @return string|null
     */
    public function getClientIdTokenSignedResponseAlg(): ?string;

    /**
     * Set id_token_signed_response_alg metadata parameter used by the client.
     * @param string|null $idTokenSignedResponseAlg
     */
    public function setClientIdTokenSignedResponseAlg(?string $idTokenSignedResponseAlg): void;
}
