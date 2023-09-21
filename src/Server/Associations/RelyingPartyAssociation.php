<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Associations;

use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;

class RelyingPartyAssociation implements RelyingPartyAssociationInterface
{
    public function __construct(
        protected string $clientId,
        protected string $userId,
        protected ?string $sessionId,
        /**
         * Registered back-channel logout URI for the client.
         */
        protected ?string $backChannelLogoutUri = null
    ) {
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function setClientId(string $clientId): void
    {
        $this->clientId = $clientId;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function setUserId(string $userId): void
    {
        $this->userId = $userId;
    }

    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    public function setSessionId(?string $sessionId): void
    {
        $this->sessionId = $sessionId;
    }

    public function getBackChannelLogoutUri(): ?string
    {
        return $this->backChannelLogoutUri;
    }

    public function setBackChannelLogoutUri(?string $backChannelLogoutUri): void
    {
        $this->backChannelLogoutUri = $backChannelLogoutUri;
    }
}
