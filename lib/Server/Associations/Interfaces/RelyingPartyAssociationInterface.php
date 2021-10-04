<?php

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
}
