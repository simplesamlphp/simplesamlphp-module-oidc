<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Interfaces;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;

interface ClientEntityInterface extends OAuth2ClientEntityInterface, MementoInterface
{
    public function toArray(): array;

    public function getSecret(): string;

    public function restoreSecret(string $secret): self;

    public function getDescription(): string;

    public function getAuthSourceId(): ?string;

    /**
     * @return string[]
     */
    public function getScopes(): array;

    public function isEnabled(): bool;

    public function getOwner(): ?string;

    /**
     * @return string[]
     */
    public function getPostLogoutRedirectUri(): array;

    /**
     * @param string[] $postLogoutRedirectUri
     */
    public function setPostLogoutRedirectUri(array $postLogoutRedirectUri): void;

    /**
     * @return string|null
     */
    public function getBackChannelLogoutUri(): ?string;

    /**
     * @param string|null $backChannelLogoutUri
     */
    public function setBackChannelLogoutUri(?string $backChannelLogoutUri): void;

    public function getEntityIdentifier(): ?string;

    /**
     * @return string[]
     */
    public function getRedirectUris(): array;

    /**
     * @return string[]
     */
    public function getClientRegistrationTypes(): array;

    /**
     * @return array[]|null
     */
    public function getFederationJwks(): ?array;

    /**
     * @return array[]|null
     */
    public function getJwks(): ?array;

    public function getJwksUri(): ?string;
    public function getSignedJwksUri(): ?string;
    public function getRegistrationType(): RegistrationTypeEnum;
    public function getUpdatedAt(): ?DateTimeImmutable;
    public function getCreatedAt(): ?DateTimeImmutable;
    public function getExpiresAt(): ?DateTimeImmutable;
    public function isExpired(): bool;
    public function isFederated(): bool;
    public function isGeneric(): bool;

    public function getExtraMetadata(): array;
    public function getIdTokenSignedResponseAlg(): ?string;
}
