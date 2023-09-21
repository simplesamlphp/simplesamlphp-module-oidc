<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entity\Interfaces;

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;

interface ClientEntityInterface extends OAuth2ClientEntityInterface, MementoInterface
{
    /**
     * @param string[] $redirectUri
     * @param string[] $scopes
     * @param string|null $authSource
     * @param string|null $owner
     * @return self
     */
    public static function fromData(
        string $id,
        string $secret,
        string $name,
        string $description,
        array $redirectUri,
        array $scopes,
        bool $isEnabled,
        bool $isConfidential = false,
        ?string $authSource = null,
        ?string $owner = null
    ): self;

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
}
