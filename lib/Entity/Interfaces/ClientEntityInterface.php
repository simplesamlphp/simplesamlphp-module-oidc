<?php

namespace SimpleSAML\Module\oidc\Entity\Interfaces;

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\MementoInterface;

interface ClientEntityInterface extends OAuth2ClientEntityInterface, MementoInterface
{
    public static function fromData(
        string $id,
        string $secret,
        string $name,
        string $description,
        array $redirectUri,
        array $scopes,
        bool $isEnabled,
        bool $isConfidential = false,
        ?string $authSource = null
    ): self;

    public function toArray(): array;

    public function getSecret(): string;

    public function restoreSecret(string $secret): self;

    public function getDescription(): string;

    public function getAuthSource(): ?string;

    public function getScopes(): array;

    public function isEnabled(): bool;
}
