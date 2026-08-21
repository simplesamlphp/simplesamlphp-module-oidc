<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;

    /**
     * @param string[] $claims
     */
    public function __construct(
        string $identifier,
        protected ?string $description = null,
        protected ?string $icon = null,
        protected array $claims = [],
    ) {
        if ($identifier === '') {
            throw new \InvalidArgumentException('Scope identifier cannot be empty.');
        }

        $this->identifier = $identifier;
    }

    public function getIcon(): ?string
    {
        return $this->icon;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * @return array<string>
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }
}
