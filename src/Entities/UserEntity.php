<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities;

use DateTimeImmutable;
use InvalidArgumentException;
use League\OAuth2\Server\Entities\UserEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entities\Traits\FormatForDatabaseTrait;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class UserEntity implements UserEntityInterface, MementoInterface, ClaimSetInterface
{
    use FormatForDatabaseTrait;


    /** @var non-empty-string */
    private readonly string $identifier;


    public function __construct(
        string $identifier,
        private readonly DateTimeImmutable $createdAt,
        private DateTimeImmutable $updatedAt,
        private array $claims = [],
    ) {
        if ($identifier === '') {
            throw new InvalidArgumentException('User identifier cannot be empty.');
        }

        $this->identifier = $identifier;
    }


    /**
     * {@inheritdoc}
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'claims' => json_encode($this->getClaims(), JSON_INVALID_UTF8_SUBSTITUTE),
            'updated_at' => $this->formatForDatabase($this->getUpdatedAt()),
            'created_at' => $this->formatForDatabase($this->getCreatedAt()),
        ];
    }


    public function getIdentifier(): string
    {
        return $this->identifier;
    }


    public function getClaims(): array
    {
        return $this->claims;
    }


    public function setClaims(array $claims): self
    {
        $this->claims = $claims;
        return $this;
    }


    public function getUpdatedAt(): DateTimeImmutable
    {
        return $this->updatedAt;
    }


    public function setUpdatedAt(DateTimeImmutable $updatedAt): self
    {
        $this->updatedAt = $updatedAt;
        return $this;
    }


    public function getCreatedAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }
}
