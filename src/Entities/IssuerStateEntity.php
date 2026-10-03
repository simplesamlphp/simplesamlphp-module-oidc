<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Entities\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entities\Traits\FormatForDatabaseTrait;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class IssuerStateEntity implements MementoInterface
{
    use FormatForDatabaseTrait;


    public function __construct(
        protected readonly string $value,
        protected readonly DateTimeImmutable $createdAt,
        protected readonly DateTimeImmutable $expirestAt,
        protected bool $isRevoked = false,
    ) {
    }


    public function getState(): array
    {
        return [
            'value' => $this->getValue(),
            'created_at' => $this->formatForDatabase($this->getCreatedAt()),
            'expires_at' => $this->formatForDatabase($this->getExpirestAt()),
            'is_revoked' => $this->isRevoked(),
        ];
    }


    public function getValue(): string
    {
        return $this->value;
    }


    public function getCreatedAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }


    public function getExpirestAt(): DateTimeImmutable
    {
        return $this->expirestAt;
    }


    public function isRevoked(): bool
    {
        return $this->isRevoked;
    }


    public function revoke(): void
    {
        $this->isRevoked = true;
    }
}
