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


    /**
     * @param string[] $credentialConfigurationIds The configurations the Credential Offer carrying this state
     * offered, and so the only ones a request following it may ask for.
     * @param ?string $offerId The Credential Offer this state was made for (its offer record), copied to the access
     * token its redemption mints; null for a state stored before states named their offer.
     */
    public function __construct(
        protected readonly string $value,
        protected readonly DateTimeImmutable $createdAt,
        protected readonly DateTimeImmutable $expirestAt,
        protected bool $isRevoked = false,
        protected readonly array $credentialConfigurationIds = [],
        protected readonly ?string $offerId = null,
    ) {
    }


    /**
     * @throws \JsonException
     */
    public function getState(): array
    {
        return [
            'value' => $this->getValue(),
            'created_at' => $this->formatForDatabase($this->getCreatedAt()),
            'expires_at' => $this->formatForDatabase($this->getExpirestAt()),
            'is_revoked' => $this->isRevoked(),
            'credential_configuration_ids' => json_encode(
                array_values($this->getCredentialConfigurationIds()),
                JSON_THROW_ON_ERROR,
            ),
            'offer_id' => $this->getOfferId(),
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


    /**
     * @return string[]
     */
    public function getCredentialConfigurationIds(): array
    {
        return $this->credentialConfigurationIds;
    }


    public function getOfferId(): ?string
    {
        return $this->offerId;
    }


    public function revoke(): void
    {
        $this->isRevoked = true;
    }
}
