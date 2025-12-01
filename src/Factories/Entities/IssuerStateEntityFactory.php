<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Exceptions\OpenIdException;

class IssuerStateEntityFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Helpers $helpers,
    ) {
    }

    /**
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function buildNew(
        ?string $value = null,
        ?DateTimeImmutable $createdAt = null,
        ?DateTimeImmutable $expiresAt = null,
        bool $isRevoked = false,
    ): IssuerStateEntity {
        $value ??= hash('sha256', $this->helpers->random()->getIdentifier());

        $createdAt ??= $this->helpers->dateTime()->getUtc();
        $expiresAt ??= $createdAt->add($this->moduleConfig->getIssuerStateDuration());

        return $this->fromData($value, $createdAt, $expiresAt, $isRevoked);
    }

    /**
     * @param string $value Issuer State Entity value, max 64 characters.
     * @throws OpenIdException
     */
    public function fromData(
        string $value,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $expiresAt,
        bool $isRevoked = false,
    ): IssuerStateEntity {
        if (strlen($value) > 64) {
            throw new OpenIdException('Invalid Issuer State Entity value.');
        }

        return new IssuerStateEntity($value, $createdAt, $expiresAt, $isRevoked);
    }

    /**
     * @param mixed[] $state
     * @return IssuerStateEntity
     * @throws OpenIdException
     */
    public function fromState(array $state): IssuerStateEntity
    {
        if (
            !is_string($value = $state['value']) ||
            !is_string($createdAt = $state['created_at']) ||
            !is_string($expiresAt = $state['expires_at'])
        ) {
            throw new OpenIdException('Invalid Issuer State Entity state.');
        }

        if (strlen($value) > 64) {
            throw new OpenIdException('Invalid Issuer State Entity value.');
        }

        $isRevoked = (bool)($state['is_revoked'] ?? true);

        return new IssuerStateEntity(
            $value,
            $this->helpers->dateTime()->getUtc($createdAt),
            $this->helpers->dateTime()->getUtc($expiresAt),
            $isRevoked,
        );
    }
}
