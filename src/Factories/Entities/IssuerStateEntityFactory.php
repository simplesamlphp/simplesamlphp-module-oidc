<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use JsonException;
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
     * @param string[] $credentialConfigurationIds The configurations the Credential Offer offers.
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function buildNew(
        ?string $value = null,
        ?DateTimeImmutable $createdAt = null,
        ?DateTimeImmutable $expiresAt = null,
        bool $isRevoked = false,
        array $credentialConfigurationIds = [],
    ): IssuerStateEntity {
        $value ??= hash('sha256', $this->helpers->random()->getIdentifier());

        $createdAt ??= $this->helpers->dateTime()->getUtc();
        $expiresAt ??= $createdAt->add($this->moduleConfig->getVciIssuerStateDuration());

        return $this->fromData($value, $createdAt, $expiresAt, $isRevoked, $credentialConfigurationIds);
    }


    /**
     * @param string $value Issuer State Entity value, max 64 characters.
     * @param string[] $credentialConfigurationIds The configurations the Credential Offer offers.
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    public function fromData(
        string $value,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $expiresAt,
        bool $isRevoked = false,
        array $credentialConfigurationIds = [],
    ): IssuerStateEntity {
        if (strlen($value) > 64) {
            throw new OpenIdException('Invalid Issuer State Entity value.');
        }

        return new IssuerStateEntity($value, $createdAt, $expiresAt, $isRevoked, $credentialConfigurationIds);
    }


    /**
     * A state stored before the offered configurations were (no `credential_configuration_ids`, or NULL) offers
     * none, so no request following it can ask for a credential.
     *
     * @param mixed[] $state
     * @return \SimpleSAML\Module\oidc\Entities\IssuerStateEntity
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
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
            $this->credentialConfigurationIdsFromState($state['credential_configuration_ids'] ?? null),
        );
    }


    /**
     * @return string[]
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function credentialConfigurationIdsFromState(mixed $credentialConfigurationIds): array
    {
        if ($credentialConfigurationIds === null) {
            return [];
        }

        try {
            /** @psalm-suppress MixedAssignment */
            $credentialConfigurationIds = is_string($credentialConfigurationIds) ?
            json_decode($credentialConfigurationIds, true, 512, JSON_THROW_ON_ERROR) :
            null;
        } catch (JsonException) {
            $credentialConfigurationIds = null;
        }

        if (!is_array($credentialConfigurationIds) || !array_is_list($credentialConfigurationIds)) {
            throw new OpenIdException('Invalid Issuer State Entity credential configuration IDs.');
        }

        $list = [];
        /** @psalm-suppress MixedAssignment */
        foreach ($credentialConfigurationIds as $credentialConfigurationId) {
            if (!is_string($credentialConfigurationId)) {
                throw new OpenIdException('Invalid Issuer State Entity credential configuration IDs.');
            }

            $list[] = $credentialConfigurationId;
        }

        return $list;
    }
}
