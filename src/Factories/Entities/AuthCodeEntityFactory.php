<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class AuthCodeEntityFactory
{
    public function __construct(
        protected readonly Helpers $helpers,
        protected readonly ScopeEntityFactory $scopeEntityFactory,
    ) {
    }

    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    public function fromData(
        string $id,
        OAuth2ClientEntityInterface $client,
        array $scopes,
        DateTimeImmutable $expiryDateTime,
        ?string $userIdentifier = null,
        ?string $redirectUri = null,
        ?string $nonce = null,
        bool $isRevoked = false,
    ): AuthCodeEntity {
        return new AuthCodeEntity(
            $id,
            $client,
            $scopes,
            $expiryDateTime,
            $userIdentifier,
            $redirectUri,
            $nonce,
            $isRevoked,
        );
    }

    /**
     * @throws \Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function fromState(array $state): AuthCodeEntity
    {
        if (
            !is_string($state['scopes']) ||
            !is_string($state['id']) ||
            !is_string($state['expires_at']) ||
            !is_a($state['client'], ClientEntityInterface::class)
        ) {
            throw OidcServerException::serverError('Invalid Auth Code Entity state');
        }

        $stateScopes = json_decode($state['scopes'], true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($stateScopes)) {
            throw OidcServerException::serverError('Invalid Auth Code Entity state: scopes');
        }

        $scopes = array_map(
            /**
             * @return \SimpleSAML\Module\oidc\Entities\ScopeEntity
             */
            fn(string $scope) => $this->scopeEntityFactory->fromData($scope),
            $stateScopes,
        );

        $id = $state['id'];
        $client = $state['client'];
        $expiryDateTime = $this->helpers->dateTime()->getUtc($state['expires_at']);
        $userIdentifier = empty($state['user_id']) ? null : (string)$state['user_id'];
        $redirectUri = empty($state['redirect_uri']) ? null : (string)$state['redirect_uri'];
        $nonce = empty($state['nonce']) ? null : (string)$state['nonce'];
        $isRevoked = (bool) $state['is_revoked'];

        return $this->fromData(
            $id,
            $client,
            $scopes,
            $expiryDateTime,
            $userIdentifier,
            $redirectUri,
            $nonce,
            $isRevoked,
        );
    }
}
