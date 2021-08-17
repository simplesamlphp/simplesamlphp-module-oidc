<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Entity;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Module\oidc\Entity\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entity\Traits\RevokeTokenTrait;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;
use SimpleSAML\Module\oidc\Entity\Interfaces\EntityStringRepresentationInterface;

class AccessTokenEntity implements
    AccessTokenEntityInterface,
    MementoInterface,
    EntityStringRepresentationInterface
{
    use AccessTokenTrait;
    use TokenEntityTrait;
    use EntityTrait;
    use RevokeTokenTrait;

    /**
     * String representation of access token issued to the client.
     * @var string $stringRepresentation
     */
    protected $stringRepresentation;

    /**
     * Constructor.
     */
    private function __construct()
    {
    }

    /**
     * Create new Access Token from data.
     *
     * @param ScopeEntityInterface[] $scopes
     */
    public static function fromData(
        OAuth2ClientEntityInterface $clientEntity,
        array $scopes,
        string $userIdentifier = null
    ): self {
        $accessToken = new self();

        $accessToken->setClient($clientEntity);
        $accessToken->setUserIdentifier($userIdentifier);
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        return $accessToken;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromState(array $state): self
    {
        $accessToken = new self();

        /** @psalm-var string $scope */
        $scopes = array_map(function (string $scope) {
            return ScopeEntity::fromData($scope);
        }, json_decode($state['scopes'], true));

        $accessToken->identifier = $state['id'];
        $accessToken->scopes = $scopes;
        $accessToken->expiryDateTime = \DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc($state['expires_at'])
        );
        $accessToken->userIdentifier = $state['user_id'];
        $accessToken->client = $state['client'];
        $accessToken->isRevoked = (bool) $state['is_revoked'];

        return $accessToken;
    }

    /**
     * {@inheritdoc}
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'scopes' => json_encode($this->scopes),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'user_id' => $this->getUserIdentifier(),
            'client_id' => $this->getClient()->getIdentifier(),
            'is_revoked' => (int) $this->isRevoked(),
        ];
    }

    /**
     * Generate string representation, save it in a field, and return it.
     * @return string
     */
    public function __toString()
    {
        return $this->stringRepresentation = $this->convertToJWT()->toString();
    }

    /**
     * Get string representation of access token at the moment of casting it to string.
     * @return string|null String representation or null if it was not casted to string yet.
     */
    public function toString(): ?string
    {
        return $this->stringRepresentation;
    }
}
