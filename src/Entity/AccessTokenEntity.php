<?php

declare(strict_types=1);

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

use DateTimeImmutable;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Entity\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Entity\Traits\AssociateWithAuthCodeTrait;
use SimpleSAML\Module\oidc\Entity\Traits\RevokeTokenTrait;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class AccessTokenEntity implements
    AccessTokenEntityInterface,
    EntityStringRepresentationInterface
{
    use AccessTokenTrait;
    use TokenEntityTrait;
    use EntityTrait;
    use RevokeTokenTrait;
    use AssociateWithAuthCodeTrait;

    /**
     * String representation of access token issued to the client.
     * @var string|null $stringRepresentation
     */
    protected ?string $stringRepresentation = null;

    /**
     * Claims that were individual requested
     * @var array $requestedClaims
     */
    protected array $requestedClaims;

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
        string $userIdentifier = null,
        string $authCodeId = null,
        array $requestedClaims = null
    ): self {
        $accessToken = new self();

        $accessToken->setClient($clientEntity);
        $accessToken->setUserIdentifier($userIdentifier);
        $accessToken->setAuthCodeId($authCodeId);
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }
        $accessToken->setRequestedClaims($requestedClaims ?? []);

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
        $accessToken->expiryDateTime = DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc($state['expires_at'])
        );
        $accessToken->userIdentifier = $state['user_id'];
        $accessToken->client = $state['client'];
        $accessToken->isRevoked = (bool) $state['is_revoked'];
        $accessToken->authCodeId = $state['auth_code_id'];
        $accessToken->requestedClaims = json_decode($state['requested_claims'] ?? '[]', true);
        return $accessToken;
    }

    /**
     * @return array
     */
    public function getRequestedClaims(): array
    {
        return $this->requestedClaims;
    }

    /**
     * @param array $requestedClaims
     */
    public function setRequestedClaims(array $requestedClaims): void
    {
        $this->requestedClaims = $requestedClaims;
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
            'auth_code_id' => $this->getAuthCodeId(),
            'requested_claims' => json_encode($this->requestedClaims)
        ];
    }

    /**
     * Generate string representation, save it in a field, and return it.
     * @return string
     * @throws OAuthServerException
     */
    public function __toString(): string
    {
        return $this->stringRepresentation = $this->convertToJWT()->toString();
    }

    /**
     * Get string representation of access token at the moment of casting it to string.
     * @return string|null String representation or null if it was not cast to string yet.
     */
    public function toString(): ?string
    {
        return $this->stringRepresentation;
    }

    /**
     * Implemented instead of original AccessTokenTrait::convertToJWT() method in order to remove microseconds from
     * timestamps and to add claims like iss, etc., by using our own JWT builder service.
     *
     * @return Token
     * @throws OAuthServerException
     */
    protected function convertToJWT(): Token
    {
        $jwtBuilderService = new JsonWebTokenBuilderService();

        $jwtBuilder = $jwtBuilderService->getDefaultJwtTokenBuilder()
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withClaim('scopes', $this->getScopes());

        return $jwtBuilderService->getSignedJwtTokenFromBuilder($jwtBuilder);
    }
}
