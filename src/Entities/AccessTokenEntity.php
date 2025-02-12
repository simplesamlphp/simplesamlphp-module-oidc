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

namespace SimpleSAML\Module\oidc\Entities;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Entities\Traits\AssociateWithAuthCodeTrait;
use SimpleSAML\Module\oidc\Entities\Traits\RevokeTokenTrait;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use Stringable;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class AccessTokenEntity implements AccessTokenEntityInterface, EntityStringRepresentationInterface, Stringable
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
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    public function __construct(
        string $id,
        OAuth2ClientEntityInterface $clientEntity,
        array $scopes,
        DateTimeImmutable $expiryDateTime,
        CryptKey $privateKey,
        protected JsonWebTokenBuilderService $jsonWebTokenBuilderService,
        int|string|null $userIdentifier = null,
        ?string $authCodeId = null,
        ?array $requestedClaims = null,
        ?bool $isRevoked = false,
        ?Configuration $jwtConfiguration = null,
    ) {
        $this->setIdentifier($id);
        $this->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }
        $this->setExpiryDateTime($expiryDateTime);
        $this->setPrivateKey($privateKey);
        $this->setUserIdentifier($userIdentifier);
        $this->setAuthCodeId($authCodeId);
        $this->setRequestedClaims($requestedClaims ?? []);
        if ($isRevoked) {
            $this->revoke();
        }
        $jwtConfiguration !== null ? $this->jwtConfiguration = $jwtConfiguration : $this->initJwtConfiguration();
    }

    /**
     * @return array
     */
    public function getRequestedClaims(): array
    {
        return $this->requestedClaims;
    }

    public function setRequestedClaims(array $requestedClaims): void
    {
        $this->requestedClaims = $requestedClaims;
    }

    /**
     * {@inheritdoc}
     * @throws \JsonException
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'scopes' => json_encode($this->scopes, JSON_THROW_ON_ERROR),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'user_id' => $this->getUserIdentifier(),
            'client_id' => $this->getClient()->getIdentifier(),
            'is_revoked' => $this->isRevoked(),
            'auth_code_id' => $this->getAuthCodeId(),
            'requested_claims' => json_encode($this->requestedClaims, JSON_THROW_ON_ERROR),
        ];
    }

    /**
     * Generate string representation, save it in a field, and return it.
     * @return string
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
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
     * @return \Lcobucci\JWT\Token
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Exception
     */
    protected function convertToJWT(): Token
    {
        /** @psalm-suppress ArgumentTypeCoercion */
        $jwtBuilder = $this->jsonWebTokenBuilderService->getProtocolJwtBuilder()
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy((string)$this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withClaim('scopes', $this->getScopes());

        return $this->jsonWebTokenBuilderService->getSignedProtocolJwt($jwtBuilder);
    }
}
