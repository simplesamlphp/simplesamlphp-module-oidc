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
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;

class ClientEntity implements ClientEntityInterface
{
    use EntityTrait;
    use ClientTrait;

    public const KEY_ID = 'id';
    public const KEY_SECRET = 'secret';
    public const KEY_NAME = 'name';
    public const KEY_DESCRIPTION = 'description';
    public const KEY_AUTH_SOURCE = 'auth_source';
    public const KEY_REDIRECT_URI = 'redirect_uri';
    public const KEY_SCOPES = 'scopes';
    public const KEY_IS_ENABLED = 'is_enabled';
    public const KEY_IS_CONFIDENTIAL = 'is_confidential';
    public const KEY_OWNER = 'owner';
    public const KEY_POST_LOGOUT_REDIRECT_URI = 'post_logout_redirect_uri';
    public const KEY_BACKCHANNEL_LOGOUT_URI = 'backchannel_logout_uri';
    public const KEY_ENTITY_IDENTIFIER = 'entity_identifier';
    public const KEY_CLIENT_REGISTRATION_TYPES = 'client_registration_types';
    public const KEY_FEDERATION_JWKS = 'federation_jwks';
    public const KEY_JWKS = 'jwks';
    public const KEY_JWKS_URI = 'jwks_uri';
    public const KEY_SIGNED_JWKS_URI = 'signed_jwks_uri';
    public const KEY_REGISTRATION_TYPE = 'registration_type';
    public const KEY_UPDATED_AT = 'updated_at';
    public const KEY_CREATED_AT = 'created_at';
    public const KEY_EXPIRES_AT = 'expires_at';
    public const KEY_IS_FEDERATED = 'is_federated';
    public const KEY_IS_GENERIC = 'is_generic';
    public const KEY_EXTRA_METADATA = 'extra_metadata';

    private string $secret;

    private string $description;

    private ?string $authSource = null;

    /**
     * @var string[] $scopes
     */
    private array $scopes;

    private bool $isEnabled = true;

    private ?string $owner = null;

    /**
     * @var string[]|null
     */
    private ?array $postLogoutRedirectUri = null;

    private ?string $backChannelLogoutUri = null;
    private ?string $entityIdentifier = null;
    /**
     * @var string[]|null
     */
    private ?array $clientRegistrationTypes = null;
    /**
     * @var ?array[]|null
     */
    private ?array $federationJwks = null;
    /**
     * @var ?array[]|null
     */
    private ?array $jwks = null;
    private ?string $jwksUri = null;
    private ?string $signedJwksUri = null;
    private RegistrationTypeEnum $registrationType;
    private ?DateTimeImmutable $updatedAt;
    private ?DateTimeImmutable $createdAt;
    private ?DateTimeImmutable $expiresAt;
    private bool $isFederated;
    private bool $isGeneric;
    private ?array $extraMetadata;

    /**
     * @param string[] $redirectUri
     * @param string[] $scopes
     * @param string[] $postLogoutRedirectUri
     * @param string[] $clientRegistrationTypes
     * @param array[] $federationJwks
     * @param array[] $jwks
     */
    public function __construct(
        string $identifier,
        string $secret,
        string $name,
        string $description,
        array $redirectUri,
        array $scopes,
        bool $isEnabled,
        bool $isConfidential = false,
        ?string $authSource = null,
        ?string $owner = null,
        array $postLogoutRedirectUri = [],
        ?string $backChannelLogoutUri = null,
        ?string $entityIdentifier = null,
        ?array $clientRegistrationTypes = null,
        ?array $federationJwks = null,
        ?array $jwks = null,
        ?string $jwksUri = null,
        ?string $signedJwksUri = null,
        RegistrationTypeEnum $registrationType = RegistrationTypeEnum::Manual,
        ?DateTimeImmutable $updatedAt = null,
        ?DateTimeImmutable $createdAt = null,
        ?DateTimeImmutable $expiresAt = null,
        bool $isFederated = false,
        bool $isGeneric = false,
        ?array $extraMetadata = null,
    ) {
        $this->identifier = $identifier;
        $this->secret = $secret;
        $this->name = $name;
        $this->description = $description;
        $this->authSource = empty($authSource) ? null : $authSource;
        $this->redirectUri = $redirectUri;
        $this->scopes = $scopes;
        $this->isEnabled = $isEnabled;
        $this->isConfidential = $isConfidential;
        $this->owner = empty($owner) ? null : $owner;
        $this->postLogoutRedirectUri = $postLogoutRedirectUri;
        $this->backChannelLogoutUri = empty($backChannelLogoutUri) ? null : $backChannelLogoutUri;
        $this->entityIdentifier = empty($entityIdentifier) ? null : $entityIdentifier;
        $this->clientRegistrationTypes = $clientRegistrationTypes;
        $this->federationJwks = $federationJwks;
        $this->jwks = $jwks;
        $this->jwksUri = $jwksUri;
        $this->signedJwksUri = $signedJwksUri;
        $this->registrationType = $registrationType;
        $this->updatedAt = $updatedAt;
        $this->createdAt = $createdAt;
        $this->expiresAt = $expiresAt;
        $this->isFederated = $isFederated;
        $this->isGeneric = $isGeneric;
        $this->extraMetadata = $extraMetadata;
    }

    /**
     * {@inheritdoc}
     * @throws \JsonException
     */
    public function getState(): array
    {
        return [
            self::KEY_ID => $this->getIdentifier(),
            self::KEY_SECRET => $this->getSecret(),
            self::KEY_NAME => $this->getName(),
            self::KEY_DESCRIPTION => $this->getDescription(),
            self::KEY_AUTH_SOURCE => $this->getAuthSourceId(),
            self::KEY_REDIRECT_URI => json_encode($this->getRedirectUri(), JSON_THROW_ON_ERROR),
            self::KEY_SCOPES => json_encode($this->getScopes(), JSON_THROW_ON_ERROR),
            self::KEY_IS_ENABLED => $this->isEnabled(),
            self::KEY_IS_CONFIDENTIAL => $this->isConfidential(),
            self::KEY_OWNER => $this->getOwner(),
            self::KEY_POST_LOGOUT_REDIRECT_URI => json_encode($this->getPostLogoutRedirectUri(), JSON_THROW_ON_ERROR),
            self::KEY_BACKCHANNEL_LOGOUT_URI => $this->getBackChannelLogoutUri(),
            self::KEY_ENTITY_IDENTIFIER => $this->getEntityIdentifier(),
            self::KEY_CLIENT_REGISTRATION_TYPES => is_null($this->clientRegistrationTypes) ?
                null :
                json_encode($this->getClientRegistrationTypes(), JSON_THROW_ON_ERROR),
            self::KEY_FEDERATION_JWKS => is_null($this->federationJwks) ?
                null :
                json_encode($this->getFederationJwks()),
            self::KEY_JWKS => is_null($this->jwks) ?
                null :
                json_encode($this->getJwks()),
            self::KEY_JWKS_URI => $this->getJwksUri(),
            self::KEY_SIGNED_JWKS_URI => $this->getSignedJwksUri(),
            self::KEY_REGISTRATION_TYPE => $this->getRegistrationType()->value,
            self::KEY_UPDATED_AT => $this->getUpdatedAt()?->format('Y-m-d H:i:s'),
            self::KEY_CREATED_AT => $this->getCreatedAt()?->format('Y-m-d H:i:s'),
            self::KEY_EXPIRES_AT => $this->getExpiresAt()?->format('Y-m-d H:i:s'),
            self::KEY_IS_FEDERATED => $this->isFederated(),
            self::KEY_IS_GENERIC => $this->isGeneric(),
            self::KEY_EXTRA_METADATA => is_null($this->extraMetadata) ?
                null :
                json_encode($this->extraMetadata, JSON_THROW_ON_ERROR),
        ];
    }

    public function toArray(): array
    {
        return [
            self::KEY_ID => $this->identifier,
            self::KEY_SECRET => $this->secret,
            self::KEY_NAME => $this->name,
            self::KEY_DESCRIPTION => $this->description,
            self::KEY_AUTH_SOURCE => $this->authSource,
            self::KEY_REDIRECT_URI => $this->redirectUri,
            self::KEY_SCOPES => $this->scopes,
            self::KEY_IS_ENABLED => $this->isEnabled,
            self::KEY_IS_CONFIDENTIAL => $this->isConfidential,
            self::KEY_OWNER => $this->owner,
            self::KEY_POST_LOGOUT_REDIRECT_URI => $this->postLogoutRedirectUri,
            self::KEY_BACKCHANNEL_LOGOUT_URI => $this->backChannelLogoutUri,
            self::KEY_ENTITY_IDENTIFIER => $this->entityIdentifier,
            self::KEY_CLIENT_REGISTRATION_TYPES => $this->clientRegistrationTypes,
            self::KEY_FEDERATION_JWKS => $this->federationJwks,
            self::KEY_JWKS => $this->jwks,
            self::KEY_JWKS_URI => $this->jwksUri,
            self::KEY_SIGNED_JWKS_URI => $this->signedJwksUri,
            self::KEY_REGISTRATION_TYPE => $this->registrationType,
            self::KEY_UPDATED_AT => $this->updatedAt,
            self::KEY_CREATED_AT => $this->createdAt,
            self::KEY_EXPIRES_AT => $this->expiresAt,
            self::KEY_IS_FEDERATED => $this->isFederated,
            self::KEY_IS_GENERIC => $this->isGeneric,

            // Extra metadata
            ClaimsEnum::IdTokenSignedResponseAlg->value => $this->getIdTokenSignedResponseAlg(),
        ];
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function restoreSecret(string $secret): ClientEntityInterface
    {
        $this->secret = $secret;

        return $this;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getAuthSourceId(): ?string
    {
        return $this->authSource;
    }

    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function isEnabled(): bool
    {
        return $this->isEnabled;
    }

    public function getOwner(): ?string
    {
        return $this->owner;
    }

    public function getPostLogoutRedirectUri(): array
    {
        return $this->postLogoutRedirectUri ?? [];
    }

    public function setPostLogoutRedirectUri(array $postLogoutRedirectUri): void
    {
        $this->postLogoutRedirectUri = $postLogoutRedirectUri;
    }

    public function getBackChannelLogoutUri(): ?string
    {
        return $this->backChannelLogoutUri;
    }

    public function setBackChannelLogoutUri(?string $backChannelLogoutUri): void
    {
        $this->backChannelLogoutUri = $backChannelLogoutUri;
    }

    /**
     * Get the RP Entity Identifier, as used in OpenID Federation specification.
     * This is different from the client ID.
     */
    public function getEntityIdentifier(): ?string
    {
        return $this->entityIdentifier;
    }

    public function getRedirectUris(): array
    {
        return is_string($this->redirectUri) ? [$this->redirectUri] : $this->redirectUri;
    }

    /**
     * Get client registration types.
     * Since this is required property, it will fall back to 'automatic', if not set on client.
     *
     * @return string[]
     */
    public function getClientRegistrationTypes(): array
    {
        if (empty($this->clientRegistrationTypes)) {
            return [ClientRegistrationTypesEnum::Automatic->value];
        }

        return $this->clientRegistrationTypes;
    }

    public function getFederationJwks(): ?array
    {
        return $this->federationJwks;
    }

    public function getJwks(): ?array
    {
        return $this->jwks;
    }

    public function getJwksUri(): ?string
    {
        return $this->jwksUri;
    }

    public function getSignedJwksUri(): ?string
    {
        return $this->signedJwksUri;
    }

    public function getRegistrationType(): RegistrationTypeEnum
    {
        return $this->registrationType;
    }

    public function getUpdatedAt(): ?DateTimeImmutable
    {
        return $this->updatedAt;
    }

    public function getCreatedAt(): ?DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getExpiresAt(): ?DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isExpired(): bool
    {
        return $this->expiresAt !== null && $this->expiresAt < new DateTimeImmutable();
    }

    public function isFederated(): bool
    {
        return $this->isFederated;
    }

    public function isGeneric(): bool
    {
        return $this->isGeneric;
    }

    public function getExtraMetadata(): array
    {
        return $this->extraMetadata ?? [];
    }

    public function getIdTokenSignedResponseAlg(): ?string
    {
        if (!is_array($this->extraMetadata)) {
            return null;
        }

        $idTokenSignedResponseAlg = $this->extraMetadata['id_token_signed_response_alg'] ?? null;

        if (!is_string($idTokenSignedResponseAlg)) {
            return null;
        }

        return $idTokenSignedResponseAlg;
    }
}
