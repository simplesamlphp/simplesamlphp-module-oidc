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
use PDO;
// use SimpleSAML\Module\oidc\Codebooks\ClaimValues\ClientRegistrationTypesEnum;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
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

    /**
     * Constructor.
     */
    private function __construct()
    {
    }

    /**
     * @param string[] $redirectUri
     * @param string[] $scopes
     * @param string[] $postLogoutRedirectUri
     * @param string[] $clientRegistrationTypes
     * @param array[] $federationJwks
     * @param array[] $jwks
     */
    public static function fromData(
        string $id,
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
    ): ClientEntityInterface {
        $client = new self();

        $client->identifier = $id;
        $client->secret = $secret;
        $client->name = $name;
        $client->description = $description;
        $client->authSource = empty($authSource) ? null : $authSource;
        $client->redirectUri = $redirectUri;
        $client->scopes = $scopes;
        $client->isEnabled = $isEnabled;
        $client->isConfidential = $isConfidential;
        $client->owner = empty($owner) ? null : $owner;
        $client->postLogoutRedirectUri = $postLogoutRedirectUri;
        $client->backChannelLogoutUri = empty($backChannelLogoutUri) ? null : $backChannelLogoutUri;
        $client->entityIdentifier = empty($entityIdentifier) ? null : $entityIdentifier;
        $client->clientRegistrationTypes = $clientRegistrationTypes;
        $client->federationJwks = $federationJwks;
        $client->jwks = $jwks;
        $client->jwksUri = $jwksUri;
        $client->signedJwksUri = $signedJwksUri;
        $client->registrationType = $registrationType;
        $client->updatedAt = $updatedAt;
        $client->createdAt = $createdAt;
        $client->expiresAt = $expiresAt;
        $client->isFederated = $isFederated;

        return $client;
    }

    /**
     * TODO mivanci Move to dedicated factory class.
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public static function fromState(array $state): self
    {
        $client = new self();

        if (
            !is_string($state['id']) ||
            !is_string($state['secret']) ||
            !is_string($state['name']) ||
            !is_string($state['redirect_uri']) ||
            !is_string($state['scopes']) ||
            !is_string($state['registration_type'])
        ) {
            throw OidcServerException::serverError('Invalid Client Entity state');
        }

        $client->identifier = $state['id'];
        $client->secret = $state['secret'];
        $client->name = $state['name'];
        $client->description = (string)($state['description'] ?? '');
        $client->authSource = empty($state['auth_source']) ? null : (string)$state['auth_source'];

        /** @var string[] $redirectUris */
        $redirectUris = json_decode($state['redirect_uri'], true, 512, JSON_THROW_ON_ERROR);
        $client->redirectUri = $redirectUris;

        /** @var string[] $scopes */
        $scopes = json_decode($state['scopes'], true, 512, JSON_THROW_ON_ERROR);
        $client->scopes = $scopes;

        $client->isEnabled = (bool) $state['is_enabled'];
        $client->isConfidential = (bool) ($state['is_confidential'] ?? false);
        $client->owner = empty($state['owner']) ? null : (string)$state['owner'];

        /** @var string[] $postLogoutRedirectUris */
        $postLogoutRedirectUris = json_decode(
            (string)($state['post_logout_redirect_uri'] ?? "[]"),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        $client->postLogoutRedirectUri = $postLogoutRedirectUris;


        $client->backChannelLogoutUri = empty($state['backchannel_logout_uri']) ?
        null :
        (string)$state['backchannel_logout_uri'];

        $client->entityIdentifier = empty($state['entity_identifier']) ?
        null :
        (string)$state['entity_identifier'];

        /** @var ?string[] $clientRegistrationTypes */
        $clientRegistrationTypes = empty($state['client_registration_types']) ?
        null :
        json_decode((string)$state['client_registration_types'], true, 512, JSON_THROW_ON_ERROR);
        $client->clientRegistrationTypes = $clientRegistrationTypes;

        /** @var ?array[] $federationJwks */
        $federationJwks = empty($state['federation_jwks']) ?
        null :
        json_decode((string)$state['federation_jwks'], true, 512, JSON_THROW_ON_ERROR);
        $client->federationJwks = $federationJwks;

        /** @var ?array[] $jwks */
        $jwks = empty($state['jwks']) ?
        null :
        json_decode((string)$state['jwks'], true, 512, JSON_THROW_ON_ERROR);
        $client->jwks = $jwks;

        $client->jwksUri = empty($state['jwks_uri']) ? null : (string)$state['jwks_uri'];
        $client->signedJwksUri = empty($state['signed_jwks_uri']) ? null : (string)$state['signed_jwks_uri'];

        $client->registrationType = RegistrationTypeEnum::from(trim($state['registration_type']));

        $client->updatedAt = empty($state['updated_at']) ? null :
        TimestampGenerator::utcImmutable((string)$state['updated_at']);
        $client->createdAt = empty($state['created_at']) ? null :
        TimestampGenerator::utcImmutable((string)$state['created_at']);
        $client->expiresAt = empty($state['expires_at']) ? null :
        TimestampGenerator::utcImmutable((string)$state['expires_at']);

        $client->isFederated = (bool)$state['is_federated'];

        return $client;
    }

    /**
     * {@inheritdoc}
     * @throws \JsonException
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'secret' => $this->getSecret(),
            'name' => $this->getName(),
            'description' => $this->getDescription(),
            'auth_source' => $this->getAuthSourceId(),
            'redirect_uri' => json_encode($this->getRedirectUri(), JSON_THROW_ON_ERROR),
            'scopes' => json_encode($this->getScopes(), JSON_THROW_ON_ERROR),
            'is_enabled' => [$this->isEnabled(), PDO::PARAM_BOOL],
            'is_confidential' => [$this->isConfidential(), PDO::PARAM_BOOL],
            'owner' => $this->getOwner(),
            'post_logout_redirect_uri' => json_encode($this->getPostLogoutRedirectUri(), JSON_THROW_ON_ERROR),
            'backchannel_logout_uri' => $this->getBackChannelLogoutUri(),
            'entity_identifier' => $this->getEntityIdentifier(),
            'client_registration_types' => is_null($this->clientRegistrationTypes) ?
                null :
                json_encode($this->getClientRegistrationTypes(), JSON_THROW_ON_ERROR),
            'federation_jwks' => is_null($this->federationJwks) ?
                null :
                json_encode($this->getFederationJwks()),
            'jwks' => is_null($this->jwks) ?
                null :
                json_encode($this->getJwks()),
            'jwks_uri' => $this->getJwksUri(),
            'signed_jwks_uri' => $this->getSignedJwksUri(),
            'registration_type' => $this->getRegistrationType()->value,
            'updated_at' => $this->getUpdatedAt()?->format('Y-m-d H:i:s'),
            'created_at' => $this->getCreatedAt()?->format('Y-m-d H:i:s'),
            'expires_at' => $this->getExpiresAt()?->format('Y-m-d H:i:s'),
            'is_federated' => [$this->isFederated(), PDO::PARAM_BOOL],
        ];
    }

    public function toArray(): array
    {
        return [
            'id' => $this->identifier,
            'secret' => $this->secret,
            'name' => $this->name,
            'description' => $this->description,
            'auth_source' => $this->authSource,
            'redirect_uri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'is_enabled' => $this->isEnabled,
            'is_confidential' => $this->isConfidential,
            'owner' => $this->owner,
            'post_logout_redirect_uri' => $this->postLogoutRedirectUri,
            'backchannel_logout_uri' => $this->backChannelLogoutUri,
            'entity_identifier' => $this->entityIdentifier,
            'client_registration_types' => $this->clientRegistrationTypes,
            'federation_jwks' => $this->federationJwks,
            'jwks' => $this->jwks,
            'jwks_uri' => $this->jwksUri,
            'signed_jwks_uri' => $this->signedJwksUri,
            'registration_type' => $this->registrationType,
            'updated_at' => $this->updatedAt,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'is_federated' => $this->isFederated,
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
}
