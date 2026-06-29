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
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;

class ClientEntity implements ClientEntityInterface
{
    use EntityTrait;
    use ClientTrait;


    public const string KEY_ID = 'id';
    public const string KEY_SECRET = 'secret';
    public const string KEY_NAME = 'name';
    public const string KEY_DESCRIPTION = 'description';
    public const string KEY_AUTH_SOURCE = 'auth_source';
    public const string KEY_REDIRECT_URI = 'redirect_uri';
    public const string KEY_SCOPES = 'scopes';
    public const string KEY_IS_ENABLED = 'is_enabled';
    public const string KEY_IS_CONFIDENTIAL = 'is_confidential';
    public const string KEY_OWNER = 'owner';
    public const string KEY_POST_LOGOUT_REDIRECT_URI = 'post_logout_redirect_uri';
    public const string KEY_BACKCHANNEL_LOGOUT_URI = 'backchannel_logout_uri';
    public const string KEY_ENTITY_IDENTIFIER = 'entity_identifier';
    public const string KEY_CLIENT_REGISTRATION_TYPES = 'client_registration_types';
    public const string KEY_FEDERATION_JWKS = 'federation_jwks';
    public const string KEY_JWKS = 'jwks';
    public const string KEY_JWKS_URI = 'jwks_uri';
    public const string KEY_SIGNED_JWKS_URI = 'signed_jwks_uri';
    public const string KEY_REGISTRATION_TYPE = 'registration_type';
    public const string KEY_UPDATED_AT = 'updated_at';
    public const string KEY_CREATED_AT = 'created_at';
    public const string KEY_EXPIRES_AT = 'expires_at';
    public const string KEY_IS_GENERIC = 'is_generic';
    public const string KEY_EXTRA_METADATA = 'extra_metadata';
    /**
     * Hash of the OpenID Connect Dynamic Client Registration Access Token, used to authenticate read requests at
     * the Client Configuration Endpoint. The plaintext token is shown to the client only once (at registration).
     */
    public const string KEY_REGISTRATION_ACCESS_TOKEN = 'registration_access_token';
    public const string KEY_ALLOWED_RESPONSE_MODES = 'allowed_response_modes';
    /**
     * Per-client Authentication Processing Filters. Stored as an entry inside
     * the extra metadata JSON blob.
     */
    public const string KEY_AUTH_PROC_FILTERS = 'authproc';

    /**
     * Client properties (metadata keys) which are "administrator-only":
     * they may only be set by a trusted administrator (via the admin UI / API,
     * i.e. ClientEntityFactory::fromData()), and MUST NOT be honored when they
     * arrive in client-supplied registration metadata (OIDC Dynamic Client
     * Registration or OpenID Federation). See the deny-list handling and the
     * accompanying explanation in
     * \SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory::fromRegistrationData().
     *
     * @var string[]
     */
    public const array ADMIN_ONLY_METADATA_KEYS = [
        self::KEY_AUTH_PROC_FILTERS,
    ];


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
    private bool $isGeneric;
    private ?array $extraMetadata;
    private ?string $registrationAccessToken;

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
        bool $isGeneric = false,
        ?array $extraMetadata = null,
        ?string $registrationAccessToken = null,
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
        $this->isGeneric = $isGeneric;
        $this->extraMetadata = $extraMetadata;
        $this->registrationAccessToken = $registrationAccessToken;
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
            self::KEY_IS_GENERIC => $this->isGeneric(),
            self::KEY_EXTRA_METADATA => is_null($this->extraMetadata) ?
                null :
                json_encode($this->extraMetadata, JSON_THROW_ON_ERROR),
            self::KEY_REGISTRATION_ACCESS_TOKEN => $this->registrationAccessToken,
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
            self::KEY_IS_GENERIC => $this->isGeneric,

            // Extra metadata
            ClaimsEnum::IdTokenSignedResponseAlg->value => $this->getIdTokenSignedResponseAlg(),
            self::KEY_ALLOWED_RESPONSE_MODES => $this->getAllowedResponseModes(),
            ClaimsEnum::RequirePushedAuthorizationRequests->value => $this->getRequirePushedAuthorizationRequests(),
            ClaimsEnum::RequireSignedRequestObject->value => $this->getRequireSignedRequestObject(),
            ClaimsEnum::RequestUris->value => $this->getRequestUris(),
            ClaimsEnum::GrantTypes->value => $this->getGrantTypes(),
            ClaimsEnum::ResponseTypes->value => $this->getResponseTypes(),
            ClaimsEnum::TokenEndpointAuthMethod->value => $this->getTokenEndpointAuthMethod(),
            ClaimsEnum::DefaultMaxAge->value => $this->getDefaultMaxAge(),
            ClaimsEnum::RequireAuthTime->value => $this->getRequireAuthTime(),
            ClaimsEnum::DefaultAcrValues->value => $this->getDefaultAcrValues(),
            ClaimsEnum::InitiateLoginUri->value => $this->getInitiateLoginUri(),
            ClaimsEnum::SoftwareId->value => $this->getSoftwareId(),
            ClaimsEnum::SoftwareVersion->value => $this->getSoftwareVersion(),
            ClaimsEnum::LogoUri->value => $this->getLogoUri(),
            ClaimsEnum::ClientUri->value => $this->getClientUri(),
            ClaimsEnum::PolicyUri->value => $this->getPolicyUri(),
            ClaimsEnum::TosUri->value => $this->getTosUri(),
            ClaimsEnum::ApplicationType->value => $this->getApplicationType(),
            ClaimsEnum::Contacts->value => $this->getContacts(),
            self::KEY_AUTH_PROC_FILTERS => $this->getAuthProcFilters(),
            self::KEY_REGISTRATION_ACCESS_TOKEN => $this->registrationAccessToken,
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

    public function isGeneric(): bool
    {
        return $this->isGeneric;
    }

    public function getExtraMetadata(): array
    {
        return $this->extraMetadata ?? [];
    }

    /**
     * Hash of the Registration Access Token associated with this client, or null if none was issued (e.g. clients
     * not created via OIDC Dynamic Client Registration).
     */
    public function getRegistrationAccessTokenHash(): ?string
    {
        return $this->registrationAccessToken;
    }

    public function setRegistrationAccessTokenHash(?string $registrationAccessTokenHash): void
    {
        $this->registrationAccessToken = $registrationAccessTokenHash;
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

    public function getAllowedResponseModes(): array
    {
        /** @psalm-suppress MixedAssignment */
        $allowedResponseModes = $this->extraMetadata[self::KEY_ALLOWED_RESPONSE_MODES] ?? null;

        if (is_array($allowedResponseModes)) {
            return $allowedResponseModes;
        }

        return [
            ResponseModesEnum::Query->value,
            ResponseModesEnum::Fragment->value,
            ResponseModesEnum::FormPost->value,
        ];
    }

    public function getRequirePushedAuthorizationRequests(): bool
    {
        if (!is_array($this->extraMetadata)) {
            return false;
        }

        return (bool)($this->extraMetadata[ClaimsEnum::RequirePushedAuthorizationRequests->value] ?? false);
    }

    public function getRequireSignedRequestObject(): bool
    {
        if (!is_array($this->extraMetadata)) {
            return false;
        }

        return (bool)($this->extraMetadata[ClaimsEnum::RequireSignedRequestObject->value] ?? false);
    }

    /**
     * Per-client Authentication Processing Filters, in the same format as the
     * global ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS option. These run, in
     * addition to the global filters, during authentication for this client
     * (the SimpleSAMLphp ProcessingChain merges them as the "SP" side filters).
     *
     * @return array
     */
    public function getAuthProcFilters(): array
    {
        if (!is_array($this->extraMetadata)) {
            return [];
        }

        /** @var mixed $authProcFilters */
        $authProcFilters = $this->extraMetadata[self::KEY_AUTH_PROC_FILTERS] ?? null;

        return is_array($authProcFilters) ? $authProcFilters : [];
    }

    /**
     * @return string[]
     */
    public function getRequestUris(): array
    {
        if (!is_array($this->extraMetadata)) {
            return [];
        }

        /** @var mixed $uris */
        $uris = $this->extraMetadata[ClaimsEnum::RequestUris->value] ?? null;
        if (!is_array($uris)) {
            return [];
        }

        $stringUris = [];
        /** @var mixed $uri */
        foreach ($uris as $uri) {
            if (is_string($uri)) {
                $stringUris[] = $uri;
            }
        }

        return $stringUris;
    }

    /**
     * The OAuth 2.0 grant types the client is registered to use. Defaults to ["authorization_code"]
     * (OpenID Connect Dynamic Client Registration 1.0 default) when not explicitly registered.
     *
     * @return string[]
     */
    public function getGrantTypes(): array
    {
        /** @var mixed $grantTypes */
        $grantTypes = is_array($this->extraMetadata) ?
        ($this->extraMetadata[ClaimsEnum::GrantTypes->value] ?? null) : null;

        if (!is_array($grantTypes)) {
            return [GrantTypesEnum::AuthorizationCode->value];
        }

        return array_values(array_filter($grantTypes, 'is_string'));
    }

    /**
     * The OAuth 2.0 response types the client is registered to use. Defaults to ["code"]
     * (OpenID Connect Dynamic Client Registration 1.0 default) when not explicitly registered.
     *
     * @return string[]
     */
    public function getResponseTypes(): array
    {
        /** @var mixed $responseTypes */
        $responseTypes = is_array($this->extraMetadata) ?
        ($this->extraMetadata[ClaimsEnum::ResponseTypes->value] ?? null) : null;

        if (!is_array($responseTypes)) {
            return [ResponseTypesEnum::Code->value];
        }

        return array_values(array_filter($responseTypes, 'is_string'));
    }

    /**
     * The client authentication method the client is registered to use at the token endpoint. Defaults to
     * 'client_secret_basic' for confidential clients and 'none' for public clients when not explicitly registered
     * (OpenID Connect Dynamic Client Registration 1.0).
     */
    public function getTokenEndpointAuthMethod(): string
    {
        /** @var mixed $method */
        $method = is_array($this->extraMetadata) ?
        ($this->extraMetadata[ClaimsEnum::TokenEndpointAuthMethod->value] ?? null) : null;

        if (is_string($method) && $method !== '') {
            return $method;
        }

        return $this->isConfidential() ?
        TokenEndpointAuthMethodsEnum::ClientSecretBasic->value :
        TokenEndpointAuthMethodsEnum::None->value;
    }

    /**
     * Default Maximum Authentication Age (seconds) applied when the authorization request omits max_age, or null
     * when not registered.
     */
    public function getDefaultMaxAge(): ?int
    {
        /** @var mixed $value */
        $value = is_array($this->extraMetadata) ?
        ($this->extraMetadata[ClaimsEnum::DefaultMaxAge->value] ?? null) : null;

        if (is_int($value) && $value >= 0) {
            return $value;
        }

        // Tolerate a numeric string (e.g. when read back from JSON-ish storage).
        if (is_string($value) && $value !== '' && ctype_digit($value)) {
            return (int)$value;
        }

        return null;
    }

    /**
     * Whether the auth_time claim is required in the ID Token issued to this client.
     */
    public function getRequireAuthTime(): bool
    {
        /** @var mixed $value */
        $value = is_array($this->extraMetadata) ?
        ($this->extraMetadata[ClaimsEnum::RequireAuthTime->value] ?? null) : null;

        return $value === true || $value === 'true' || $value === 1 || $value === '1';
    }

    /**
     * Default ACR values requested when the authorization request omits acr_values.
     *
     * @return string[]
     */
    public function getDefaultAcrValues(): array
    {
        /** @var mixed $values */
        $values = is_array($this->extraMetadata) ?
        ($this->extraMetadata[ClaimsEnum::DefaultAcrValues->value] ?? null) : null;

        if (!is_array($values)) {
            return [];
        }

        return array_values(array_filter($values, 'is_string'));
    }

    /**
     * URI a third party can use to initiate login for this client (informational; the OP does not act on it).
     */
    public function getInitiateLoginUri(): ?string
    {
        return $this->getStringExtraMetadata(ClaimsEnum::InitiateLoginUri->value);
    }

    /**
     * RFC 7591 software_id (informational).
     */
    public function getSoftwareId(): ?string
    {
        return $this->getStringExtraMetadata(ClaimsEnum::SoftwareId->value);
    }

    /**
     * RFC 7591 software_version (informational).
     */
    public function getSoftwareVersion(): ?string
    {
        return $this->getStringExtraMetadata(ClaimsEnum::SoftwareVersion->value);
    }

    /**
     * logo_uri (informational; subject to impersonation protection on the DCR path).
     */
    public function getLogoUri(): ?string
    {
        return $this->getStringExtraMetadata(ClaimsEnum::LogoUri->value);
    }

    /**
     * client_uri (informational).
     */
    public function getClientUri(): ?string
    {
        return $this->getStringExtraMetadata(ClaimsEnum::ClientUri->value);
    }

    /**
     * policy_uri (informational; subject to impersonation protection on the DCR path).
     */
    public function getPolicyUri(): ?string
    {
        return $this->getStringExtraMetadata(ClaimsEnum::PolicyUri->value);
    }

    /**
     * tos_uri (informational; subject to impersonation protection on the DCR path).
     */
    public function getTosUri(): ?string
    {
        return $this->getStringExtraMetadata(ClaimsEnum::TosUri->value);
    }

    /**
     * application_type (web or native), or null when not registered.
     */
    public function getApplicationType(): ?string
    {
        return $this->getStringExtraMetadata(ClaimsEnum::ApplicationType->value);
    }

    /**
     * contacts (e.g. administrator e-mail addresses).
     *
     * @return string[]
     */
    public function getContacts(): array
    {
        /** @var mixed $contacts */
        $contacts = is_array($this->extraMetadata) ?
        ($this->extraMetadata[ClaimsEnum::Contacts->value] ?? null) : null;

        if (!is_array($contacts)) {
            return [];
        }

        return array_values(array_filter($contacts, 'is_string'));
    }

    private function getStringExtraMetadata(string $key): ?string
    {
        /** @var mixed $value */
        $value = is_array($this->extraMetadata) ? ($this->extraMetadata[$key] ?? null) : null;

        return (is_string($value) && $value !== '') ? $value : null;
    }
}
