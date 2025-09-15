<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ApplicationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;
use SimpleSAML\OpenID\Codebooks\ScopesEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;

class ClientEntityFactory
{
    public function __construct(
        private readonly SspBridge $sspBridge,
        private readonly Helpers $helpers,
        private readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        private readonly RequestParamsResolver $requestParamsResolver,
        private readonly ModuleConfig $moduleConfig,
    ) {
    }

    /**
     * @param string[] $redirectUri
     * @param string[] $scopes
     * @param string[] $postLogoutRedirectUri
     * @param string[] $clientRegistrationTypes
     * @param array[] $federationJwks
     * @param array[] $jwks
     */
    public function fromData(
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
        bool $isGeneric = false,
    ): ClientEntityInterface {
        return new ClientEntity(
            $id,
            $secret,
            $name,
            $description,
            $redirectUri,
            $scopes,
            $isEnabled,
            $isConfidential,
            $authSource,
            $owner,
            $postLogoutRedirectUri,
            $backChannelLogoutUri,
            $entityIdentifier,
            $clientRegistrationTypes,
            $federationJwks,
            $jwks,
            $jwksUri,
            $signedJwksUri,
            $registrationType,
            $updatedAt,
            $createdAt,
            $expiresAt,
            $isFederated,
            $isGeneric,
        );
    }

    /**
     * Resolve client data from registration metadata.
     *
     * @param array[] $federationJwks
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @psalm-suppress MixedAssignment
     */
    public function fromRegistrationData(
        array $metadata,
        RegistrationTypeEnum $registrationType,
        ?DateTimeImmutable $expiresAt = null,
        ?ClientEntityInterface $existingClient = null,
        ?string $clientIdentifier = null,
        ?array $federationJwks = null,
        ?ServerRequestInterface $authorizationRequest = null,
    ): ClientEntityInterface {

        $id = $clientIdentifier ?? $existingClient?->getIdentifier() ??
        $this->sspBridge->utils()->random()->generateID();

        $secret = $existingClient?->getSecret() ?? $this->sspBridge->utils()->random()->generateID();

        $name = (string)($metadata[ClaimsEnum::ClientName->value] ?? $existingClient?->getName() ?? $id);

        $description = $existingClient?->getDescription() ?? '';

        $authSource = $existingClient?->getAuthSourceId();

        (isset($metadata[ClaimsEnum::RedirectUris->value]) && is_array($metadata[ClaimsEnum::RedirectUris->value])) ||
        throw OidcServerException::accessDenied('redirect URIs missing');
        $redirectUris = $this->helpers->arr()->ensureStringValues($metadata[ClaimsEnum::RedirectUris->value]);

        $scopes = $metadata[ClaimsEnum::Scope->value] ?? $existingClient?->getScopes();
        $scopes = is_array($scopes) ? $this->helpers->arr()->ensureStringValues($scopes) :
        $this->helpers->str()->convertScopesStringToArray((string)$scopes);
        // Filter to only allowed scopes
        $scopes = array_filter(
            $scopes,
            fn(string $scope): bool => $this->claimTranslatorExtractor->hasClaimSet($scope),
        );
        // Let's ensure there is at least 'openid' scope present.
        $scopes = empty($scopes) ? [ScopesEnum::OpenId->value] : $scopes;

        $isEnabled = $existingClient?->isEnabled() ?? true;

        $isConfidential = $existingClient?->isConfidential() ?? $this->determineIsConfidential(
            $metadata,
            $authorizationRequest,
        );

        $owner = $existingClient?->getOwner();

        $postLogoutRedirectUris = isset($metadata[ClaimsEnum::PostLogoutRedirectUris->value]) &&
        is_array($metadata[ClaimsEnum::PostLogoutRedirectUris->value]) ?
        $this->helpers->arr()->ensureStringValues($metadata[ClaimsEnum::PostLogoutRedirectUris->value]) :
        $existingClient?->getPostLogoutRedirectUri() ?? [];

        $backChannelLogoutUri = isset($metadata[ClaimsEnum::BackChannelLogoutUri->value]) &&
        is_string($metadata[ClaimsEnum::BackChannelLogoutUri->value]) ?
        $metadata[ClaimsEnum::BackChannelLogoutUri->value] :
        $existingClient?->getBackChannelLogoutUri();

        $entityIdentifier = $clientIdentifier ?? $existingClient?->getEntityIdentifier();

        $clientRegistrationTypes = isset($metadata[ClaimsEnum::ClientRegistrationTypes->value]) &&
        is_array($metadata[ClaimsEnum::ClientRegistrationTypes->value]) ?
        $this->helpers->arr()->ensureStringValues($metadata[ClaimsEnum::ClientRegistrationTypes->value]) :
        $existingClient?->getClientRegistrationTypes();

        $federationJwks = $federationJwks ?? $existingClient?->getFederationJwks();

        /** @var ?array[] $jwks */
        $jwks = isset($metadata[ClaimsEnum::Jwks->value]) &&
        is_array($metadata[ClaimsEnum::Jwks->value]) &&
        array_key_exists(ClaimsEnum::Keys->value, $metadata[ClaimsEnum::Jwks->value]) &&
        (!empty($metadata[ClaimsEnum::Jwks->value][ClaimsEnum::Keys->value])) ?
        $metadata[ClaimsEnum::Jwks->value] :
        $existingClient?->getJwks();

        $jwksUri = isset($metadata[ClaimsEnum::JwksUri->value]) &&
        is_string($metadata[ClaimsEnum::JwksUri->value]) ?
        $metadata[ClaimsEnum::JwksUri->value] :
        $existingClient?->getJwksUri();

        $signedJwksUri = isset($metadata[ClaimsEnum::SignedJwksUri->value]) &&
        is_string($metadata[ClaimsEnum::SignedJwksUri->value]) ?
        $metadata[ClaimsEnum::SignedJwksUri->value] :
        $existingClient?->getSignedJwksUri();

//        $registrationType = $registrationType;

        $updatedAt = $this->helpers->dateTime()->getUtc();

        $createdAt = $existingClient ? $existingClient->getCreatedAt() : $updatedAt;

//        $expiresAt = $expiresAt;

        $isFederated = $existingClient?->isFederated() ?? false;
        $isGeneric = $existingClient?->isGeneric() ?? false;

        return $this->fromData(
            $id,
            $secret,
            $name,
            $description,
            $redirectUris,
            $scopes,
            $isEnabled,
            $isConfidential,
            $authSource,
            $owner,
            $postLogoutRedirectUris,
            $backChannelLogoutUri,
            $entityIdentifier,
            $clientRegistrationTypes,
            $federationJwks,
            $jwks,
            $jwksUri,
            $signedJwksUri,
            $registrationType,
            $updatedAt,
            $createdAt,
            $expiresAt,
            $isFederated,
            $isGeneric,
        );
    }

    protected function determineIsConfidential(
        array $metadata,
        ?ServerRequestInterface $authorizationRequest,
    ): bool {
        if (
            array_key_exists(ClaimsEnum::ApplicationType->value, $metadata) &&
            $metadata[ClaimsEnum::ApplicationType->value] === ApplicationTypesEnum::Native->value
        ) {
            // Native application type is strong indication of public client.
            return false;
        }

        if (
            array_key_exists(ClaimsEnum::TokenEndpointAuthMethod->value, $metadata) &&
            $metadata[ClaimsEnum::TokenEndpointAuthMethod->value] === TokenEndpointAuthMethodsEnum::None->value
        ) {
            // Value 'none' for token auth method is strong indication of public client.
            return false;
        }

        if (
            array_key_exists(ClaimsEnum::GrantTypes->value, $metadata) &&
            is_array($metadata[ClaimsEnum::GrantTypes->value]) &&
            in_array(GrantTypesEnum::Implicit->value, $metadata[ClaimsEnum::GrantTypes->value], true)
        ) {
            // Explicit statement of implicit grant type is indication of public client.
            return false;
        }

        if (
            array_key_exists(ClaimsEnum::ResponseTypes->value, $metadata) &&
            is_array($metadata[ClaimsEnum::ResponseTypes->value]) &&
            (in_array(ResponseTypesEnum::IdToken->value, $metadata[ClaimsEnum::ResponseTypes->value], true) ||
                in_array(ResponseTypesEnum::IdTokenToken->value, $metadata[ClaimsEnum::ResponseTypes->value], true))
        ) {
            // Response type 'id_token' or 'id_token token' is indication of public client.
            return false;
        }

        if (
            $authorizationRequest &&
            $this->requestParamsResolver->get(ParamsEnum::CodeChallenge->value, $authorizationRequest)
        ) {
            // Usage of code_challenge parameter indicates public client.
            return false;
        }

        // Assume confidential client.
        return true;
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function fromState(array $state): ClientEntityInterface
    {
        if (
            !is_string($state[ClientEntity::KEY_ID]) ||
            !is_string($state[ClientEntity::KEY_SECRET]) ||
            !is_string($state[ClientEntity::KEY_NAME]) ||
            !is_string($state[ClientEntity::KEY_REDIRECT_URI]) ||
            !is_string($state[ClientEntity::KEY_SCOPES]) ||
            !is_string($state[ClientEntity::KEY_REGISTRATION_TYPE])
        ) {
            throw OidcServerException::serverError('Invalid Client Entity state');
        }

        $id = $state[ClientEntity::KEY_ID];
        $secret = $state[ClientEntity::KEY_SECRET];
        $name = $state[ClientEntity::KEY_NAME];
        $description = (string)($state[ClientEntity::KEY_DESCRIPTION] ?? '');

        /** @var string[] $redirectUris */
        $redirectUris = json_decode($state[ClientEntity::KEY_REDIRECT_URI], true, 512, JSON_THROW_ON_ERROR);

        /** @var string[] $scopes */
        $scopes = json_decode($state[ClientEntity::KEY_SCOPES], true, 512, JSON_THROW_ON_ERROR);

        $isEnabled = (bool) $state[ClientEntity::KEY_IS_ENABLED];

        $isConfidential = (bool) ($state[ClientEntity::KEY_IS_CONFIDENTIAL] ?? false);

        $authSource = empty($state[ClientEntity::KEY_AUTH_SOURCE]) ?
        null :
        (string)$state[ClientEntity::KEY_AUTH_SOURCE];

        $owner = empty($state[ClientEntity::KEY_OWNER]) ? null : (string)$state[ClientEntity::KEY_OWNER];

        /** @var string[] $postLogoutRedirectUris */
        $postLogoutRedirectUris = json_decode(
            (string)($state[ClientEntity::KEY_POST_LOGOUT_REDIRECT_URI] ?? "[]"),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        $backChannelLogoutUri = empty($state[ClientEntity::KEY_BACKCHANNEL_LOGOUT_URI]) ?
        null :
        (string)$state[ClientEntity::KEY_BACKCHANNEL_LOGOUT_URI];

        $entityIdentifier = empty($state[ClientEntity::KEY_ENTITY_IDENTIFIER]) ?
        null :
        (string)$state[ClientEntity::KEY_ENTITY_IDENTIFIER];

        /** @var ?string[] $clientRegistrationTypes */
        $clientRegistrationTypes = empty($state[ClientEntity::KEY_CLIENT_REGISTRATION_TYPES]) ?
        null :
        json_decode((string)$state[ClientEntity::KEY_CLIENT_REGISTRATION_TYPES], true, 512, JSON_THROW_ON_ERROR);

        /** @var ?array[] $federationJwks */
        $federationJwks = empty($state[ClientEntity::KEY_FEDERATION_JWKS]) ?
        null :
        json_decode((string)$state[ClientEntity::KEY_FEDERATION_JWKS], true, 512, JSON_THROW_ON_ERROR);

        /** @var ?array[] $jwks */
        $jwks = empty($state[ClientEntity::KEY_JWKS]) ?
        null :
        json_decode((string)$state[ClientEntity::KEY_JWKS], true, 512, JSON_THROW_ON_ERROR);

        $jwksUri = empty($state[ClientEntity::KEY_JWKS_URI]) ? null : (string)$state[ClientEntity::KEY_JWKS_URI];
        $signedJwksUri = empty($state[ClientEntity::KEY_SIGNED_JWKS_URI]) ?
        null :
        (string)$state[ClientEntity::KEY_SIGNED_JWKS_URI];

        $registrationType = RegistrationTypeEnum::from(trim($state[ClientEntity::KEY_REGISTRATION_TYPE]));

        $updatedAt = empty($state[ClientEntity::KEY_UPDATED_AT]) ? null :
        $this->helpers->dateTime()->getUtc((string)$state[ClientEntity::KEY_UPDATED_AT]);
        $createdAt = empty($state[ClientEntity::KEY_CREATED_AT]) ? null :
        $this->helpers->dateTime()->getUtc((string)$state[ClientEntity::KEY_CREATED_AT]);
        $expiresAt = empty($state[ClientEntity::KEY_EXPIRES_AT]) ? null :
        $this->helpers->dateTime()->getUtc((string)$state[ClientEntity::KEY_EXPIRES_AT]);

        $isFederated = (bool)$state[ClientEntity::KEY_IS_FEDERATED];
        $isGeneric = (bool)$state[ClientEntity::KEY_IS_GENERIC];

        return $this->fromData(
            $id,
            $secret,
            $name,
            $description,
            $redirectUris,
            $scopes,
            $isEnabled,
            $isConfidential,
            $authSource,
            $owner,
            $postLogoutRedirectUris,
            $backChannelLogoutUri,
            $entityIdentifier,
            $clientRegistrationTypes,
            $federationJwks,
            $jwks,
            $jwksUri,
            $signedJwksUri,
            $registrationType,
            $updatedAt,
            $createdAt,
            $expiresAt,
            $isFederated,
            $isGeneric,
        );
    }

    public function getGenericForVci(): ClientEntityInterface
    {
        $clientId = 'vci_' .
        hash('sha256', 'vci_'  . $this->moduleConfig->sspConfig()->getString('secretsalt'));

        $clientSecret = $this->helpers->random()->getIdentifier();

        $credentialConfigurationIdsSupported = $this->moduleConfig->getCredentialConfigurationIdsSupported();

        $createdAt = $this->helpers->dateTime()->getUtc();

        return $this->fromData(
            id: $clientId,
            secret: $clientSecret,
            name: 'VCI Generic Client',
            description: 'Generic client for Verifiable Credential Issuance flows.',
            redirectUri: ['openid-credential-offer://'],
            scopes: ['openid', ...$credentialConfigurationIdsSupported],
            isEnabled: true,
            updatedAt: $createdAt,
            createdAt: $createdAt,
            isGeneric: true,
        );
    }
}
