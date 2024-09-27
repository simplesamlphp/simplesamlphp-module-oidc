<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use DateTimeImmutable;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
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
    ) {
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

        return ClientEntity::fromData(
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
}
