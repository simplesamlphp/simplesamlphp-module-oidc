<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\OpenID\Codebooks\ApplicationTypeEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodEnum;

class ClientEntityFactory
{
    public function __construct(
        private readonly SspBridge $sspBridge,
        private readonly Helpers $helpers,
    ) {
    }

    /**
     * Resolve client data from registration metadata. Resolved data can be used to create new ClientEntity instance.
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     *
     * @psalm-suppress MixedAssignment
     */
    public function resolveRegistrationData(
        array $metadata,
        ?ClientEntity $client = null,
        ?string $clientIdentifier = null,
    ): array {
        $data = [];

        $data[ClientEntity::KEY_ID] = $clientIdentifier ?? $client?->getIdentifier() ?? $this->sspBridge->utils()->random()->generateID();

        $data[ClientEntity::KEY_SECRET] = $client?->getSecret() ?? $this->sspBridge->utils()->random()->generateID();

        $data[ClientEntity::KEY_NAME] = $metadata[ClaimsEnum::ClientName->value] ?? $client?->getName() ?? $data[ClientEntity::KEY_ID];

        $data[ClientEntity::KEY_DESCRIPTION] = $client?->getDescription() ?? '';

        $data[ClientEntity::KEY_AUTH_SOURCE] = $client?->getAuthSourceId();

        $data[ClientEntity::KEY_REDIRECT_URI] = $metadata[ClaimsEnum::RedirectUris->value] ??
        throw OidcServerException::accessDenied('redirect URIs missing');

        $scopes = $metadata[ClaimsEnum::Scope->value] ?? $client?->getScopes();
        $data[ClientEntity::KEY_SCOPES] = is_array($scopes) ? $scopes :
        $this->helpers->str()->convertScopesStringToArray((string)$scopes);

        $data[ClientEntity::KEY_IS_ENABLED] = $client?->isEnabled() ?? true;

        $data[ClientEntity::KEY_IS_CONFIDENTIAL] = $client?->isConfidential() ??
        $this->guessIsConfidential($metadata);

        $data[ClientEntity::KEY_OWNER] = $client?->getOwner();

        $data[ClientEntity::KEY_POST_LOGOUT_REDIRECT_URI] = $metadata[ClaimsEnum::PostLogoutRedirectUris->value] ??
        $client?->getPostLogoutRedirectUri();

        $data[ClientEntity::KEY_BACKCHANNEL_LOGOUT_URI] = $metadata[ClaimsEnum::BackChannelLogoutUri->value] ??
        $client?->getBackChannelLogoutUri();

        return $data;
    }

    protected function guessIsConfidential(array $metadata): bool
    {
        if (
            array_key_exists(ClaimsEnum::ApplicationType->value, $metadata) &&
            $metadata[ClaimsEnum::ApplicationType->value] === ApplicationTypeEnum::Native->value
        ) {
            // Native application type is strong indication of public client.
            return false;
        }

        if (
            array_key_exists(ClaimsEnum::TokenEndpointAuthMethod->value, $metadata) &&
            $metadata[ClaimsEnum::TokenEndpointAuthMethod->value] === TokenEndpointAuthMethodEnum::None->value
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

        // Assume confidential client.
        return true;
    }
}
