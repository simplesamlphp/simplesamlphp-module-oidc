<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\OpenID\Codebooks\ApplicationTypeEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
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

        // TODO mivanci Continue with checking if grant types contain 'implicit' value.
//        if (
//            array_key_exists(ClaimsEnum::GrantTypes->value, $metadata)
//        ) {
//
//        }

        // Assume confidential client.
        return true;
    }
}
