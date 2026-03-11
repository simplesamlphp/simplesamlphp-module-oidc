<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\OAuth2;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use Symfony\Component\HttpFoundation\JsonResponse;

class OAuth2ServerConfigurationController
{
    public function __construct(
        protected readonly OpMetadataService $opMetadataService,
        protected readonly Routes $routes,
        protected readonly ModuleConfig $moduleConfig,
    ) {
    }

    public function __invoke(): JsonResponse
    {
        // We'll reuse OIDC configuration.
        $configuration = $this->opMetadataService->getMetadata();

        if (
            $this->moduleConfig->getApiEnabled() &&
            $this->moduleConfig->getApiOAuth2TokenIntrospectionEndpointEnabled()
        ) {
            $configuration[ClaimsEnum::IntrospectionEndpoint->value] = $this->routes->urlApiOAuth2TokenIntrospection();
            $configuration[ClaimsEnum::IntrospectionEndpointAuthMethodsSupported->value] = [
                ClientAuthenticationMethodsEnum::ClientSecretBasic->value,
                ClientAuthenticationMethodsEnum::ClientSecretPost->value,
                ClientAuthenticationMethodsEnum::PrivateKeyJwt->value,
                AccessTokenTypesEnum::Bearer->value,
            ];
            $configuration[ClaimsEnum::IntrospectionEndpointAuthSigningAlgValuesSupported->value] = $this->moduleConfig
                ->getSupportedAlgorithms()
                ->getSignatureAlgorithmBag()
                ->getAllNamesUnique();
        }

        return $this->routes->newJsonResponse(
            $configuration,
        );

        // TODO mivanci Add ability for claim 'signed_metadata' when moving to simplesamlphp/openid, as per
        // https://www.rfc-editor.org/rfc/rfc8414.html#section-2.1, with caching support.
    }
}
