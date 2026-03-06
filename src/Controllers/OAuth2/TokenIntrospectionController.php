<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\OAuth2;

use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class TokenIntrospectionController
{
    /**
     * @throws OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
        protected readonly Authorization $apiAuthorization,
        protected readonly RequestParamsResolver $requestParamsResolver,
        protected readonly BearerTokenValidator $bearerTokenValidator,
    ) {
        if (!$this->moduleConfig->getApiEnabled()) {
            $this->loggerService->warning('API capabilities not enabled.');
            throw OidcServerException::forbidden('API capabilities not enabled.');
        }

        if (!$this->moduleConfig->getApiOAuth2TokenIntrospectionEndpointEnabled()) {
            $this->loggerService->warning('OAuth2 Token Introspection API endpoint not enabled.');
            throw OidcServerException::forbidden('OAuth2 Token Introspection API endpoint not enabled.');
        }
    }

    public function __invoke(Request $request): Response
    {
        // TODO mivanci Add support for Refresh Tokens.
        // TODO mivanci Add endpoint to OAuth2 discovery document.

        try {
            $this->ensureAuthenticatedClient($request);
        } catch (AuthorizationException $e) {
            $this->loggerService->error(
                'TokenIntrospectionController::invoke: AuthorizationException: ' . $e->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'unauthorized',
                description: $e->getMessage(),
                httpCode: Response::HTTP_UNAUTHORIZED,
            );
        }

        $allowedMethods = [HttpMethodsEnum::POST];

        $tokenParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::Token->value,
            $request,
            $allowedMethods,
        );

        if (!$tokenParam) {
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'Missing token parameter.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        // For now, we will only support Access Tokens.
//        $tokenTypeHintParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
//            ParamsEnum::TokenTypeHint->value,
//            $request,
//            $allowedMethods,
//        );

        try {
            $accessToken = $this->bearerTokenValidator->ensureValidAccessToken($tokenParam);
        } catch (\Throwable $e) {
            $this->loggerService->error('Token validation failed: ' . $e->getMessage());
            return $this->routes->newJsonResponse(['active' => false]);
        }
        $scopeClaim = null;
        /** @psalm-suppress MixedAssignment */
        $accessTokenScopes = $accessToken->getPayloadClaim('scopes');
        if (is_array($accessTokenScopes)) {
            $accessTokenScopes = array_filter(
                $accessTokenScopes,
                static fn($scope) => is_string($scope) && !empty($scope),
            );
            $scopeClaim = implode(' ', $accessTokenScopes);
        }

        $audience = is_array($audience = $accessToken->getAudience()) ? $audience[0] ?? null : null;

        $payload = array_filter([
            'active' => true,
            'scope' => $scopeClaim,
            'token_type' => 'Bearer',
            ClaimsEnum::Exp->value => $accessToken->getExpirationTime(),
            ClaimsEnum::Iat->value => $accessToken->getIssuedAt(),
            ClaimsEnum::Nbf->value => $accessToken->getNotBefore(),
            ClaimsEnum::Sub->value => $accessToken->getSubject(),
            ClaimsEnum::Aud->value => $audience,
            ClaimsEnum::Iss->value => $accessToken->getIssuer(),
            ClaimsEnum::Jti->value => $accessToken->getJwtId(),
        ]);

        return $this->routes->newJsonResponse($payload);
    }

    /**
     * @throws AuthorizationException
     */
    protected function ensureAuthenticatedClient(Request $request): void
    {
        $this->loggerService->debug('TokenIntrospectionController::ensureAuthenticatedClient - start');
        $this->loggerService->debug('Trying supported OAuth2 client authentication methods.');

        // First, try regular OAuth2 client authentication methods.
        $resolvedClientAuthenticationMethod = $this->authenticatedOAuth2ClientResolver->forAnySupportedMethod($request);

        if (
            $resolvedClientAuthenticationMethod instanceof ResolvedClientAuthenticationMethod &&
            $resolvedClientAuthenticationMethod->getClientAuthenticationMethod()->isNotNone()
        ) {
            $this->loggerService->debug(
                'Client authenticated using supported OAuth2 client authentication method: ' .
                $resolvedClientAuthenticationMethod->getClientAuthenticationMethod()->value,
            );
            return;
        }

        $this->loggerService->debug('No regular OAuth2 client authentication method found.');
        $this->loggerService->debug('Trying API client authentication method.');


        $this->apiAuthorization->requireTokenForAnyOfScope(
            $request,
            [ApiScopesEnum::OAuth2TokenIntrospection, ApiScopesEnum::OAuth2All, ApiScopesEnum::All],
        );
    }
}
