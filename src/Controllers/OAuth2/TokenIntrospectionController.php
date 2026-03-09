<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\OAuth2;

use SimpleSAML\Module\oidc\Bridges\OAuth2Bridge;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
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
        protected readonly OAuth2Bridge $oAuth2Bridge,
        protected readonly RefreshTokenRepository $refreshTokenRepository,
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

        $tokenTypeHintParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::TokenTypeHint->value,
            $request,
            $allowedMethods,
        );

        $payload = null;
        if (is_null($tokenTypeHintParam)) {
            $payload = $this->resolveAccessTokenPayload($tokenParam) ??
            $this->resolveRefreshTokenPayload($tokenParam);
        } elseif ($tokenTypeHintParam === 'access_token') {
            $payload = $this->resolveAccessTokenPayload($tokenParam);
        } elseif ($tokenTypeHintParam === 'refresh_token') {
            $payload = $this->resolveRefreshTokenPayload($tokenParam);
        }

        $payload = $payload ?? ['active' => false];

        return $this->routes->newJsonResponse($payload);
    }

    protected function resolveAccessTokenPayload(string $tokenParam): ?array
    {
        try {
            $accessToken = $this->bearerTokenValidator->ensureValidAccessToken($tokenParam);
        } catch (\Throwable $e) {
            $this->loggerService->error('Access token validation failed: ' . $e->getMessage());
            return null;
        }

        // See \SimpleSAML\Module\oidc\Entities\AccessTokenEntity::convertToJWT
        // for claims set on the access token.

        $scopeClaim = null;
        /** @psalm-suppress MixedAssignment */
        $accessTokenScopes = $accessToken->getPayloadClaim('scopes');
        if (is_array($accessTokenScopes)) {
            $scopeClaim = $this->prepareScopeString($accessTokenScopes);
        }

        $clientId = is_array($audience = $accessToken->getAudience()) ? $audience[0] ?? null : null;

        return array_filter([
            'active' => true,
            'scope' => $scopeClaim,
            'client_id' => $clientId,
            'token_type' => 'Bearer',
            ClaimsEnum::Exp->value => $accessToken->getExpirationTime(),
            ClaimsEnum::Iat->value => $accessToken->getIssuedAt(),
            ClaimsEnum::Nbf->value => $accessToken->getNotBefore(),
            ClaimsEnum::Sub->value => $accessToken->getSubject(),
            ClaimsEnum::Aud->value => $accessToken->getAudience(),
            ClaimsEnum::Iss->value => $accessToken->getIssuer(),
            ClaimsEnum::Jti->value => $accessToken->getJwtId(),
        ]);
    }

    /**
     * @psalm-suppress MixedAssignment
     */
    public function resolveRefreshTokenPayload(string $tokenParam): ?array
    {
        try {
            $decryptedToken = $this->oAuth2Bridge->decrypt($tokenParam);
            $tokenData = json_decode($decryptedToken, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $e) {
            $this->loggerService->error('Refresh token decrypting failed: ' . $e->getMessage());
            return null;
        }

        if (!is_array($tokenData)) {
            $this->loggerService->error('Refresh token has unexpected type.');
            return null;
        }

        // See \League\OAuth2\Server\ResponseTypes\BearerTokenResponse::generateHttpResponse for claims set on
        // the refresh token.

        $expireTime = is_int($expireTime = $tokenData['expire_time'] ?? null) ? $expireTime : null;

        if (is_null($expireTime)) {
            $this->loggerService->error('Refresh token has no expiration time.');
            return null;
        }

        if ($expireTime < time()) {
            $this->loggerService->error('Refresh token has expired.');
            return null;
        }

        $refreshTokenId = is_string($refreshTokenId = $tokenData['refresh_token_id'] ?? null) ? $refreshTokenId : null;

        if (is_null($refreshTokenId)) {
            $this->loggerService->error('Refresh token has no ID.');
            return null;
        }

        try {
            if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenId)) {
                $this->loggerService->error('Refresh token has been revoked.');
                return null;
            }
        } catch (OidcServerException $e) {
            $this->loggerService->error('Refresh token revocation check failed: ' . $e->getMessage());
            return null;
        }

        $scopeClaim = null;
        $refreshTokenScopes = $tokenData['scopes'] ?? null;
        if (is_array($refreshTokenScopes)) {
            $scopeClaim = $this->prepareScopeString($refreshTokenScopes);
        }

        $clientId = is_string($clientId = $tokenData['client_id'] ?? null) ? $clientId : null;

        return array_filter([
            'active' => true,
            'scope' => $scopeClaim,
            'client_id' => $clientId,
            ClaimsEnum::Exp->value => $expireTime,
            ClaimsEnum::Sub->value => is_string($tokenData['user_id'] ?? null) ? $tokenData['user_id'] : null,
            ClaimsEnum::Aud->value => $clientId,
            ClaimsEnum::Jti->value => $refreshTokenId,
        ]);
    }

    protected function prepareScopeString(array $scopes): string
    {
        $scopes = array_filter(
            $scopes,
            static fn($scope) => is_string($scope) && !empty($scope),
        );

        return implode(' ', $scopes);
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
                sprintf(
                    'Client %s authenticated using supported OAuth2 client authentication method %s.',
                    $resolvedClientAuthenticationMethod->getClient()->getIdentifier(),
                    $resolvedClientAuthenticationMethod->getClientAuthenticationMethod()->value,
                ),
            );

            return;
        }

        $this->loggerService->debug('No regular OAuth2 client authentication method found.');
        $this->loggerService->debug('Trying API client authentication method.');

        $this->apiAuthorization->requireTokenForAnyOfScope(
            $request,
            [ApiScopesEnum::OAuth2TokenIntrospection, ApiScopesEnum::OAuth2All, ApiScopesEnum::All],
        );

        $this->loggerService->debug('API client authenticated.');
    }
}
