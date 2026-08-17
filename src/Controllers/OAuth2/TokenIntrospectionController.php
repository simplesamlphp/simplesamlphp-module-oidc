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
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;
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
            $introspectionAuthorization = $this->resolveIntrospectionAuthorization($request);
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
            $payload = $this->resolveAccessTokenPayload($tokenParam, $introspectionAuthorization) ??
            $this->resolveRefreshTokenPayload($tokenParam, $introspectionAuthorization);
        } elseif ($tokenTypeHintParam === 'access_token') {
            $payload = $this->resolveAccessTokenPayload($tokenParam, $introspectionAuthorization);
        } elseif ($tokenTypeHintParam === 'refresh_token') {
            $payload = $this->resolveRefreshTokenPayload($tokenParam, $introspectionAuthorization);
        }

        $payload = $payload ?? ['active' => false];

        return $this->routes->newJsonResponse($payload);
    }

    /**
     * Whether the caller is to be told about a token issued to the given client, logging any refusal.
     *
     * Asked with the owner as the token itself gives it, before the payload is assembled: the payload has
     * its empty values dropped, so reading the owner back out of it would lose a client identifier which
     * PHP considers falsy, and refuse that client its own tokens.
     */
    protected function isTokenIntrospectableBy(
        IntrospectionAuthorization $introspectionAuthorization,
        mixed $tokenClientId,
    ): bool {
        $clientId = (is_string($tokenClientId) && $tokenClientId !== '') ? $tokenClientId : null;

        if ($introspectionAuthorization->mayIntrospectTokenOf($clientId)) {
            return true;
        }

        $this->loggerService->warning(
            sprintf(
                'Client %s asked about a token which was not issued to it. Answering as if the token ' .
                'was not active.',
                (string)$introspectionAuthorization->getClientId(),
            ),
        );

        // Deliberately the same answer an expired, revoked or made up token gets. Saying that the token
        // exists but is none of the caller's business would turn the endpoint into an oracle it could ask
        // about tokens it has come into possession of, which is what RFC 7662 section 2.2 has in mind when
        // it has an unauthorized request answered as an inactive token.
        return false;
    }

    protected function resolveAccessTokenPayload(
        string $tokenParam,
        IntrospectionAuthorization $introspectionAuthorization,
    ): ?array {
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

        if (!$this->isTokenIntrospectableBy($introspectionAuthorization, $clientId)) {
            return null;
        }

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
    protected function resolveRefreshTokenPayload(
        string $tokenParam,
        IntrospectionAuthorization $introspectionAuthorization,
    ): ?array {
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

        if (!$this->isTokenIntrospectableBy($introspectionAuthorization, $clientId)) {
            return null;
        }

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
     * Establish who is asking, and with it which tokens they are entitled to be told about.
     *
     * Authenticating is not on its own permission to introspect. A client which authenticates as itself is
     * held to its own tokens, since anything else would let any registered client - including one which
     * registered itself through Dynamic Client Registration - read the subject, scopes and lifetime of
     * tokens belonging to every other client of this OP.
     *
     * @throws AuthorizationException
     * @throws \Exception
     */
    protected function resolveIntrospectionAuthorization(Request $request): IntrospectionAuthorization
    {
        $this->loggerService->debug('TokenIntrospectionController::resolveIntrospectionAuthorization - start');
        $this->loggerService->debug('Trying supported OAuth2 client authentication methods.');

        // First, try regular OAuth2 client authentication methods.
        $resolvedClientAuthenticationMethod = $this->authenticatedOAuth2ClientResolver->forAnySupportedMethod($request);

        if (
            $resolvedClientAuthenticationMethod instanceof ResolvedClientAuthenticationMethod &&
            $resolvedClientAuthenticationMethod->getClientAuthenticationMethod()->isNotNone()
        ) {
            $clientId = $resolvedClientAuthenticationMethod->getClient()->getIdentifier();

            $this->loggerService->debug(
                sprintf(
                    'Client %s authenticated using supported OAuth2 client authentication method %s.',
                    $clientId,
                    $resolvedClientAuthenticationMethod->getClientAuthenticationMethod()->value,
                ),
            );

            if (
                in_array(
                    $clientId,
                    $this->moduleConfig->getApiOAuth2TokenIntrospectionResourceServerClientIds(),
                    true,
                )
            ) {
                $this->loggerService->debug(
                    sprintf(
                        'Client %s is configured as a resource server, so it may introspect any token.',
                        $clientId,
                    ),
                );

                return IntrospectionAuthorization::forAnyToken();
            }

            return IntrospectionAuthorization::forTokensOfClient($clientId);
        }

        $this->loggerService->debug('No regular OAuth2 client authentication method found.');
        $this->loggerService->debug('Trying API client authentication method.');

        $this->apiAuthorization->requireTokenForAnyOfScope(
            $request,
            [ApiScopesEnum::OAuth2TokenIntrospection, ApiScopesEnum::OAuth2All, ApiScopesEnum::All],
        );

        $this->loggerService->debug('API client authenticated.');

        // The administrative path. Reaching it means either a logged in SimpleSAMLphp administrator or an
        // API token the deployment issued and scoped by hand, neither of which is tied to a single client.
        return IntrospectionAuthorization::forAnyToken();
    }
}
