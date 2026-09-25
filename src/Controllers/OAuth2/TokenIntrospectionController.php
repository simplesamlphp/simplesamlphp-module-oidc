<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\OAuth2;

use Exception;
use SimpleSAML\Module\oidc\Bridges\OAuth2Bridge;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException;
use SimpleSAML\Module\oidc\Factories\IntrospectionReleasePolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\Introspection\ProxiedTokenIntrospector;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Exceptions\JwsParseException;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\ParsedJws;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class TokenIntrospectionController
{
    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
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
        protected readonly AccessTokenRepository $accessTokenRepository,
        protected readonly UserRepository $userRepository,
        protected readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        protected readonly IntrospectionReleasePolicyFactory $introspectionReleasePolicyFactory,
        protected readonly ProxiedTokenIntrospector $proxiedTokenIntrospector,
        protected readonly Jws $jws,
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
        } catch (Throwable $e) {
            // Not a verdict on the caller: a database or cache which did not answer while the caller was being
            // authenticated. Answering 401 would tell a caller with valid credentials that they are invalid
            // (RFC 7662 section 2.3 reserves it for that), so this is the OP's failure, and says so.
            $this->loggerService->error(
                'TokenIntrospectionController::invoke: error while authenticating the caller: ' . $e->getMessage(),
                ['exception' => $e::class],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Unable to process the introspection request.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
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

        try {
            $payload = $this->resolvePayload($tokenParam, $tokenTypeHintParam, $introspectionAuthorization);
        } catch (UpstreamIntrospectionException) {
            // No answer about a token this OP did not issue, from the authorization server asked about it. Not a
            // verdict on the token either, for the same reason as below; logged where it happened, at the level
            // its cause deserves.
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Unable to process the introspection request.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        } catch (Throwable $e) {
            // Again not a verdict, this time on the token: the OP could not read what it answers from (the resource
            // owner's record, say). Answering 'active: false' would have a resource server refuse a valid token,
            // and RFC 7662 section 2.2 lets it cache that answer.
            $this->loggerService->error(
                'TokenIntrospectionController::invoke: error while resolving the token: ' . $e->getMessage(),
                ['exception' => $e::class],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Unable to process the introspection request.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        $payload ??= ['active' => false];

        return $this->routes->newJsonResponse($payload);
    }


    /**
     * The answer about the presented token, or null for one to be answered as inactive.
     *
     * Which kind of token it is, is told from its shape, and the token_type_hint plays no part in that: RFC 7662
     * section 2.1 lets an authorization server "ignore this parameter, particularly if it is able to detect the
     * token type automatically", and a hint naming the wrong type would otherwise have to be searched past. An
     * access token is a compact JWS, while a refresh token of this OP is an encrypted value which never is one, so
     * each value is looked up as the one kind it can be. A JWS naming another issuer is a token this OP did not
     * issue, and is asked about upstream (AARC-G052 proxied token introspection), the hint travelling with it
     * unchanged.
     *
     * Both are read with the library's own parser, the one the validator uses, so that no token of this OP can be
     * taken for something else here, and the value is parsed once: the library tells a value which is not a JWS at
     * all from a JWS which fails a check as it is built.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException When no answer was had from
     * upstream.
     * @throws \Throwable When a record can not be read, or the release policy fails: not a verdict on the token.
     */
    protected function resolvePayload(
        string $tokenParam,
        ?string $tokenTypeHintParam,
        IntrospectionAuthorization $introspectionAuthorization,
    ): ?array {
        // Read without verifying it, and only to route the question. A token naming this OP, or no usable issuer
        // (none, or one which is not a string as RFC 7519 section 4.1.1 has it), is validated here like any other,
        // and one which only claims to be this OP's fails that. So is one whose lifetime is over or has not begun by
        // this OP's clock, beyond the configured leeway: the parsed JWS judges that as it is built, the validator
        // refuses it for the same reason and logs it, and there is no point in asking anyone else about it.
        try {
            $parsedJws = $this->jws->parsedJwsFactory()->fromToken($tokenParam);
            $tokenIssuer = $parsedJws->getIssuer();
        } catch (JwsParseException) {
            return $this->resolveRefreshTokenPayload($tokenParam, $introspectionAuthorization);
        } catch (OpenIdException) {
            return $this->resolveAccessTokenPayload($tokenParam, $introspectionAuthorization);
        }

        if (!is_null($tokenIssuer) && $tokenIssuer !== $this->moduleConfig->getIssuer()) {
            return $this->proxiedTokenIntrospector->introspect(
                $tokenParam,
                $parsedJws,
                $tokenTypeHintParam,
                $introspectionAuthorization,
            );
        }

        return $this->resolveAccessTokenPayload($tokenParam, $introspectionAuthorization);
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
                $introspectionAuthorization->getCallerId(),
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
        } catch (OpenIdException | TokenNotFoundException $e) {
            // The validator's verdicts: not a JWS of ours, not an access token, expired, revoked (the library's
            // exceptions), or no record of it (the repository's). A failed read is none of these -- SimpleSAMLphp's
            // database layer throws a plain Exception, a fetch a PDOException, a corrupt record an
            // OidcServerException -- and is not caught here.
            $this->loggerService->error('Access token validation failed: ' . $e->getMessage());
            return null;
        }

        // See \SimpleSAML\Module\oidc\Entities\AccessTokenEntity::convertToJWT
        // for claims set on the access token.

        $scopes = [];
        /** @psalm-suppress MixedAssignment */
        $accessTokenScopes = $accessToken->getPayloadClaim('scopes');
        if (is_array($accessTokenScopes)) {
            $scopes = $this->scopeTokens($accessTokenScopes);
        }

        $clientId = is_array($audience = $accessToken->getAudience()) ? $audience[0] ?? null : null;

        if (!$this->isTokenIntrospectableBy($introspectionAuthorization, $clientId)) {
            return null;
        }

        $resourceOwner = $this->resolveResourceOwner($accessToken);

        if ($resourceOwner === false) {
            return null;
        }

        $tokenMembers = $this->withoutAbsentMembers([
            'active' => true,
            'scope' => $scopes === [] ? null : implode(' ', $scopes),
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

        // A token minted before the module wrote a 'typ' header carries the internal user identifier as its 'sub',
        // not the resolved subject; for such a token the 'sub' the granted scopes release stands in its place, as it
        // does at the UserInfo endpoint, so that the two endpoints name the End-User the same way for every token.
        // Settled before the policy is asked, so that it is the subject the policy sees and the only one the answer
        // can carry: a policy which takes 'openid' away must not bring the internal identifier back.
        if (is_null($accessToken->getType()) && $resourceOwner instanceof UserEntity) {
            $legacySubject = $this->resolveLegacySubject($scopes, $resourceOwner);

            if (!is_null($legacySubject)) {
                $tokenMembers[ClaimsEnum::Sub->value] = $legacySubject;
            }
        }

        $decision = $this->decideRelease(
            $introspectionAuthorization,
            IntrospectedTokenOrigin::local($this->moduleConfig->getIssuer()),
            $scopes,
            $tokenMembers,
            sprintf('access token %s', (string)$accessToken->getJwtId()),
        );

        if (is_null($decision)) {
            return null;
        }

        $releasedScopes = $decision->releasedScopesOf($scopes);

        // The user claims of the released scopes, and only of those, so that a scope the decision took away can
        // not leave its claims behind. They are read from the resource owner's record as it is now: the claims
        // the UserInfo endpoint releases for the same token, from the same record, so a resource server learns the
        // same about the user whichever endpoint it asks. The 'claims' request parameter (OpenID Connect Core 1.0
        // section 5.5) targets the ID token and the UserInfo endpoint and plays no part here, as it plays none in
        // the access token's own user claims. Nothing is read from the presented token: it is a snapshot taken
        // when it was minted. A released identity claim which is not a non-empty string throws, and is answered
        // as the OP's failure.
        $userClaims = $resourceOwner instanceof UserEntity ?
        $this->claimTranslatorExtractor->extract($releasedScopes, $resourceOwner->getClaims()) :
        [];

        $tokenMembers = $this->withReleasedScope($tokenMembers, $scopes, $releasedScopes);

        // The user claims are further top-level members, as RFC 7662 section 2.2 allows ("Specific implementations
        // MAY extend this structure with their own service-specific response names"). The token's own members are
        // written first and keep the name on a clash: with 'openid' released, the user claims carry a 'sub' resolved
        // from the user record as it is now, while the response reports the subject the token was minted with, the
        // one the ID token issued alongside carries (see the 'sub' note in UserInfoController). The withheld
        // members go last, so that nothing assembled here can put one back: 'sub' is a token member as well as a
        // user claim.
        return $decision->withholdFrom($tokenMembers + $userClaims);
    }


    /**
     * The resource owner whose user claims an active access token releases, as their record is now.
     *
     * Null for a token issued without a user (a client credentials token, a pre-authorized code with no holder).
     * False when the token is not to be reported as active: its own record is gone, or its resource owner's is. The
     * validator has already looked the token's record up, so the former only happens when the record went between
     * the two reads. The latter is decided, not incidental: deleting a user deletes the tokens issued to them (the
     * database cascades it), which is a revocation RFC 7662 section 4 has the authorization server "determine
     * whether or not such a revocation has taken place"; a copy of the token's row in the protocol cache can answer
     * for it until the token expires, and this is where that copy stops passing the token as active.
     *
     * @throws \Throwable When a record can not be read; not a verdict on the token, and answered as the OP's
     * failure.
     */
    protected function resolveResourceOwner(ParsedJws $accessToken): UserEntity|false|null
    {
        $jti = $accessToken->getJwtId();

        // The validator refuses a token without one; a null here would mean it was not run.
        if (is_null($jti)) {
            return false;
        }

        $accessTokenEntity = $this->accessTokenRepository->findById($jti);

        if (!$accessTokenEntity instanceof AccessTokenEntity) {
            $this->loggerService->warning(
                sprintf('Access token %s has no record. Answering as if the token was not active.', $jti),
            );
            return false;
        }

        // Null for a token issued without a user; the entity keeps no empty identifier.
        $userIdentifier = $accessTokenEntity->getUserIdentifier();

        if (is_null($userIdentifier)) {
            return null;
        }

        $user = $this->userRepository->getUserEntityByIdentifier($userIdentifier);

        if (!$user instanceof UserEntity) {
            $this->loggerService->warning(
                sprintf(
                    'Access token %s was issued to user %s, whose record is gone. Answering as if the token was ' .
                    'not active.',
                    $jti,
                    $userIdentifier,
                ),
            );
            return false;
        }

        return $user;
    }


    /**
     * The 'sub' the granted scopes release, resolved on its own: for a token minted before the module wrote a 'typ'
     * header, whose own 'sub' is the internal user identifier. Only the subject is read and checked, so that no
     * other claim of a granted scope (an identity claim with an invalid value, say) can fail the answer before the
     * release policy has decided whether that scope is released at all. Null when no granted scope releases 'sub',
     * or the user record yields none.
     *
     * @param string[] $scopes
     * @throws \RuntimeException When the resolved 'sub' is not a non-empty string; answered as the OP's failure.
     */
    protected function resolveLegacySubject(array $scopes, UserEntity $resourceOwner): ?string
    {
        foreach ($scopes as $scope) {
            $claimSet = $this->claimTranslatorExtractor->getClaimSet($scope);

            if (!is_null($claimSet) && in_array(ClaimsEnum::Sub->value, $claimSet->getClaims(), true)) {
                return $this->claimTranslatorExtractor->extractSubject($resourceOwner->getClaims());
            }
        }

        return null;
    }


    /**
     * The release policy's decision about an active token the caller is entitled to ask about; null when the
     * policy denies the caller the answer, which is then given as for an inactive token, and nothing says why.
     * RFC 7662 section 2.2 answers a properly authorized request as inactive when "the protected resource is
     * not allowed to introspect this particular token".
     *
     * @param string[] $grantedScopes
     * @param array<string, mixed> $tokenMembers The answer as it stands before the decision is applied.
     * @param string $token What to call the token in the log.
     * @throws \SimpleSAML\Error\ConfigurationError When the configured policy can not be built, or its decision
     * names a member no decision may withhold.
     * @throws \Throwable Whatever the policy throws. Like the above, not a verdict on the token, and answered as
     * the OP's failure.
     */
    protected function decideRelease(
        IntrospectionAuthorization $introspectionAuthorization,
        IntrospectedTokenOrigin $origin,
        array $grantedScopes,
        array $tokenMembers,
        string $token,
    ): ?IntrospectionReleaseDecision {
        $decision = $this->introspectionReleasePolicyFactory->build()->decide(
            $introspectionAuthorization,
            $origin,
            $grantedScopes,
            $tokenMembers,
        );

        if (!$decision->isDenied()) {
            return $decision;
        }

        $this->loggerService->notice(
            sprintf(
                'The introspection release policy denies %s %s the answer about %s. Answering as if the token ' .
                'was not active.',
                $introspectionAuthorization->getRole()->value,
                $introspectionAuthorization->getCallerId(),
                $token,
            ),
        );

        return null;
    }


    /**
     * The token members with 'scope' naming only the released scopes, and without it when none is released.
     * Unchanged when every granted scope is released.
     *
     * @param array<string, mixed> $tokenMembers
     * @param string[] $grantedScopes
     * @param string[] $releasedScopes
     * @return array<string, mixed>
     */
    protected function withReleasedScope(array $tokenMembers, array $grantedScopes, array $releasedScopes): array
    {
        if ($releasedScopes === $grantedScopes) {
            return $tokenMembers;
        }

        if ($releasedScopes === []) {
            unset($tokenMembers['scope']);
        } else {
            $tokenMembers['scope'] = implode(' ', $releasedScopes);
        }

        return $tokenMembers;
    }


    /**
     * Leave out only what is absent (null or an empty string): a subject of "0" is valid and must be reported.
     *
     * @param array<string, mixed> $members
     * @return array<string, mixed>
     */
    protected function withoutAbsentMembers(array $members): array
    {
        return array_filter($members, fn(mixed $value): bool => $value !== null && $value !== '');
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
        } catch (Exception $e) {
            $this->loggerService->error('Refresh token decrypting failed: ' . $e->getMessage());
            return null;
        }

        if (!is_array($tokenData)) {
            $this->loggerService->error('Refresh token has unexpected type.');
            return null;
        }

        // See \SimpleSAML\Module\oidc\Server\ResponseTypes\TokenResponse::generateHttpResponse for claims set on
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
        } catch (TokenNotFoundException $e) {
            // The repository's answer for a token it has no record of (its user's deletion cascaded to it, say):
            // a token which "does not exist on this server" is inactive (RFC 7662 section 2.2). A failed read
            // is not this exception, and is not caught here.
            $this->loggerService->error('Refresh token has no record: ' . $e->getMessage());
            return null;
        }

        $scopes = [];
        $refreshTokenScopes = $tokenData['scopes'] ?? null;
        if (is_array($refreshTokenScopes)) {
            $scopes = $this->scopeTokens($refreshTokenScopes);
        }

        $clientId = is_string($clientId = $tokenData['client_id'] ?? null) ? $clientId : null;

        if (!$this->isTokenIntrospectableBy($introspectionAuthorization, $clientId)) {
            return null;
        }

        // The subject the token was issued with, the same one its access token and ID token carry; a payload
        // written before the module recorded it has only the internal user identifier, which then stands as it
        // does in that token's access token.
        $subject = is_string($tokenData['sub'] ?? null) ? $tokenData['sub'] : null;
        $subject ??= is_string($tokenData['user_id'] ?? null) ? $tokenData['user_id'] : null;

        $tokenMembers = $this->withoutAbsentMembers([
            'active' => true,
            'scope' => $scopes === [] ? null : implode(' ', $scopes),
            'client_id' => $clientId,
            ClaimsEnum::Exp->value => $expireTime,
            ClaimsEnum::Sub->value => $subject,
            ClaimsEnum::Aud->value => $clientId,
            ClaimsEnum::Jti->value => $refreshTokenId,
        ]);

        $decision = $this->decideRelease(
            $introspectionAuthorization,
            IntrospectedTokenOrigin::local($this->moduleConfig->getIssuer()),
            $scopes,
            $tokenMembers,
            sprintf('refresh token %s', $refreshTokenId),
        );

        if (is_null($decision)) {
            return null;
        }

        // No user claims to read: a refresh token carries the token members only.
        return $decision->withholdFrom(
            $this->withReleasedScope($tokenMembers, $scopes, $decision->releasedScopesOf($scopes)),
        );
    }


    /**
     * The scope tokens among the values of a token's legacy 'scopes' array; only an absent one (not a string, or
     * the empty string) is left out, so a scope named "0" stands.
     *
     * @return string[]
     */
    protected function scopeTokens(array $scopes): array
    {
        $scopeTokens = [];

        /** @psalm-suppress MixedAssignment */
        foreach ($scopes as $scope) {
            if (is_string($scope) && $scope !== '') {
                $scopeTokens[] = $scope;
            }
        }

        return $scopeTokens;
    }


    /**
     * Establish who is asking, and with it which tokens they are entitled to be told about.
     *
     * Authenticating is not on its own permission to introspect. A client which authenticates as itself is
     * held to its own tokens, since anything else would let any registered client - including one which
     * registered itself through Dynamic Client Registration - read the subject, scopes and lifetime of
     * tokens belonging to every other client of this OP. The deployment names the clients which are more than
     * that - its resource servers, and the upstream hub - and the administrative path (a logged in
     * administrator, an API token) is its own role; see IntrospectionCallerRoleEnum.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     * @throws \SimpleSAML\Error\ConfigurationError When a client is named in two roles, or there is no key to
     * fingerprint an API token which has no name.
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

            // Read first: it refuses a client named in both roles, which must not be settled by whichever
            // list happened to be consulted first.
            if (
                in_array(
                    $clientId,
                    $this->moduleConfig->getApiOAuth2TokenIntrospectionUpstreamHubClientIds(),
                    true,
                )
            ) {
                $this->loggerService->debug(
                    sprintf(
                        'Client %s is configured as the upstream hub, so it may introspect any token this OP ' .
                        'issued.',
                        $clientId,
                    ),
                );

                return IntrospectionAuthorization::forUpstreamHub($clientId);
            }

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

                return IntrospectionAuthorization::forResourceServer($clientId);
            }

            return IntrospectionAuthorization::forClient($clientId);
        }

        $this->loggerService->debug('No regular OAuth2 client authentication method found.');
        $this->loggerService->debug('Trying API client authentication method.');

        $principal = $this->apiAuthorization->requireCallerForAnyOfScope(
            $request,
            [ApiScopesEnum::OAuth2TokenIntrospection, ApiScopesEnum::OAuth2All, ApiScopesEnum::All],
        );

        $this->loggerService->debug(sprintf('API client %s authenticated.', $principal));

        // The administrative path. Reaching it means either a logged in SimpleSAMLphp administrator or an
        // API token the deployment issued and scoped by hand, neither of which is tied to a single client.
        return IntrospectionAuthorization::forAdministrative($principal);
    }
}
