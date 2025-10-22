<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\CodeChallengeVerifiers\PlainVerifier;
use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Grant\AuthCodeGrant as OAuth2AuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface as OAuth2AuthCodeRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithRequestRules;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\OidcCapableGrantTypeInterface;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\PkceEnabledGrantTypeInterface;
use SimpleSAML\Module\oidc\Server\Grants\Traits\IssueAccessTokenTrait;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeVerifierRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IssuerStateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeOfflineAccessRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AcrResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AuthTimeResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\NonceResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\SessionIdResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

use function array_key_exists;

class AuthCodeGrant extends OAuth2AuthCodeGrant implements
    // phpcs:ignore
    PkceEnabledGrantTypeInterface,
    // phpcs:ignore
    OidcCapableGrantTypeInterface,
    // phpcs:ignore
    AuthorizationValidatableWithRequestRules
{
    use IssueAccessTokenTrait;

    protected DateInterval $authCodeTTL;

    /** @var \League\OAuth2\Server\CodeChallengeVerifiers\CodeChallengeVerifierInterface[] */
    protected array $codeChallengeVerifiers = [];

    /**
     * @var \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $authCodeRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $accessTokenRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $refreshTokenRepository;

    /**
     * @var bool
     * @psalm-suppress PropertyNotSetInConstructor
      */
    protected $revokeRefreshTokens;

    /**
     * @var string
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $defaultScope;

    /**
     * @var \League\OAuth2\Server\Repositories\UserRepositoryInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $userRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\ScopeRepositoryInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $scopeRepository;

    /**
     * @var \League\OAuth2\Server\Repositories\ClientRepositoryInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $clientRepository;

    /**
     * @var \League\OAuth2\Server\CryptKey
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $privateKey;

    /** @var HttpMethodsEnum[]  */
    protected array $allowedAuthorizationHttpMethods = [HttpMethodsEnum::GET, HttpMethodsEnum::POST];

    /** @var HttpMethodsEnum[]  */
    protected array $allowedTokenHttpMethods = [HttpMethodsEnum::POST];

    /**
     * @psalm-type AuthCodePayloadObject = object{
     *     scopes: null|string|array,
     *     user_id: null|string,
     *     code_challenge?: non-empty-string,
     *     code_challenge_method?: non-empty-string,
     *     auth_code_id: string,
     *     nonce?: null|non-empty-string,
     *     auth_time?: null|int,
     *     acr?: null|string,
     *     session_id?: null|string
     * }
     * @throws \Exception
     */
    public function __construct(
        OAuth2AuthCodeRepositoryInterface $authCodeRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL,
        protected RequestRulesManager $requestRulesManager,
        protected RequestParamsResolver $requestParamsResolver,
        AccessTokenEntityFactory $accessTokenEntityFactory,
        protected AuthCodeEntityFactory $authCodeEntityFactory,
        protected RefreshTokenIssuer $refreshTokenIssuer,
        protected Helpers $helpers,
        protected LoggerService $loggerService,
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);

        $this->setAuthCodeRepository($authCodeRepository);
        $this->setAccessTokenRepository($accessTokenRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->authCodeTTL = $authCodeTTL;

        if (in_array('sha256', hash_algos(), true)) {
            $s256Verifier = new S256Verifier();
            $this->codeChallengeVerifiers[$s256Verifier->getMethod()] = $s256Verifier;
        }

        $plainVerifier = new PlainVerifier();
        $this->codeChallengeVerifiers[$plainVerifier->getMethod()] = $plainVerifier;

        $this->accessTokenEntityFactory = $accessTokenEntityFactory;
    }

    /**
     * Reimplemented in order to support HTTP POST method.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @return bool
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        $this->loggerService->debug('AuthCodeGrant::canRespondToAuthorizationRequest');

        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $this->allowedAuthorizationHttpMethods,
        );

        return (array_key_exists('response_type', $requestParams)
            && $requestParams['response_type'] === 'code'
            && isset($requestParams['client_id']));
    }

    /**
     * Check if the authorization request is OIDC candidate (can respond with ID token).
     */
    public function isOidcCandidate(
        OAuth2AuthorizationRequest $authorizationRequest,
    ): bool {
        // Check if the scopes contain 'oidc' scope
        return (bool) $this->helpers->arr()->findByCallback(
            $authorizationRequest->getScopes(),
            fn(ScopeEntityInterface $scope) => $scope->getIdentifier() === 'openid',
        );
    }

    /**
     * @inheritDoc
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function completeAuthorizationRequest(
        OAuth2AuthorizationRequest $authorizationRequest,
    ): ResponseTypeInterface {
        if ($authorizationRequest instanceof AuthorizationRequest) {
            return $this->completeOidcAuthorizationRequest($authorizationRequest);
        }

        return parent::completeAuthorizationRequest($authorizationRequest);
    }

    /**
     * This is reimplementation of OAuth2 completeAuthorizationRequest method with addition of nonce handling.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \JsonException
     */
    public function completeOidcAuthorizationRequest(
        AuthorizationRequest $authorizationRequest,
    ): RedirectResponse {
        $user = $authorizationRequest->getUser();
        if ($user instanceof UserEntity === false) {
            throw new LogicException('An instance of UserEntity should be set on the ' .
                'AuthorizationRequest');
        }

        $finalRedirectUri = $authorizationRequest->getRedirectUri()
        ?? $this->getClientRedirectUri($authorizationRequest);

        if ($authorizationRequest->isAuthorizationApproved() !== true) {
            // The user denied the client, redirect them back with an error
            throw OidcServerException::accessDenied(
                'The user denied the request',
                $finalRedirectUri,
                null,
                $authorizationRequest->getState(),
            );
        }

        // The user approved the client, redirect them back with an auth code
        $authCode = $this->issueOidcAuthCode(
            $this->authCodeTTL,
            $authorizationRequest->getClient(),
            $user->getIdentifier(),
            $finalRedirectUri,
            $authorizationRequest,
        );

        $payload = [
            'client_id'             => $authCode->getClient()->getIdentifier(),
            'redirect_uri'          => $authCode->getRedirectUri(),
            'auth_code_id'          => $authCode->getIdentifier(),
            'scopes'                => $authCode->getScopes(),
            'user_id'               => $authCode->getUserIdentifier(),
            'expire_time'           => (new DateTimeImmutable())->add($this->authCodeTTL)->getTimestamp(),
            'code_challenge'        => $authorizationRequest->getCodeChallenge(),
            'code_challenge_method' => $authorizationRequest->getCodeChallengeMethod(),
            'nonce'                 => $authorizationRequest->getNonce(),
            'auth_time'             => $authorizationRequest->getAuthTime(),
            'claims'                => $authorizationRequest->getClaims(),
            'acr'                   => $authorizationRequest->getAcr(),
            'session_id'            => $authorizationRequest->getSessionId(),
            // Do not add anything else to the payload, as it will make it dangerously long to send it as a query
            // parameter. Use storage instead.
        ];

        $jsonPayload = json_encode($payload, JSON_THROW_ON_ERROR);

        $response = new RedirectResponse();
        $response->setRedirectUri(
            $this->makeRedirectUri(
                $finalRedirectUri,
                [
                    'code'  => $this->encrypt($jsonPayload),
                    'state' => $authorizationRequest->getState(),
                ],
            ),
        );

        return $response;
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueOidcAuthCode(
        DateInterval $authCodeTTL,
        OAuth2ClientEntityInterface $client,
        string $userIdentifier,
        string $redirectUri,
        AuthorizationRequest $authorizationRequest,
    ): AuthCodeEntityInterface {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        if (!is_a($this->authCodeRepository, AuthCodeRepositoryInterface::class)) {
            throw OidcServerException::serverError('Unexpected auth code repository entity type.');
        }

        $flowType = $authorizationRequest->isVciRequest() ?
        FlowTypeEnum::VciAuthorizationCode :
        FlowTypeEnum::OidcAuthorizationCode;

        while ($maxGenerationAttempts-- > 0) {
            try {
                $authCode = $this->authCodeEntityFactory->fromData(
                    $this->generateUniqueIdentifier(),
                    $client,
                    $authorizationRequest->getScopes(),
                    (new DateTimeImmutable())->add($authCodeTTL),
                    $userIdentifier,
                    $redirectUri,
                    $authorizationRequest->getNonce(),
                    $authorizationRequest->getIssuerState(),
                    flowTypeEnum: $flowType,
                    authorizationDetails: $authorizationRequest->getAuthorizationDetails(),
                    boundClientId: $authorizationRequest->getBoundClientId(),
                    boundRedirectUri: $authorizationRequest->getBoundRedirectUri(),
                );
                $this->authCodeRepository->persistNewAuthCode($authCode);

                return $authCode;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        throw OAuthServerException::serverError('Could not issue OIDC Auth Code.');
    }

    /**
     * Get the client redirect URI if not set in the request.
     *
     * @param \League\OAuth2\Server\RequestTypes\AuthorizationRequest $authorizationRequest
     *
     * @return string
     */
    protected function getClientRedirectUri(OAuth2AuthorizationRequest $authorizationRequest): string
    {
        $rediretctUri = $authorizationRequest->getClient()->getRedirectUri();

        if (is_array($rediretctUri)) {
            return $rediretctUri[0];
        }

        return $rediretctUri;
    }

    /**
     * Reimplementation of respondToAccessTokenRequest because of features like nonce, private_key_jwt, acr...
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface $responseType
     * @param \DateInterval $accessTokenTTL
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     * @throws \Throwable
     *
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        // OAuth2 implementation
        //[$clientId] = $this->getClientCredentials($request);

        $this->loggerService->debug(
            'AuthCodeGrant::respondToAccessTokenRequest',
            $this->requestParamsResolver->getAllBasedOnAllowedMethods($request, $this->allowedTokenHttpMethods),
        );

        $encryptedAuthCode = $this->getRequestParameter('code', $request);

        if ($encryptedAuthCode === null) {
            $this->loggerService->debug('Code parameter not provided.');
            throw OAuthServerException::invalidRequest('code');
        }

        try {
            /**
             * @noinspection PhpUndefinedClassInspection
             * @psalm-var AuthCodePayloadObject $authCodePayload
             */
            $authCodePayload = json_decode($this->decrypt($encryptedAuthCode), null, 512, JSON_THROW_ON_ERROR);
        } catch (LogicException $e) {
            throw OAuthServerException::invalidRequest('code', 'Cannot decrypt the authorization code', $e);
        }

        if (!property_exists($authCodePayload, 'auth_code_id')) {
            throw OAuthServerException::invalidRequest('code', 'Authorization code malformed');
        }

        if (! is_a($this->authCodeRepository, AuthCodeRepository::class)) {
            throw OidcServerException::serverError('Unexpected auth code repository entity type.');
        }

        $storedAuthCodeEntity = $this->authCodeRepository->findById($authCodePayload->auth_code_id);

        if ($storedAuthCodeEntity === null) {
            throw OAuthServerException::invalidGrant('Authorization code not found');
        }

        // Client used during authorization request.
        $authorizationClientEntity = $storedAuthCodeEntity->getClient();

        if (! $authorizationClientEntity instanceof ClientEntity) {
            throw OidcServerException::serverError('Unexpected Client Entity instance.');
        }

        $rulesToExecute = [
            CodeVerifierRule::class,
        ];

        if (! $authorizationClientEntity->isGeneric()) {
            $this->loggerService->debug('Executing standard rules for non-generic clients.');
            $rulesToExecute = [
                ClientRule::class,
                ClientRedirectUriRule::class,
                ClientAuthenticationRule::class,
                ...$rulesToExecute,
            ];
        } else {
            $this->loggerService->debug('Generic client encountered. Checking for authorization bound params.');
            // We used generic client in the flow, so check for bound client_id and redirect_uri.
            // Currently used client_id and redirect_uri must be the same as in authorization request.
            $clientId = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
                ParamsEnum::ClientId->value,
                $request,
                $this->allowedTokenHttpMethods,
            );

            // For now, we require client_id, however, in the future this will have to be resolved based on used
            // client authentication...
            if (! $clientId) {
                throw OidcServerException::invalidRequest('client_id');
            }

            if ($clientId !== $storedAuthCodeEntity->getBoundClientId()) {
                throw OAuthServerException::invalidGrant('Authorization code not intended for this client_id.');
            }

            $redirectUri = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
                ParamsEnum::RedirectUri->value,
                $request,
                $this->allowedTokenHttpMethods,
            );

            if (! $redirectUri) {
                throw OidcServerException::invalidRequest(ParamsEnum::RedirectUri->value);
            }

            if ($redirectUri !== $storedAuthCodeEntity->getBoundRedirectUri()) {
                throw OAuthServerException::invalidGrant('Authorization code not intended for this redirect_uri.');
            }

            $this->requestRulesManager->predefineResult(new Result(ClientRule::class, $authorizationClientEntity));
        }

        $resultBag = $this->requestRulesManager->check(
            $request,
            $rulesToExecute,
            false,
            $this->allowedTokenHttpMethods,
        );

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $authorizationClientEntity->isGeneric() ?
        $authorizationClientEntity :
        $resultBag->getOrFail(ClientRule::class)->getValue();

        /** @var ?string $clientAuthenticationParam */
        $clientAuthenticationParam = $authorizationClientEntity->isGeneric() ?
        null :
        $resultBag->getOrFail(ClientAuthenticationRule::class)->getValue();

        /** @var ?string $codeVerifier */
        $codeVerifier = $resultBag->getOrFail(CodeVerifierRule::class)->getValue();

        $utilizedClientAuthenticationParams = [];

        if (!is_null($clientAuthenticationParam)) {
            $utilizedClientAuthenticationParams[] = $clientAuthenticationParam;
        }
        if (!is_null($codeVerifier)) {
            $utilizedClientAuthenticationParams[] = ParamsEnum::CodeVerifier->value;
        }

        if (empty($utilizedClientAuthenticationParams)) {
            throw OidcServerException::accessDenied('Client authentication not performed.');
        }

        // OAuth2 implementation
        //$client = $this->getClientEntityOrFail((string)$clientId, $request);

        // OAuth2 implementation
        // Only validate the client if it is confidential
//        if ($client->isConfidential()) {
//            $this->validateClient($request);
//        }

        $this->validateAuthorizationCode($authCodePayload, $client, $request, $storedAuthCodeEntity);

        $scopes = $this->scopeRepository->finalizeScopes(
            $this->validateScopes($authCodePayload->scopes),
            $this->getIdentifier(),
            $client,
            $authCodePayload->user_id,
        );

        // OAuth2 implementation
//        $codeVerifier = $this->getRequestParameter('code_verifier', $request);

        // If a code challenge isn't present but a code verifier is, reject the request to block PKCE downgrade attack
        if (empty($authCodePayload->code_challenge) && $codeVerifier !== null) {
            throw OAuthServerException::invalidRequest(
                'code_challenge',
                'code_verifier received when no code_challenge is present',
            );
        }

        // Validate code challenge
        if (!empty($authCodePayload->code_challenge)) {
            if ($codeVerifier === null) {
                throw OAuthServerException::invalidRequest('code_verifier');
            }

            // OAuth2 implementation
            // Validate code_verifier according to RFC-7636
            // @see: https://tools.ietf.org/html/rfc7636#section-4.1
//            if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeVerifier) !== 1) {
//                throw OAuthServerException::invalidRequest(
//                    'code_verifier',
//                    'Code Verifier must follow the specifications of RFC-7636.',
//                );
//            }

            if (property_exists($authCodePayload, 'code_challenge_method')) {
                if (isset($this->codeChallengeVerifiers[$authCodePayload->code_challenge_method])) {
                    $codeChallengeVerifier = $this->codeChallengeVerifiers[$authCodePayload->code_challenge_method];

                    if (
                        $codeChallengeVerifier->verifyCodeChallenge(
                            $codeVerifier,
                            $authCodePayload->code_challenge,
                        ) === false
                    ) {
                        throw OAuthServerException::invalidGrant('Failed to verify `code_verifier`.');
                    }
                } else {
                    throw OAuthServerException::serverError(
                        sprintf(
                            'Unsupported code challenge method `%s`',
                            ($authCodePayload->code_challenge_method ?? ''),
                        ),
                    );
                }
            }
        }

        /** @var array $claims */
        $claims = property_exists($authCodePayload, 'claims') ?
        json_decode(json_encode($authCodePayload->claims, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR)
        : null;

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken(
            $accessTokenTTL,
            $client,
            $authCodePayload->user_id,
            $scopes,
            $authCodePayload->auth_code_id,
            $claims,
            $storedAuthCodeEntity->getFlowTypeEnum(),
            $storedAuthCodeEntity->getAuthorizationDetails(),
            $storedAuthCodeEntity->getBoundClientId(),
            $storedAuthCodeEntity->getBoundRedirectUri(),
            $storedAuthCodeEntity->getIssuerState(),
        );
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);

        // Set nonce in response if the auth code had one set.
        if (
            $responseType instanceof NonceResponseTypeInterface &&
            property_exists($authCodePayload, 'nonce') &&
            ! empty($authCodePayload->nonce)
        ) {
            $responseType->setNonce($authCodePayload->nonce);
        }

        if (
            $responseType instanceof AuthTimeResponseTypeInterface &&
            property_exists($authCodePayload, 'auth_time') &&
            ! empty($authCodePayload->auth_time)
        ) {
            $responseType->setAuthTime($authCodePayload->auth_time);
        }

        if (
            $responseType instanceof AcrResponseTypeInterface &&
            property_exists($authCodePayload, 'acr') &&
            ! empty($authCodePayload->acr)
        ) {
            $responseType->setAcr($authCodePayload->acr);
        }

        if (
            $responseType instanceof SessionIdResponseTypeInterface &&
            property_exists($authCodePayload, 'session_id') &&
            ! empty($authCodePayload->session_id)
        ) {
            $responseType->setSessionId($authCodePayload->session_id);
        }

        // Release refresh token if it is requested by using offline_access scope.
        if ($this->helpers->scope()->exists($scopes, 'offline_access')) {
            // Issue and persist new refresh token if given
            $refreshToken = $this->issueRefreshToken($accessToken, $authCodePayload->auth_code_id);

            if ($refreshToken !== null) {
                $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));
                $responseType->setRefreshToken($refreshToken);
            }
        }

        // Revoke used auth code
        $this->authCodeRepository->revokeAuthCode($authCodePayload->auth_code_id);

        return $responseType;
    }

    /**
     * Reimplementation because of private parent access
     *
     * @param object $authCodePayload
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface $client
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function validateAuthorizationCode(
        object $authCodePayload,
        OAuth2ClientEntityInterface $client,
        ServerRequestInterface $request,
        AuthCodeEntity $storedAuthCodeEntity,
    ): void {
        /**
         * @noinspection PhpUndefinedClassInspection
         * @psalm-var AuthCodePayloadObject $authCodePayload
         */

        if (! is_a($this->accessTokenRepository, AccessTokenRepositoryInterface::class)) {
            throw OidcServerException::serverError('Unexpected access token repository entity type.');
        }

        if (! is_a($this->refreshTokenRepository, RefreshTokenRepositoryInterface::class)) {
            throw OidcServerException::serverError('Unexpected refresh token repository entity type.');
        }

        if (time() > $authCodePayload->expire_time) {
            throw OAuthServerException::invalidGrant('Authorization code has expired');
        }

        if ($storedAuthCodeEntity->isRevoked()) {
            // Code is reused, all related tokens must be revoked, per https://tools.ietf.org/html/rfc6749#section-4.1.2
            $this->accessTokenRepository->revokeByAuthCodeId($authCodePayload->auth_code_id);
            $this->refreshTokenRepository->revokeByAuthCodeId($authCodePayload->auth_code_id);
            throw OAuthServerException::invalidGrant('Authorization code has been revoked');
        }

        if ($authCodePayload->client_id !== $client->getIdentifier()) {
            throw OAuthServerException::invalidRequest('code', 'Authorization code was not issued to this client');
        }

        // The redirect URI is required in this request
        $redirectUri = $this->getRequestParameter('redirect_uri', $request);
        if (empty($authCodePayload->redirect_uri) === false && $redirectUri === null) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }

        if ($authCodePayload->redirect_uri !== $redirectUri) {
            throw OAuthServerException::invalidRequest(
                'redirect_uri',
                'Invalid redirect URI or not the same as in authorization request',
            );
        }
    }

    /**
     * @inheritDoc
     * @throws \Throwable
     */
    public function validateAuthorizationRequestWithRequestRules(
        ServerRequestInterface $request,
        ResultBagInterface $resultBag,
    ): OAuth2AuthorizationRequest {
        $this->loggerService->debug('AuthCodeGrant::validateAuthorizationRequestWithRequestRules');

        $rulesToExecute = [
            ClientIdRule::class,
            RequestObjectRule::class,
            PromptRule::class,
            MaxAgeRule::class,
            ScopeRule::class,
            RequestedClaimsRule::class,
            AcrValuesRule::class,
            ScopeOfflineAccessRule::class,
            RequiredOpenIdScopeRule::class,
            CodeChallengeRule::class,
            CodeChallengeMethodRule::class,
            IssuerStateRule::class,
            AuthorizationDetailsRule::class,
        ];

        // Since we have already validated redirect_uri, and we have state, make it available for other checkers.
        $this->requestRulesManager->predefineResultBag($resultBag);

        /** @var string $redirectUri */
        $redirectUri = $resultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $resultBag->getOrFail(ClientRule::class)->getValue();

        $this->loggerService->debug('AuthCodeGrant: Resolved data:', [
            'redirectUri' => $redirectUri,
            'state' => $state,
            'clientId' => $client->getIdentifier(),
        ]);

        // Some rules have to have certain things available in order to work properly...
        $this->requestRulesManager->setData('default_scope', $this->defaultScope);
        $this->requestRulesManager->setData('scope_delimiter_string', self::SCOPE_DELIMITER_STRING);

        $resultBag = $this->requestRulesManager->check(
            $request,
            $rulesToExecute,
            false,
            $this->allowedAuthorizationHttpMethods,
        );

        $this->loggerService->debug('AuthCodeGrant: executed rules.', ['rulesToExecute' => $rulesToExecute]);

        /** @var \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes */
        $scopes = $resultBag->getOrFail(ScopeRule::class)->getValue();

        $this->loggerService->debug('AuthCodeGrant: Resolved scopes: ', ['scopes' => $scopes]);

        $oAuth2AuthorizationRequest = new OAuth2AuthorizationRequest();

        $oAuth2AuthorizationRequest->setClient($client);
        $oAuth2AuthorizationRequest->setRedirectUri($redirectUri);
        $oAuth2AuthorizationRequest->setScopes($scopes);
        $oAuth2AuthorizationRequest->setGrantTypeId($this->getIdentifier());

        if ($state !== null) {
            $oAuth2AuthorizationRequest->setState($state);
        }

        /** @var ?string $codeChallenge */
        $codeChallenge = $resultBag->getOrFail(CodeChallengeRule::class)->getValue();
        if ($codeChallenge) {
            $this->loggerService->debug('AuthCodeGrant: Code challenge: ', [
                'codeChallenge' => $codeChallenge,
            ]);
            /** @var string $codeChallengeMethod */
            $codeChallengeMethod = $resultBag->getOrFail(CodeChallengeMethodRule::class)->getValue();

            $oAuth2AuthorizationRequest->setCodeChallenge($codeChallenge);
            $oAuth2AuthorizationRequest->setCodeChallengeMethod($codeChallengeMethod);
        } else {
            $this->loggerService->debug('AuthCodeGrant: No code challenge present.');
        }

        $isOidcCandidate = $this->isOidcCandidate($oAuth2AuthorizationRequest);



        $this->loggerService->debug('AuthCodeGrant: Is OIDC candidate: ', [
            'isOidcCandidate' => $isOidcCandidate,
        ]);

        $isVciAuthorizationCodeRequest = $this->requestParamsResolver->isVciAuthorizationCodeRequest(
            $request,
            $this->allowedAuthorizationHttpMethods,
        );

        $this->loggerService->debug('AuthCodeGrant: Is VCI authorization code request: ', [
            'isVciAuthorizationCodeRequest' => $isVciAuthorizationCodeRequest,
        ]);


        if (
            (! $isOidcCandidate) &&
            (! $isVciAuthorizationCodeRequest)
        ) {
            $this->loggerService->debug('Not an OIDC nor VCI request, returning as OAuth2 request.');
            return $oAuth2AuthorizationRequest;
        }

        $this->loggerService->debug('AuthCodeGrant: OIDC or VCI request, continuing with request setup.');

        $authorizationRequest = AuthorizationRequest::fromOAuth2AuthorizationRequest($oAuth2AuthorizationRequest);

        $nonce = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::Nonce->value,
            $request,
            $this->allowedAuthorizationHttpMethods,
        );
        $this->loggerService->debug('AuthCodeGrant: Nonce: ', ['nonce' => $nonce]);
        if ($nonce !== null) {
            $authorizationRequest->setNonce($nonce);
        }

        $maxAge = $resultBag->get(MaxAgeRule::class);
        $this->loggerService->debug('AuthCodeGrant: MaxAge: ', ['maxAge' => $maxAge]);
        if (null !== $maxAge) {
            $authorizationRequest->setAuthTime((int) $maxAge->getValue());
        }

        $requestClaims = $resultBag->get(RequestedClaimsRule::class);
        $this->loggerService->debug('AuthCodeGrant: Requested claims: ', ['requestClaims' => $requestClaims]);
        if (null !== $requestClaims) {
            /** @var ?array $requestClaimValues */
            $requestClaimValues = $requestClaims->getValue();
            if (is_array($requestClaimValues)) {
                $authorizationRequest->setClaims($requestClaimValues);
            }
        }

        /** @var array|null $acrValues */
        $acrValues = $resultBag->getOrFail(AcrValuesRule::class)->getValue();
        $this->loggerService->debug('AuthCodeGrant: ACR values: ', ['acrValues' => $acrValues]);
        $authorizationRequest->setRequestedAcrValues($acrValues);


        $authorizationRequest->setIsVciRequest($isVciAuthorizationCodeRequest);
        $flowType = $isVciAuthorizationCodeRequest ?
        FlowTypeEnum::VciAuthorizationCode : FlowTypeEnum::OidcAuthorizationCode;
        $this->loggerService->debug('AuthCodeGrant: FlowType: ', ['flowType' => $flowType]);
        $authorizationRequest->setFlowType($flowType);

        /** @var ?string $issuerState */
        $issuerState = $resultBag->get(IssuerStateRule::class)?->getValue();
        $this->loggerService->debug('AuthCodeGrant: Issuer state: ', ['issuerState' => $issuerState]);
        $authorizationRequest->setIssuerState($issuerState);

        /** @var ?array $authorizationDetails */
        $authorizationDetails = $resultBag->get(AuthorizationDetailsRule::class)?->getValue();
        $this->loggerService->debug(
            'AuthCodeGrant: Authorization details: ',
            ['authorizationDetails' => $authorizationDetails],
        );
        $authorizationRequest->setAuthorizationDetails($authorizationDetails);

        // TODO This is a band-aid fix for having credential claims in the userinfo endpoint when
        // only VCI authorizationDetails are supplied. This requires configuring a matching OIDC scope
        // that has all the credential type claims as well.
        if (is_array($authorizationDetails)) {
            /** @psalm-suppress MixedAssignment */
            foreach ($authorizationDetails as $authorizationDetail) {
                if (
                    is_array($authorizationDetail) &&
                    (isset($authorizationDetail['type'])) &&
                    ($authorizationDetail['type']) === 'openid_credential'
                ) {
                    /** @psalm-suppress MixedAssignment */
                    $credentialConfigurationId = $authorizationDetail['credential_configuration_id'] ?? null;
                    if (is_string($credentialConfigurationId)) {
                        $scopes[] = new ScopeEntity($credentialConfigurationId);
                    }
                }
            }
            $this->loggerService->debug('authorizationDetails Resolved Scopes: ', ['scopes' => $scopes]);
            $authorizationRequest->setScopes($scopes);
        }

        // Check if we are using a generic client for this request. This can happen for non-registered clients
        // in VCI flows. This can be removed once the VCI clients (wallets) are properly registered using DCR.
        if ($client->isGeneric()) {
            $this->loggerService->debug(
                'AuthCodeGrant: Generic client is used for authorization request.',
                ['genericClientId' => $client->getIdentifier()],
            );
            // The generic client was used. Make sure to store actually used client_id and redirect_uri params.
            /** @var string $clientIdParam */
            $clientIdParam = $resultBag->getOrFail(ClientIdRule::class)->getValue();
            $this->loggerService->debug(
                'AuthCodeGrant: Binding client_id param to request: ',
                ['clientIdParam' => $clientIdParam],
            );
            $authorizationRequest->setBoundClientId($clientIdParam);

            $this->loggerService->debug(
                'AuthCodeGrant: Binding redirect_uri param to request: ',
                ['redirectUri' => $redirectUri],
            );
            $authorizationRequest->setBoundRedirectUri($redirectUri);
        }

        $this->loggerService->debug('AuthCodeGrant: Finished setting up authorization request.');

        return $authorizationRequest;
    }

    /**
     * @param \League\OAuth2\Server\Entities\AccessTokenEntityInterface $accessToken
     * @param string|null $authCodeId
     * @return \SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface|null
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueRefreshToken(
        OAuth2AccessTokenEntityInterface $accessToken,
        ?string $authCodeId = null,
    ): ?RefreshTokenEntityInterface {
        if (! is_a($accessToken, AccessTokenEntityInterface::class)) {
            throw OidcServerException::serverError('Unexpected access token entity type.');
        }

        return $this->refreshTokenIssuer->issue(
            $accessToken,
            $this->refreshTokenTTL,
            $authCodeId,
            self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS,
        );
    }
}
