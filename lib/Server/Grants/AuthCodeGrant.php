<?php

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\CodeChallengeVerifiers\CodeChallengeVerifierInterface;
use League\OAuth2\Server\CodeChallengeVerifiers\PlainVerifier;
use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
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
use SimpleSAML\Module\oidc\Entity\Interfaces\AuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithClientAndRedirectUriInterface;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\OidcCapableGrantTypeInterface;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\PkceEnabledGrantTypeInterface;
use SimpleSAML\Module\oidc\Server\Grants\Traits\IssueAccessTokenTrait;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AuthTimeResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\NonceResponseTypeInterface;
use SimpleSAML\Module\oidc\Utils\Arr;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;

class AuthCodeGrant extends OAuth2AuthCodeGrant implements
    PkceEnabledGrantTypeInterface,
    OidcCapableGrantTypeInterface,
    AuthorizationValidatableWithClientAndRedirectUriInterface
{
    use IssueAccessTokenTrait;

    /**
     * @var DateInterval
     */
    protected $authCodeTTL;

    /**
     * @var CodeChallengeVerifierInterface[]
     */
    protected $codeChallengeVerifiers = [];

    /**
     * @var AuthCodeRepositoryInterface
     */
    protected $authCodeRepository;

    /**
     * @var AccessTokenRepositoryInterface
     */
    protected $accessTokenRepository;

    /**
     * @var RefreshTokenRepositoryInterface
     */
    protected $refreshTokenRepository;

    /**
     * @var RequestRulesManager
     */
    private $requestRulesManager;

    /**
     * @var bool $requireCodeChallengeForPublicClients
     */
    protected $requireCodeChallengeForPublicClients = true;

    public function __construct(
        OAuth2AuthCodeRepositoryInterface $authCodeRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL,
        RequestRulesManager $requestRulesManager
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);

        $this->setAuthCodeRepository($authCodeRepository);
        $this->setAccessTokenRepository($accessTokenRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->authCodeTTL = $authCodeTTL;
        $this->requestRulesManager = $requestRulesManager;

        if (\in_array('sha256', \hash_algos(), true)) {
            $s256Verifier = new S256Verifier();
            $this->codeChallengeVerifiers[$s256Verifier->getMethod()] = $s256Verifier;
        }

        $plainVerifier = new PlainVerifier();
        $this->codeChallengeVerifiers[$plainVerifier->getMethod()] = $plainVerifier;
    }

    /**
     * @param ClientEntityInterface $client
     * @return bool
     */
    protected function shouldCheckPkce(ClientEntityInterface $client): bool
    {
        return $this->requireCodeChallengeForPublicClients &&
            ! $client->isConfidential();
    }

    /**
     * Check if the authorization request is OIDC candidate (can respond with ID token).
     *
     * @param OAuth2AuthorizationRequest $authorizationRequest
     * @return bool
     */
    public function isOidcCandidate(
        OAuth2AuthorizationRequest $authorizationRequest
    ): bool {
        // Check if the scopes contain 'oidc' scope
        // TODO mivanci move away from static Arr dependency
        return (bool) Arr::find($authorizationRequest->getScopes(), function (ScopeEntityInterface $scope) {
            return $scope->getIdentifier() === 'openid';
        });
    }

    /**
     * @inheritDoc
     */
    public function completeAuthorizationRequest(
        OAuth2AuthorizationRequest $authorizationRequest
    ): ResponseTypeInterface {
        if ($authorizationRequest instanceof AuthorizationRequest) {
            return $this->completeOidcAuthorizationRequest($authorizationRequest);
        }

        return parent::completeAuthorizationRequest($authorizationRequest);
    }

    /**
     * This is reimplementation of OAuth2 completeAuthorizationRequest method with addition of nonce handling.
     *
     * @param AuthorizationRequest $authorizationRequest
     * @return RedirectResponse
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function completeOidcAuthorizationRequest(
        AuthorizationRequest $authorizationRequest
    ): RedirectResponse {
        $user = $authorizationRequest->getUser();
        if ($user instanceof UserEntityInterface === false) {
            throw new LogicException('An instance of UserEntityInterface should be set on the ' .
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
                $authorizationRequest->getState()
            );
        }

        // The user approved the client, redirect them back with an auth code
        $authCode = $this->issueOidcAuthCode(
            $this->authCodeTTL,
            $authorizationRequest->getClient(),
            $user->getIdentifier(),
            $finalRedirectUri,
            $authorizationRequest->getScopes(),
            $authorizationRequest->getNonce()
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
        ];

        $jsonPayload = \json_encode($payload);

        if ($jsonPayload === false) {
            throw new LogicException('An error was encountered when JSON encoding the authorization ' .
                'request response');
        }

        $response = new RedirectResponse();
        $response->setRedirectUri(
            $this->makeRedirectUri(
                $finalRedirectUri,
                [
                    'code'  => $this->encrypt($jsonPayload),
                    'state' => $authorizationRequest->getState(),
                ]
            )
        );

        return $response;
    }

    /**
     * @param DateInterval $authCodeTTL
     * @param OAuth2ClientEntityInterface $client
     * @param string $userIdentifier
     * @param string $redirectUri
     * @param array $scopes
     * @param string|null $nonce
     * @return AuthCodeEntityInterface
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueOidcAuthCode(
        DateInterval $authCodeTTL,
        OAuth2ClientEntityInterface $client,
        string $userIdentifier,
        string $redirectUri,
        array $scopes = [],
        string $nonce = null
    ): AuthCodeEntityInterface {

        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $authCode = $this->authCodeRepository->getNewAuthCode();
        $authCode->setExpiryDateTime((new DateTimeImmutable())->add($authCodeTTL));
        $authCode->setClient($client);
        $authCode->setUserIdentifier($userIdentifier);
        $authCode->setRedirectUri($redirectUri);
        if (null !== $nonce) {
            $authCode->setNonce($nonce);
        }

        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }

        while ($maxGenerationAttempts-- > 0) {
            $authCode->setIdentifier($this->generateUniqueIdentifier());
            try {
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
     * @param OAuth2AuthorizationRequest $authorizationRequest
     *
     * @return string
     */
    protected function getClientRedirectUri(OAuth2AuthorizationRequest $authorizationRequest): string
    {
        $rediretctUri = $authorizationRequest->getClient()->getRedirectUri();

        if (\is_array($rediretctUri)) {
            return $rediretctUri[0];
        }

        return $rediretctUri;
    }

    /**
     * Reimplementation respondToAccessTokenRequest because of nonce feature.
     *
     * @param ServerRequestInterface $request
     * @param ResponseTypeInterface  $responseType
     * @param DateInterval           $accessTokenTTL
     *
     * @throws OAuthServerException
     *
     * @return ResponseTypeInterface
     *
     * TODO refactor to request checkers
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        list($clientId) = $this->getClientCredentials($request);

        $client = $this->getClientEntityOrFail($clientId, $request);

        // Only validate the client if it is confidential
        if ($client->isConfidential()) {
            $this->validateClient($request);
        }

        $encryptedAuthCode = $this->getRequestParameter('code', $request, null);

        if ($encryptedAuthCode === null) {
            throw OAuthServerException::invalidRequest('code');
        }

        try {
            $authCodePayload = \json_decode($this->decrypt($encryptedAuthCode));

            $this->validateAuthorizationCode($authCodePayload, $client, $request);

            $scopes = $this->scopeRepository->finalizeScopes(
                $this->validateScopes($authCodePayload->scopes),
                $this->getIdentifier(),
                $client,
                $authCodePayload->user_id
            );
        } catch (LogicException $e) {
            throw OAuthServerException::invalidRequest('code', 'Cannot decrypt the authorization code', $e);
        }

        // Validate code challenge
        if (!empty($authCodePayload->code_challenge)) {
            $codeVerifier = $this->getRequestParameter('code_verifier', $request, null);

            if ($codeVerifier === null) {
                throw OAuthServerException::invalidRequest('code_verifier');
            }

            // Validate code_verifier according to RFC-7636
            // @see: https://tools.ietf.org/html/rfc7636#section-4.1
            if (\preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeVerifier) !== 1) {
                throw OAuthServerException::invalidRequest(
                    'code_verifier',
                    'Code Verifier must follow the specifications of RFC-7636.'
                );
            }

            if (\property_exists($authCodePayload, 'code_challenge_method')) {
                if (isset($this->codeChallengeVerifiers[$authCodePayload->code_challenge_method])) {
                    $codeChallengeVerifier = $this->codeChallengeVerifiers[$authCodePayload->code_challenge_method];

                    if (
                        $codeChallengeVerifier->verifyCodeChallenge(
                            $codeVerifier,
                            $authCodePayload->code_challenge
                        ) === false
                    ) {
                        throw OAuthServerException::invalidGrant('Failed to verify `code_verifier`.');
                    }
                } else {
                    throw OAuthServerException::serverError(
                        \sprintf(
                            'Unsupported code challenge method `%s`',
                            $authCodePayload->code_challenge_method
                        )
                    );
                }
            }
        }

        $claims = property_exists($authCodePayload, 'claims') ?
            json_decode(json_encode($authCodePayload->claims), true)
            : null;

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken(
            $accessTokenTTL,
            $client,
            $authCodePayload->user_id,
            $scopes,
            $authCodePayload->auth_code_id,
            $claims
        );
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);

        // Set nonce in response if the auth code had one set.
        if (
            $responseType instanceof NonceResponseTypeInterface &&
            \property_exists($authCodePayload, 'nonce') &&
            ! empty($authCodePayload->nonce)
        ) {
            $responseType->setNonce($authCodePayload->nonce);
        }

        if (
            $responseType instanceof AuthTimeResponseTypeInterface &&
            \property_exists($authCodePayload, 'auth_time') &&
            ! empty($authCodePayload->auth_time)
        ) {
            $responseType->setAuthTime($authCodePayload->auth_time);
        }

        // Issue and persist new refresh token if given
        $refreshToken = $this->issueRefreshToken($accessToken, $authCodePayload->auth_code_id);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));
            $responseType->setRefreshToken($refreshToken);
        }

        // Revoke used auth code
        $this->authCodeRepository->revokeAuthCode($authCodePayload->auth_code_id);

        return $responseType;
    }

    /**
     * Reimplementation because of private parent access
     *
     * @param \stdClass $authCodePayload
     * @param OAuth2ClientEntityInterface $client
     * @param ServerRequestInterface $request
     * @throws OAuthServerException
     */
    protected function validateAuthorizationCode(
        \stdClass $authCodePayload,
        OAuth2ClientEntityInterface $client,
        ServerRequestInterface $request
    ): void {
        if (!\property_exists($authCodePayload, 'auth_code_id')) {
            throw OAuthServerException::invalidRequest('code', 'Authorization code malformed');
        }

        if (\time() > $authCodePayload->expire_time) {
            throw OAuthServerException::invalidGrant('Authorization code has expired');
        }

        if ($this->authCodeRepository->isAuthCodeRevoked($authCodePayload->auth_code_id) === true) {
            // Code is reused, all related tokens must be revoked, per https://tools.ietf.org/html/rfc6749#section-4.1.2
            $this->accessTokenRepository->revokeByAuthCodeId($authCodePayload->auth_code_id);
            $this->refreshTokenRepository->revokeByAuthCodeId($authCodePayload->auth_code_id);
            throw OAuthServerException::invalidGrant('Authorization code has been revoked');
        }

        if ($authCodePayload->client_id !== $client->getIdentifier()) {
            throw OAuthServerException::invalidRequest('code', 'Authorization code was not issued to this client');
        }

        // The redirect URI is required in this request
        $redirectUri = $this->getRequestParameter('redirect_uri', $request, null);
        if (empty($authCodePayload->redirect_uri) === false && $redirectUri === null) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }

        if ($authCodePayload->redirect_uri !== $redirectUri) {
            throw OAuthServerException::invalidRequest('redirect_uri', 'Invalid redirect URI');
        }
    }

    /**
     * @inheritDoc
     */
    public function validateAuthorizationRequestWithClientAndRedirectUri(
        ServerRequestInterface $request,
        ClientEntityInterface $client,
        string $redirectUri,
        string $state = null
    ): OAuth2AuthorizationRequest {
        $rulesToExecute = [
            RequestParameterRule::class,
            PromptRule::class,
            MaxAgeRule::class,
            ScopeRule::class,
            RequestedClaimsRule::class
        ];

        // Since we have already validated redirect_uri and we have state, make it available for other checkers.
        $this->requestRulesManager->predefineResult(new Result(RedirectUriRule::class, $redirectUri));
        $this->requestRulesManager->predefineResult(new Result(StateRule::class, $state));

        // Some rules have to have certain things available in order to work properly...
        $this->requestRulesManager->setData('default_scope', $this->defaultScope);
        $this->requestRulesManager->setData('scope_delimiter_string', self::SCOPE_DELIMITER_STRING);

        $shouldCheckPkce = $this->shouldCheckPkce($client);
        if ($shouldCheckPkce) {
            $rulesToExecute[] = CodeChallengeRule::class;
            $rulesToExecute[] = CodeChallengeMethodRule::class;
        }

        $resultBag = $this->requestRulesManager->check($request, $rulesToExecute);

        /** @var array $scopes */
        $scopes = $resultBag->getOrFail(ScopeRule::class)->getValue();

        $oAuth2AuthorizationRequest = new OAuth2AuthorizationRequest();

        $oAuth2AuthorizationRequest->setClient($client);
        $oAuth2AuthorizationRequest->setRedirectUri($redirectUri);
        $oAuth2AuthorizationRequest->setScopes($scopes);
        $oAuth2AuthorizationRequest->setGrantTypeId($this->getIdentifier());

        if ($state !== null) {
            $oAuth2AuthorizationRequest->setState($state);
        }

        if ($shouldCheckPkce) {
            /** @var string $codeChallenge */
            $codeChallenge = $resultBag->getOrFail(CodeChallengeRule::class)->getValue();
            $codeChallengeMethod = $resultBag->getOrFail(CodeChallengeMethodRule::class)->getValue();

            $oAuth2AuthorizationRequest->setCodeChallenge($codeChallenge);
            $oAuth2AuthorizationRequest->setCodeChallengeMethod($codeChallengeMethod);
        }

        if (! $this->isOidcCandidate($oAuth2AuthorizationRequest)) {
            return $oAuth2AuthorizationRequest;
        }

        $authorizationRequest = AuthorizationRequest::fromOAuth2AuthorizationRequest($oAuth2AuthorizationRequest);

        /** @var string|null $nonce */
        $nonce = $request->getQueryParams()['nonce'] ?? null;
        if ($nonce !== null) {
            $authorizationRequest->setNonce($nonce);
        }

        $maxAge = $resultBag->get(MaxAgeRule::class);
        if (null !== $maxAge) {
            $authorizationRequest->setAuthTime((int) $maxAge->getValue());
        }

        $requestClaims = $resultBag->get(RequestedClaimsRule::class);
        if (null !== $requestClaims) {
            $authorizationRequest->setClaims($requestClaims->getValue());
        }

        return $authorizationRequest;
    }

    /**
     * @param OAuth2AccessTokenEntityInterface $accessToken
     * @param string|null $authCodeId
     * @return RefreshTokenEntityInterface|null
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueRefreshToken(
        OAuth2AccessTokenEntityInterface $accessToken,
        string $authCodeId = null
    ): ?RefreshTokenEntityInterface {
        $refreshToken = $this->refreshTokenRepository->getNewRefreshToken();

        if ($refreshToken === null) {
            return null;
        }

        $refreshToken->setExpiryDateTime((new DateTimeImmutable())->add($this->refreshTokenTTL));
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setAuthCodeId($authCodeId);

        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        while ($maxGenerationAttempts-- > 0) {
            $refreshToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);
                break;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        return $refreshToken;
    }
}
