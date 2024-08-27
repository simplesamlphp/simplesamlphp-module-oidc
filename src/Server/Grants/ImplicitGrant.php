<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Traits\IssueAccessTokenTrait;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

class ImplicitGrant extends OAuth2ImplicitGrant
{
    use IssueAccessTokenTrait;

    /**
     * @psalm-suppress PropertyNotSetInConstructor
     * @var \League\OAuth2\Server\CryptKey
     */
    protected $privateKey;

    public function __construct(
        protected IdTokenBuilder $idTokenBuilder,
        DateInterval $accessTokenTTL,
        AccessTokenRepositoryInterface $accessTokenRepository,
        string $queryDelimiter = '#',
        RequestRulesManager $requestRulesManager = null,
        protected Helpers $helpers = new Helpers(),
    ) {
        parent::__construct($accessTokenTTL, $queryDelimiter, $requestRulesManager);
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        $requestParams = $this->helpers->http()->getAllRequestParamsBasedOnAllowedMethods(
            $request,
            [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
        ) ?? [];

        if (
            !isset($requestParams['response_type']) ||
            !is_string($requestParams['response_type']) ||
            !isset($requestParams['client_id'])
        ) {
            return false;
        }

        $responseType = explode(" ", $requestParams['response_type']);

        return in_array('id_token', $responseType, true) &&
        ! in_array('code', $responseType, true); // ...avoid triggering hybrid flow
    }

    /**
     * {@inheritdoc}
     * @param \League\OAuth2\Server\RequestTypes\AuthorizationRequest $authorizationRequest
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function completeAuthorizationRequest(
        OAuth2AuthorizationRequest $authorizationRequest,
    ): ResponseTypeInterface {
        if ($authorizationRequest instanceof AuthorizationRequest) {
            return $this->completeOidcAuthorizationRequest($authorizationRequest);
        }

        throw new LogicException('Unexpected OAuth2AuthorizationRequest type.');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function validateAuthorizationRequestWithCheckerResultBag(
        ServerRequestInterface $request,
        ResultBagInterface $resultBag,
    ): OAuth2AuthorizationRequest {
        $oAuth2AuthorizationRequest =
        parent::validateAuthorizationRequestWithCheckerResultBag($request, $resultBag);

        $rulesToExecute = [
            RequestParameterRule::class,
            PromptRule::class,
            MaxAgeRule::class,
            RequiredOpenIdScopeRule::class,
            ResponseTypeRule::class,
            AddClaimsToIdTokenRule::class,
            RequiredNonceRule::class,
            RequestedClaimsRule::class,
            AcrValuesRule::class,
        ];

        $this->requestRulesManager->predefineResultBag($resultBag);

        $resultBag = $this->requestRulesManager->check(
            $request,
            $rulesToExecute,
            $this->shouldUseFragment(),
            [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
        );

        $authorizationRequest = AuthorizationRequest::fromOAuth2AuthorizationRequest($oAuth2AuthorizationRequest);

        // nonce existence is validated using a rule, so we can get it from there.
        $authorizationRequest->setNonce((string)$resultBag->getOrFail(RequiredNonceRule::class)->getValue());

        $maxAge = $resultBag->get(MaxAgeRule::class);
        if (null !== $maxAge) {
            $authorizationRequest->setAuthTime((int) $maxAge->getValue());
        }

        $requestClaims = $resultBag->get(RequestedClaimsRule::class);
        if (null !== $requestClaims) {
            /** @var ?array $requestClaimValues */
            $requestClaimValues = $requestClaims->getValue();
            if (is_array($requestClaimValues)) {
                $authorizationRequest->setClaims($requestClaimValues);
            }
        }
        /** @var bool $addClaimsToIdToken */
        $addClaimsToIdToken = ($resultBag->getOrFail(AddClaimsToIdTokenRule::class))->getValue();
        $authorizationRequest->setAddClaimsToIdToken($addClaimsToIdToken);

        /** @var string $responseType */
        $responseType = ($resultBag->getOrFail(ResponseTypeRule::class))->getValue();
        $authorizationRequest->setResponseType($responseType);

        /** @var array|null $acrValues */
        $acrValues = $resultBag->getOrFail(AcrValuesRule::class)->getValue();
        $authorizationRequest->setRequestedAcrValues($acrValues);

        return $authorizationRequest;
    }

    /**
     * @throws \Exception
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    private function completeOidcAuthorizationRequest(AuthorizationRequest $authorizationRequest): ResponseTypeInterface
    {
        $user = $authorizationRequest->getUser();

        if ($user instanceof UserEntity === false) {
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $redirectUrl = $this->getRedirectUrl($authorizationRequest);

        if ($authorizationRequest->isAuthorizationApproved() !== true) {
            throw OidcServerException::accessDenied(
                'The user denied the request',
                $redirectUrl,
                null,
                $authorizationRequest->getState(),
                $this->shouldUseFragment(),
            );
        }

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes(
            $authorizationRequest->getScopes(),
            $this->getIdentifier(),
            $authorizationRequest->getClient(),
            $user->getIdentifier(),
        );

        $responseParams = [
            'state' => $authorizationRequest->getState(),
        ];

        $accessToken = $this->issueAccessToken(
            $this->accessTokenTTL,
            $authorizationRequest->getClient(),
            $user->getIdentifier(),
            $finalizedScopes,
            null,
            $authorizationRequest->getClaims(),
        );

        if ($accessToken instanceof EntityStringRepresentationInterface === false) {
            throw new RuntimeException('AccessToken must implement ' . EntityStringRepresentationInterface::class);
        }
        if ($accessToken instanceof AccessTokenEntity === false) {
            throw new RuntimeException('AccessToken must be ' . AccessTokenEntity::class);
        }

        $addAccessTokenHashToIdToken = false;
        if ($authorizationRequest->shouldReturnAccessTokenInAuthorizationResponse()) {
            $addAccessTokenHashToIdToken = true;

            $responseParams['access_token'] = $accessToken->toString() ?? (string) $accessToken;
            $responseParams['token_type'] = 'Bearer';
            $responseParams['expires_in'] = $accessToken->getExpiryDateTime()->getTimestamp() - time();
        }

        $idToken = $this->idTokenBuilder->build(
            $user,
            $accessToken,
            $authorizationRequest->getAddClaimsToIdToken(),
            $addAccessTokenHashToIdToken,
            $authorizationRequest->getNonce(),
            $authorizationRequest->getAuthTime(),
            $authorizationRequest->getAcr(),
            $authorizationRequest->getSessionId(),
        );

        $responseParams['id_token'] = $idToken->toString();

        $response = new RedirectResponse();

        $response->setRedirectUri(
            $this->makeRedirectUri(
                $redirectUrl,
                $responseParams,
                $this->queryDelimiter,
            ),
        );

        return $response;
    }

    private function getRedirectUrl(AuthorizationRequest $authorizationRequest): string
    {
        $redirectUri = $authorizationRequest->getRedirectUri();
        if ($redirectUri !== null) {
            return $redirectUri;
        }

        $redirectUris = $authorizationRequest->getClient()->getRedirectUri();
        if (is_array($redirectUris)) {
            return $redirectUris[0];
        }

        return $redirectUris;
    }

    /**
     * Check if fragment should be used for params transportation in HTTP responses
     *
     * @return bool
     */
    protected function shouldUseFragment(): bool
    {
        return $this->queryDelimiter === '#';
    }
}
