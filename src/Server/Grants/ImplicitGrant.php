<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use Exception;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Traits\IssueAccessTokenTrait;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ResponseTypeRule;
use Throwable;

class ImplicitGrant extends OAuth2ImplicitGrant
{
    use IssueAccessTokenTrait;

    /**
     * @var CryptKey
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $privateKey;

    public function __construct(
        protected IdTokenBuilder $idTokenBuilder,
        DateInterval $accessTokenTTL,
        AccessTokenRepositoryInterface $accessTokenRepository,
        string $queryDelimiter = '#',
        RequestRulesManager $requestRulesManager = null
    ) {
        parent::__construct($accessTokenTTL, $queryDelimiter, $requestRulesManager);
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        $queryParams = $request->getQueryParams();
        if (
            !isset($queryParams['response_type']) ||
            !is_string($queryParams['response_type']) ||
            !isset($queryParams['client_id'])
        ) {
            return false;
        }

        $responseType = explode(" ", $queryParams['response_type']);

        return in_array('id_token', $responseType, true) &&
        ! in_array('code', $responseType, true); // ...avoid triggering hybrid flow
    }

    /**
     * {@inheritdoc}
     * @param OAuth2AuthorizationRequest $authorizationRequest
     * @return ResponseTypeInterface
     * @throws OidcServerException
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function completeAuthorizationRequest(
        OAuth2AuthorizationRequest $authorizationRequest
    ): ResponseTypeInterface {
        if ($authorizationRequest instanceof AuthorizationRequest) {
            return $this->completeOidcAuthorizationRequest($authorizationRequest);
        }

        throw new LogicException('Unexpected OAuth2AuthorizationRequest type.');
    }

    /**
     * @throws Throwable
     * @throws OidcServerException
     */
    public function validateAuthorizationRequestWithCheckerResultBag(
        ServerRequestInterface $request,
        ResultBagInterface $resultBag
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
            AcrValuesRule::class
        ];

        $this->requestRulesManager->predefineResultBag($resultBag);

        $resultBag = $this->requestRulesManager->check($request, $rulesToExecute, $this->shouldUseFragment());

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
     * @throws UniqueTokenIdentifierConstraintViolationException
     * @throws OAuthServerException
     * @throws OidcServerException
     * @throws Exception
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
                $this->shouldUseFragment()
            );
        }

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes(
            $authorizationRequest->getScopes(),
            $this->getIdentifier(),
            $authorizationRequest->getClient(),
            $user->getIdentifier()
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
            $authorizationRequest->getClaims()
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
            $authorizationRequest->getSessionId()
        );

        $responseParams['id_token'] = $idToken->toString();

        $response = new RedirectResponse();

        $response->setRedirectUri(
            $this->makeRedirectUri(
                $redirectUrl,
                $responseParams,
                $this->queryDelimiter
            )
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
