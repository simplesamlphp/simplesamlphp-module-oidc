<?php

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Traits\IssueAccessTokenTrait;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ResponseTypeRule;

class ImplicitGrant extends OAuth2ImplicitGrant
{
    use IssueAccessTokenTrait;

    /**
     * @var IdTokenBuilder
     */
    protected $idTokenBuilder;

    public function __construct(
        IdTokenBuilder $idTokenBuilder,
        DateInterval $accessTokenTTL,
        AccessTokenRepositoryInterface $accessTokenRepository,
        $queryDelimiter = '#',
        RequestRulesManager $requestRulesManager = null
    ) {
        parent::__construct($accessTokenTTL, $queryDelimiter, $requestRulesManager);
        $this->accessTokenRepository = $accessTokenRepository;
        $this->idTokenBuilder = $idTokenBuilder;
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request)
    {
        $queryParams = $request->getQueryParams();
        if (!isset($queryParams['response_type']) || !isset($queryParams['client_id'])) {
            return false;
        }

        $responseType = explode(" ", $queryParams['response_type']);

        return in_array('id_token', $responseType, true) &&
            ! in_array('code', $responseType, true); // ...avoid triggering hybrid flow
    }

    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(OAuth2AuthorizationRequest $authorizationRequest)
    {
        if ($authorizationRequest instanceof AuthorizationRequest) {
            return $this->completeOidcAuthorizationRequest($authorizationRequest);
        }

        throw new LogicException('Unexpected OAuth2AuthorizationRequest type.');
    }

    /**
     * @throws \Throwable
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
        $authorizationRequest->setNonce($resultBag->getOrFail(RequiredNonceRule::class)->getValue());

        $maxAge = $resultBag->get(MaxAgeRule::class);
        if (null !== $maxAge) {
            $authorizationRequest->setAuthTime((int) $maxAge->getValue());
        }

        $requestClaims = $resultBag->get(RequestedClaimsRule::class);
        if (null !== $requestClaims) {
            $authorizationRequest->setClaims($requestClaims->getValue());
        }
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

    private function completeOidcAuthorizationRequest(AuthorizationRequest $authorizationRequest): ResponseTypeInterface
    {
        $user = $authorizationRequest->getUser();

        if ($user instanceof UserEntityInterface === false) {
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
            throw new \RuntimeException('AccessToken must implement ' . EntityStringRepresentationInterface::class);
        }
        if ($accessToken instanceof AccessTokenEntity === false) {
            throw new \RuntimeException('AccessToken must be ' . AccessTokenEntity::class);
        }

        $addAccessTokenHashToIdToken = false;
        if ($authorizationRequest->shouldReturnAccessTokenInAuthorizationResponse()) {
            $addAccessTokenHashToIdToken = true;

            $responseParams['access_token'] = $accessToken->toString() ?? (string) $accessToken;
            $responseParams['token_type'] = 'Bearer';
            $responseParams['expires_in'] = $accessToken->getExpiryDateTime()->getTimestamp() - \time();
        }

        $idToken = $this->idTokenBuilder->build(
            $user,
            $accessToken,
            $authorizationRequest->getAddClaimsToIdToken(),
            $addAccessTokenHashToIdToken,
            $authorizationRequest->getNonce(),
            $authorizationRequest->getAuthTime(),
            $authorizationRequest->getAcr()
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
            return (string) $redirectUris[0];
        }

        return (string) $redirectUris;
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
