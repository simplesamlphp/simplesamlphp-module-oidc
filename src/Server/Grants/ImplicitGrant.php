<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use League\OAuth2\Server\Grant\ImplicitGrant as OAuth2ImplicitGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface as OAuth2AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithRequestRules;
use SimpleSAML\Module\oidc\Server\Grants\Traits\IssueAccessTokenTrait;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class ImplicitGrant extends OAuth2ImplicitGrant implements AuthorizationValidatableWithRequestRules
{
    use IssueAccessTokenTrait;

    /** @var HttpMethodsEnum[]  */
    protected array $allowedAuthorizationHttpMethods = [HttpMethodsEnum::GET, HttpMethodsEnum::POST];

    public function __construct(
        protected IdTokenBuilder $idTokenBuilder,
        protected DateInterval $accessTokenTTL,
        AccessTokenRepositoryInterface $accessTokenRepository,
        protected RequestRulesManager $requestRulesManager,
        protected RequestParamsResolver $requestParamsResolver,
        AccessTokenEntityFactory $accessTokenEntityFactory,
        protected LoggerService $loggerService,
    ) {
        parent::__construct($accessTokenTTL);

        $this->accessTokenRepository = $accessTokenRepository;
        $this->accessTokenEntityFactory = $accessTokenEntityFactory;
    }

    /**
     * {@inheritdoc}
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $this->allowedAuthorizationHttpMethods,
        );

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
     * @param \League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface $authorizationRequest
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function completeAuthorizationRequest(
        OAuth2AuthorizationRequestInterface $authorizationRequest,
    ): ResponseTypeInterface {
        if ($authorizationRequest instanceof AuthorizationRequest) {
            return $this->completeOidcAuthorizationRequest($authorizationRequest);
        }

        $this->loggerService->error(
            'Implicit grant failed: unexpected authorization request type.',
            ['type' => $authorizationRequest::class],
        );
        throw new LogicException('Unexpected OAuth2AuthorizationRequest type.');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function validateAuthorizationRequestWithRequestRules(
        ServerRequestInterface $request,
        ResultBagInterface $resultBag,
    ): OAuth2AuthorizationRequestInterface {
        $rulesToExecute = [
            ScopeRule::class,
            RequestObjectRule::class,
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

        $redirectUri = $resultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        $client = $resultBag->getOrFail(ClientRule::class)->getValue();
        $responseMode = $resultBag->getOrFail(ResponseModeRule::class)->getValue();

        // Some rules need certain things available in order to work properly...
        $this->requestRulesManager->setData('default_scope', $this->defaultScope);
        $this->requestRulesManager->setData('scope_delimiter_string', self::SCOPE_DELIMITER_STRING);

        $resultBag = $this->requestRulesManager->check(
            $request,
            $rulesToExecute,
            $responseMode,
            $this->allowedAuthorizationHttpMethods,
        );

        $scopes = $resultBag->getOrFail(ScopeRule::class)->getValue();

        $authorizationRequest = new AuthorizationRequest();
        $authorizationRequest->setClient($client);
        $authorizationRequest->setRedirectUri($redirectUri);
        $authorizationRequest->setScopes($scopes);
        $authorizationRequest->setGrantTypeId($this->getIdentifier());
        if ($state !== null) {
            $authorizationRequest->setState($state);
        }

        // nonce existence is validated using a rule, so we can get it from there.
        $authorizationRequest->setNonce($resultBag->getOrFail(RequiredNonceRule::class)->getValue());

        $maxAge = $resultBag->get(MaxAgeRule::class);
        if (null !== $maxAge) {
            $authorizationRequest->setAuthTime($maxAge->getValue());
        }

        $requestClaims = $resultBag->get(RequestedClaimsRule::class);
        if (null !== $requestClaims) {
            /** @var ?array $requestClaimValues */
            $requestClaimValues = $requestClaims->getValue();
            if (is_array($requestClaimValues)) {
                $authorizationRequest->setClaims($requestClaimValues);
            }
        }
        $addClaimsToIdToken = ($resultBag->getOrFail(AddClaimsToIdTokenRule::class))->getValue();
        $authorizationRequest->setAddClaimsToIdToken($addClaimsToIdToken);

        $responseType = ($resultBag->getOrFail(ResponseTypeRule::class))->getValue();
        $authorizationRequest->setResponseType($responseType);

        $acrValues = $resultBag->getOrFail(AcrValuesRule::class)->getValue();
        $authorizationRequest->setRequestedAcrValues($acrValues);

        $responseMode = $resultBag->getOrFail(ResponseModeRule::class)->getValue();
        $authorizationRequest->setResponseMode($responseMode);

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
            $this->loggerService->error(
                'Implicit grant failed: no authenticated user set on the authorization request.',
                ['client_id' => $authorizationRequest->getClient()->getIdentifier()],
            );
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $redirectUrl = $this->getRedirectUrl($authorizationRequest);

        if ($authorizationRequest->isAuthorizationApproved() !== true) {
            $this->loggerService->notice(
                'Implicit grant: authorization request denied by the user.',
                ['client_id' => $authorizationRequest->getClient()->getIdentifier()],
            );
            throw OidcServerException::accessDenied(
                'The user denied the request',
                $redirectUrl,
                null,
                $authorizationRequest->getState(),
                $authorizationRequest->getResponseMode(),
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
            $this->loggerService->error(
                'Implicit grant failed: issued access token does not implement ' .
                EntityStringRepresentationInterface::class . '.',
                ['client_id' => $authorizationRequest->getClient()->getIdentifier()],
            );
            throw new RuntimeException('AccessToken must implement ' . EntityStringRepresentationInterface::class);
        }
        if ($accessToken instanceof AccessTokenEntity === false) {
            $this->loggerService->error(
                'Implicit grant failed: issued access token is not an instance of ' . AccessTokenEntity::class . '.',
                ['client_id' => $authorizationRequest->getClient()->getIdentifier()],
            );
            throw new RuntimeException('AccessToken must be ' . AccessTokenEntity::class);
        }

        $addAccessTokenHashToIdToken = false;
        if ($authorizationRequest->shouldReturnAccessTokenInAuthorizationResponse()) {
            $addAccessTokenHashToIdToken = true;

            $responseParams['access_token'] = $accessToken->toString();
            $responseParams['token_type'] = 'Bearer';
            $responseParams['expires_in'] = $accessToken->getExpiryDateTime()->getTimestamp() - time();
        }

        // Decide whether the user's (scope-derived) claims go into the ID Token. The response-type-driven decision
        // (AddClaimsToIdTokenRule) already requests them for response_type=id_token, where there is no access token
        // to call the UserInfo endpoint with. For id_token token the claims would otherwise be available only at
        // UserInfo, so we additionally honor the per-client, administrator-only `add_claims_to_id_token` option,
        // matching the authorization code flow (see TokenResponse::prepareIdTokenExtraParam()).
        $client = $authorizationRequest->getClient();
        $addClaimsToIdToken = $authorizationRequest->getAddClaimsToIdToken()
        || ($client instanceof ClientEntity && $client->getAddClaimsToIdToken());

        $idToken = $this->idTokenBuilder->buildFor(
            $user,
            $accessToken,
            $addClaimsToIdToken,
            $addAccessTokenHashToIdToken,
            $authorizationRequest->getNonce(),
            $authorizationRequest->getAuthTime(),
            $authorizationRequest->getAcr(),
            $authorizationRequest->getSessionId(),
        );

        $responseParams['id_token'] = $idToken->getToken();

        $responseMode = $authorizationRequest->getResponseMode() ?? new FragmentResponseMode();
        $response = $responseMode->buildResponse(
            $redirectUrl,
            $responseParams,
        );

        $this->loggerService->notice(
            'Implicit grant: authorization approved; ID token issued.',
            ['client_id' => $authorizationRequest->getClient()->getIdentifier()],
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
}
