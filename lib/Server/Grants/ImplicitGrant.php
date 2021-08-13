<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants;

use DateInterval;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Modules\OpenIDConnect\Services\IdTokenBuilder;
use SimpleSAML\Modules\OpenIDConnect\Services\RequestedClaimsEncoderService;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\MaxAgeRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RequestedClaimsRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RequestParameterRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\ScopeRule;

class ImplicitGrant extends OAuth2ImplicitGrant
{
    /**
     * @var IdTokenBuilder
     */
    private $idTokenBuilder;

    /**
     * @var RequestedClaimsEncoderService
     */
    private $requestedClaimsEncoderService;

    public function __construct(
        IdTokenBuilder $idTokenBuilder,
        DateInterval $accessTokenTTL,
        $queryDelimiter = '#',
        RequestRulesManager $requestRulesManager = null,
        RequestedClaimsEncoderService $requestedClaimsEncoderService
    ) {
        parent::__construct($accessTokenTTL, $queryDelimiter, $requestRulesManager);
        $this->requestedClaimsEncoderService = $requestedClaimsEncoderService;
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

        return in_array('id_token', $responseType, true);
    }

    /**
     * {@inheritdoc}
     */
    public function completeAuthorizationRequest(OAuth2AuthorizationRequest $authorizationRequest)
    {

        if ($authorizationRequest instanceof AuthorizationRequest) {
            return $this->completeOidcAuthorizationRequest($authorizationRequest);
        }

        return parent::completeAuthorizationRequest($authorizationRequest);
    }

    public function validateAuthorizationRequestWithClientAndRedirectUri(ServerRequestInterface $request, ClientEntityInterface $client, string $redirectUri, string $state = null): OAuth2AuthorizationRequest
    {
        $oAuth2AuthorizationRequest = parent::validateAuthorizationRequestWithClientAndRedirectUri($request, $client, $redirectUri, $state);

        $rulesToExecute = [
            RequestParameterRule::class,
            PromptRule::class,
            MaxAgeRule::class,
            ScopeRule::class,
            RequestedClaimsRule::class
        ];

        $resultBag = $this->requestRulesManager->check($request, $rulesToExecute);

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

    private function completeOidcAuthorizationRequest(AuthorizationRequest $authorizationRequest): ResponseTypeInterface
    {
        $user = $authorizationRequest->getUser();

        if ($user instanceof UserEntityInterface === false) {
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $redirectUrl = $this->getRedirectUrl($authorizationRequest);

        // The user approved the client, redirect them back with an access token
        if ($authorizationRequest->isAuthorizationApproved() === true) {
            // Finalize the requested scopes
            $finalizedScopes = $this->scopeRepository->finalizeScopes(
                $authorizationRequest->getScopes(),
                $this->getIdentifier(),
                $authorizationRequest->getClient(),
                $user->getIdentifier()
            );

            /**
             * There isn't a great way to tie into oauth2-server's token generation without just copying
             * and pasting code. As a workaround we convert the claims to a scope so it can persist for
             * access and refresh tokens.
             */
            $claimsScope = $this->requestedClaimsEncoderService->encodeRequestedClaimsAsScope(
                $authorizationRequest->getClaims()
            );
            if ($claimsScope) {
                $finalizedScopes[] = $claimsScope;
            }

            $accessToken = $this->issueAccessToken(
                $this->accessTokenTTL,
                $authorizationRequest->getClient(),
                $user->getIdentifier(),
                $finalizedScopes
            );

            $idToken = $this->idTokenBuilder->build(
                $accessToken,
                $authorizationRequest->getNonce(),
                $authorizationRequest->getAuthTime()
            );

            $response = new RedirectResponse();
            $response->setRedirectUri(
                $this->makeRedirectUri(
                    $redirectUrl,
                    [
                        'id_token'     => $idToken->toString(),
                        'access_token' => (string) $accessToken,
                        'token_type'   => 'Bearer',
                        'expires_in'   => $accessToken->getExpiryDateTime()->getTimestamp() - \time(),
                        'state'        => $authorizationRequest->getState(),
                    ],
                    $this->queryDelimiter
                )
            );

            return $response;
        }

        // The user denied the client, redirect them back with an error
        throw OAuthServerException::accessDenied(
            'The user denied the request',
            $this->makeRedirectUri(
                $redirectUrl,
                [
                    'state' => $authorizationRequest->getState(),
                ]
            )
        );
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
}
