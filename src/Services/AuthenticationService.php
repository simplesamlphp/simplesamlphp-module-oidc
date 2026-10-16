<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface as OAuth2AuthorizationRequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NoState;
use SimpleSAML\Error\UserAborted;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controllers\EndSessionController;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Factories\ProcessingChainFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeResolver;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\AuthorizationErrorRedirect;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use Throwable;

class AuthenticationService
{
    /**
     * Login parameter (state array key) used to pre-fill the username on the SimpleSAMLphp core UserPass login form.
     */
    public const string LOGIN_PARAM_USERNAME = 'core:username';

    /**
     * State array key under which the AuthorizationErrorRedirect of the authorization request being authenticated is
     * kept: in the authentication source's state (a login parameter, authenticate()) and in the processing chain's
     * (prepareStateArray()).
     */
    public const string STATE_KEY_AUTHORIZATION_ERROR_REDIRECT = 'oidc:AuthorizationErrorRedirect';


    /**
     * ID of auth source used during authn.
     */
    private ?string $authSourceId = null;

    /**
     * Ordered list of candidate user identifier attributes.
     * @var string[]
     */
    private readonly array $userIdAttrs;


    /**
     * @throws \Exception
     */
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly AuthSimpleFactory $authSimpleFactory,
        private readonly ClientRepository $clientRepository,
        private readonly OpMetadataService $opMetadataService,
        private readonly SessionService $sessionService,
        private readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        private readonly ModuleConfig $moduleConfig,
        private readonly ProcessingChainFactory $processingChainFactory,
        private readonly StateService $stateService,
        private readonly RequestParamsResolver $requestParamsResolver,
        private readonly UserEntityFactory $userEntityFactory,
        private readonly Routes $routes,
        private readonly UserIdentifierResolver $userIdentifierResolver,
        private readonly ResponseModeResolver $responseModeResolver,
        private readonly PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository,
    ) {
        $this->userIdAttrs = $this->moduleConfig->getUserIdentifierAttributes();
    }


    /**
     * @param   \Psr\Http\Message\ServerRequestInterface           $request
     * @param   \League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface       $authorizationRequest
     *
     * @return array
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\UnserializableException
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function processRequest(
        ServerRequestInterface $request,
        OAuth2AuthorizationRequestInterface $authorizationRequest,
    ): array {
        $oidcClient = $authorizationRequest->getClient();
        $authSimple = $this->authSimpleFactory->build($oidcClient);

        $this->authSourceId = $authSimple->getAuthSource()->getAuthId();

        if (! $authSimple->isAuthenticated()) {
            $this->authenticate(
                $authSimple,
                $this->resolveAuthorizationErrorRedirect($authorizationRequest),
                $this->resolveLoginParams($authorizationRequest),
            );
        } elseif ($this->sessionService->getIsAuthnPerformedInPreviousRequest()) {
            $this->sessionService->setIsAuthnPerformedInPreviousRequest(false);

            $this->sessionService->registerLogoutHandler(
                $this->authSourceId,
                EndSessionController::class,
                'logoutHandler',
            );
        } else {
            $this->sessionService->setIsCookieBasedAuthn(true);
        }

        $state = $this->prepareStateArray($authSimple, $oidcClient, $request, $authorizationRequest);
        $this->runAuthProcs($state);

        return $state;
    }


    /**
     * @param array|null $state
     *
     * @return \SimpleSAML\Module\oidc\Entities\UserEntity
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function getAuthenticateUser(
        ?array $state,
    ): UserEntity {
        if (!isset($state['Attributes']) || !is_array($state['Attributes'])) {
            throw new Exception('State array does not contain any attributes.');
        }

        $claims = $state['Attributes'];

        $userId = $this->userIdentifierResolver->resolve($this->userIdAttrs, $claims);

        if ($userId === null) {
            throw new Exception(
                sprintf(
                    'None of the configured user identifier attributes (%s) exist in the user attribute state.' .
                    ' Available attributes are: %s.',
                    implode(', ', $this->userIdAttrs),
                    implode(', ', array_keys($claims)),
                ),
            );
        }

        $user = $this->userRepository->getUserEntityByIdentifier($userId);

        if ($user) {
            $user->setClaims($claims);
            $this->userRepository->update($user);
        } else {
            $user = $this->userEntityFactory->fromData($userId, $claims);
            $this->userRepository->add($user);
        }

        if (empty($state['Oidc']['RelyingPartyMetadata']['id'])) {
            throw new Exception('OIDC RelyingPartyMetadata ID does not exist in state.');
        }

        $client = $this->clientRepository->findById((string)$state['Oidc']['RelyingPartyMetadata']['id']);
        if (!$client) {
            throw new OidcException('Client not found.');
        }

        // A plain OAuth 2.0 login gets its client no ID token, so no session with this OP which it could be told the
        // end of (OpenID Connect Back-Channel Logout 1.0): the client is not associated with the session, and gets no
        // logout token on account of this login.
        /** @psalm-suppress MixedAssignment */
        $authorizationRequest = $state['authorizationRequest'] ?? null;
        if (
            $authorizationRequest instanceof AuthorizationRequest &&
            $authorizationRequest->getFlowType() === FlowTypeEnum::OAuth2AuthorizationCode
        ) {
            return $user;
        }

        $this->addRelyingPartyAssociation($client, $user);

        return $user;
    }

    /**
     * @param   array|null  $state
     *
     * @return \League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface
     * @throws \SimpleSAML\Error\Exception
     */

    public function getAuthorizationRequestFromState(array|null $state): OAuth2AuthorizationRequestInterface
    {
        if (!isset($state['authorizationRequest'])) {
            throw new Exception('Authorization Request is not set.');
        }

        if ($state['authorizationRequest'] instanceof AuthorizationRequest) {
            return $state['authorizationRequest'];
        } elseif ($state['authorizationRequest'] instanceof OAuth2AuthorizationRequestInterface) {
            return $state['authorizationRequest'];
        } else {
            throw new Exception('Authorization Request is not valid.');
        }
    }

    /**
     * @param   \SimpleSAML\Auth\Simple                      $authSimple
     * @param   \League\OAuth2\Server\Entities\ClientEntityInterface       $client
     * @param   \Psr\Http\Message\ServerRequestInterface      $request
     * @param   \League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface  $authorizationRequest
     *
     * @return array
     * @throws \SimpleSAML\Error\AuthSource
     */

    public function prepareStateArray(
        Simple $authSimple,
        OAuth2ClientEntityInterface $client,
        ServerRequestInterface $request,
        OAuth2AuthorizationRequestInterface $authorizationRequest,
    ): array {
        $state = $authSimple->getAuthDataArray();

        $clientArray = $client instanceof ClientEntityInterface ? $client->toArray() : [];

        $state['Oidc'] = [
            'OpenIdProviderMetadata' => $this->opMetadataService->getMetadata(),
            'RelyingPartyMetadata' => array_filter(
                $clientArray,
                fn(/** @param array-key $key */ $key) => $key !== 'secret',
                ARRAY_FILTER_USE_KEY,
            ),
            // Read as the grants validate the request (AuthCodeGrant::$allowedAuthorizationHttpMethods): from the
            // query of a GET, from the body of a POST. A request_uri the other one carries is then not redeemed
            // here either.
            'AuthorizationRequestParameters' => array_filter(
                $this->requestParamsResolver->getAllBasedOnAllowedMethods(
                    $request,
                    [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
                ),
                function (/** @param array-key $key */ $key) {
                    $authzParams = ['response_type', 'client_id', 'redirect_uri', 'scope', 'code_challenge_method'];
                    return in_array($key, $authzParams, true);
                },
                ARRAY_FILTER_USE_KEY,
            ),
        ];

        // Source and destination entity IDs, useful for e.g. F-ticks logging...
        $state['Source'] = ['entityid' => $state['Oidc']['OpenIdProviderMetadata']['issuer']];
        $state['Destination'] = ['entityid' => $state['Oidc']['RelyingPartyMetadata']['id']];

        $state[State::RESTART] = $request->getUri()->__toString();

        // Data required after we get back from a ProcessingChain redirect
        $state['authorizationRequest'] = $authorizationRequest;
        $state['authSourceId'] = $authSimple->getAuthSource()->getAuthId();

        // Where the client is answered if the End-User cancels in an authentication processing filter.
        $state[self::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT] = $this->resolveAuthorizationErrorRedirect(
            $authorizationRequest,
        );

        return $state;
    }


    /**
     * The redirect an error response to the authorization request takes: its redirect URI, which the grants have
     * validated, its `state`, its response mode, and the Pushed Authorization Request it was made with, if any. A
     * request with no redirect URI has none, and a cancelled authentication of it is shown to the End-User as
     * SimpleSAMLphp shows it.
     */
    public function resolveAuthorizationErrorRedirect(
        OAuth2AuthorizationRequestInterface $authorizationRequest,
    ): ?AuthorizationErrorRedirect {
        if (($redirectUri = $authorizationRequest->getRedirectUri()) === null) {
            return null;
        }

        return new AuthorizationErrorRedirect(
            $redirectUri,
            $authorizationRequest->getState(),
            $authorizationRequest instanceof AuthorizationRequest ?
                $authorizationRequest->getResponseMode()?->getMode() :
                null,
            $authorizationRequest instanceof AuthorizationRequest ?
                $authorizationRequest->getPushedAuthorizationRequestUri() :
                null,
        );
    }


    /**
     * @return bool
     */
    public function isCookieBasedAuthn(): bool
    {
        return (bool) $this->sessionService->getIsCookieBasedAuthn();
    }


    /**
     * @return string|null
     */
    public function getAuthSourceId(): ?string
    {
        return $this->authSourceId;
    }


    /**
     * @return string|null
     */
    public function getSessionId(): ?string
    {
        return $this->sessionService->getCurrentSession()->getSessionId();
    }


    /**
     * Resolve additional login parameters to pass to the authentication source, based on the authorization request.
     *
     * Currently this propagates the login_hint authorization request parameter to the SimpleSAMLphp login page as
     * the pre-filled username (the standard 'core:username' state key consumed by the core UserPass login form).
     * Per specification this is a hint about the identifier the End-User might use to log in, so it is best-effort:
     * auth sources that do not use the core login form simply ignore it, and an incorrect value is corrected by the
     * user (or the login simply fails with invalid credentials).
     *
     * @return array<string,mixed>
     */
    protected function resolveLoginParams(OAuth2AuthorizationRequestInterface $authorizationRequest): array
    {
        if (
            !$authorizationRequest instanceof AuthorizationRequest ||
            ($loginHint = $authorizationRequest->getLoginHint()) === null
        ) {
            return [];
        }

        return [self::LOGIN_PARAM_USERNAME => $loginHint];
    }


    /**
     * Log the End-User in for an authorization request. An exception the authentication source raises through its
     * state (State::throwException()), the End-User cancelling among them, comes back to the authorization endpoint
     * through the ErrorURL, with the redirect the client is answered at (rethrowAuthenticationException()).
     *
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function authenticate(
        Simple $authSimple,
        ?AuthorizationErrorRedirect $authorizationErrorRedirect,
        array $loginParams = [],
    ): void {
        $this->sessionService->setIsCookieBasedAuthn(false);
        $this->sessionService->setIsAuthnPerformedInPreviousRequest(true);

        if ($authorizationErrorRedirect !== null) {
            $loginParams['ErrorURL'] = $this->routes->getModuleUrl(RoutesEnum::Authorization->value);
            $loginParams[self::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT] = $authorizationErrorRedirect;
        }

        $authSimple->login($loginParams);
    }


    /**
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\NotFound
     * @throws \JsonException
     */
    public function authenticateForClient(
        ClientEntityInterface $clientEntity,
        AuthorizationErrorRedirect $authorizationErrorRedirect,
        array $loginParams = [],
    ): void {
        $this->authenticate($this->authSimpleFactory->build($clientEntity), $authorizationErrorRedirect, $loginParams);
    }


    /**
     * Answer an authentication which SimpleSAMLphp ended with an exception and handed back to the authorization
     * endpoint (State::throwException(), through the ErrorURL authenticate() gives the login or the exception handler
     * URL runAuthProcs() gives the processing chain). The End-User cancelling (UserAborted) is answered to the client
     * with `access_denied` (answerCancelledAuthentication()); any other exception is thrown as it was raised, so
     * SimpleSAMLphp shows it as it would have without the handler.
     *
     * Whatever the exception, a login the module started for the request did not complete. It leaves the mark
     * authenticate() set, that a login was performed, which would have the next request take the session for a
     * fresh login (processRequest()): after a failed re-authentication for `prompt=login` or `max_age`, the earlier
     * session. So the mark is cleared, for a state the module prepared.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NoState
     */
    public function rethrowAuthenticationException(array $queryParameters): never
    {
        $exceptionStateId = $queryParameters[State::EXCEPTION_PARAM] ?? null;
        if (!is_string($exceptionStateId) || $exceptionStateId === '') {
            throw new NoState();
        }

        $state = $this->stateService->loadExceptionState($exceptionStateId);
        if ($state === null) {
            throw new NoState();
        }

        if (($state[self::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT] ?? null) instanceof AuthorizationErrorRedirect) {
            $this->sessionService->setIsAuthnPerformedInPreviousRequest(false);
        }

        /** @psalm-suppress MixedAssignment */
        $exception = $state[State::EXCEPTION_DATA] ?? null;

        if ($exception instanceof UserAborted) {
            throw $this->answerCancelledAuthentication($state, $exception);
        }

        if ($exception instanceof Throwable) {
            throw $exception;
        }

        throw new Exception('Exception state does not contain an exception.');
    }


    /**
     * Determine whether the given subject identifier corresponds to the End-User described by the released
     * (post-authproc) attributes. This is used to verify an `id_token_hint` subject against the authenticated
     * End-User at the authorization endpoint (see AuthorizationController).
     *
     * A single canonical subject is derived using the same default logic that produces the `sub` claim during token
     * issuance (see IdTokenBuilder and addRelyingPartyAssociation()): the resolved user identifier, unless a `sub`
     * claim mapping (openid scope) produces a value, which then takes precedence. Deriving one value (rather than
     * accepting several candidate forms) is important for security: distinct subject namespaces could otherwise
     * collide across users (one user's mapped `sub` equalling another user's raw identifier), which would let an
     * `id_token_hint` match the wrong End-User.
     *
     * This mirrors the canonical subject resolution in IdTokenBuilder, which issues the same value for a given user
     * regardless of the flow, client claim-release settings or granted scopes, so the comparison is exact.
     *
     * @param array<array-key,mixed> $attributes Released (post-authproc) attributes.
     */
    public function subjectMatchesAttributes(string $subject, array $attributes): bool
    {
        $userId = $this->userIdentifierResolver->resolve($this->userIdAttrs, $attributes);
        if ($userId === null) {
            return false;
        }

        // We need to make sure that we use 'sub' as a user identifier, if configured. The subject alone: this runs
        // before the authentication processing filters for a prompt=none request, so an identity claim whose
        // attribute a filter still has to supply must not get in the way of the comparison.
        $canonicalSubject = $this->claimTranslatorExtractor->extractSubject($attributes) ?? $userId;

        return hash_equals($canonicalSubject, $subject);
    }


    /**
     * Store Relying on Party Association to the current session.
     * @throws \Exception
     */
    protected function addRelyingPartyAssociation(ClientEntityInterface $oidcClient, UserEntity $user): void
    {
        // We need to make sure that we use 'sub' as user identifier, if configured. The subject alone is stored.
        $subject = $this->claimTranslatorExtractor->extractSubject($user->getClaims());

        $this->sessionService->addRelyingPartyAssociation(
            new RelyingPartyAssociation(
                $oidcClient->getIdentifier(),
                $subject ?? $user->getIdentifier(),
                $this->getSessionId(),
                $oidcClient->getBackChannelLogoutUri(),
                $oidcClient->getIdTokenSignedResponseAlg(),
            ),
        );
    }


    /**
     * This is a wrapper around Auth/State::loadState that facilitates testing by
     * hiding the static method
     *
     * @param   array  $queryParameters
     *
     * @return array|null
     * @throws \SimpleSAML\Error\NoState
     */
    public function manageState(array $queryParameters): ?array
    {
        if (empty($queryParameters[ProcessingChain::AUTHPARAM])) {
            throw new NoState();
        }

        $stateId = (string)$queryParameters[ProcessingChain::AUTHPARAM];
        $state = $this->stateService->loadState($stateId, ProcessingChain::COMPLETED_STAGE);

        if (!empty($state['authSourceId'])) {
            $this->authSourceId = (string)$state['authSourceId'];
            unset($state['authSourceId']);
        }

        return $state;
    }


    /**
     * Run authproc filters with the processing chain.
     *
     * This is the single source of truth for the metadata that drives the
     * ProcessingChain. We build it once here and store it back into the state;
     * the ProcessingChainFactory then only consumes the prepared state:
     * - IdP metadata uses the OIDC issuer as the entityId and carries the global
     *   authproc filters (from the module configuration).
     * - SP metadata uses the client ID as the entityId and carries the
     *   per-client authproc filters (from the client's metadata).
     * The SimpleSAMLphp ProcessingChain then merges both filter lists by
     * priority, mimicking SAML IdP + SP authproc filters.
     *
     * @param   array  $state
     *
     * @return void
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\UnserializableException
     * @throws \Exception
     */
    protected function runAuthProcs(array &$state): void
    {
        $state['ReturnURL'] = $this->routes->getModuleUrl(RoutesEnum::Authorization->value);
        // An exception a filter raises once it has sent the End-User to a page of its own comes back to the
        // authorization endpoint too (State::throwException(), rethrowAuthenticationException()). One raised before
        // that is thrown out of processState(), below.
        $state[State::EXCEPTION_HANDLER_URL] = $state['ReturnURL'];

        // Note: we only augment the existing Source / Destination entries (which
        // already carry the 'entityid' set in prepareStateArray()) with their
        // respective authproc filter lists. No state keys are removed.
        $state['Source'] = [
            'entityid' => $state['Source']['entityid'] ?? '',
            'authproc' => $this->moduleConfig->getAuthProcFilters(),
        ];
        $state['Destination'] = [
            'entityid' => $state['Destination']['entityid'] ?? '',
            'authproc' => $this->resolveClientAuthProcFilters($state),
        ];

        try {
            $this->processingChainFactory->build($state)->processState($state);
        } catch (UserAborted $exception) {
            throw $this->answerCancelledAuthentication($state, $exception);
        }
    }


    /**
     * The `access_denied` the client is answered with when the End-User cancelled the authentication (UserAborted),
     * at the redirect kept in the state (RFC 6749 sections 4.1.2.1 and 4.2.2.1); the authorization endpoint adds
     * `iss`. It is the response to the request, so a Pushed Authorization Request the request was made with is
     * consumed first, as AuthorizationServer::completeAuthorizationRequest() consumes it for a successful one: one
     * request_uri yields at most one response.
     *
     * @throws \SimpleSAML\Error\UserAborted when the state holds no redirect to answer the client at, so that
     * SimpleSAMLphp shows the cancel as it would have
     * @throws \SimpleSAML\Error\BadRequest when the pushed request has had its response already
     */
    protected function answerCancelledAuthentication(array $state, UserAborted $exception): OidcServerException
    {
        $authorizationErrorRedirect = $state[self::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT] ?? null;
        if (!$authorizationErrorRedirect instanceof AuthorizationErrorRedirect) {
            throw $exception;
        }

        if (
            ($requestUri = $authorizationErrorRedirect->getPushedAuthorizationRequestUri()) !== null &&
            !$this->pushedAuthorizationRequestRepository->consume($requestUri)
        ) {
            // From another tab, or a replay of the request: no second response, as AuthorizationServer refuses one.
            throw new BadRequest('Pushed authorization request has already been used.');
        }

        $responseMode = $authorizationErrorRedirect->getResponseMode();

        return OidcServerException::accessDenied(
            'The End-User cancelled the authentication.',
            $authorizationErrorRedirect->getRedirectUri(),
            $exception,
            $authorizationErrorRedirect->getState(),
            $responseMode === null ? null : $this->responseModeResolver->forMode($responseMode),
        );
    }


    /**
     * Resolve per-client authproc filters from the OIDC relying party metadata
     * present in the authentication state (exposed there by prepareStateArray()).
     */
    protected function resolveClientAuthProcFilters(array $state): array
    {
        $relyingPartyMetadata = $state['Oidc']['RelyingPartyMetadata'] ?? null;
        if (!is_array($relyingPartyMetadata)) {
            return [];
        }

        /** @var mixed $authProcFilters */
        $authProcFilters = $relyingPartyMetadata[ClientEntity::KEY_AUTH_PROC_FILTERS] ?? null;

        return is_array($authProcFilters) ? $authProcFilters : [];
    }
}
