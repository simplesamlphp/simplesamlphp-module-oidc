<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface as OAuth2AuthorizationRequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NoState;
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
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;

class AuthenticationService
{
    /**
     * Login parameter (state array key) used to pre-fill the username on the SimpleSAMLphp core UserPass login form.
     */
    public const string LOGIN_PARAM_USERNAME = 'core:username';


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
            $this->authenticate($authSimple, $this->resolveLoginParams($authorizationRequest));
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
            'AuthorizationRequestParameters' => array_filter(
                $this->requestParamsResolver->getAll($request),
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

        return $state;
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
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function authenticate(
        Simple $authSimple,
        array $loginParams = [],
    ): void {
        $this->sessionService->setIsCookieBasedAuthn(false);
        $this->sessionService->setIsAuthnPerformedInPreviousRequest(true);

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
        array $loginParams = [],
    ): void {
        $this->authenticate($this->authSimpleFactory->build($clientEntity), $loginParams);
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

        // We need to make sure that we use 'sub' as user identifier, if configured.
        $claims = $this->claimTranslatorExtractor->extract(['openid'], $attributes);
        $canonicalSubject = (isset($claims['sub']) && is_scalar($claims['sub'])) ? (string)$claims['sub'] : $userId;

        return hash_equals($canonicalSubject, $subject);
    }


    /**
     * Store Relying on Party Association to the current session.
     * @throws \Exception
     */
    protected function addRelyingPartyAssociation(ClientEntityInterface $oidcClient, UserEntity $user): void
    {
        // We need to make sure that we use 'sub' as user identifier, if configured.
        $claims = $this->claimTranslatorExtractor->extract(['openid'], $user->getClaims());

        $this->sessionService->addRelyingPartyAssociation(
            new RelyingPartyAssociation(
                $oidcClient->getIdentifier(),
                (string)($claims['sub'] ?? $user->getIdentifier()),
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

        $this->processingChainFactory->build($state)->processState($state);
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
