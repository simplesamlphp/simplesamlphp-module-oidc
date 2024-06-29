<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Services;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\State;
use SimpleSAML\Error;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NoState;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controller\EndSessionController;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

class AuthenticationService
{
    use GetClientFromRequestTrait;

    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected string|State $authState = \SimpleSAML\Auth\State::class;

    /**
     * ID of auth source used during authn.
     */
    private ?string $authSourceId = null;

    /**
     * @var string
     */
    private string $userIdAttr;

    /**
     * @throws \Exception
     */
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly AuthSimpleFactory $authSimpleFactory,
        ClientRepository $clientRepository,
        private readonly OpMetadataService $opMetadataService,
        private readonly SessionService $sessionService,
        private readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        private readonly ModuleConfig $moduleConfig,
    ) {
        $this->clientRepository = $clientRepository;
        $this->userIdAttr = $this->moduleConfig->getUserIdentifierAttribute();
    }

    /**
     * @param   ServerRequestInterface           $request
     * @param   OAuth2AuthorizationRequest       $authorizationRequest
     *
     * @return array
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Exception
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws Error\UnserializableException
     * @throws \JsonException
     */
    public function processRequest(
        ServerRequestInterface $request,
        OAuth2AuthorizationRequest $authorizationRequest,
    ): array {
        $oidcClient = $this->getClientFromRequest($request);
        $authSimple = $this->authSimpleFactory->build($oidcClient);

        $this->authSourceId = $authSimple->getAuthSource()->getAuthId();

        if (! $authSimple->isAuthenticated()) {
            $this->authenticate($request);
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
     * @param   array  $state
     *
     * @return UserEntity
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function getAuthenticateUser(
        array $state,
    ): UserEntity {
        if (!isset($state['Attributes']) || !is_array($state['Attributes'])) {
            throw new Error\Exception('State array does not contain any attributes.');
        }

        $claims = $state['Attributes'];

        if (!array_key_exists($this->userIdAttr, $claims) || !is_array($claims[$this->userIdAttr])) {
            $attr = implode(', ', array_keys($claims));
            throw new Error\Exception(
                'Attribute `useridattr` doesn\'t exists in claims. Available attributes are: ' . $attr,
            );
        }

        $userId = (string)$claims[$this->userIdAttr][0];
        $user = $this->userRepository->getUserEntityByIdentifier($userId);

        if ($user) {
            $user->setClaims($claims);
            $this->userRepository->update($user);
        } else {
            $user = UserEntity::fromData($userId, $claims);
            $this->userRepository->add($user);
        }

        if (empty($state['Oidc']['RelyingPartyMetadata']['id'])) {
            throw new Error\Exception('OIDC RelyingPartyMetadata ID does not exist in state.');
        }

        $client = $this->clientRepository->findById((string)$state['Oidc']['RelyingPartyMetadata']['id']);
        if (!$client) {
            throw new Error\NotFound('Client not found.');
        }

        $this->addRelyingPartyAssociation($client, $user);

        return $user;
    }

    /**
     * @param   array  $state
     *
     * @return AuthorizationRequest
     * @throws Exception
     */

    public function getAuthorizationRequestFromState(array $state): AuthorizationRequest
    {
        if (!($state['authorizationRequest'] instanceof AuthorizationRequest)) {
            throw new Exception('Authorization Request is not valid');
        }
        return $state['authorizationRequest'];
    }

    /**
     * @param   Simple                      $authSimple
     * @param   ClientEntityInterface       $client
     * @param   ServerRequestInterface      $request
     * @param   OAuth2AuthorizationRequest  $authorizationRequest
     *
     * @return array
     * @throws Error\AuthSource
     */

    public function prepareStateArray(
        Simple $authSimple,
        ClientEntityInterface $client,
        ServerRequestInterface $request,
        OAuth2AuthorizationRequest $authorizationRequest,
    ): array {
        $state = $authSimple->getAuthDataArray();

        $state['Oidc'] = [
            'OpenIdProviderMetadata' => $this->opMetadataService->getMetadata(),
            'RelyingPartyMetadata' => array_filter(
                $client->toArray(),
                fn(/** @param array-key $key */ $key) => $key !== 'secret',
                ARRAY_FILTER_USE_KEY,
            ),
            'AuthorizationRequestParameters' => array_filter(
                $request->getQueryParams(),
                function (/** @param array-key $key */ $key) {
                    $authzParams = ['response_type', 'client_id', 'redirect_uri', 'scope', 'code_challenge_method'];
                    return in_array($key, $authzParams);
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
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param State $authState
     */
    public function setAuthState(State $authState): void
    {
        $this->authState = $authState;
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
     * @param   ServerRequestInterface  $request
     * @param   array                   $loginParams
     *
     * @return void
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */

    public function authenticate(
        ServerRequestInterface $request,
        array $loginParams = [],
    ): void {
        $oidcClient = $this->getClientFromRequest($request);
        $authSimple = $this->authSimpleFactory->build($oidcClient);

        $this->sessionService->setIsCookieBasedAuthn(false);
        $this->sessionService->setIsAuthnPerformedInPreviousRequest(true);

        $authSimple->login($loginParams);
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
            ),
        );
    }

    /**
     * This is a wrapper around Auth/State::loadState that facilitates testing by
     * hiding the static method
     *
     * @param   array  $queryParameters
     *
     * @return array
     * @throws NoState
     */
    public function loadState(array $queryParameters): array
    {
        if (empty($queryParameters[ProcessingChain::AUTHPARAM])) {
            throw new NoState();
        }

        $stateId = (string)$queryParameters[ProcessingChain::AUTHPARAM];
        \assert($this->authState instanceof State);
        $state = $this->authState::loadState($stateId, ProcessingChain::COMPLETED_STAGE);

        $this->authSourceId = (string)$state['authSourceId'];
        unset($state['authSourceId']);

        return $state;
    }

    /**
     * Run authproc filters with the processing chain
     * Creating the ProcessingChain require metadata.
     * - For the idp metadata use the OIDC issuer as the entityId (and the authprocs from the main config file)
     * - For the sp metadata use the client id as the entityId (and don’t set authprocs).
     *
     * @param   array  $state
     *
     * @return void
     * @throws Exception
     * @throws Error\UnserializableException
     */
    protected function runAuthProcs(array &$state): void
    {
        $idpMetadata = [
            'entityid' => $state['Source']['entityid'] ?? '',
            // ProcessChain needs to know the list of authproc filters we defined in module_oidc configuration
            'authproc' => $this->moduleConfig->getAuthProcFilters(),
        ];
        $spMetadata = [
            'entityid' => $state['Destination']['entityid'] ?? '',
        ];
        $pc = new ProcessingChain(
            $idpMetadata,
            $spMetadata,
            'oidc',
        );

        $state['ReturnURL'] = $this->moduleConfig->getModuleUrl(RoutesEnum::OpenIdAuthorization->value);
        $state['Destination'] = $spMetadata;
        $state['Source'] = $idpMetadata;

        $pc->processState($state);
    }
}
