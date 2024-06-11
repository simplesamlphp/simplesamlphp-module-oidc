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
use SimpleSAML\Error\AuthSource;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Error\UnserializableException;
use SimpleSAML\Module\oidc\Controller\EndSessionController;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

class AuthenticationService
{
    use GetClientFromRequestTrait;

    /**
     * ID of auth source used during authn.
     */
    private ?string $authSourceId = null;
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
        private readonly ModuleConfig $moduleConfig
    ) {
        $this->clientRepository = $clientRepository;
        $this->userIdAttr = $this->moduleConfig->getUserIdentifierAttribute();
    }

    /**
     * @param   ServerRequestInterface      $request
     * @param   OAuth2AuthorizationRequest  $authorizationRequest
     * @param   array                       $loginParams
     * @param   bool                        $forceAuthn
     *
     * @return void
     * @throws AuthSource
     * @throws BadRequest
     * @throws Exception
     * @throws NotFound
     * @throws OidcServerException
     * @throws UnserializableException
     * @throws \JsonException
     */
    public function handleState(
        ServerRequestInterface $request,
        OAuth2AuthorizationRequest $authorizationRequest,
        array $loginParams = [],
        bool $forceAuthn = false,
    ): void {
        $oidcClient = $this->getClientFromRequest($request);
        $authSimple = $this->authSimpleFactory->build($oidcClient);

        $this->authSourceId = $authSimple->getAuthSource()->getAuthId();

        if (! $authSimple->isAuthenticated() || $forceAuthn === true) {
            $this->sessionService->setIsCookieBasedAuthn(false);
            $this->sessionService->setIsAuthnPerformedInPreviousRequest(true);

            $authSimple->login($loginParams);
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

        $state = $this->prepareStateArray($authSimple, $oidcClient, $request);
        $state['authorizationRequest'] = $authorizationRequest;
        $this->runAuthProcs($state);
    }


    /**
     * @param   array                   $state
     *
     * @return UserEntity
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function getAuthenticateUser(
        array &$state
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

        if (!$user) {
            $user = UserEntity::fromData($userId, $claims);
            $this->userRepository->add($user);
        } else {
            $user->setClaims($claims);
            $this->userRepository->update($user);
        }

        $client = $this->clientRepository->findById($state['Oidc']['RelyingPartyMetadata']['id']);
        if (!$client) {
            throw new Error\NotFound('Client not found.');
        }

        $this->addRelyingPartyAssociation($client, $user);

        return $user;
    }

    private function prepareStateArray(
        Simple $authSimple,
        ClientEntityInterface $client,
        ServerRequestInterface $request,
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

        return $state;
    }

    public function isCookieBasedAuthn(): bool
    {
        return (bool) $this->sessionService->getIsCookieBasedAuthn();
    }

    public function getAuthSourceId(): ?string
    {
        return $this->authSourceId;
    }

    public function getSessionId(): ?string
    {
        return $this->sessionService->getCurrentSession()->getSessionId();
    }

    /**
     * Store Relying Party Association to the current session.
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
     * Run authproc filters with the processing chain
     * Creating the ProcessingChain require metadata.
     * - For the idp metadata use the OIDC issuer as the entityId (and the authprocs from the main config file)
     * - For the sp metadata use the client id as the entityId (and don’t set authprocs).
     *
     * @param   array  $state
     *
     * @return void
     * @throws Exception
     * @throws UnserializableException
     */
    protected function runAuthProcs(array &$state): void
    {
        $idpMetadata = [
            'entityid' => $state['Source']['entityid'],
            // ProcessChain needs to know the list of authproc filters we defined in module_oidc configuration
            'authproc' => $this->moduleConfig->getAuthProcFilters()
        ];
        $spMetadata = [
            'entityid' => $state['Destination']['entityid']
        ];
        $pc = new ProcessingChain(
            $idpMetadata,
            $spMetadata,
            explode('.', $this->moduleConfig::OPTION_AUTH_PROCESSING_FILTERS)[1]
        );

        $state['ReturnURL'] = $this->moduleConfig->getModuleUrl('authorize.php');
        $state['Destination'] = $spMetadata;
        $state['Source'] = $idpMetadata;

        $pc->processState($state);

        // If no filter(s) is available in the configuration, it will enforce a redirect
        // to the authentication endpoint.
        ProcessingChain::resumeProcessing($state);
    }
}
