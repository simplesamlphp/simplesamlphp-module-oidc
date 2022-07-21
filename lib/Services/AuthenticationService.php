<?php

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

use Exception;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\State;
use SimpleSAML\Error;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Controller\LogoutController;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;

class AuthenticationService
{
    use GetClientFromRequestTrait;

    private UserRepository $userRepository;

    private AuthSimpleFactory $authSimpleFactory;

    private string $userIdAttr;

    private AuthProcService $authProcService;

    private OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService;

    private SessionService $sessionService;

    /**
     * ID of auth source used during authn.
     */
    private ?string $authSourceId;

    private ClaimTranslatorExtractor $claimTranslatorExtractor;

    public function __construct(
        UserRepository $userRepository,
        AuthSimpleFactory $authSimpleFactory,
        AuthProcService $authProcService,
        ClientRepository $clientRepository,
        OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService,
        SessionService $sessionService,
        ClaimTranslatorExtractor $claimTranslatorExtractor,
        string $userIdAttr
    ) {
        $this->userRepository = $userRepository;
        $this->authSimpleFactory = $authSimpleFactory;
        $this->authProcService = $authProcService;
        $this->clientRepository = $clientRepository;
        $this->oidcOpenIdProviderMetadataService = $oidcOpenIdProviderMetadataService;
        $this->sessionService = $sessionService;
        $this->claimTranslatorExtractor = $claimTranslatorExtractor;
        $this->userIdAttr = $userIdAttr;
    }

    /**
     * @param ServerRequestInterface $request
     * @param array $loginParams
     * @param bool $forceAuthn
     * @return UserEntity
     * @throws Error\Exception
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Exception
     */
    public function getAuthenticateUser(
        ServerRequestInterface $request,
        array $loginParams = [],
        bool $forceAuthn = false
    ): UserEntity {
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
                LogoutController::class,
                'logoutHandler'
            );
        } else {
            $this->sessionService->setIsCookieBasedAuthn(true);
        }

        $state = $this->prepareStateArray($authSimple, $oidcClient, $request);
        $state = $this->authProcService->processState($state);
        $claims = $state['Attributes'];

        if (!array_key_exists($this->userIdAttr, $claims)) {
            $attr = implode(', ', array_keys($claims));
            throw new Error\Exception(
                'Attribute `useridattr` doesn\'t exists in claims. Available attributes are: ' . $attr
            );
        }

        $userId = $claims[$this->userIdAttr][0];
        $user = $this->userRepository->getUserEntityByIdentifier($userId);

        if (!$user) {
            $user = UserEntity::fromData($userId, $claims);
            $this->userRepository->add($user);
        } else {
            $user->setClaims($claims);
            $this->userRepository->update($user);
        }

        $this->addRelyingPartyAssociation($oidcClient, $user);

        return $user;
    }

    /**
     * @param Simple $authSimple
     * @param ClientEntityInterface $client
     * @param ServerRequestInterface $request
     * @return array
     */
    private function prepareStateArray(
        Simple $authSimple,
        ClientEntityInterface $client,
        ServerRequestInterface $request
    ): array {
        $state = $authSimple->getAuthDataArray();

        $state['Oidc'] = [
            'OpenIdProviderMetadata' => $this->oidcOpenIdProviderMetadataService->getMetadata(),
            'RelyingPartyMetadata' => array_filter($client->toArray(), function (string $key) {
                return $key !== 'secret';
            }, ARRAY_FILTER_USE_KEY),
            'AuthorizationRequestParameters' => array_filter($request->getQueryParams(), function (string $key) {
                $relevantAuthzParams = ['response_type', 'client_id', 'redirect_uri', 'scope', 'code_challenge_method'];
                return in_array($key, $relevantAuthzParams);
            }, ARRAY_FILTER_USE_KEY),
        ];

        // Source and destination entity IDs, useful for eg. F-ticks logging...
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
     * @param ClientEntityInterface $oidcClient
     * @param UserEntity $user
     * @throws Exception
     */
    protected function addRelyingPartyAssociation(ClientEntityInterface $oidcClient, UserEntity $user): void
    {
        // We need to make sure that we use 'sub' as user identifier, if configured.
        $claims = $this->claimTranslatorExtractor->extract(['openid'], $user->getClaims());

        $this->sessionService->addRelyingPartyAssociation(
            new RelyingPartyAssociation(
                $oidcClient->getIdentifier(),
                $claims['sub'] ?? $user->getIdentifier(),
                $this->getSessionId(),
                $oidcClient->getBackChannelLogoutUri()
            )
        );
    }
}
