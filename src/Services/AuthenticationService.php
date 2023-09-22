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

use Exception;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\State;
use SimpleSAML\Error;
use SimpleSAML\Module\oidc\Controller\LogoutController;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

class AuthenticationService
{
    use GetClientFromRequestTrait;

    /**
     * ID of auth source used during authn.
     */
    private ?string $authSourceId = null;

    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly AuthSimpleFactory $authSimpleFactory,
        private readonly AuthProcService $authProcService,
        ClientRepository $clientRepository,
        private readonly OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService,
        private readonly SessionService $sessionService,
        private readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        private readonly string $userIdAttr
    ) {
        $this->clientRepository = $clientRepository;
    }

    /**
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

        if (!isset($state['Attributes']) || !is_array($state['Attributes'])) {
            throw new Error\Exception('State array does not contain any attributes.');
        }

        $claims = $state['Attributes'];

        if (!array_key_exists($this->userIdAttr, $claims) || !is_array($claims[$this->userIdAttr])) {
            $attr = implode(', ', array_keys($claims));
            throw new Error\Exception(
                'Attribute `useridattr` doesn\'t exists in claims. Available attributes are: ' . $attr
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

        $this->addRelyingPartyAssociation($oidcClient, $user);

        return $user;
    }

    /**
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
            'RelyingPartyMetadata' => array_filter(
                $client->toArray(),
                fn(string $key) => $key !== 'secret',
                ARRAY_FILTER_USE_KEY
            ),
            'AuthorizationRequestParameters' => array_filter($request->getQueryParams(), function (string $key) {
                $relevantAuthzParams = ['response_type', 'client_id', 'redirect_uri', 'scope', 'code_challenge_method'];
                return in_array($key, $relevantAuthzParams);
            }, ARRAY_FILTER_USE_KEY),
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
     * @throws Exception
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
                $oidcClient->getBackChannelLogoutUri()
            )
        );
    }
}
