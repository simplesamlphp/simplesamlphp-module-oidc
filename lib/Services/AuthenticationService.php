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

use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Session;

class AuthenticationService
{
    use GetClientFromRequestTrait;

    /**
     * @var UserRepository
     */
    private $userRepository;
    /**
     * @var AuthSimpleFactory
     */
    private $authSimpleFactory;
    /**
     * @var string
     */
    private $userIdAttr;
    /**
     * @var AuthProcService
     */
    private $authProcService;
    /**
     * @var OidcOpenIdProviderMetadataService
     */
    private $oidcOpenIdProviderMetadataService;

    /**
     * @var bool
     */
    private $isCookieBasedAuthn = false;
    /**
     * @var Session
     */
    private $session;

    public const SESSION_DATA_TYPE = 'oidc-authn';

    public const SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN = 'is-cookie-based-authn';

    public const SESSION_DATA_ID_RP_ASSOCIATIONS = 'rp-associations';

    /**
     * ID of authsource used during authn.
     * @var string|null
     */
    private $authSourceId;

    public function __construct(
        UserRepository $userRepository,
        AuthSimpleFactory $authSimpleFactory,
        AuthProcService $authProcService,
        ClientRepository $clientRepository,
        OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService,
        Session $session,
        string $userIdAttr
    ) {
        $this->userRepository = $userRepository;
        $this->authSimpleFactory = $authSimpleFactory;
        $this->authProcService = $authProcService;
        $this->clientRepository = $clientRepository;
        $this->oidcOpenIdProviderMetadataService = $oidcOpenIdProviderMetadataService;
        $this->session = $session;
        $this->userIdAttr = $userIdAttr;
    }

    /**
     * @param ServerRequest $request
     * @return UserEntity
     * @throws \Exception
     */
    public function getAuthenticateUser(ServerRequest $request): UserEntity
    {
        $oidcClient = $this->getClientFromRequest($request);
        $authSimple = $this->authSimpleFactory->build($request);

        $this->authSourceId = $authSimple->getAuthSource()->getAuthId();

        // Distinguish if the user already had active session or the actual authn was performed.
        $this->isCookieBasedAuthn = $this->session->getData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN
        ) ?? false;

        if ($authSimple->isAuthenticated()) {
            $this->session->setData(
                self::SESSION_DATA_TYPE,
                self::SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN,
                true,
                Session::DATA_TIMEOUT_SESSION_END
            );
        } else {
            $this->session->setData(self::SESSION_DATA_TYPE, self::SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN, false);
            $authSimple->login();
        }

        $this->markRpAssociation($oidcClient);

        $state = $this->prepareStateArray($authSimple, $oidcClient, $request);
        $state = $this->authProcService->processState($state);
        $claims = $state['Attributes'];

        if (!\array_key_exists($this->userIdAttr, $claims)) {
            $attr = implode(', ', array_keys($claims));
            throw new Exception('Attribute `useridattr` doesn\'t exists in claims. Available attributes are: ' . $attr);
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

        return $user;
    }

    /**
     * @param Simple $authSimple
     * @param ClientEntityInterface $client
     * @param ServerRequest $request
     * @return array
     */
    private function prepareStateArray(Simple $authSimple, ClientEntityInterface $client, ServerRequest $request): array
    {
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

        return $state;
    }

    public function isCookieBasedAuthn(): ?bool
    {
        return $this->isCookieBasedAuthn;
    }

    public function getAuthSourceId(): ?string
    {
        return $this->authSourceId;
    }

    public function getSessionId(): ?string
    {
        return $this->session->getSessionId();
    }

    protected function markRpAssociation(ClientEntityInterface $oidcClient): void
    {
        $associations = $this->getRpAssociations();

        if (! in_array($oidcClient->getIdentifier(), $associations)) {
            $associations[] = $oidcClient->getIdentifier();
        }

        $this->session->setData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_RP_ASSOCIATIONS,
            $associations,
            Session::DATA_TIMEOUT_SESSION_END
        );
    }

    public function getRpAssociations(): array
    {
        return $this->session->getData(self::SESSION_DATA_TYPE, self::SESSION_DATA_ID_RP_ASSOCIATIONS) ?? [];
    }
}
