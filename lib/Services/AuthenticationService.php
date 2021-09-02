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

    public function __construct(
        UserRepository $userRepository,
        AuthSimpleFactory $authSimpleFactory,
        AuthProcService $authProcService,
        ClientRepository $clientRepository,
        OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService,
        string $userIdAttr
    ) {
        $this->userRepository = $userRepository;
        $this->authSimpleFactory = $authSimpleFactory;
        $this->authProcService = $authProcService;
        $this->clientRepository = $clientRepository;
        $this->oidcOpenIdProviderMetadataService = $oidcOpenIdProviderMetadataService;
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

        $authSimple->requireAuth();

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
}
