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

namespace spec\SimpleSAML\Modules\OpenIDConnect\Services;

use Laminas\Diactoros\ServerRequest;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Error\Exception;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthenticationService;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthProcService;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Services\OidcOpenIdProviderMetadataService;

class AuthenticationServiceSpec extends ObjectBehavior
{
    public const AUTH_SOURCE = 'auth_source';
    public const USER_ID_ATTR = 'uid';
    public const USERNAME = 'username';
    public const OIDC_METADATA = ['issuer' => 'https://idp.example.org'];
    public const IDP_METADATA = ['entityid' => 'https://idp.example.org'];
    public const USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];
    public const AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];
    public const CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    public const STATE = [
        'Attributes' => self::AUTH_DATA['Attributes'],
        'OidcOpenIdProviderMetadata' => self::OIDC_METADATA,
        'OidcRelyingPartyMetadata' => self::CLIENT_ENTITY,
        'IdPMetadata' => self::IDP_METADATA
    ];
    public const AUTHZ_REQUEST_PARAMS = ['client_id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];

    /**
     * @param ServerRequest $request
     * @param ClientEntity $clientEntity
     * @param UserRepository $userRepository
     * @param AuthSimpleFactory $authSimpleFactory
     * @param Simple $simple
     * @param AuthProcService $authProcService
     * @param ClientRepository $clientRepository
     * @param ConfigurationService $configurationService
     * @param OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService
     * @return void
     */
    public function let(
        ServerRequest $request,
        ClientEntity $clientEntity,
        UserRepository $userRepository,
        AuthSimpleFactory $authSimpleFactory,
        Simple $simple,
        AuthProcService $authProcService,
        ClientRepository $clientRepository,
        ConfigurationService $configurationService,
        OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService
    ): void {
        $request->getQueryParams()->willReturn(self::AUTHZ_REQUEST_PARAMS);
        $clientEntity->getAuthSource()->willReturn(self::AUTH_SOURCE);
        $clientEntity->toArray()->willReturn(self::CLIENT_ENTITY);
        $clientRepository->findById(self::CLIENT_ENTITY['id'])->willReturn($clientEntity);
        $simple->getAttributes()->willReturn(self::AUTH_DATA['Attributes']);
        $simple->getAuthDataArray()->willReturn(self::AUTH_DATA);
        $authSimpleFactory->build(self::AUTH_SOURCE)->willReturn($simple);
        $oidcOpenIdProviderMetadataService->getMetadata()->willReturn(self::OIDC_METADATA);
        $configurationService->getAuthProcFilters()->willReturn([]);
        $authProcService->processState(Argument::type('array'))->willReturn(self::STATE);

        $this->beConstructedWith(
            $configurationService,
            $userRepository,
            $authSimpleFactory,
            $authProcService,
            $clientRepository,
            $oidcOpenIdProviderMetadataService,
            self::USER_ID_ATTR
        );
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(AuthenticationService::class);
    }

    /**
     * @param ServerRequest $request
     * @param Simple $simple
     * @param UserRepository $userRepository
     * @return void
     * @throws \Exception
     */
    public function it_creates_new_user(
        ServerRequest $request,
        Simple $simple,
        UserRepository $userRepository
    ): void {
        $simple->requireAuth()->shouldBeCalled();

        $userRepository->getUserEntityByIdentifier(self::USERNAME)->shouldBeCalled()->willReturn(null);
        $userRepository->add(Argument::type(UserEntity::class))->shouldBeCalled();

        $this->getAuthenticateUser($request)->shouldHaveIdentifier(self::USERNAME);
        $this->getAuthenticateUser($request)->shouldHaveClaims(self::USER_ENTITY_ATTRIBUTES);
    }

    /**
     * @param ServerRequest $request
     * @param Simple $simple
     * @param UserRepository $userRepository
     * @param UserEntity $userEntity
     * @return void
     * @throws \Exception
     */
    public function it_returns_an_user(
        ServerRequest $request,
        Simple $simple,
        UserRepository $userRepository,
        UserEntity $userEntity
    ): void {
        $simple->requireAuth()->shouldBeCalled();

        $userRepository->getUserEntityByIdentifier(self::USERNAME)->shouldBeCalled()->willReturn($userEntity);
        $userEntity->setClaims(self::USER_ENTITY_ATTRIBUTES)->shouldBeCalled();
        $userRepository->update($userEntity)->shouldBeCalled();
        $this->getAuthenticateUser($request)->shouldBe($userEntity);
    }

    public function it_throws_exception_if_claims_not_exists(
        ServerRequest $request,
        AuthProcService $authProcService,
        Simple $simple
    ): void {
        $simple->requireAuth()->shouldBeCalled();

        $invalidState = self::STATE;
        unset($invalidState['Attributes'][self::USER_ID_ATTR]);

        $authProcService->processState(Argument::type('array'))->shouldBeCalled()->willReturn($invalidState);

        $this->shouldThrow(Exception::class)->during('getAuthenticateUser', [$request]);
    }

    public function getMatchers(): array
    {
        return [
            'haveIdentifier' => function (UserEntity $subject, $id) {
                return $subject->getIdentifier() === $id;
            },
            'haveClaims' => function (UserEntity $subject, array $claims) {
                return $subject->getClaims() === $claims;
            },
        ];
    }
}
