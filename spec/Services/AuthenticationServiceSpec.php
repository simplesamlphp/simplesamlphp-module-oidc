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

namespace spec\SimpleSAML\Module\oidc\Services;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\Source;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\AuthProcService;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\OidcOpenIdProviderMetadataService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Session;

class AuthenticationServiceSpec extends ObjectBehavior
{
    public const AUTH_SOURCE = 'auth_source';
    public const USER_ID_ATTR = 'uid';
    public const USERNAME = 'username';
    public const OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];
    public const USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];
    public const AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];
    public const CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    public const AUTHZ_REQUEST_PARAMS = ['client_id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    public const STATE = [
        'Attributes' => self::AUTH_DATA['Attributes'],
        'Oidc' => [
            'OpenIdProviderMetadata' => self::OIDC_OP_METADATA,
            'RelyingPartyMetadata' => self::CLIENT_ENTITY,
            'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
        ],
    ];

    public static $uri = 'https://some-server/authorize.php?abc=efg';



    /**
     * @param ServerRequest $request
     * @param ClientEntity $clientEntity
     * @param UserRepository $userRepository
     * @param AuthSimpleFactory $authSimpleFactory
     * @param Simple $simple
     * @param AuthProcService $authProcService
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
        OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService,
        SessionService $sessionService,
        ClaimTranslatorExtractor $claimTranslatorExtractor
    ): void {
        $request->getQueryParams()->willReturn(self::AUTHZ_REQUEST_PARAMS);
        $request->getUri()->willReturn(new Uri(self::$uri));
        $clientEntity->getAuthSourceId()->willReturn(self::AUTH_SOURCE);
        $clientEntity->toArray()->willReturn(self::CLIENT_ENTITY);
        $clientRepository->findById(self::CLIENT_ENTITY['id'])->willReturn($clientEntity);
        $simple->getAttributes()->willReturn(self::AUTH_DATA['Attributes']);
        $simple->getAuthDataArray()->willReturn(self::AUTH_DATA);
        $authSimpleFactory->build($clientEntity)->willReturn($simple);
        $oidcOpenIdProviderMetadataService->getMetadata()->willReturn(self::OIDC_OP_METADATA);
        $configurationService->getAuthProcFilters()->willReturn([]);
        $authProcService->processState(Argument::type('array'))->willReturn(self::STATE);

        $this->beConstructedWith(
            $userRepository,
            $authSimpleFactory,
            $authProcService,
            $clientRepository,
            $oidcOpenIdProviderMetadataService,
            $sessionService,
            $claimTranslatorExtractor,
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
        UserRepository $userRepository,
        Source $source,
        ClientEntity $clientEntity,
        SessionService $sessionService,
        Session $session,
        ClaimTranslatorExtractor $claimTranslatorExtractor
    ): void {
        $clientId = 'client123';
        $source->getAuthId()->willReturn('theAuthId');
        $simple->isAuthenticated()->shouldBeCalled()->willReturn(false);
        $simple->login([])->shouldBeCalled();
        $simple->getAuthSource()->shouldBeCalled()->willReturn($source);
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn($clientId);
        $clientEntity->getBackChannelLogoutUri()->shouldBeCalled()->willReturn(null);
        $relyingPartyAssociation = new RelyingPartyAssociation($clientId, self::USERNAME, null);
        $sessionService->addRelyingPartyAssociation($relyingPartyAssociation);
        $sessionService->getCurrentSession()->shouldBeCalled()->willReturn($session);
        $sessionService->setIsCookieBasedAuthn(false)->shouldBeCalled();
        $sessionService->setIsAuthnPerformedInPreviousRequest(true)->shouldBeCalled();

        $userRepository->getUserEntityByIdentifier(self::USERNAME)->shouldBeCalled()->willReturn(null);
        $userRepository->add(Argument::type(UserEntity::class))->shouldBeCalled();

        $claimTranslatorExtractor->extract(['openid'], Argument::type('array'))->willReturn([]);

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
        UserEntity $userEntity,
        Source $source,
        ClientEntity $clientEntity,
        SessionService $sessionService,
        Session $session,
        ClaimTranslatorExtractor $claimTranslatorExtractor
    ): void {
        $clientId = 'client123';
        $userId = 'user123';
        $source->getAuthId()->willReturn('theAuthId');
        $simple->isAuthenticated()->shouldBeCalled()->willReturn(false);
        $simple->login([])->shouldBeCalled();
        $simple->getAuthSource()->shouldBeCalled()->willReturn($source);
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn($clientId);
        $clientEntity->getBackChannelLogoutUri()->shouldBeCalled()->willReturn(null);
        $userEntity->getIdentifier()->shouldBeCalled()->willReturn($userId);
        $sessionService->setIsCookieBasedAuthn(false)->shouldBeCalled();
        $sessionService->setIsAuthnPerformedInPreviousRequest(true)->shouldBeCalled();
        $relyingPartyAssociation = new RelyingPartyAssociation($clientId, $userId, null);
        $sessionService->addRelyingPartyAssociation($relyingPartyAssociation);
        $sessionService->getCurrentSession()->shouldBeCalled()->willReturn($session);

        $userRepository->getUserEntityByIdentifier(self::USERNAME)->shouldBeCalled()->willReturn($userEntity);
        $userEntity->setClaims(self::USER_ENTITY_ATTRIBUTES)->shouldBeCalled();
        $userRepository->update($userEntity)->shouldBeCalled();

        $userEntity->getClaims()->shouldBeCalled()->willReturn([]);
        $claimTranslatorExtractor->extract(['openid'], Argument::type('array'))->willReturn([]);

        $this->getAuthenticateUser($request)->shouldBe($userEntity);
    }

    public function it_throws_exception_if_claims_not_exists(
        ServerRequest $request,
        AuthProcService $authProcService,
        Simple $simple,
        Source $source,
        SessionService $sessionService
    ): void {
        $source->getAuthId()->willReturn('theAuthId');
        $simple->isAuthenticated()->shouldBeCalled()->willReturn(false);
        $simple->login([])->shouldBeCalled();
        $simple->getAuthSource()->shouldBeCalled()->willReturn($source);
        $sessionService->setIsCookieBasedAuthn(false)->shouldBeCalled();
        $sessionService->setIsAuthnPerformedInPreviousRequest(true)->shouldBeCalled();

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
