<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Services;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\Source;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Session;

/**
 * @covers \SimpleSAML\Module\oidc\Services\AuthenticationService
 */
class AuthenticationServiceTest extends TestCase
{
    final public const AUTH_SOURCE = 'auth_source';
    final public const USER_ID_ATTR = 'uid';
    final public const USERNAME = 'username';
    final public const OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];
    final public const USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];
    final public const AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];
    final public const CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    final public const AUTHZ_REQUEST_PARAMS = ['client_id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    final public const STATE = [
        'Attributes' => self::AUTH_DATA['Attributes'],
        'Oidc' => [
            'OpenIdProviderMetadata' => self::OIDC_OP_METADATA,
            'RelyingPartyMetadata' => self::CLIENT_ENTITY,
            'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
        ],
    ];

    public static string $uri = 'https://some-server/authorize.php?abc=efg';

    protected MockObject $claimTranslatorExtractorMock;
    protected MockObject $serverRequestMock;
    protected MockObject $clientEntityMock;
    protected MockObject $userRepositoryMock;
    protected MockObject $authSimpleFactoryMock;
    protected MockObject $authSimpleMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $oidcOpenIdProviderMetadataServiceMock;
    protected MockObject $sessionServiceMock;
    protected MockObject $authSourceMock;
    protected MockObject $sessionMock;
    protected MockObject $userEntityMock;

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function setUp(): void
    {
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->authSimpleFactoryMock = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleMock = $this->createMock(Simple::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->oidcOpenIdProviderMetadataServiceMock = $this->createMock(OpMetadataService::class);
        $this->sessionServiceMock = $this->createMock(SessionService::class);
        $this->claimTranslatorExtractorMock = $this->createMock(ClaimTranslatorExtractor::class);
        $this->authSourceMock = $this->createMock(Source::class);
        $this->sessionMock = $this->createMock(Session::class);
        $this->userEntityMock = $this->createMock(UserEntity::class);

        $this->serverRequestMock->method('getQueryParams')->willReturn(self::AUTHZ_REQUEST_PARAMS);
        $this->serverRequestMock->method('getUri')->willReturn(new Uri(self::$uri));

        $this->clientEntityMock->method('getAuthSourceId')->willReturn(self::AUTH_SOURCE);
        $this->clientEntityMock->method('toArray')->willReturn(self::CLIENT_ENTITY);

        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->authSimpleMock->method('getAttributes')->willReturn(self::AUTH_DATA['Attributes']);
        $this->authSimpleMock->method('getAuthDataArray')->willReturn(self::AUTH_DATA);

        $this->authSimpleFactoryMock->method('build')->willReturn($this->authSimpleMock);

        $this->oidcOpenIdProviderMetadataServiceMock->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);

        $this->moduleConfigMock->method('getAuthProcFilters')->willReturn([]);
        $this->moduleConfigMock->method('getUserIdentifierAttribute')->willReturn(self::USER_ID_ATTR);

        $this->sessionServiceMock->method('getCurrentSession')->willReturn($this->sessionMock);
    }

    public function prepareMockedInstance(): AuthenticationService
    {
        return new AuthenticationService(
            $this->userRepositoryMock,
            $this->authSimpleFactoryMock,
            $this->clientRepositoryMock,
            $this->oidcOpenIdProviderMetadataServiceMock,
            $this->sessionServiceMock,
            $this->claimTranslatorExtractorMock,
            $this->moduleConfigMock,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthenticationService::class,
            $this->prepareMockedInstance(),
        );
    }

    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     */
    public function testItCreatesNewUser(): void
    {
        $clientId = 'client123';
        $this->authSourceMock->method('getAuthId')->willReturn('theAuthId');

        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(false);
        $this->authSimpleMock->expects($this->once())->method('login')->with([]);
        $this->authSimpleMock->expects($this->once())->method('getAuthSource')->willReturn($this->authSourceMock);

        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn($clientId);
        $this->clientEntityMock->expects($this->once())->method('getBackChannelLogoutUri')->willReturn(null);

        $this->sessionServiceMock->expects($this->once())->method('getCurrentSession')->willReturn($this->sessionMock);
        $this->sessionServiceMock->expects($this->once())->method('setIsCookieBasedAuthn')->with(false);
        $this->sessionServiceMock->expects($this->once())->method('setIsAuthnPerformedInPreviousRequest')->with(true);

        $this->userRepositoryMock->expects($this->once())->method('getUserEntityByIdentifier')->willReturn(null);
        $this->userRepositoryMock->expects($this->once())->method('add')->with($this->isInstanceOf(UserEntity::class));

        $this->claimTranslatorExtractorMock->method('extract')->with(['openid'], $this->isType('array'))
            ->willReturn([]);

        $userEntity = $this->prepareMockedInstance()->getAuthenticateUser($this->serverRequestMock);

        $this->assertSame(
            $userEntity->getIdentifier(),
            self::USERNAME,
        );
        $this->assertSame(
            $userEntity->getClaims(),
            self::USER_ENTITY_ATTRIBUTES,
        );
    }

    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     */
    public function testItReturnsAnUser(): void
    {
        $clientId = 'client123';
        $userId = 'user123';

        $this->authSourceMock->method('getAuthId')->willReturn('theAuthId');

        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(false);
        $this->authSimpleMock->expects($this->once())->method('login')->with([]);
        $this->authSimpleMock->expects($this->once())->method('getAuthSource')->willReturn($this->authSourceMock);

        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn($clientId);
        $this->clientEntityMock->expects($this->once())->method('getBackChannelLogoutUri')->willReturn(null);

        $this->userEntityMock->expects($this->once())->method('getIdentifier')->willReturn($userId);
        $this->userEntityMock->expects($this->once())->method('setClaims')->with(self::USER_ENTITY_ATTRIBUTES);
        $this->userEntityMock->expects($this->once())->method('getClaims')->willReturn([]);

        $this->userRepositoryMock->expects($this->once())->method('getUserEntityByIdentifier')
            ->willReturn($this->userEntityMock);
        $this->userRepositoryMock->expects($this->once())->method('update')->with($this->userEntityMock);

        $this->sessionServiceMock->expects($this->once())->method('getCurrentSession')->willReturn($this->sessionMock);
        $this->sessionServiceMock->expects($this->once())->method('setIsCookieBasedAuthn')->with(false);
        $this->sessionServiceMock->expects($this->once())->method('setIsAuthnPerformedInPreviousRequest')->with(true);

        $this->claimTranslatorExtractorMock->expects($this->once())->method('extract')
            ->with(['openid'], $this->isType('array'))
            ->willReturn([]);

        $this->assertSame(
            $this->prepareMockedInstance()->getAuthenticateUser($this->serverRequestMock),
            $this->userEntityMock,
        );
    }

    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     */
    public function testItThrowsIfClaimsNotExist(): void
    {
        $this->authSourceMock->method('getAuthId')->willReturn('theAuthId');

        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(false);
        $this->authSimpleMock->expects($this->once())->method('login');
        $this->authSimpleMock->expects($this->once())->method('getAuthSource')->willReturn($this->authSourceMock);

        $this->sessionServiceMock->expects($this->once())->method('setIsCookieBasedAuthn')->with(false);
        $this->sessionServiceMock->expects($this->once())->method('setIsAuthnPerformedInPreviousRequest')->with(true);

        $invalidState = self::STATE;
        unset($invalidState['Attributes'][self::USER_ID_ATTR]);

        $this->expectException(Exception::class);

        $this->prepareMockedInstance()->getAuthenticateUser($this->serverRequestMock);
    }
}
