<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\Source;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\AuthProcService;
use SimpleSAML\Module\oidc\Services\OidcOpenIdProviderMetadataService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Session;

/**
 * @covers \SimpleSAML\Module\oidc\Services\AuthenticationService
 */
class AuthenticationServiceTest extends TestCase
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

    protected \PHPUnit\Framework\MockObject\MockObject $claimTranslatorExtractorMock;
    protected \PHPUnit\Framework\MockObject\MockObject $serverRequestMock;
    protected \PHPUnit\Framework\MockObject\MockObject $clientEntityMock;
    protected \PHPUnit\Framework\MockObject\MockObject $userRepositoryMock;
    protected \PHPUnit\Framework\MockObject\MockObject $authSimpleFactoryMock;
    protected \PHPUnit\Framework\MockObject\MockObject $authSimpleMock;
    protected \PHPUnit\Framework\MockObject\MockObject $authProcServiceMock;
    protected \PHPUnit\Framework\MockObject\MockObject $clientRepositoryMock;
    protected \PHPUnit\Framework\MockObject\MockObject $moduleConfigMock;
    protected \PHPUnit\Framework\MockObject\MockObject $oidcOpenIdProviderMetadataServiceMock;
    protected \PHPUnit\Framework\MockObject\MockObject $sessionServiceMock;
    protected \PHPUnit\Framework\MockObject\MockObject $authSourceMock;
    protected \PHPUnit\Framework\MockObject\MockObject $sessionMock;
    protected \PHPUnit\Framework\MockObject\MockObject $userEntityMock;

    protected function setUp(): void
    {
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->authSimpleFactoryMock = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleMock = $this->createMock(Simple::class);
        $this->authProcServiceMock = $this->createMock(AuthProcService::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->oidcOpenIdProviderMetadataServiceMock = $this->createMock(OidcOpenIdProviderMetadataService::class);
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

        $this->sessionServiceMock->method('getCurrentSession')->willReturn($this->sessionMock);
    }

    public function prepareMockedInstance(): AuthenticationService
    {
        return new AuthenticationService(
            $this->userRepositoryMock,
            $this->authSimpleFactoryMock,
            $this->authProcServiceMock,
            $this->clientRepositoryMock,
            $this->oidcOpenIdProviderMetadataServiceMock,
            $this->sessionServiceMock,
            $this->claimTranslatorExtractorMock,
            self::USER_ID_ATTR
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthenticationService::class,
            $this->prepareMockedInstance()
        );
    }

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

        $this->authProcServiceMock->method('processState')->willReturn(self::STATE);

        $userEntity = $this->prepareMockedInstance()->getAuthenticateUser($this->serverRequestMock);

        $this->assertSame(
            $userEntity->getIdentifier(),
            self::USERNAME
        );
        $this->assertSame(
            $userEntity->getClaims(),
            self::USER_ENTITY_ATTRIBUTES
        );
    }

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

        $this->authProcServiceMock->method('processState')->willReturn(self::STATE);

        $this->assertSame(
            $this->prepareMockedInstance()->getAuthenticateUser($this->serverRequestMock),
            $this->userEntityMock
        );
    }

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

        $this->authProcServiceMock->expects($this->once())->method('processState')->willReturn($invalidState);

        $this->expectException(Exception::class);

        $this->prepareMockedInstance()->getAuthenticateUser($this->serverRequestMock);
    }
}
