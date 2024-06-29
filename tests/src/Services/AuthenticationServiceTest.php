<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Services;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NoState;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
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
    final public const URI = 'https://some-server/authorize.php?abc=efg';
    final public const AUTH_SOURCE = 'auth_source';
    final public const USER_ID_ATTR = 'uid';
    final public const USERNAME = 'username';
    final public const OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];
    final public const USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR    => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];
    final public const AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];
    final public const CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    final public const AUTHZ_REQUEST_PARAMS = ['client_id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    final public const STATE = [
        'Attributes' => self::AUTH_DATA['Attributes'],
        'Oidc'       => [
            'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
            'RelyingPartyMetadata'           => self::CLIENT_ENTITY,
            'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
        ],
    ];


    protected MockObject $claimTranslatorExtractorMock;
    protected MockObject $serverRequestMock;
    protected MockObject $clientEntityMock;
    protected MockObject $userRepositoryMock;
    protected MockObject $authSimpleFactoryMock;
    protected MockObject $authSimpleMock;
    protected MockObject $authorizationRequestMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $oidcOpenIdProviderMetadataServiceMock;
    protected MockObject $sessionServiceMock;
    protected MockObject $authSourceMock;
    protected MockObject $sessionMock;
    protected MockObject $userEntityMock;

    /**
     * @return void
     */
    public static function setUpBeforeClass(): void
    {
        // To make lib/SimpleSAML/Utils/HTTP::getSelfURL() work...
        global $_SERVER;
        $_SERVER['REQUEST_URI'] = '';
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function setUp(): void
    {
        $this->serverRequestMock                     = $this->createMock(ServerRequest::class);
        $this->clientEntityMock                      = $this->createMock(ClientEntity::class);
        $this->userRepositoryMock                    = $this->createMock(UserRepository::class);
        $this->authSimpleFactoryMock                 = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleMock                        = $this->createMock(Simple::class);
        $this->authorizationRequestMock              = $this->createMock(AuthorizationRequest::class);
        $this->clientRepositoryMock                  = $this->createMock(ClientRepository::class);
        $this->moduleConfigMock                      = $this->createMock(ModuleConfig::class);
        $this->oidcOpenIdProviderMetadataServiceMock = $this->createMock(OpMetadataService::class);
        $this->sessionServiceMock                    = $this->createMock(SessionService::class);
        $this->claimTranslatorExtractorMock          = $this->createMock(ClaimTranslatorExtractor::class);
        $this->authSourceMock                        = $this->createMock(Source::class);
        $this->sessionMock                           = $this->createMock(Session::class);
        $this->userEntityMock                        = $this->createMock(UserEntity::class);

        $this->serverRequestMock->method('getQueryParams')->willReturn(self::AUTHZ_REQUEST_PARAMS);
        $this->serverRequestMock->method('getUri')->willReturn(new Uri(self::URI));

        $this->clientEntityMock->method('getAuthSourceId')->willReturn(self::AUTH_SOURCE);
        $this->clientEntityMock->method('toArray')->willReturn(self::CLIENT_ENTITY);
        $this->authSimpleMock->method('getAttributes')->willReturn(self::AUTH_DATA['Attributes']);
        $this->authSimpleMock->method('getAuthDataArray')->willReturn(self::AUTH_DATA);

        $this->authSimpleFactoryMock->method('build')->willReturn($this->authSimpleMock);

        $this->oidcOpenIdProviderMetadataServiceMock->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);

        $this->moduleConfigMock->method('getUserIdentifierAttribute')->willReturn(self::USER_ID_ATTR);

        $this->sessionServiceMock->method('getCurrentSession')->willReturn($this->sessionMock);
    }

    /**
     * @return AuthenticationService
     */
    public function prepareMockedInstance(): AuthenticationService
    {
        return $this->getMockBuilder(AuthenticationService::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                                     $this->userRepositoryMock,
                                     $this->authSimpleFactoryMock,
                                     $this->clientRepositoryMock,
                                     $this->oidcOpenIdProviderMetadataServiceMock,
                                     $this->sessionServiceMock,
                                     $this->claimTranslatorExtractorMock,
                                     $this->moduleConfigMock,
                                 ])
            ->onlyMethods(['getClientFromRequest'])
            ->getMock();
    }

    /**
     * @return void
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthenticationService::class,
            $this->prepareMockedInstance(),
        );
    }

    /**
     * @return void
     * @throws Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testItCreatesNewUser(): void
    {
        $clientId = 'client123';
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn($clientId);
        $userEntity = $this->prepareMockedInstance()->getAuthenticateUser(self::STATE);

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
        $userId   = 'user123';

        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn($clientId);
        $this->clientEntityMock->expects($this->once())->method('getBackChannelLogoutUri')->willReturn(null);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->userEntityMock->expects($this->once())->method('getIdentifier')->willReturn($userId);
        $this->userEntityMock->expects($this->once())->method('setClaims')->with(self::USER_ENTITY_ATTRIBUTES);
        $this->userEntityMock->expects($this->once())->method('getClaims')->willReturn([]);

        $this->userRepositoryMock->expects($this->once())->method('getUserEntityByIdentifier')
            ->willReturn($this->userEntityMock);
        $this->userRepositoryMock->expects($this->once())->method('update')->with($this->userEntityMock);

        $this->claimTranslatorExtractorMock->expects($this->once())->method('extract')
            ->with(['openid'], $this->isType('array'))
            ->willReturn([]);

        $this->assertSame(
            $this->prepareMockedInstance()->getAuthenticateUser(self::STATE),
            $this->userEntityMock,
        );
    }

    /**
     * @return array
     */
    public static function getUserState(): array
    {
        return [
            'No Attributes'                   => [
                [
                    'Oidc' => [
                        'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
                        'RelyingPartyMetadata'           => self::CLIENT_ENTITY,
                        'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
                    ],
                ],
            ],
            'No OIDC RelyingPartyMetadata ID' => [
                [
                    'Attributes' => self::AUTH_DATA['Attributes'],
                    'Oidc'       => [
                        'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
                        'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
                    ],
                ],
            ],
            'No Client'                       => [
                [
                    'Attributes' => self::AUTH_DATA['Attributes'],
                    'Oidc'       => [
                        'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
                        'RelyingPartyMetadata'           => self::CLIENT_ENTITY,
                        'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
                    ],
                ],
            ],
        ];
    }

    /**
     * @throws BadRequest
     * @throws OidcServerException
     * @throws \JsonException
     */
    #[DataProvider('getUserState')]
    public function testGetAuthenticateUserItThrowsWhenState(array $state): void
    {
        if (!isset($state['Oidc']['RelyingPartyMetadata']['id'])) {
            $this->expectException(Exception::class);
            $this->expectExceptionMessageMatches('/OIDC RelyingPartyMetadata ID does not exist in state./');
        } elseif (isset($state['Attributes'])) {
            $this->expectException(NotFound::class);
            $this->expectExceptionMessageMatches('/Client not found./');
            $this->clientRepositoryMock->method('findById')->willReturn(null);
        } else {
            $this->expectException(Exception::class);
            $this->expectExceptionMessageMatches('/State array does not contain any attributes./');
        }
        $this->prepareMockedInstance()->getAuthenticateUser($state);
    }

    /**
     * @return void
     * @throws Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testGetAuthenticateUserItThrowsIfClaimsNotExist(): void
    {
        $invalidState = self::STATE;
        unset($invalidState['Attributes'][self::USER_ID_ATTR]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches(
            "/Attribute `useridattr` doesn\'t exists in claims. Available attributes are:/",
        );

        $this->prepareMockedInstance()->getAuthenticateUser($invalidState);
    }

    /**
     * @return void
     * @throws \JsonException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testItAuthenticates(): void
    {
        $this->authSimpleMock->expects($this->once())->method('login')->with([]);
        $this->prepareMockedInstance()
            ->method('getClientFromRequest')
            ->with($this->serverRequestMock)
            ->willReturn($this->clientEntityMock);

        $this->prepareMockedInstance()->authenticate($this->serverRequestMock);
    }

    /**
     * @return void
     * @throws \SimpleSAML\Error\AuthSource
     */
    public function testItConstructsStateArray(): void
    {
        $state                         = self::STATE;
        $state['Source']               = [
            'entityid' => $state['Oidc']['OpenIdProviderMetadata']['issuer'],
        ];
        $state['Destination']          = [
            'entityid' => $state['Oidc']['RelyingPartyMetadata']['id'],
        ];
        $state[State::RESTART]         = self::URI;
        $state['authorizationRequest'] = $this->authorizationRequestMock;
        $state['authSourceId']         = '';

        $this->assertSame(
            $state,
            $this->prepareMockedInstance()->prepareStateArray(
                $this->authSimpleMock,
                $this->clientEntityMock,
                $this->serverRequestMock,
                $this->authorizationRequestMock,
            ),
        );
    }

    /**
     * @return array
     */
    public static function isAuthnPerformedInPreviousRequest(): array
    {
        return [
            [false],
            [true],
        ];
    }

    /**
     * @throws SimpleSAML\Error\AuthSource
     * @throws SimpleSAML\Error\BadRequest
     * @throws SimpleSAML\Error\Exception
     * @throws JsonException
     * @throws SimpleSAML\Error\OidcServerException
     * @throws SimpleSAML\Error\NotFound
     */
    #[DataProvider('isAuthnPerformedInPreviousRequest')]
    #[TestDox('Process Request with authentication performed in previous request: $isAuthnPer')]
    public function testItProcessesRequest(bool $isAuthnPer): void
    {
        $authenticationServiceMock = $this->getMockBuilder(AuthenticationService::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                                     $this->userRepositoryMock,
                                     $this->authSimpleFactoryMock,
                                     $this->clientRepositoryMock,
                                     $this->oidcOpenIdProviderMetadataServiceMock,
                                     $this->sessionServiceMock,
                                     $this->claimTranslatorExtractorMock,
                                     $this->moduleConfigMock,
                                 ])
            ->onlyMethods(['getClientFromRequest', 'runAuthProcs', 'prepareStateArray'])
            ->getMock();

        $this->moduleConfigMock->method('getAuthProcFilters')->willReturn([]);
        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(true);
        $authenticationServiceMock->method('getClientFromRequest')->with($this->serverRequestMock)
            ->willReturn($this->clientEntityMock);
        $authenticationServiceMock->method('prepareStateArray')->with(
            $this->authSimpleMock,
            $this->clientEntityMock,
            $this->serverRequestMock,
            $this->authorizationRequestMock,
        )->willReturn(self::STATE);

        $this->sessionServiceMock->method('getIsAuthnPerformedInPreviousRequest')->willReturn($isAuthnPer);

        $this->assertSame(
            $authenticationServiceMock->processRequest(
                $this->serverRequestMock,
                $this->authorizationRequestMock,
            ),
            self::STATE,
        );
    }

    /**
     * @throws NoState
     */
    public function testItThrowsOnMissingQueryParameterAuthparam(): void
    {
        $this->expectException(NoState::class);
        $this->prepareMockedInstance()->loadState([]);
    }

    /**
     * @throws NoState
     */
    public function testLoadStateFromProcessingChainRedirect(): void
    {
        $queryParameters = [
            ProcessingChain::AUTHPARAM => '123',
        ];

        $mock = $this->prepareMockedInstance();
        $mock->setAuthState(
            new class () extends State {
                public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
                {
                    return [
                        'Attributes'   => AuthenticationServiceTest::AUTH_DATA['Attributes'],
                        'Oidc'         => [
                            'OpenIdProviderMetadata'         => AuthenticationServiceTest::OIDC_OP_METADATA,
                            'RelyingPartyMetadata'           => AuthenticationServiceTest::CLIENT_ENTITY,
                            'AuthorizationRequestParameters' => AuthenticationServiceTest::AUTHZ_REQUEST_PARAMS,
                        ],
                        'authSourceId' => '456',
                    ];
                }
            },
        );

        $this->assertSame(
            self::STATE,
            $mock->loadState($queryParameters),
        );

        $this->assertEquals('456', $mock->getAuthSourceId());
    }

    /**
     * @return void
     */
    public function testItRunAuthProcs(): void
    {
        $authProcFilters = [
            25 => [
                'class' => 'core:AttributeMap',
                'oid2name',
            ],
        ];
        $returnUrl       = 'http://example.com/authorization';
        $this->moduleConfigMock->method('getAuthProcFilters')->willReturn($authProcFilters);
        $this->moduleConfigMock->method('getModuleUrl')->willReturn($returnUrl);
        $mockedInstance = new class (
            $this->userRepositoryMock,
            $this->authSimpleFactoryMock,
            $this->clientRepositoryMock,
            $this->oidcOpenIdProviderMetadataServiceMock,
            $this->sessionServiceMock,
            $this->claimTranslatorExtractorMock,
            $this->moduleConfigMock,
        ) extends AuthenticationService {
            public function runAuthProcsPublic(array &$state): void
            {
                $this->runAuthProcs($state);
            }
        };

        $state = self::STATE;
        $mockedInstance->runAuthProcsPublic($state);

        $this->assertEquals($state['ReturnURL'], $returnUrl);
        $this->assertEquals($state['Source']['authproc'], $authProcFilters);
    }

    /**
     * @return void
     * @throws Exception
     */
    public function testItGetsAuthorizationRequestFromState(): void
    {
        $authorizationRequest = new AuthorizationRequest();
        $state = [
            ...self::STATE,
            'authorizationRequest' => $authorizationRequest,
        ];

        $this->assertEquals(
            $this->prepareMockedInstance()->getAuthorizationRequestFromState($state),
            $authorizationRequest,
        );
    }

    /**
     * @return array
     */
    public static function authorizationRequestValues(): array
    {
        return [
            'invalid'                   => [
                [
                    ...self::STATE,
                    'authorizationRequest' => string::class,
                ],
            ],
            'not set' => [
                [
                    ...self::STATE,
                ],
            ],
        ];
    }

    /**
     * @param   array  $state
     *
     * @return void
     * @throws Exception
     */
    #[DataProvider('authorizationRequestValues')]
    public function testGetsAuthorizationRequestFromStateThrowsOnInvalid(array $state): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Authorization Request is not valid./');
        $this->prepareMockedInstance()->getAuthorizationRequestFromState($state);
    }
}
