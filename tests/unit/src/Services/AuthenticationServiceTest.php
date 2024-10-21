<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
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
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Factories\ProcessingChainFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Services\StateService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
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

    protected MockObject $authSimpleFactoryMock;
    protected MockObject $authSimpleMock;
    protected MockObject $authSourceMock;
    protected MockObject $authorizationRequestMock;
    protected MockObject $claimTranslatorExtractorMock;
    protected MockObject $clientEntityMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $opMetadataService;
    protected MockObject $processingChainFactoryMock;
    protected MockObject $processingChainMock;
    protected MockObject $serverRequestMock;
    protected MockObject $sessionMock;
    protected MockObject $sessionServiceMock;
    protected MockObject $stateServiceMock;
    protected MockObject $userEntityMock;
    protected MockObject $userRepositoryMock;
    protected MockObject $helpersMock;
    protected MockObject $clientHelperMock;
    protected MockObject $requestParamsResolverMock;
    protected MockObject $userEntityFactoryMock;

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
        $this->authSimpleFactoryMock                 = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleMock                        = $this->createMock(Simple::class);
        $this->authSourceMock                        = $this->createMock(Source::class);
        $this->authorizationRequestMock              = $this->createMock(AuthorizationRequest::class);
        $this->claimTranslatorExtractorMock          = $this->createMock(ClaimTranslatorExtractor::class);
        $this->clientEntityMock                      = $this->createMock(ClientEntity::class);
        $this->clientRepositoryMock                  = $this->createMock(ClientRepository::class);
        $this->moduleConfigMock                      = $this->createMock(ModuleConfig::class);
        $this->opMetadataService                     = $this->createMock(OpMetadataService::class);
        $this->processingChainFactoryMock            = $this->createMock(ProcessingChainFactory::class);
        $this->processingChainMock                   = $this->createMock(ProcessingChain::class);
        $this->serverRequestMock                     = $this->createMock(ServerRequest::class);
        $this->sessionMock                           = $this->createMock(Session::class);
        $this->sessionServiceMock                    = $this->createMock(SessionService::class);
        $this->stateServiceMock                      = $this->createMock(StateService::class);
        $this->userEntityMock                        = $this->createMock(UserEntity::class);
        $this->userRepositoryMock                    = $this->createMock(UserRepository::class);

        $this->authSimpleFactoryMock->method('build')->willReturn($this->authSimpleMock);
        $this->authSimpleMock->method('getAttributes')->willReturn(self::AUTH_DATA['Attributes']);
        $this->authSimpleMock->method('getAuthDataArray')->willReturn(self::AUTH_DATA);
        $this->clientEntityMock->method('getAuthSourceId')->willReturn(self::AUTH_SOURCE);
        $this->clientEntityMock->method('toArray')->willReturn(self::CLIENT_ENTITY);
        $this->moduleConfigMock->method('getUserIdentifierAttribute')->willReturn(self::USER_ID_ATTR);
        $this->opMetadataService->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);
        $this->processingChainFactoryMock->method('build')->willReturn($this->processingChainMock);
        $this->serverRequestMock->method('getQueryParams')->willReturn(self::AUTHZ_REQUEST_PARAMS);
        $this->serverRequestMock->method('getUri')->willReturn(new Uri(self::URI));
        $this->sessionServiceMock->method('getCurrentSession')->willReturn($this->sessionMock);

        $this->helpersMock = $this->createMock(Helpers::class);
        $this->clientHelperMock = $this->createMock(Helpers\Client::class);
        $this->helpersMock->method('client')->willReturn($this->clientHelperMock);

        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->requestParamsResolverMock->method('getAll')->with($this->serverRequestMock)
            ->willReturn(self::AUTHZ_REQUEST_PARAMS);

        $this->userEntityFactoryMock = $this->createMock(UserEntityFactory::class);
    }

    /**
     * @return AuthenticationService
     */
    public function mock(): AuthenticationService
    {
        return $this->getMockBuilder(AuthenticationService::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs(
                [
                     $this->userRepositoryMock,
                     $this->authSimpleFactoryMock,
                     $this->clientRepositoryMock,
                     $this->opMetadataService,
                     $this->sessionServiceMock,
                     $this->claimTranslatorExtractorMock,
                     $this->moduleConfigMock,
                     $this->processingChainFactoryMock,
                     $this->stateServiceMock,
                     $this->helpersMock,
                     $this->requestParamsResolverMock,
                     $this->userEntityFactoryMock,
                ],
            )->onlyMethods([])
            ->getMock();
    }

    /**
     * @return void
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthenticationService::class,
            $this->mock(),
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

        $this->userEntityMock->method('getIdentifier')->willReturn(self::USERNAME);
        $this->userEntityMock->method('getClaims')->willReturn(self::USER_ENTITY_ATTRIBUTES);

        $this->userEntityFactoryMock->expects($this->once())->method('fromData')
            ->with(self::USERNAME, self::USER_ENTITY_ATTRIBUTES)
            ->willReturn($this->userEntityMock);

        $userEntity = $this->mock()->getAuthenticateUser(self::STATE);

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
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \JsonException
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
            $this->mock()->getAuthenticateUser(self::STATE),
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
                Exception::class,
                '/State array does not contain any attributes./',
            ],
            'No OIDC RelyingPartyMetadata ID' => [
                [
                    'Attributes' => self::AUTH_DATA['Attributes'],
                    'Oidc'       => [
                        'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
                        'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
                    ],
                ],
                Exception::class,
                '/OIDC RelyingPartyMetadata ID does not exist in state./',
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
                NotFound::class,
                '/Client not found./',
            ],
        ];
    }

    /**
     * @param array $state
     * @param string $exceptionClass
     * @param string $exceptionMessage
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('getUserState')]
    #[TestDox('getAuthenticateUser throws $exceptionClass with message: "$exceptionMessage" when $_dataName')]
    public function testGetAuthenticateUserItThrowsWhenState(
        array $state,
        string $exceptionClass,
        string $exceptionMessage,
    ): void {
        if (isset($state['Attributes'])) {
            // Needed for the 3rd use case
            $this->clientRepositoryMock->method('findById')->willReturn(null);
        }
        $this->expectException($exceptionClass);
        $this->expectExceptionMessageMatches($exceptionMessage);
        $this->mock()->getAuthenticateUser($state);
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

        $this->mock()->getAuthenticateUser($invalidState);
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
        $this->clientHelperMock->expects($this->once())
            ->method('getFromRequest')
            ->willReturn($this->clientEntityMock);

        $this->mock()->authenticate($this->serverRequestMock);
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
            $this->mock()->prepareStateArray(
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
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\UnserializableException
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
                                     $this->opMetadataService,
                                     $this->sessionServiceMock,
                                     $this->claimTranslatorExtractorMock,
                                     $this->moduleConfigMock,
                                     $this->processingChainFactoryMock,
                                     $this->stateServiceMock,
                                     $this->helpersMock,
                                     $this->requestParamsResolverMock,
                                     $this->userEntityFactoryMock,
                                 ])
            ->onlyMethods(['runAuthProcs', 'prepareStateArray'])
            ->getMock();

        $this->moduleConfigMock->method('getAuthProcFilters')->willReturn([]);
        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(true);
        $this->clientHelperMock->method('getFromRequest')->willReturn($this->clientEntityMock);
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
        $this->mock()->manageState([]);
    }

    /**
     * @throws NoState
     */
    public function testLoadStateFromProcessingChainRedirect(): void
    {
        $queryParameters = [
            ProcessingChain::AUTHPARAM => '123',
        ];
        $state = [
            'Attributes'   => AuthenticationServiceTest::AUTH_DATA['Attributes'],
            'Oidc'         => [
                'OpenIdProviderMetadata'         => AuthenticationServiceTest::OIDC_OP_METADATA,
                'RelyingPartyMetadata'           => AuthenticationServiceTest::CLIENT_ENTITY,
                'AuthorizationRequestParameters' => AuthenticationServiceTest::AUTHZ_REQUEST_PARAMS,
            ],
            'authSourceId' => '456',
        ];
        $this->stateServiceMock->method('loadState')->willReturn($state);


        $mock = $this->mock();

        $this->assertSame(
            self::STATE,
            $mock->manageState($queryParameters),
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
            $this->opMetadataService,
            $this->sessionServiceMock,
            $this->claimTranslatorExtractorMock,
            $this->moduleConfigMock,
            $this->processingChainFactoryMock,
            $this->stateServiceMock,
            $this->helpersMock,
            $this->requestParamsResolverMock,
            $this->userEntityFactoryMock,
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
     * @return array
     */
    public static function authorizationRequestInstanceOf(): array
    {
        $authorizationRequest = new AuthorizationRequest();
        $oAuth2AuthorizationRequest = new OAuth2AuthorizationRequest();
        return [
            'Instance of AuthorizationRequest'                   => [
                [
                    ...self::STATE,
                    'authorizationRequest' => $authorizationRequest,
                ],
                $authorizationRequest,
                AuthorizationRequest::class,
            ],
            'Instance of OAuth2AuthorizationRequest'                   => [
                [
                    ...self::STATE,
                    'authorizationRequest' => $oAuth2AuthorizationRequest,
                ],
                $oAuth2AuthorizationRequest,
                OAuth2AuthorizationRequest::class,
            ],
        ];
    }

    /**
     * @param   array                                            $state
     * @param   AuthorizationRequest|OAuth2AuthorizationRequest  $authorizationRequest
     * @param   string                                           $instanceOf
     *
     * @return void
     * @throws Exception
     */
    #[DataProvider('authorizationRequestInstanceOf')]
    public function testItGetsAuthorizationRequestFromState(
        array $state,
        AuthorizationRequest|OAuth2AuthorizationRequest $authorizationRequest,
        string $instanceOf,
    ): void {
        $this->assertEquals(
            $this->mock()->getAuthorizationRequestFromState($state),
            $authorizationRequest,
        );

        $this->assertInstanceOf(
            $instanceOf,
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
                    'authorizationRequest' => 'invalid',
                ],
                '/Authorization Request is not valid./',
            ],
            'not set' => [
                [
                    ...self::STATE,
                ],
                '/Authorization Request is not set./',
            ],
        ];
    }

    /**
     * @param   array  $state
     * @param string $exceptionMessage
     *
     * @return void
     * @throws Exception
     */
    #[DataProvider('authorizationRequestValues')]
    public function testGetsAuthorizationRequestFromStateThrowsOnInvalid(array $state, string $exceptionMessage): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches($exceptionMessage);
        $this->mock()->getAuthorizationRequestFromState($state);
    }
}
