<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Uri;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NoState;
use SimpleSAML\Error\UserAborted;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Factories\ProcessingChainFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Client;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeResolver;
use SimpleSAML\Module\oidc\Server\ResponseTypes\HtmlResponse;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Services\StateService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\AuthorizationErrorRedirect;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;
use SimpleSAML\Session;

/**
 * @covers \SimpleSAML\Module\oidc\Services\AuthenticationService
 */
#[AllowMockObjectsWithoutExpectations]
class AuthenticationServiceTest extends TestCase
{
    final public const string URI = 'https://some-server/authorize.php?abc=efg';

    final public const string AUTHORIZATION_URL = 'https://some-server/module.php/oidc/authorization';

    final public const string REDIRECT_URI = 'https://rp.example.org/cb';

    final public const string PUSHED_REQUEST_URI = 'urn:ietf:params:oauth:request_uri:pushed-request';

    final public const string AUTH_SOURCE = 'auth_source';

    final public const string USER_ID_ATTR = 'uid';

    final public const string USERNAME = 'username';

    final public const array OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];

    final public const array USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR    => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];

    final public const array AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];

    final public const array CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];

    final public const array AUTHZ_REQUEST_PARAMS = [
        'client_id' => 'clientid',
        'redirect_uri' => 'https://rp.example.org',
    ];

    final public const array STATE = [
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

    protected MockObject $routesMock;

    protected ResponseModeResolver $responseModeResolver;

    protected MockObject $formPostResponseModeMock;

    protected MockObject $pushedAuthorizationRequestRepositoryMock;


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
        $this->moduleConfigMock->method('getUserIdentifierAttributes')->willReturn([self::USER_ID_ATTR]);
        $this->opMetadataService->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);
        $this->processingChainFactoryMock->method('build')->willReturn($this->processingChainMock);
        $this->serverRequestMock->method('getQueryParams')->willReturn(self::AUTHZ_REQUEST_PARAMS);
        $this->serverRequestMock->method('getUri')->willReturn(new Uri(self::URI));
        $this->sessionServiceMock->method('getCurrentSession')->willReturn($this->sessionMock);

        $this->helpersMock = $this->createMock(Helpers::class);
        $this->clientHelperMock = $this->createMock(Client::class);
        $this->helpersMock->method('client')->willReturn($this->clientHelperMock);

        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        // The authorization request as the grants validate it: from the query of a GET, the body of a POST.
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->with($this->serverRequestMock, [HttpMethodsEnum::GET, HttpMethodsEnum::POST])
            ->willReturn(self::AUTHZ_REQUEST_PARAMS);

        $this->userEntityFactoryMock = $this->createMock(UserEntityFactory::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->formPostResponseModeMock = $this->createMock(FormPostResponseMode::class);
        $this->responseModeResolver = new ResponseModeResolver(
            new QueryResponseMode(),
            new FragmentResponseMode(),
            $this->formPostResponseModeMock,
        );
        $this->pushedAuthorizationRequestRepositoryMock = $this->createMock(
            PushedAuthorizationRequestRepository::class,
        );
    }


    /**
     * @return \SimpleSAML\Module\oidc\Services\AuthenticationService
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
                     $this->requestParamsResolverMock,
                     $this->userEntityFactoryMock,
                     $this->routesMock,
                     new UserIdentifierResolver(),
                     $this->responseModeResolver,
                     $this->pushedAuthorizationRequestRepositoryMock,
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
     * @throws \SimpleSAML\Error\Exception
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

        $this->claimTranslatorExtractorMock->expects($this->once())->method('extractSubject')
            ->with($this->isArray())
            ->willReturn(null);

        $this->assertSame(
            $this->mock()->getAuthenticateUser(self::STATE),
            $this->userEntityMock,
        );
    }


    /**
     * @return array<string, array{0: ?\SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum, 1: bool}>
     */
    public static function associationProvider(): array
    {
        return [
            'a plain OAuth 2.0 login' => [FlowTypeEnum::OAuth2AuthorizationCode, false],
            'an OpenID Connect login' => [FlowTypeEnum::OidcAuthorizationCode, true],
            'a credential login' => [FlowTypeEnum::VciAuthorizationCode, true],
            'a login whose request names no flow' => [null, true],
        ];
    }


    /**
     * A plain OAuth 2.0 login gets its client no ID token, so no session with the OP which it could be told the
     * end of: the client is not associated with the session, and gets no back-channel logout token on account of
     * this login. Every other login is associated as before.
     *
     * @throws \Exception
     */
    #[DataProvider('associationProvider')]
    public function testAssociatesTheClientWithTheSessionUnlessTheLoginIsAPlainOAuth2One(
        ?FlowTypeEnum $flowType,
        bool $associated,
    ): void {
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->userRepositoryMock->method('getUserEntityByIdentifier')->willReturn($this->userEntityMock);
        $this->userEntityMock->method('getClaims')->willReturn([]);
        $this->sessionServiceMock->expects($associated ? $this->once() : $this->never())
            ->method('addRelyingPartyAssociation');

        $authorizationRequest = new AuthorizationRequest();
        $authorizationRequest->setFlowType($flowType);
        $state = self::STATE;
        $state['authorizationRequest'] = $authorizationRequest;

        $this->assertSame($this->userEntityMock, $this->mock()->getAuthenticateUser($state));
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
                OidcException::class,
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
     * @throws \SimpleSAML\Error\Exception
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
        $this->expectExceptionMessageMatches("/None of the configured user identifier attributes/");

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
        $authorizationErrorRedirect = new AuthorizationErrorRedirect(self::REDIRECT_URI, 'the-state');
        $this->routesMock->method('getModuleUrl')
            ->with(RoutesEnum::Authorization->value)
            ->willReturn(self::AUTHORIZATION_URL);

        // An exception the authentication source raises comes back to the authorization endpoint, which finds the
        // redirect to answer the client at in the state the login parameters go into.
        $this->authSimpleMock->expects($this->once())->method('login')->with([
            'core:username' => 'user',
            'ErrorURL' => self::AUTHORIZATION_URL,
            AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT => $authorizationErrorRedirect,
        ]);

        $this->mock()->authenticateForClient(
            $this->clientEntityMock,
            $authorizationErrorRedirect,
            ['core:username' => 'user'],
        );
    }


    /**
     * A request with no redirect URI can not be answered at one, so its login gets no ErrorURL, and SimpleSAMLphp
     * handles an exception of it as it would without the module.
     *
     * @throws \Throwable
     */
    public function testALoginWithNoRedirectGetsNoErrorUrl(): void
    {
        $this->routesMock->expects($this->never())->method('getModuleUrl');
        $this->authSimpleMock->expects($this->once())->method('login')->with(['core:username' => 'user']);

        $this->mock()->authenticate($this->authSimpleMock, null, ['core:username' => 'user']);
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
        // The request mock has no redirect URI, so there is no redirect to keep.
        $state[AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT] = null;

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
     * The processing chain's state keeps the request's redirect, so that a filter's cancel is answered to the
     * client.
     *
     * @throws \SimpleSAML\Error\AuthSource
     */
    public function testTheStateArrayKeepsTheAuthorizationErrorRedirect(): void
    {
        $this->authorizationRequestMock->method('getRedirectUri')->willReturn(self::REDIRECT_URI);
        $this->authorizationRequestMock->method('getState')->willReturn('the-state');
        $this->authorizationRequestMock->method('getResponseMode')->willReturn(ResponseModesEnum::Fragment);

        $state = $this->mock()->prepareStateArray(
            $this->authSimpleMock,
            $this->clientEntityMock,
            $this->serverRequestMock,
            $this->authorizationRequestMock,
        );

        $this->assertEquals(
            new AuthorizationErrorRedirect(self::REDIRECT_URI, 'the-state', ResponseModesEnum::Fragment),
            $state[AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT],
        );
    }


    /**
     * @throws \Throwable
     */
    public function testItResolvesTheAuthorizationErrorRedirectOfARequest(): void
    {
        $this->authorizationRequestMock->method('getRedirectUri')->willReturn(self::REDIRECT_URI);
        $this->authorizationRequestMock->method('getState')->willReturn('the-state');
        $this->authorizationRequestMock->method('getResponseMode')->willReturn(ResponseModesEnum::Fragment);
        $this->authorizationRequestMock->method('getPushedAuthorizationRequestUri')
            ->willReturn(self::PUSHED_REQUEST_URI);

        $authorizationErrorRedirect = $this->mock()->resolveAuthorizationErrorRedirect($this->authorizationRequestMock);

        $this->assertSame(self::REDIRECT_URI, $authorizationErrorRedirect?->getRedirectUri());
        $this->assertSame('the-state', $authorizationErrorRedirect?->getState());
        // By its value: the response mode itself does not go into the session.
        $this->assertSame(ResponseModesEnum::Fragment, $authorizationErrorRedirect?->getResponseMode());
        $this->assertSame(self::PUSHED_REQUEST_URI, $authorizationErrorRedirect?->getPushedAuthorizationRequestUri());
    }


    /**
     * A request of the League library has no response mode, so its errors go in the default one.
     *
     * @throws \Throwable
     */
    public function testTheAuthorizationErrorRedirectOfALeagueRequestHasNoResponseMode(): void
    {
        $authorizationRequest = new OAuth2AuthorizationRequest();
        $authorizationRequest->setRedirectUri(self::REDIRECT_URI);
        $authorizationRequest->setState('the-state');

        $authorizationErrorRedirect = $this->mock()->resolveAuthorizationErrorRedirect($authorizationRequest);

        $this->assertSame(self::REDIRECT_URI, $authorizationErrorRedirect?->getRedirectUri());
        $this->assertSame('the-state', $authorizationErrorRedirect?->getState());
        $this->assertNull($authorizationErrorRedirect?->getResponseMode());
        $this->assertNull($authorizationErrorRedirect?->getPushedAuthorizationRequestUri());
    }


    /**
     * @throws \Throwable
     */
    public function testARequestWithNoRedirectUriHasNoAuthorizationErrorRedirect(): void
    {
        $this->assertNull($this->mock()->resolveAuthorizationErrorRedirect(new OAuth2AuthorizationRequest()));
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
                                     $this->requestParamsResolverMock,
                                     $this->userEntityFactoryMock,
                                     $this->routesMock,
                                     new UserIdentifierResolver(),
                                     $this->responseModeResolver,
                                     $this->pushedAuthorizationRequestRepositoryMock,
                                 ])
            ->onlyMethods(['runAuthProcs', 'prepareStateArray'])
            ->getMock();

        $this->moduleConfigMock->method('getAuthProcFilters')->willReturn([]);
        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(true);
        $this->authorizationRequestMock->method('getClient')->willReturn($this->clientEntityMock);
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
     * When the user is not yet authenticated and a login_hint is present in the authorization request, it must be
     * propagated to the authentication source as the pre-filled username (the 'core:username' login parameter).
     *
     * @throws \Throwable
     */
    public function testItPropagatesLoginHintToAuthentication(): void
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
                                     $this->requestParamsResolverMock,
                                     $this->userEntityFactoryMock,
                                     $this->routesMock,
                                     new UserIdentifierResolver(),
                                     $this->responseModeResolver,
                                     $this->pushedAuthorizationRequestRepositoryMock,
                                 ])
            ->onlyMethods(['runAuthProcs', 'prepareStateArray', 'authenticate'])
            ->getMock();

        $this->authSimpleMock->method('getAuthSource')->willReturn($this->authSourceMock);
        $this->authSourceMock->method('getAuthId')->willReturn(self::AUTH_SOURCE);
        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(false);
        $this->authorizationRequestMock->method('getClient')->willReturn($this->clientEntityMock);
        $this->authorizationRequestMock->method('getLoginHint')->willReturn('user@example.org');
        $this->authorizationRequestMock->method('getRedirectUri')->willReturn(self::REDIRECT_URI);
        $this->authorizationRequestMock->method('getState')->willReturn('the-state');
        $authenticationServiceMock->method('prepareStateArray')->willReturn(self::STATE);

        $authenticationServiceMock->expects($this->once())
            ->method('authenticate')
            ->with(
                $this->authSimpleMock,
                new AuthorizationErrorRedirect(self::REDIRECT_URI, 'the-state'),
                ['core:username' => 'user@example.org'],
            );

        $this->assertSame(
            $authenticationServiceMock->processRequest(
                $this->serverRequestMock,
                $this->authorizationRequestMock,
            ),
            self::STATE,
        );
    }


    /**
     * The subject matches when it equals the resolved user identifier (the default `sub` produced by
     * IdTokenBuilder when no `sub` mapping is in effect).
     */
    public function testSubjectMatchesAttributesMatchesUserIdentifier(): void
    {
        $this->claimTranslatorExtractorMock->method('extractSubject')
            ->with(self::USER_ENTITY_ATTRIBUTES)
            ->willReturn(null);

        $this->assertTrue(
            $this->mock()->subjectMatchesAttributes(self::USERNAME, self::USER_ENTITY_ATTRIBUTES),
        );
    }


    /**
     * The subject also matches a mapped `sub` claim, so a hint issued when the `sub` mapping was applied is
     * accepted for the same user.
     */
    public function testSubjectMatchesAttributesMatchesMappedSubClaim(): void
    {
        $this->claimTranslatorExtractorMock->method('extractSubject')
            ->with(self::USER_ENTITY_ATTRIBUTES)
            ->willReturn('mapped-subject');

        $this->assertTrue(
            $this->mock()->subjectMatchesAttributes('mapped-subject', self::USER_ENTITY_ATTRIBUTES),
        );
    }


    /**
     * A subject that matches neither the user identifier nor a mapped `sub` claim identifies a different
     * End-User and must not match.
     */
    public function testSubjectMatchesAttributesRejectsDifferentSubject(): void
    {
        $this->claimTranslatorExtractorMock->method('extractSubject')
            ->with(self::USER_ENTITY_ATTRIBUTES)
            ->willReturn(null);

        $this->assertFalse(
            $this->mock()->subjectMatchesAttributes('someone-else', self::USER_ENTITY_ATTRIBUTES),
        );
    }


    /**
     * When no user identifier can be resolved from the attributes, no subject can match.
     */
    public function testSubjectMatchesAttributesReturnsFalseWhenNoIdentifier(): void
    {
        $this->assertFalse(
            $this->mock()->subjectMatchesAttributes('anything', ['someOtherAttribute' => ['value']]),
        );
    }


    /**
     * @throws \SimpleSAML\Error\NoState
     */
    public function testItThrowsOnMissingQueryParameterAuthparam(): void
    {
        $this->expectException(NoState::class);
        $this->mock()->manageState([]);
    }


    /**
     * @throws \SimpleSAML\Error\NoState
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
        $this->routesMock->method('getModuleUrl')->willReturn($returnUrl);
        $mockedInstance = $this->authProcRunner();

        $state = self::STATE;
        $mockedInstance->runAuthProcsPublic($state);

        $this->assertEquals($state['ReturnURL'], $returnUrl);
        // An exception a filter raises after sending the End-User to a page of its own comes back there too.
        $this->assertSame($returnUrl, $state[State::EXCEPTION_HANDLER_URL]);
        $this->assertEquals($state['Source']['authproc'], $authProcFilters);
        // The client in STATE has no per-client filters, so the SP side is empty.
        $this->assertSame([], $state['Destination']['authproc']);
        // Existing state keys must be preserved (nothing dropped).
        $this->assertArrayHasKey('Oidc', $state);
        $this->assertArrayHasKey('Attributes', $state);
    }


    /**
     * Per-client authproc filters (from the relying party metadata) must be
     * applied on the SP (Destination) side, while the global filters remain on
     * the IdP (Source) side. The two are merged by the ProcessingChain.
     *
     * @return void
     */
    public function testRunAuthProcsAppliesPerClientAuthProcFilters(): void
    {
        $globalFilters = [25 => ['class' => 'core:AttributeMap', 'oid2name']];
        $clientFilters = [60 => ['class' => 'core:AttributeAdd', 'groups' => ['members']]];
        $returnUrl     = 'http://example.com/authorization';
        $this->moduleConfigMock->method('getAuthProcFilters')->willReturn($globalFilters);
        $this->routesMock->method('getModuleUrl')->willReturn($returnUrl);
        $mockedInstance = $this->authProcRunner();

        $state = self::STATE;
        // Per-client authproc filters live in the relying party metadata.
        $state['Oidc']['RelyingPartyMetadata'][ClientEntity::KEY_AUTH_PROC_FILTERS] = $clientFilters;

        $mockedInstance->runAuthProcsPublic($state);

        $this->assertSame($globalFilters, $state['Source']['authproc']);
        $this->assertSame($clientFilters, $state['Destination']['authproc']);
    }


    /**
     * A filter which raises UserAborted before it sends the End-User anywhere has it thrown out of processState():
     * the client is answered with access_denied, at the redirect in the state, in its response mode, with its state.
     *
     * @throws \Throwable
     */
    public function testACancelInAProcessingFilterIsAnsweredToTheClient(): void
    {
        $userAborted = new UserAborted();
        $this->processingChainMock->method('processState')->willThrowException($userAborted);
        // The filters run once the End-User is authenticated, so processRequest() has seen to the login's mark.
        $this->sessionServiceMock->expects($this->never())->method('setIsAuthnPerformedInPreviousRequest');
        // No pushed request to consume.
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->never())->method('consume');
        $state = self::STATE;
        $state[AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT] = new AuthorizationErrorRedirect(
            self::REDIRECT_URI,
            'the-state',
            ResponseModesEnum::Fragment,
        );

        try {
            $this->authProcRunner()->runAuthProcsPublic($state);
            $this->fail('A cancel in a filter must be answered to the client.');
        } catch (OidcServerException $exception) {
            $this->assertSame($userAborted, $exception->getPrevious());
            $this->assertSame(
                ['error' => 'access_denied', 'state' => 'the-state'],
                $this->redirectedErrorOf($exception, PHP_URL_FRAGMENT),
            );
        }
    }


    /**
     * Any other exception of a filter is thrown as it was raised, as before the module took cancels back.
     *
     * @throws \Throwable
     */
    public function testAnotherExceptionOfAProcessingFilterIsThrownAsItWas(): void
    {
        $failure = new Exception('A filter failed.');
        $this->processingChainMock->method('processState')->willThrowException($failure);
        $this->sessionServiceMock->expects($this->never())->method('setIsAuthnPerformedInPreviousRequest');
        $state = self::STATE;
        $state[AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT] = new AuthorizationErrorRedirect(
            self::REDIRECT_URI,
            'the-state',
        );

        try {
            $this->authProcRunner()->runAuthProcsPublic($state);
            $this->fail('The failure of a filter must be thrown.');
        } catch (Exception $exception) {
            $this->assertSame($failure, $exception);
        }
    }


    /**
     * With no redirect in the state there is nothing to answer the client at, so the cancel is thrown as it was.
     *
     * @throws \Throwable
     */
    public function testACancelWithNoRedirectInTheStateIsThrownAsItWas(): void
    {
        $userAborted = new UserAborted();
        $this->processingChainMock->method('processState')->willThrowException($userAborted);
        $this->sessionServiceMock->expects($this->never())->method('setIsAuthnPerformedInPreviousRequest');
        $state = self::STATE;

        try {
            $this->authProcRunner()->runAuthProcsPublic($state);
            $this->fail('A cancel with no redirect must be thrown.');
        } catch (UserAborted $exception) {
            $this->assertSame($userAborted, $exception);
        }
    }


    /**
     * A cancel which SimpleSAMLphp hands back to the authorization endpoint, from a login or from a filter's page,
     * is answered to the client at the redirect in the state; with no response mode in it, in the query.
     *
     * @throws \Throwable
     */
    public function testACancelHandedBackIsAnsweredToTheClient(): void
    {
        $userAborted = new UserAborted();
        $this->stateServiceMock->expects($this->once())
            ->method('loadExceptionState')
            ->with('exception-state-id')
            ->willReturn([
                State::EXCEPTION_DATA => $userAborted,
                AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT =>
                    new AuthorizationErrorRedirect(self::REDIRECT_URI, 'the-state'),
            ]);
        // The login did not complete, so the next request must not take the session for a fresh login.
        $this->sessionServiceMock->expects($this->once())
            ->method('setIsAuthnPerformedInPreviousRequest')
            ->with(false);

        try {
            $this->mock()->rethrowAuthenticationException([State::EXCEPTION_PARAM => 'exception-state-id']);
            $this->fail('A cancel handed back must be answered to the client.');
        } catch (OidcServerException $exception) {
            $this->assertSame($userAborted, $exception->getPrevious());
            $this->assertSame(
                ['error' => 'access_denied', 'state' => 'the-state'],
                $this->redirectedErrorOf($exception, PHP_URL_QUERY),
            );
        }
    }


    /**
     * Any other exception handed back is thrown as it was raised, which SimpleSAMLphp shows as it did when no
     * handler took it back.
     *
     * @throws \Throwable
     */
    public function testAnotherExceptionHandedBackIsThrownAsItWas(): void
    {
        $failure = new Exception('The upstream identity provider answered with an error.');
        $this->stateServiceMock->method('loadExceptionState')->willReturn([
            State::EXCEPTION_DATA => $failure,
            AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT =>
                new AuthorizationErrorRedirect(self::REDIRECT_URI, 'the-state'),
        ]);
        // A failed login did not complete either.
        $this->sessionServiceMock->expects($this->once())
            ->method('setIsAuthnPerformedInPreviousRequest')
            ->with(false);
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->never())->method('consume');

        try {
            $this->mock()->rethrowAuthenticationException([State::EXCEPTION_PARAM => 'exception-state-id']);
            $this->fail('An exception handed back must be thrown.');
        } catch (Exception $exception) {
            $this->assertSame($failure, $exception);
        }
    }


    /**
     * An exception state the module did not prepare holds no redirect: the cancel is thrown as it was, and the
     * session is left alone.
     *
     * @throws \Throwable
     */
    public function testACancelHandedBackWithNoRedirectInTheStateIsThrownAsItWas(): void
    {
        $userAborted = new UserAborted();
        $this->stateServiceMock->method('loadExceptionState')->willReturn([State::EXCEPTION_DATA => $userAborted]);
        $this->sessionServiceMock->expects($this->never())->method('setIsAuthnPerformedInPreviousRequest');

        try {
            $this->mock()->rethrowAuthenticationException([State::EXCEPTION_PARAM => 'exception-state-id']);
            $this->fail('A cancel with no redirect must be thrown.');
        } catch (UserAborted $exception) {
            $this->assertSame($userAborted, $exception);
        }
    }


    /**
     * The cancel's access_denied is the response to the pushed request, so it consumes the request first, as a
     * successful response does: one request_uri yields at most one response.
     *
     * @throws \Throwable
     */
    public function testACancelOfAPushedRequestConsumesIt(): void
    {
        $this->stateServiceMock->method('loadExceptionState')->willReturn([
            State::EXCEPTION_DATA => new UserAborted(),
            AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT => new AuthorizationErrorRedirect(
                self::REDIRECT_URI,
                'the-state',
                null,
                self::PUSHED_REQUEST_URI,
            ),
        ]);
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())
            ->method('consume')
            ->with(self::PUSHED_REQUEST_URI)
            ->willReturn(true);

        try {
            $this->mock()->rethrowAuthenticationException([State::EXCEPTION_PARAM => 'exception-state-id']);
            $this->fail('A cancel of a pushed request must be answered to the client.');
        } catch (OidcServerException $exception) {
            $this->assertSame(
                ['error' => 'access_denied', 'state' => 'the-state'],
                $this->redirectedErrorOf($exception, PHP_URL_QUERY),
            );
        }
    }


    /**
     * A pushed request which had its response meanwhile, in another tab or by a replay, gets no second one: the cancel
     * is refused as AuthorizationServer refuses a second successful response, and the client is not answered.
     *
     * @throws \Throwable
     */
    public function testACancelOfAPushedRequestWhichHadItsResponseIsRefused(): void
    {
        $userAborted = new UserAborted();
        $this->processingChainMock->method('processState')->willThrowException($userAborted);
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())
            ->method('consume')
            ->with(self::PUSHED_REQUEST_URI)
            ->willReturn(false);
        $state = self::STATE;
        $state[AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT] = new AuthorizationErrorRedirect(
            self::REDIRECT_URI,
            'the-state',
            null,
            self::PUSHED_REQUEST_URI,
        );

        $this->expectException(BadRequest::class);

        $this->authProcRunner()->runAuthProcsPublic($state);
    }


    /**
     * A cancel in the form_post response mode is posted to the client by the form_post response mode, with the
     * error and the state.
     *
     * @throws \Throwable
     */
    public function testACancelInTheFormPostResponseModeIsPostedToTheClient(): void
    {
        $this->stateServiceMock->method('loadExceptionState')->willReturn([
            State::EXCEPTION_DATA => new UserAborted(),
            AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT => new AuthorizationErrorRedirect(
                self::REDIRECT_URI,
                'the-state',
                ResponseModesEnum::FormPost,
            ),
        ]);
        $page = new HtmlResponse();
        $page->setHtml('<form method="post"></form>');
        $this->formPostResponseModeMock->expects($this->once())
            ->method('buildResponse')
            ->with(
                self::REDIRECT_URI,
                $this->callback(static fn(array $params): bool =>
                    ($params['error'] ?? null) === 'access_denied' && ($params['state'] ?? null) === 'the-state'),
            )
            ->willReturn($page);

        try {
            $this->mock()->rethrowAuthenticationException([State::EXCEPTION_PARAM => 'exception-state-id']);
            $this->fail('A cancel must be answered to the client.');
        } catch (OidcServerException $exception) {
            $response = $exception->generateHttpResponse(new Response());
            $this->assertSame('<form method="post"></form>', (string)$response->getBody());
            $this->assertSame('', $response->getHeaderLine('Location'));
        }
    }


    public static function invalidExceptionStateIdProvider(): array
    {
        return [
            'missing' => [[]],
            'empty' => [[State::EXCEPTION_PARAM => '']],
            'not a string' => [[State::EXCEPTION_PARAM => ['exception-state-id']]],
        ];
    }


    /**
     * @throws \Throwable
     */
    #[DataProvider('invalidExceptionStateIdProvider')]
    public function testAnInvalidExceptionStateIdIsRefused(array $queryParameters): void
    {
        $this->stateServiceMock->expects($this->never())->method('loadExceptionState');

        $this->expectException(NoState::class);

        $this->mock()->rethrowAuthenticationException($queryParameters);
    }


    /**
     * @throws \Throwable
     */
    public function testAMissingExceptionStateIsRefused(): void
    {
        $this->stateServiceMock->method('loadExceptionState')->willReturn(null);

        $this->expectException(NoState::class);

        $this->mock()->rethrowAuthenticationException([State::EXCEPTION_PARAM => 'exception-state-id']);
    }


    /**
     * @throws \Throwable
     */
    public function testAnExceptionStateWithNoExceptionIsRefused(): void
    {
        $this->stateServiceMock->method('loadExceptionState')->willReturn([
            AuthenticationService::STATE_KEY_AUTHORIZATION_ERROR_REDIRECT =>
                new AuthorizationErrorRedirect(self::REDIRECT_URI, 'the-state'),
        ]);

        // NoState is an Exception too, so the message tells the two refusals apart.
        $this->expectExceptionMessage('Exception state does not contain an exception.');

        $this->mock()->rethrowAuthenticationException([State::EXCEPTION_PARAM => 'exception-state-id']);
    }


    /**
     * The error and state an error redirect carries to the client, in the given part of its redirect URI, which must
     * be the one of the redirect.
     *
     * @return array<string, mixed>
     */
    private function redirectedErrorOf(OidcServerException $exception, int $component): array
    {
        $location = $exception->generateHttpResponse(new Response())->getHeaderLine('Location');
        $this->assertStringStartsWith(self::REDIRECT_URI . ($component === PHP_URL_FRAGMENT ? '#' : '?'), $location);
        parse_str((string)parse_url($location, $component), $parameters);

        return array_intersect_key($parameters, ['error' => true, 'state' => true]);
    }


    /**
     * An AuthenticationService which runs runAuthProcs() for a test.
     */
    private function authProcRunner(): AuthenticationService
    {
        return new class (
            $this->userRepositoryMock,
            $this->authSimpleFactoryMock,
            $this->clientRepositoryMock,
            $this->opMetadataService,
            $this->sessionServiceMock,
            $this->claimTranslatorExtractorMock,
            $this->moduleConfigMock,
            $this->processingChainFactoryMock,
            $this->stateServiceMock,
            $this->requestParamsResolverMock,
            $this->userEntityFactoryMock,
            $this->routesMock,
            new UserIdentifierResolver(),
            $this->responseModeResolver,
            $this->pushedAuthorizationRequestRepositoryMock,
        ) extends AuthenticationService {
            public function runAuthProcsPublic(array &$state): void
            {
                $this->runAuthProcs($state);
            }
        };
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
     * @param   \SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest|\League\OAuth2\Server\RequestTypes\AuthorizationRequest
     *   $authorizationRequest
     * @param   string                                           $instanceOf
     *
     * @return void
     * @throws \SimpleSAML\Error\Exception
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
     * @throws \SimpleSAML\Error\Exception
     */
    #[DataProvider('authorizationRequestValues')]
    public function testGetsAuthorizationRequestFromStateThrowsOnInvalid(array $state, string $exceptionMessage): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches($exceptionMessage);
        $this->mock()->getAuthorizationRequestFromState($state);
    }
}
