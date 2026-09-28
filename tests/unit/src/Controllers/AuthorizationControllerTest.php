<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Closure;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Response as PsrResponse;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Locale;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Locale\Language;
use SimpleSAML\Module\oidc\Controllers\AuthorizationController;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\UiLocalesResolver;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\AuthorizationController
 */
#[AllowMockObjectsWithoutExpectations]
class AuthorizationControllerTest extends TestCase
{
    final public const string AUTH_SOURCE = 'auth_source';

    final public const string USER_ID_ATTR = 'uid';

    final public const string USERNAME = 'username';

    final public const array OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];

    final public const array USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];

    final public const array AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];

    final public const array CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];

    final public const array AUTHZ_REQUEST_PARAMS = [
        'client_id' => 'clientid',
        'redirect_uri' => 'https://rp.example.org',
    ];


    protected MockObject $authenticationServiceStub;

    protected Stub $authorizationServerStub;

    protected Stub $moduleConfigStub;

    protected MockObject $loggerServiceMock;

    protected MockObject $authorizationRequestMock;

    protected Stub $userEntityStub;

    protected Stub $serverRequestStub;

    protected Stub $responseStub;

    protected MockObject $psrHttpBridgeMock;

    protected MockObject $errorResponderMock;

    protected Stub $uiLocalesResolverStub;

    protected MockObject $sspBridgeMock;

    protected MockObject $sspBridgeLocaleMock;

    protected MockObject $sspBridgeLocaleLanguageMock;

    protected array $state;

    protected static string $sampleAuthSourceId = 'authSource123';

    protected static array $sampleAuthSourcesToAcrValuesMap = ['authSource123' => ['1', '0']];

    protected static array $sampleRequestedAcrs = ['values' => ['1', '0'], 'essential' => false];

    protected MockObject $symfonyRequestMock;

    protected MockObject $symfonyResponseMock;

    protected MockObject $responseHeaderBagMock;

    protected MockObject $httpFoundationFactoryMock;

    /** What the controller handed to ErrorResponder::forException(); see captureTheErrorGivenToTheResponder(). */
    protected ?OAuthServerException $errorGivenToTheResponder = null;


    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->authenticationServiceStub = $this->createMock(AuthenticationService::class);
        $this->authorizationServerStub = $this->createStub(AuthorizationServer::class);
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->authorizationRequestMock = $this->createMock(AuthorizationRequest::class);
        $this->userEntityStub = $this->createStub(UserEntity::class);
        $this->serverRequestStub = $this->createStub(ServerRequest::class);
        $this->responseStub = $this->createStub(ResponseInterface::class);

        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);

        $this->uiLocalesResolverStub = $this->createStub(UiLocalesResolver::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sspBridgeLocaleMock = $this->createMock(Locale::class);
        $this->sspBridgeLocaleLanguageMock = $this->createMock(Language::class);
        $this->sspBridgeMock->method('locale')->willReturn($this->sspBridgeLocaleMock);
        $this->sspBridgeLocaleMock->method('language')->willReturn($this->sspBridgeLocaleLanguageMock);

        $this->state = [
            'Attributes' => self::AUTH_DATA['Attributes'],
            'Oidc' => [
                'OpenIdProviderMetadata' => self::OIDC_OP_METADATA,
                'RelyingPartyMetadata' => self::CLIENT_ENTITY,
                'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
            ],
            'authorizationRequest' => $this->authorizationRequestMock,
        ];

        $this->symfonyRequestMock = $this->createMock(Request::class);
        $this->symfonyResponseMock = $this->createMock(Response::class);
        $this->responseHeaderBagMock = $this->createMock(ResponseHeaderBag::class);
        $this->symfonyResponseMock->headers = $this->responseHeaderBagMock;

        $this->httpFoundationFactoryMock = $this->createMock(HttpFoundationFactory::class);
        $this->httpFoundationFactoryMock->method('createResponse')->willReturn($this->symfonyResponseMock);
        $this->psrHttpBridgeMock->method('getHttpFoundationFactory')->willReturn($this->httpFoundationFactoryMock);
    }


    public static function queryParameterValues(): array
    {
        return [
            'Has ProcessingChain Query Param' => [
                [ProcessingChain::AUTHPARAM => '123'],
            ],
            'No Query Parameters' => [
                [],
            ],
        ];
    }


    protected function mock(
        ?AuthenticationService $authenticationService = null,
        ?AuthorizationServer $authorizationServer = null,
        ?ModuleConfig $moduleConfig = null,
        ?LoggerService $loggerService = null,
        ?PsrHttpBridge $psrHttpBridge = null,
        ?ErrorResponder $errorResponder = null,
        ?UiLocalesResolver $uiLocalesResolver = null,
        ?SspBridge $sspBridge = null,
    ): AuthorizationController {
        $authenticationService ??= $this->authenticationServiceStub;
        $authorizationServer ??= $this->authorizationServerStub;
        $moduleConfig ??= $this->moduleConfigStub;
        $loggerService ??= $this->loggerServiceMock;
        $psrHttpBridge ??= $this->psrHttpBridgeMock;
        $errorResponder ??= $this->errorResponderMock;
        $uiLocalesResolver ??= $this->uiLocalesResolverStub;
        $sspBridge ??= $this->sspBridgeMock;

        return new AuthorizationController(
            $authenticationService,
            $authorizationServer,
            $moduleConfig,
            $loggerService,
            $psrHttpBridge,
            $errorResponder,
            $uiLocalesResolver,
            $sspBridge,
        );
    }

    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    #[DataProvider('queryParameterValues')]
    public function testReturnsResponseWhenInvoked(array $queryParameters): void
    {
        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn($queryParameters);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub->method('getAuthenticateUser')
            ->willReturn($this->userEntityStub);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $controller = $this->mock();

        if (empty($queryParameters)) {
            $this->authenticationServiceStub->expects($this->once())
                ->method('processRequest')
                ->with(
                    $this->serverRequestStub,
                    $this->authorizationRequestMock,
                );
        }

        $this->assertInstanceOf(ResponseInterface::class, $controller($this->serverRequestStub));
    }


    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    public function testValidateAcrThrowsIfAuthSourceIdNotSetInAuthorizationRequest(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->expectException(OidcServerException::class);

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    public function testValidateAcrThrowsIfCookieBasedAuthnNotSetInAuthorizationRequest(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);

        $this->expectException(OidcServerException::class);

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    public function testValidateAcrSetsForcedAcrForCookieAuthentication(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(true);

        $this->moduleConfigStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn(self::$sampleAuthSourcesToAcrValuesMap);
        $this->moduleConfigStub->method('getForcedAcrValueForCookieAuthentication')->willReturn('0');

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('0');

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    public function testValidateAcrThrowsIfNoMatchedAcrForEssentialAcrs(): void
    {
        $requestedAcrs = ['values' => ['a', 'b'], 'essential' => true];
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn($requestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(false);

        $this->moduleConfigStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn(self::$sampleAuthSourcesToAcrValuesMap);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->expectException(OidcServerException::class);

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    public function testValidateAcrSetsFirstMatchedAcr(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(false);

        $this->moduleConfigStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn(self::$sampleAuthSourcesToAcrValuesMap);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);


        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('1');

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    public function testValidateAcrSetsCurrentSessionAcrIfNoMatchedAcr(): void
    {
        $requestedAcrs = ['values' => ['a', 'b'], 'essential' => false];
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn($requestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(false);

        $this->moduleConfigStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn(self::$sampleAuthSourcesToAcrValuesMap);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('1');

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    public function testValidateAcrLogsWarningIfNoAcrsConfigured(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(false);

        $authSourcesToAcrValuesMap = [self::$sampleAuthSourceId => []];
        $this->moduleConfigStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn($authSourcesToAcrValuesMap);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationRequestMock->expects($this->once())->method('setAcr');
        $this->loggerServiceMock->expects($this->once())->method('warning');

        ($this->mock())($this->serverRequestStub);
    }


    public function testItAlwaysReturnsAccessControlAllowOrigin(): void
    {
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->responseHeaderBagMock->expects($this->once())
            ->method('set')
            ->with('Access-Control-Allow-Origin', '*');

        $this->mock()->authorization($this->symfonyRequestMock);
    }


    public static function redirectedErrorProvider(): array
    {
        return [
            // Factories rather than exceptions: the controller changes the exception it is given, and a data
            // set's object is shared by every run of it.
            'raised by the module' => [
                static fn(): OAuthServerException => OidcServerException::accessDenied(
                    'denied',
                    'https://rp.example.org/cb',
                    null,
                    'the-state',
                ),
            ],
            'raised by the league library' => [
                static fn(): OAuthServerException => OAuthServerException::accessDenied(
                    'denied',
                    'https://rp.example.org/cb',
                ),
            ],
        ];
    }


    /**
     * RFC 9207 section 2 has the iss parameter in error responses as well, so an error redirected back to the
     * client carries it next to what it had, whichever library raised it, and the redirect the error renders
     * to has it.
     *
     * @param \Closure(): \League\OAuth2\Server\Exception\OAuthServerException $makeException
     * @throws \Throwable
     */
    #[DataProvider('redirectedErrorProvider')]
    public function testAddsTheIssuerToAnErrorRedirectedBackToTheClient(Closure $makeException): void
    {
        $exception = $makeException();
        $this->moduleConfigStub->method('getIssuer')->willReturn(self::OIDC_OP_METADATA['issuer']);
        $this->authorizationServerStub->method('validateAuthorizationRequest')->willThrowException($exception);
        $expectedPayload = $exception->getPayload() + ['iss' => self::OIDC_OP_METADATA['issuer']];
        $this->captureTheErrorGivenToTheResponder();

        $response = $this->mock()->authorization($this->symfonyRequestMock);

        $this->assertSame($this->symfonyResponseMock, $response);
        $this->assertSame($expectedPayload, $this->errorGivenToTheResponder?->getPayload());

        $location = $exception->generateHttpResponse(new PsrResponse())->getHeaderLine('Location');
        parse_str((string)parse_url($location, PHP_URL_QUERY), $redirectedWith);
        $this->assertSame(self::OIDC_OP_METADATA['issuer'], $redirectedWith['iss'] ?? null);
    }


    /**
     * An error which is not redirected goes to the user agent rather than to the client, so it is no
     * authorization response and gets no issuer.
     *
     * @throws \Throwable
     */
    public function testLeavesAnErrorWhichIsNotRedirectedAsItIs(): void
    {
        $this->moduleConfigStub->method('getIssuer')->willReturn(self::OIDC_OP_METADATA['issuer']);
        $exception = OidcServerException::serverError('failure');
        $this->authorizationServerStub->method('validateAuthorizationRequest')->willThrowException($exception);
        $expectedPayload = $exception->getPayload();
        $this->captureTheErrorGivenToTheResponder();

        $this->mock()->authorization($this->symfonyRequestMock);

        $this->assertSame($expectedPayload, $this->errorGivenToTheResponder?->getPayload());
    }


    private function captureTheErrorGivenToTheResponder(): void
    {
        $this->errorResponderMock->expects($this->once())
            ->method('forException')
            ->willReturnCallback(function (OAuthServerException $error): Response {
                $this->errorGivenToTheResponder = $error;

                return $this->symfonyResponseMock;
            });
    }


    /**
     * @throws \Throwable
     */
    public function testSetsUiLanguageBasedOnUiLocalesOnInitialRequest(): void
    {
        $this->authorizationRequestMock->method('getUiLocales')->willReturn('hr en');
        $this->uiLocalesResolverStub->method('resolve')->willReturn('hr');

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub->method('getQueryParams')->willReturn([]);

        $this->authenticationServiceStub->method('manageState')->willReturn($this->state);
        $this->authenticationServiceStub->method('getAuthenticateUser')->willReturn($this->userEntityStub);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->sspBridgeLocaleLanguageMock->expects($this->once())
            ->method('setLanguageCookie')
            ->with('hr');

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * @throws \Throwable
     */
    public function testDoesNotSetUiLanguageWhenNoRequestedLanguageIsAvailable(): void
    {
        $this->authorizationRequestMock->method('getUiLocales')->willReturn('de');
        $this->uiLocalesResolverStub->method('resolve')->willReturn(null);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub->method('getQueryParams')->willReturn([]);

        $this->authenticationServiceStub->method('manageState')->willReturn($this->state);
        $this->authenticationServiceStub->method('getAuthenticateUser')->willReturn($this->userEntityStub);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->sspBridgeLocaleLanguageMock->expects($this->never())
            ->method('setLanguageCookie');

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * @throws \Throwable
     */
    public function testDoesNotOverrideExistingLanguageCookieWithUiLocales(): void
    {
        $this->authorizationRequestMock->method('getUiLocales')->willReturn('hr en');
        $this->uiLocalesResolverStub->method('resolve')->willReturn('hr');
        // An explicit language choice is already stored in the language cookie.
        $this->sspBridgeLocaleLanguageMock->method('getLanguageCookie')->willReturn('de');

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub->method('getQueryParams')->willReturn([]);

        $this->authenticationServiceStub->method('manageState')->willReturn($this->state);
        $this->authenticationServiceStub->method('getAuthenticateUser')->willReturn($this->userEntityStub);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->sspBridgeLocaleLanguageMock->expects($this->never())
            ->method('setLanguageCookie');

        ($this->mock())($this->serverRequestStub);
    }


    /**
     * When an id_token_hint is present and the authenticated End-User's subject matches it, the request proceeds.
     *
     * @throws \Throwable
     */
    public function testValidateIdTokenHintPassesOnSubjectMatch(): void
    {
        $this->authorizationRequestMock->method('getRequestedAcrValues')->willReturn(null);
        $this->authorizationRequestMock->method('getIdTokenHintSubject')->willReturn('subject-a');

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub->method('getQueryParams')->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')->willReturn($this->state);
        $this->authenticationServiceStub->method('getAuthenticateUser')->willReturn($this->userEntityStub);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);
        $this->authenticationServiceStub->method('subjectMatchesAttributes')->willReturn(true);

        $this->assertInstanceOf(ResponseInterface::class, ($this->mock())($this->serverRequestStub));
    }


    /**
     * When an id_token_hint is present but the authenticated End-User's subject differs from it, the request is
     * rejected with login_required rather than issued for a different user.
     *
     * @throws \Throwable
     */
    public function testValidateIdTokenHintThrowsLoginRequiredOnSubjectMismatch(): void
    {
        $clientStub = $this->createStub(ClientEntityInterface::class);
        $clientStub->method('getIdentifier')->willReturn('clientid');

        $this->authorizationRequestMock->method('getIdTokenHintSubject')->willReturn('subject-a');
        $this->authorizationRequestMock->method('getClient')->willReturn($clientStub);
        $this->authorizationRequestMock->method('getRedirectUri')->willReturn('https://rp.example.org/cb');

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);

        $this->serverRequestStub->method('getQueryParams')->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);
        $this->authenticationServiceStub->method('subjectMatchesAttributes')->willReturn(false);

        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('End-User is not already authenticated.');

        ($this->mock())($this->serverRequestStub);
    }
}
