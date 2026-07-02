<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Controllers\AuthorizationController;
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
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\AuthorizationController
 */
class AuthorizationControllerTest extends TestCase
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

    protected Stub $authenticationServiceStub;
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

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->authenticationServiceStub = $this->createStub(AuthenticationService::class);
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
        $this->sspBridgeLocaleMock = $this->createMock(SspBridge\Locale::class);
        $this->sspBridgeLocaleLanguageMock = $this->createMock(SspBridge\Locale\Language::class);
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
        $this->symfonyResponseMock = $this->createMock(\Symfony\Component\HttpFoundation\Response::class);
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
}
