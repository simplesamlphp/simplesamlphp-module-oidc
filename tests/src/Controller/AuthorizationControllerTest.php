<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Error;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Controller\AuthorizationController;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\AuthorizationController
 */
class AuthorizationControllerTest extends TestCase
{
    protected Stub $authenticationServiceStub;
    protected Stub $authorizationServerStub;
    protected Stub $moduleConfigStub;
    protected MockObject $loggerServiceMock;
    protected MockObject $authorizationRequestMock;
    protected Stub $userEntityStub;
    protected Stub $serverRequestStub;
    protected Stub $responseStub;

    protected static string $sampleAuthSourceId = 'authSource123';

    protected static array $sampleAuthSourcesToAcrValuesMap = ['authSource123' => ['1', '0']];

    protected static array $sampleRequestedAcrs = ['values' => ['1', '0'], 'essential' => false];

    /**
     * @throws Exception
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
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
     */
    public function testReturnsResponseWhenInvoked(): void
    {
        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->authenticationServiceStub->method('getAuthenticateUser')->willReturn($this->userEntityStub);

        $controller = new AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->moduleConfigStub,
            $this->loggerServiceMock
        );

        $this->assertInstanceOf(ResponseInterface::class, $controller($this->serverRequestStub));
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
     */
    public function testValidateAcrThrowsIfAuthSourceIdNotSetInAuthorizationRequest(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);

        $this->expectException(OidcServerException::class);

        (new AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->moduleConfigStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
     */
    public function testValidateAcrThrowsIfCookieBasedAuthnNotSetInAuthorizationRequest(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);

        $this->expectException(OidcServerException::class);

        (new AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->moduleConfigStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
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

        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('0');

        (new AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->moduleConfigStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
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

        $this->expectException(OidcServerException::class);

        (new AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->moduleConfigStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
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

        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('1');

        (new AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->moduleConfigStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
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

        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('1');

        (new AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->moduleConfigStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
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

        $this->authorizationRequestMock->expects($this->once())->method('setAcr');
        $this->loggerServiceMock->expects($this->once())->method('warning');

        (new AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->moduleConfigStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }
}
