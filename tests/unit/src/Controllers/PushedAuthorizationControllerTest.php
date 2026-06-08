<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\PushedAuthorizationController;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Core;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\PushedAuthorizationController
 */
class PushedAuthorizationControllerTest extends TestCase
{
    protected MockObject $authenticatedOAuth2ClientResolverMock;
    protected MockObject $pushedAuthorizationRequestRepositoryMock;
    protected MockObject $requestRulesManagerMock;
    protected MockObject $jwksResolverMock;
    protected MockObject $coreMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $errorResponderMock;
    protected Helpers $helpers;
    protected MockObject $loggerMock;

    protected MockObject $serverRequestMock;
    protected MockObject $responseMock;
    protected MockObject $responseFactoryMock;
    protected MockObject $streamMock;

    protected function setUp(): void
    {
        $this->authenticatedOAuth2ClientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->pushedAuthorizationRequestRepositoryMock = $this->createMock(
            PushedAuthorizationRequestRepository::class,
        );
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->jwksResolverMock = $this->createMock(JwksResolver::class);
        $this->coreMock = $this->createMock(Core::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);
        $this->helpers = new Helpers();
        $this->loggerMock = $this->createMock(LoggerService::class);

        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
        $this->responseMock = $this->createMock(ResponseInterface::class);
        $this->responseFactoryMock = $this->createMock(ResponseFactoryInterface::class);
        $this->streamMock = $this->createMock(StreamInterface::class);

        $this->responseMock->method('getBody')->willReturn($this->streamMock);
        $this->responseMock->method('withStatus')->willReturn($this->responseMock);
        $this->responseMock->method('withHeader')->willReturn($this->responseMock);
        $this->responseFactoryMock->method('createResponse')->willReturn($this->responseMock);
        $this->psrHttpBridgeMock->method('getResponseFactory')->willReturn($this->responseFactoryMock);
    }

    protected function sut(): PushedAuthorizationController
    {
        return new PushedAuthorizationController(
            $this->authenticatedOAuth2ClientResolverMock,
            $this->pushedAuthorizationRequestRepositoryMock,
            $this->requestRulesManagerMock,
            $this->jwksResolverMock,
            $this->coreMock,
            $this->moduleConfigMock,
            $this->psrHttpBridgeMock,
            $this->errorResponderMock,
            $this->helpers,
            $this->loggerMock,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(PushedAuthorizationController::class, $this->sut());
    }

    public function testMethodMustBePost(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('GET');

        $this->responseMock->expects($this->once())->method('withStatus')
            ->with(405)->willReturn($this->responseMock);
        $this->responseMock->expects($this->once())->method('withHeader')
            ->with('Allow', 'POST')->willReturn($this->responseMock);

        $response = $this->sut()->__invoke($this->serverRequestMock);
        $this->assertSame($this->responseMock, $response);
    }

    public function testClientAuthenticationFailureThrows(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }

    public function testRejectsRequestUriInBody(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');

        $clientMock = $this->createMock(ClientEntityInterface::class);
        $resolvedAuth = new ResolvedClientAuthenticationMethod(
            $clientMock,
            ClientAuthenticationMethodsEnum::ClientSecretPost,
        );
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($resolvedAuth);

        $this->serverRequestMock->method('getParsedBody')->willReturn([
            'request_uri' => 'some-uri',
        ]);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }

    public function testHandlesValidParRequest(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');

        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn('client123');

        $resolvedAuth = new ResolvedClientAuthenticationMethod(
            $clientMock,
            ClientAuthenticationMethodsEnum::ClientSecretPost,
        );
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn($resolvedAuth);

        $params = [
            'redirect_uri' => 'https://localhost/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'xyz',
        ];
        $this->serverRequestMock->method('getParsedBody')->willReturn($params);

        $this->serverRequestMock->method('withParsedBody')->willReturn($this->serverRequestMock);
        $this->serverRequestMock->method('withQueryParams')->willReturn($this->serverRequestMock);

        $this->moduleConfigMock->method('getParRequestUriTtl')->willReturn(new \DateInterval('PT10M'));

        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())->method('persist');

        $this->responseMock->expects($this->once())->method('withStatus')
            ->with(201)->willReturn($this->responseMock);

        $response = $this->sut()->__invoke($this->serverRequestMock);
        $this->assertSame($this->responseMock, $response);
    }
}
