<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\AccessTokenController;
use SimpleSAML\Module\oidc\Controllers\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\AccessTokenController
 */
class AccessTokenControllerTest extends TestCase
{
    protected MockObject $authorizationServerMock;
    protected MockObject $allowedOriginRepository;
    protected MockObject $serverRequestMock;
    protected MockObject $responseMock;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $errorResponderMock;
    protected MockObject $requestFactoryMock;
    protected MockObject $responseFactoryMock;

    protected MockObject $symfonyRequestMock;

    protected MockObject $symfonyResponseMock;

    protected MockObject $httpFoundationFactoryMock;

    protected MockObject $responseHeaderBagMock;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->authorizationServerMock = $this->createMock(AuthorizationServer::class);
        $this->allowedOriginRepository = $this->createMock(AllowedOriginRepository::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->responseMock = $this->createMock(Response::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);

        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->responseFactoryMock = $this->createMock(ResponseFactoryInterface::class);
        $this->responseFactoryMock->method('createResponse')->willReturn($this->responseMock);
        $this->psrHttpBridgeMock->method('getResponseFactory')->willReturn($this->responseFactoryMock);

        $this->symfonyRequestMock = $this->createMock(Request::class);
        $this->symfonyResponseMock = $this->createMock(\Symfony\Component\HttpFoundation\Response::class);
        $this->responseHeaderBagMock = $this->createMock(ResponseHeaderBag::class);
        $this->symfonyResponseMock->headers = $this->responseHeaderBagMock;

        $this->httpFoundationFactoryMock = $this->createMock(HttpFoundationFactory::class);
        $this->httpFoundationFactoryMock->method('createResponse')->willReturn($this->symfonyResponseMock);
        $this->psrHttpBridgeMock->method('getHttpFoundationFactory')->willReturn($this->httpFoundationFactoryMock);
    }

    protected function mock(): AccessTokenController
    {
        return new AccessTokenController(
            $this->authorizationServerMock,
            $this->allowedOriginRepository,
            $this->psrHttpBridgeMock,
            $this->errorResponderMock,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AccessTokenController::class,
            $this->mock(),
        );
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testItRespondsToAccessTokenRequest(): void
    {
        $this->authorizationServerMock
            ->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->with($this->serverRequestMock, $this->isInstanceOf(ResponseInterface::class))
            ->willReturn($this->responseMock);

        $this->assertSame(
            $this->responseMock,
            $this->mock()->__invoke($this->serverRequestMock),
        );
    }

    public function testItHandlesCorsRequest(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('OPTIONS');
        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->with('Origin')
        ->willReturn('http://localhost');
        $this->allowedOriginRepository->expects($this->once())->method('has')
            ->with('http://localhost')
            ->willReturn(true);

        $this->responseMock->expects($this->atLeast(4))->method('withHeader')
            ->willReturnSelf();
        $this->responseMock->method('withBody')->willReturnSelf();

        $this->mock()->__invoke($this->serverRequestMock);
    }

    public function testItAlwaysReturnsAccessControlAllowOrigin(): void
    {
        $this->authorizationServerMock
            ->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->willReturn($this->responseMock);

        $this->responseHeaderBagMock->expects($this->once())
            ->method('set')
            ->with('Access-Control-Allow-Origin', '*');

        $this->mock()->token($this->symfonyRequestMock);
    }

    public function testItUsesRequestTrait(): void
    {
        $this->assertContains(RequestTrait::class, class_uses(AccessTokenController::class));
    }
}
