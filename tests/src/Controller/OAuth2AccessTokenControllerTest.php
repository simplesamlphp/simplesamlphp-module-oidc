<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Controller\OAuth2AccessTokenController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\OAuth2AccessTokenController
 */
class OAuth2AccessTokenControllerTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $authorizationServerMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $serverRequestMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $responseMock;

    protected function setUp(): void
    {
        $this->authorizationServerMock = $this->createMock(AuthorizationServer::class);

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->responseMock = $this->createMock(Response::class);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OAuth2AccessTokenController::class,
            new OAuth2AccessTokenController($this->authorizationServerMock)
        );
    }

    public function testItRespondsToAccessTokenRequest(): void
    {
        $this->authorizationServerMock
            ->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->with($this->serverRequestMock, $this->isInstanceOf(Response::class))
            ->willReturn($this->responseMock);

        $this->assertSame(
            $this->responseMock,
            (new OAuth2AccessTokenController($this->authorizationServerMock))->__invoke($this->serverRequestMock)
        );
    }
}
