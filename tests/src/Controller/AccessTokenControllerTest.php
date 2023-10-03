<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller;

use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Controller\AccessTokenController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\AccessTokenController
 */
class AccessTokenControllerTest extends TestCase
{
    protected MockObject $authorizationServerMock;
    protected MockObject $serverRequestMock;
    protected MockObject $responseMock;

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->authorizationServerMock = $this->createMock(AuthorizationServer::class);

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->responseMock = $this->createMock(Response::class);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AccessTokenController::class,
            new AccessTokenController($this->authorizationServerMock)
        );
    }

    /**
     * @throws OAuthServerException
     */
    public function testItRespondsToAccessTokenRequest(): void
    {
        $this->authorizationServerMock
            ->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->with($this->serverRequestMock, $this->isInstanceOf(Response::class))
            ->willReturn($this->responseMock);

        $this->assertSame(
            $this->responseMock,
            (new AccessTokenController($this->authorizationServerMock))->__invoke($this->serverRequestMock)
        );
    }
}
