<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\UserNotFound;
use SimpleSAML\Module\oidc\Controller\AccessTokenController;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\AccessTokenController
 */
class AccessTokenControllerTest extends TestCase
{
    protected MockObject $authorizationServerMock;
    protected MockObject $allowedOriginRepository;
    protected MockObject $serverRequestMock;
    protected MockObject $responseMock;

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->authorizationServerMock = $this->createMock(AuthorizationServer::class);
        $this->allowedOriginRepository = $this->createMock(AllowedOriginRepository::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->responseMock = $this->createMock(Response::class);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AccessTokenController::class,
            new AccessTokenController(
                $this->authorizationServerMock,
                $this->allowedOriginRepository
            )
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
            (new AccessTokenController(
                $this->authorizationServerMock,
                $this->allowedOriginRepository
            ))->__invoke($this->serverRequestMock)
        );
    }

    /**
     * @throws OAuthServerException
     */
    public function testItThrowsIfOriginHeaderNotAvailable(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('OPTIONS');
        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->willReturn('');

        $this->expectException(OidcServerException::class);
        $this->prepareMockedInstance()->__invoke($this->serverRequestMock);
    }

    /**
     * @return AccessTokenController
     */
    protected function prepareMockedInstance(): AccessTokenController
    {
        return new AccessTokenController($this->authorizationServerMock, $this->allowedOriginRepository);
    }
}
