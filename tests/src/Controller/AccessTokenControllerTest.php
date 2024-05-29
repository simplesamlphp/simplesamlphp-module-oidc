<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controller\AccessTokenController;
use SimpleSAML\Module\oidc\Controller\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Controller\UserInfoController;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;

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
     * @throws \Exception
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
                $this->allowedOriginRepository,
            ),
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
            ->with($this->serverRequestMock, $this->isInstanceOf(Response::class))
            ->willReturn($this->responseMock);

        $this->assertSame(
            $this->responseMock,
            (new AccessTokenController(
                $this->authorizationServerMock,
                $this->allowedOriginRepository,
            ))->__invoke($this->serverRequestMock),
        );
    }

    public function testItHandlesCorsRequest(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('OPTIONS');
        $userInfoControllerMock = $this->getMockBuilder(UserInfoController::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['handleCors'])
            ->getMock();
        $userInfoControllerMock->expects($this->once())->method('handleCors');

        $userInfoControllerMock->__invoke($this->serverRequestMock);
    }

    /**
     * @return \SimpleSAML\Module\oidc\Controller\AccessTokenController
     */
    protected function prepareMockedInstance(): AccessTokenController
    {
        return new AccessTokenController($this->authorizationServerMock, $this->allowedOriginRepository);
    }

    public function testItUsesRequestTrait(): void
    {
        $this->assertContains(RequestTrait::class, class_uses(AccessTokenController::class));
    }
}
