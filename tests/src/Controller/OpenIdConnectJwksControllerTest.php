<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Controller\OpenIdConnectJwksController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\OpenIdConnectJwksController
 */
class OpenIdConnectJwksControllerTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $jsonWebKeySetServiceMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $serverRequestMock;

    protected function setUp(): void
    {
        $this->jsonWebKeySetServiceMock = $this->createMock(JsonWebKeySetService::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OpenIdConnectJwksController::class,
            new OpenIdConnectJwksController($this->jsonWebKeySetServiceMock)
        );
    }

    public function testItReturnsJsonKeys(): void
    {
        $keys = [
            0 => [
                'kty' => 'RSA',
                'n' => 'n',
                'e' => 'e',
                'use' => 'sig',
                'kid' => 'oidc',
                'alg' => 'RS256',
            ],
        ];

        $this->jsonWebKeySetServiceMock->expects($this->once())->method('keys')->willReturn($keys);

        $this->assertSame(
            ['keys' => $keys],
            (new OpenIdConnectJwksController($this->jsonWebKeySetServiceMock))
                ->__invoke($this->serverRequestMock)
                ->getPayload()
        );
    }
}
