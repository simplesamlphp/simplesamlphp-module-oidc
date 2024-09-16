<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controller;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controller\JwksController;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\JwksController
 */
class JwksControllerTest extends TestCase
{
    protected MockObject $jsonWebKeySetServiceMock;
    protected MockObject $serverRequestMock;
    protected MockObject $psrHttpBridge;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->jsonWebKeySetServiceMock = $this->createMock(JsonWebKeySetService::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->psrHttpBridge = $this->createMock(PsrHttpBridge::class);
    }

    protected function mock(): JwksController
    {
        return new JwksController(
            $this->jsonWebKeySetServiceMock,
            $this->psrHttpBridge,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            JwksController::class,
            $this->mock(),
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

        $this->jsonWebKeySetServiceMock->expects($this->once())->method('protocolKeys')->willReturn($keys);

        $this->assertSame(
            ['keys' => $keys],
            $this->mock()->__invoke()->getPayload(),
        );
    }
}
