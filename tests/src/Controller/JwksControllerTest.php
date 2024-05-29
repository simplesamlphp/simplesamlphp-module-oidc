<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controller\JwksController;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\JwksController
 */
class JwksControllerTest extends TestCase
{
    protected MockObject $jsonWebKeySetServiceMock;
    protected MockObject $serverRequestMock;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->jsonWebKeySetServiceMock = $this->createMock(JsonWebKeySetService::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            JwksController::class,
            new JwksController($this->jsonWebKeySetServiceMock),
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
            (new JwksController($this->jsonWebKeySetServiceMock))->__invoke()->getPayload(),
        );
    }
}
