<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\JwksController;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\JwksController
 */
class JwksControllerTest extends TestCase
{
    protected MockObject $jsonWebKeySetServiceMock;
    protected MockObject $serverRequestMock;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $symfonyResponseMock;
    protected MockObject $responseHeaderBagMock;
    protected MockObject $httpFoundationFactoryMock;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->jsonWebKeySetServiceMock = $this->createMock(JsonWebKeySetService::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);

        $this->symfonyResponseMock = $this->createMock(\Symfony\Component\HttpFoundation\Response::class);
        $this->responseHeaderBagMock = $this->createMock(ResponseHeaderBag::class);
        $this->symfonyResponseMock->headers = $this->responseHeaderBagMock;

        $this->httpFoundationFactoryMock = $this->createMock(HttpFoundationFactory::class);
        $this->httpFoundationFactoryMock->method('createResponse')->willReturn($this->symfonyResponseMock);
        $this->psrHttpBridgeMock->method('getHttpFoundationFactory')->willReturn($this->httpFoundationFactoryMock);
    }

    protected function mock(
        ?JsonWebKeySetService $jsonWebKeySetService = null,
        ?PsrHttpBridge $psrHttpBridge = null,
    ): JwksController {
        $jsonWebKeySetService ??= $this->jsonWebKeySetServiceMock;
        $psrHttpBridge ??= $this->psrHttpBridgeMock;

        return new JwksController(
            $jsonWebKeySetService,
            $psrHttpBridge,
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

    public function testItAlwaysReturnsAccessControlAllowOrigin(): void
    {
        $this->responseHeaderBagMock->expects($this->once())->method('set')
            ->with('Access-Control-Allow-Origin', '*');

        $this->mock()->jwks();
    }
}
