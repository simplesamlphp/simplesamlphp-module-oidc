<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\JwksController;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jwks\Factories\JwksDecoratorFactory;
use SimpleSAML\OpenID\Jwks\JwksDecorator;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\JwksController
 */
class JwksControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $jwks;
    protected MockObject $serverRequestMock;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $symfonyResponseMock;
    protected MockObject $responseHeaderBagMock;
    protected MockObject $httpFoundationFactoryMock;
    protected MockObject $jwksDecoratorFactoryMock;
    protected MockObject $jwksDecoratorMock;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->jwks = $this->createMock(Jwks::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);

        $this->symfonyResponseMock = $this->createMock(\Symfony\Component\HttpFoundation\Response::class);
        $this->responseHeaderBagMock = $this->createMock(ResponseHeaderBag::class);
        $this->symfonyResponseMock->headers = $this->responseHeaderBagMock;

        $this->httpFoundationFactoryMock = $this->createMock(HttpFoundationFactory::class);
        $this->httpFoundationFactoryMock->method('createResponse')->willReturn($this->symfonyResponseMock);
        $this->psrHttpBridgeMock->method('getHttpFoundationFactory')->willReturn($this->httpFoundationFactoryMock);

        $this->jwksDecoratorMock = $this->createMock(JwksDecorator::class);
        $this->jwksDecoratorFactoryMock = $this->createMock(JwksDecoratorFactory::class);
        $this->jwksDecoratorFactoryMock->method('fromJwkDecorators')->willReturn($this->jwksDecoratorMock);

        $this->jwks->method('jwksDecoratorFactory')->willReturn($this->jwksDecoratorFactoryMock);
    }

    protected function mock(
        ?PsrHttpBridge $psrHttpBridge = null,
        ?ModuleConfig $moduleConfig = null,
        ?Jwks $jwks = null,
    ): JwksController {
        $psrHttpBridge ??= $this->psrHttpBridgeMock;
        $moduleConfig ??= $this->moduleConfigMock;
        $jwks ??= $this->jwks;

        return new JwksController(
            $psrHttpBridge,
            $moduleConfig,
            $jwks,
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
            'keys' => [
                'kty' => 'RSA',
                'n' => 'n',
                'e' => 'e',
                'use' => 'sig',
                'kid' => 'oidc',
                'alg' => 'RS256',
            ],
        ];

        $this->jwksDecoratorMock->expects($this->once())->method('jsonSerialize')->willReturn($keys);

        $this->assertSame(
            $keys,
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
