<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\JwksController;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jwks\Factories\JwksDecoratorFactory;
use SimpleSAML\OpenID\Jwks\JwksDecorator;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\JwksController
 */
class JwksControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $jwks;
    protected MockObject $routesMock;
    protected MockObject $jwksDecoratorFactoryMock;
    protected MockObject $jwksDecoratorMock;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->jwks = $this->createMock(Jwks::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            fn (
                array|null $data = null,
                int $status = 200,
                array $headers = [],
                bool $json = false,
            ) => new JsonResponse($data, $status, $headers, $json),
        );

        $this->jwksDecoratorMock = $this->createMock(JwksDecorator::class);
        $this->jwksDecoratorFactoryMock = $this->createMock(JwksDecoratorFactory::class);
        $this->jwksDecoratorFactoryMock->method('fromJwkDecorators')->willReturn($this->jwksDecoratorMock);

        $this->jwks->method('jwksDecoratorFactory')->willReturn($this->jwksDecoratorFactoryMock);
    }

    protected function mock(
        ?ModuleConfig $moduleConfig = null,
        ?Jwks $jwks = null,
        ?Routes $routes = null,
    ): JwksController {
        $moduleConfig ??= $this->moduleConfigMock;
        $jwks ??= $this->jwks;
        $routes ??= $this->routesMock;

        return new JwksController(
            $moduleConfig,
            $jwks,
            $routes,
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
            json_decode((string) $this->mock()->__invoke()->getContent(), true),
        );
    }

    public function testItAlwaysReturnsAccessControlAllowOrigin(): void
    {
        $response = $this->mock()->jwks();
        $this->assertTrue($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
    }
}
