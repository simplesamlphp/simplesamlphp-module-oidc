<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\OAuth2;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\OAuth2\OAuth2ServerConfigurationController;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\OAuth2\OAuth2ServerConfigurationController
 */
#[AllowMockObjectsWithoutExpectations]
class OAuth2ServerConfigurationControllerTest extends TestCase
{
    final public const array OIDC_OP_METADATA = [
        'issuer' => 'http://localhost',
        'authorization_endpoint' => 'http://localhost/authorization',
        'token_endpoint' => 'http://localhost/token',
        'introspection_endpoint' => 'http://localhost/api/oauth2/token-introspection',
    ];


    protected MockObject $opMetadataServiceMock;

    protected MockObject $routesMock;


    protected function setUp(): void
    {
        $this->opMetadataServiceMock = $this->createMock(OpMetadataService::class);
        $this->routesMock = $this->createMock(Routes::class);

        $this->opMetadataServiceMock->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);
    }


    protected function mock(
        ?OpMetadataService $opMetadataService = null,
        ?Routes $routes = null,
    ): OAuth2ServerConfigurationController {
        return new OAuth2ServerConfigurationController(
            $opMetadataService ?? $this->opMetadataServiceMock,
            $routes ?? $this->routesMock,
        );
    }


    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OAuth2ServerConfigurationController::class,
            $this->mock(),
        );
    }


    /**
     * The introspection endpoint is advertised by OpMetadataService, so that the OpenID Connect discovery
     * document carries it as well; this controller must not add or alter anything, and answers with the CORS
     * header that document answers with.
     */
    public function testItServesTheOpMetadataAsIs(): void
    {
        $jsonResponseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(self::OIDC_OP_METADATA, 200, ['Access-Control-Allow-Origin' => '*'])
            ->willReturn($jsonResponseMock);

        $this->assertSame($jsonResponseMock, $this->mock()->__invoke());
    }
}
