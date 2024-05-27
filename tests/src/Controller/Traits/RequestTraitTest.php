<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller\Traits;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controller\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\Traits\RequestTrait
 */
class RequestTraitTest extends TestCase
{
    protected $prepareMockedInstance;
    protected MockObject $serverRequestMock;
    protected MockObject $allowedOriginRepositoryMock;
    protected ReflectionMethod $handleCors;


    public function setUp(): void
    {
        $this->allowedOriginRepositoryMock = $this->createMock(AllowedOriginRepository::class);
        $this->prepareMockedInstance = new class ($this->allowedOriginRepositoryMock) {
            use RequestTrait;

            public function __construct(
                public AllowedOriginRepository $allowedOriginRepository,
            ) {
            }

            public function handleCorsWrapper(ServerRequest $request): Response
            {
                return $this->handleCors($request);
            }
        };

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
    }

    /**
     * @throws OidcServerException
     */
    public function testItThrowsIfOriginHeaderNotAvailable(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->willReturn('');

        $this->expectException(OidcServerException::class);
        $this->prepareMockedInstance->handleCorsWrapper($this->serverRequestMock);
    }

    /**
     * @throws OidcServerException
     */
    public function testItThrowsIfOriginHeaderNotAllowed(): void
    {
        $origin = 'https://example.org';

        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->willReturn($origin);
        $this->prepareMockedInstance->allowedOriginRepository->expects($this->once())->method('has')->willReturn(false);

        $this->expectException(OidcServerException::class);
        $this->prepareMockedInstance->handleCorsWrapper($this->serverRequestMock);
    }

    public function testItHandlesCorsRequest(): void
    {
        $origin = 'https://example.org';

        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->willReturn($origin);
        $this->prepareMockedInstance->allowedOriginRepository->expects($this->once())->method('has')->willReturn(true);

        $response = $this->prepareMockedInstance->handleCorsWrapper($this->serverRequestMock);
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertSame(
            $response->getHeaders(),
            [
                'Access-Control-Allow-Origin' => [$origin],
                'Access-Control-Allow-Methods' => ['GET, POST, OPTIONS'],
                'Access-Control-Allow-Headers' => ['Authorization, X-Requested-With'],
                'Access-Control-Allow-Credentials' => ['true'],
            ],
        );
    }
}
