<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Traits;

use Exception;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use ReflectionMethod;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\Traits\RequestTrait
 */
class RequestTraitTest extends TestCase
{
    protected $mock;
    protected MockObject $serverRequestMock;
    protected MockObject $allowedOriginRepositoryMock;
    protected ReflectionMethod $handleCors;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $responseMock;
    protected MockObject $responseFactoryMock;


    public function setUp(): void
    {
        $this->allowedOriginRepositoryMock = $this->createMock(AllowedOriginRepository::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->responseMock = $this->createMock(Response::class);
        $this->responseMock->method('withBody')->willReturnSelf();
        $this->responseFactoryMock = $this->createMock(ResponseFactoryInterface::class);
        $this->responseFactoryMock->method('createResponse')->willReturn($this->responseMock);
        $this->psrHttpBridgeMock->method('getResponseFactory')->willReturn($this->responseFactoryMock);

        $this->mock = new class (
            $this->allowedOriginRepositoryMock,
            $this->psrHttpBridgeMock
        ) {
            use RequestTrait;

            public function __construct(
                public AllowedOriginRepository $allowedOriginRepository,
                public PsrHttpBridge $psrHttpBridge,
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
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testItThrowsIfOriginHeaderNotAvailable(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->willReturn('');

        $this->expectException(OidcServerException::class);
        $this->mock->handleCorsWrapper($this->serverRequestMock);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testItThrowsIfOriginHeaderNotAllowed(): void
    {
        $origin = 'https://example.org';

        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->willReturn($origin);
        $this->mock->allowedOriginRepository->expects($this->once())->method('has')->willReturn(false);

        $this->expectException(OidcServerException::class);
        $this->mock->handleCorsWrapper($this->serverRequestMock);
    }

    public function testItHandlesCorsRequest(): void
    {
        $origin = 'https://example.org';

        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->willReturn($origin);
        $this->mock->allowedOriginRepository->expects($this->once())->method('has')->willReturn(true);
        $this->responseFactoryMock->expects($this->once())->method('createResponse')
            ->with(204)
            ->willReturn($this->responseMock);

        $headers = [
            'Access-Control-Allow-Origin' => [$origin],
            'Access-Control-Allow-Methods' => ['GET, POST, OPTIONS'],
            'Access-Control-Allow-Headers' => ['Authorization, X-Requested-With'],
            'Access-Control-Allow-Credentials' => ['true'],
        ];

        $this->responseMock->expects($this->atLeast(4))->method('withHeader')
        ->with(
            $this->callback(
                // Check if parameter is one of the expected header keys.
                fn($header): bool => array_key_exists($header, $headers) ||
                    throw new Exception('Invalid header (' . $header . ')'),
            ),
            $this->callback(
                // Check if parameter is one of the expected header values.
                fn($value): bool => !empty(array_filter($headers, fn($values): bool => in_array($value, $values))) ||
                    throw new Exception('Invalid header value (' . $value . ')'),
            ),
        )->willReturnSelf();

        $this->mock->handleCorsWrapper($this->serverRequestMock);
    }
}
