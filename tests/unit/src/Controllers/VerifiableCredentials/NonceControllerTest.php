<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\NonceController;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\JsonResponse;

#[CoversClass(NonceController::class)]
class NonceControllerTest extends TestCase
{
    protected MockObject $nonceServiceMock;
    protected MockObject $routesMock;
    protected MockObject $loggerServiceMock;

    public function setUp(): void
    {
        $this->nonceServiceMock = $this->createMock(NonceService::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }

    /**
     * @throws \Exception
     */
    public function testNonce(): void
    {
        $this->nonceServiceMock->expects($this->once())
            ->method('generateNonce')
            ->willReturn('mocked_nonce');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['c_nonce' => 'mocked_nonce'], 200, ['Cache-Control' => 'no-store'])
            ->willReturn($responseMock);

        $sut = new NonceController($this->nonceServiceMock, $this->routesMock, $this->loggerServiceMock);
        $response = $sut->nonce();

        $this->assertSame($responseMock, $response);
    }
}
