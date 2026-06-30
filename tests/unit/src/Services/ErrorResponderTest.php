<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;

#[CoversClass(ErrorResponder::class)]
class ErrorResponderTest extends TestCase
{
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $loggerServiceMock;

    protected function setUp(): void
    {
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }

    protected function sut(): ErrorResponder
    {
        return new ErrorResponder($this->psrHttpBridgeMock, $this->loggerServiceMock);
    }

    public function testForExceptionJsonLogsClientErrorAsNotice(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('notice');
        $this->loggerServiceMock->expects($this->never())->method('warning');
        $this->loggerServiceMock->expects($this->never())->method('error');

        $response = $this->sut()->forExceptionJson(OidcServerException::invalidRequest('client_id'));

        $this->assertSame(400, $response->getStatusCode());
    }

    public function testForExceptionJsonLogsAccessDeniedAsWarning(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('warning');
        $this->loggerServiceMock->expects($this->never())->method('error');

        $response = $this->sut()->forExceptionJson(OidcServerException::accessDenied('nope'));

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testForExceptionJsonLogsServerErrorAsError(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('error');
        $this->loggerServiceMock->expects($this->never())->method('notice');

        $response = $this->sut()->forExceptionJson(OAuthServerException::serverError('boom'));

        $this->assertSame(500, $response->getStatusCode());
    }

    public function testForExceptionLogsUnexpectedThrowableAsError(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('error');

        $response = $this->sut()->forException(new RuntimeException('unexpected'));

        $this->assertSame(500, $response->getStatusCode());
    }
}
