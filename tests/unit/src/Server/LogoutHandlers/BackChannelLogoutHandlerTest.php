<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\LogoutHandlers;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\LogoutHandlers\BackChannelLogoutHandler;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;

/**
 * @covers \SimpleSAML\Module\oidc\Server\LogoutHandlers\BackChannelLogoutHandler
 */
class BackChannelLogoutHandlerTest extends TestCase
{
    /**
     * @var mixed
     */
    private MockObject $logoutTokenBuilderMock;
    /**
     * @var mixed
     */
    private MockObject $loggerServiceMock;

    private array $sampleRelyingPartyAssociation = [];

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->logoutTokenBuilderMock = $this->createMock(LogoutTokenBuilder::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->sampleRelyingPartyAssociation[] = $this->getSampleRelyingPartyAssociation();
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testLogsErrorForInvalidUri(): void
    {
        $this->loggerServiceMock
            ->expects($this->once())
            ->method('error')
            ->with($this->stringContains('error'));

        $handler = new BackChannelLogoutHandler($this->logoutTokenBuilderMock, $this->loggerServiceMock);

        $handler->handle($this->sampleRelyingPartyAssociation);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testLogsNoticeForSuccessfulResponse(): void
    {
        $mockHandler = new MockHandler([
            new Response(200),
        ]);

        $handlerStack = HandlerStack::create($mockHandler);

        $this->loggerServiceMock
            ->expects($this->exactly(2))
            ->method('notice');

        $handler = new BackChannelLogoutHandler($this->logoutTokenBuilderMock, $this->loggerServiceMock);

        $handler->handle($this->sampleRelyingPartyAssociation, $handlerStack);
    }

    protected function getSampleRelyingPartyAssociation(
        ?string $clientId = null,
        ?string $userId = null,
        ?string $sessionId = null,
        ?string $backChannelLogoutUri = null,
    ): RelyingPartyAssociation {
        $id = substr((string) hrtime(true), -4);

        return new RelyingPartyAssociation(
            $clientId ?? 'client' . $id,
            $userId ?? 'user' . $id,
            $sessionId ?? 'session' . $id,
            $backChannelLogoutUri ?? 'https://example.org/logout/' . $id,
        );
    }
}
