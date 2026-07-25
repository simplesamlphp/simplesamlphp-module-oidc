<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\LogoutHandlers;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\RequestOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
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
    /**
     * @var mixed
     */
    private MockObject $moduleConfigMock;

    private array $sampleRelyingPartyAssociation = [];

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->logoutTokenBuilderMock = $this->createMock(LogoutTokenBuilder::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getBackChannelLogoutHttpClientOptions')->willReturn([]);

        $this->sampleRelyingPartyAssociation[] = $this->getSampleRelyingPartyAssociation();
    }

    protected function mocked(): BackChannelLogoutHandler
    {
        return new BackChannelLogoutHandler(
            $this->logoutTokenBuilderMock,
            $this->loggerServiceMock,
            $this->moduleConfigMock,
        );
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

        $this->mocked()->handle($this->sampleRelyingPartyAssociation);
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

        $this->mocked()->handle($this->sampleRelyingPartyAssociation, $handlerStack);
    }

    /**
     * TLS verification must be on unless a deployment explicitly opts out, since the Logout Token carries the
     * 'sub' / 'sid' claims. Earlier versions disabled it unconditionally.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testVerifiesTlsAndAppliesTimeoutsByDefault(): void
    {
        $options = $this->captureRequestOptions();

        $this->assertTrue($options[RequestOptions::VERIFY]);
        $this->assertSame(3, $options[RequestOptions::CONNECT_TIMEOUT]);
        $this->assertSame(3, $options[RequestOptions::TIMEOUT]);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testConfiguredHttpClientOptionsOverrideDefaults(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getBackChannelLogoutHttpClientOptions')->willReturn([
            RequestOptions::VERIFY => false,
            RequestOptions::TIMEOUT => 10,
        ]);

        $options = $this->captureRequestOptions();

        $this->assertFalse($options[RequestOptions::VERIFY]);
        $this->assertSame(10, $options[RequestOptions::TIMEOUT]);
        // Not overridden, so the handler default stands.
        $this->assertSame(3, $options[RequestOptions::CONNECT_TIMEOUT]);
    }

    /**
     * Run a single Back-Channel Logout request through a mock handler and return the effective Guzzle options,
     * which are the client config merged into the per-request options.
     *
     * @return array<string,mixed>
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function captureRequestOptions(): array
    {
        $captured = [];

        $mockHandler = new MockHandler([
            function (RequestInterface $request, array $options) use (&$captured): Response {
                $captured = $options;
                return new Response(200);
            },
        ]);

        $this->mocked()->handle($this->sampleRelyingPartyAssociation, HandlerStack::create($mockHandler));

        return $captured;
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
