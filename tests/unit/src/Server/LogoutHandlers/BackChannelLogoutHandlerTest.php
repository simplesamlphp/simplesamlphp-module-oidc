<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\LogoutHandlers;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\RequestOptions;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\LogoutHandlers\BackChannelLogoutHandler;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;
use SimpleSAML\OpenID\Exceptions\DestinationPolicyException;
use SimpleSAML\OpenID\Network\DestinationPolicy;

/**
 * @covers \SimpleSAML\Module\oidc\Server\LogoutHandlers\BackChannelLogoutHandler
 */
#[AllowMockObjectsWithoutExpectations]
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

    /**
     * A real policy rather than a mock, with the sample logout host exempted. An allow-listed host skips
     * both the address check and the pinning, so these tests resolve nothing and reach the network for
     * nothing, while still running through the middleware the handler actually installs.
     */
    private DestinationPolicy $destinationPolicy;

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

        $this->destinationPolicy = new DestinationPolicy(allowedHosts: ['example.org']);

        $this->sampleRelyingPartyAssociation[] = $this->getSampleRelyingPartyAssociation();
    }


    protected function mocked(): BackChannelLogoutHandler
    {
        return new BackChannelLogoutHandler(
            $this->logoutTokenBuilderMock,
            $this->loggerServiceMock,
            $this->moduleConfigMock,
            $this->destinationPolicy,
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
     * A logout URI is registered by the client, so this client fetches a destination the deployment did not
     * choose and has to be guarded like any other. It is built here rather than by the openid library, so
     * the guard is attached by hand and could be left off without anything else noticing.
     *
     * The stack a caller supplies has to be guarded too: if only the stack built internally were, every test
     * here would exercise an unguarded path and the guard could be removed with the suite still green.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testRefusesToSendLogoutToADestinationThePolicyForbids(): void
    {
        // Nothing is exempted, so the loopback address in the logout URI is refused on its own, with no
        // name to resolve and nothing sent.
        $this->destinationPolicy = new DestinationPolicy();

        $association = $this->getSampleRelyingPartyAssociation(
            backChannelLogoutUri: 'https://127.0.0.1/logout',
        );

        $mockHandler = new MockHandler([
            fn(): Response => $this->fail('The request reached the handler, so the guard was not applied.'),
        ]);

        // The pool turns a rejection into a logged error rather than letting it out, so the refusal shows
        // up as a failed logout for that client, naming the policy exception that caused it.
        $this->loggerServiceMock
            ->expects($this->once())
            ->method('error')
            ->with($this->stringContains(DestinationPolicyException::class));

        $this->mocked()->handle([$association], HandlerStack::create($mockHandler));
    }


    /**
     * A deployment can configure its own handler through the client options. Attaching the guard must not
     * cost it that handler, which an earlier version did by assigning over it.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testKeepsAHandlerSuppliedThroughTheConfiguredClientOptions(): void
    {
        $reached = false;

        $configuredHandler = new MockHandler([
            function () use (&$reached): Response {
                $reached = true;
                return new Response(200);
            },
        ]);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getBackChannelLogoutHttpClientOptions')->willReturn([
            'handler' => HandlerStack::create($configuredHandler),
        ]);

        $this->mocked()->handle($this->sampleRelyingPartyAssociation);

        $this->assertTrue($reached, 'The configured handler was replaced rather than guarded.');
    }


    /**
     * A configured stack outlives the call that used it, so the guard has to be replaced rather than added
     * to. Otherwise the nth logout runs n policy checks, each with its own DNS lookup, on a stack that
     * never stops growing.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testDoesNotAccumulateGuardsOnAStackReusedAcrossCalls(): void
    {
        $handlerStack = HandlerStack::create(new MockHandler([
            new Response(200),
            new Response(200),
            new Response(200),
        ]));

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getBackChannelLogoutHttpClientOptions')
            ->willReturn(['handler' => $handlerStack]);

        // HandlerStack::__toString() renders the stack twice, once in each direction, so every entry is
        // named twice in it.
        $countGuards = fn(): int => intdiv(
            substr_count((string)$handlerStack, "Name: 'oidc_destination_guard'"),
            2,
        );

        $this->mocked()->handle($this->sampleRelyingPartyAssociation);
        $afterFirst = $countGuards();

        $this->mocked()->handle($this->sampleRelyingPartyAssociation);
        $this->mocked()->handle($this->sampleRelyingPartyAssociation);

        $this->assertSame(1, $afterFirst);
        $this->assertSame($afterFirst, $countGuards(), 'The stack gained a guard per call.');
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
