<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\LogoutHandlers;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Handler\StreamHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\Utils;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use ReflectionProperty;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\LogoutHandlers\BackChannelLogoutHandler;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;
use SimpleSAML\OpenID\Exceptions\DestinationPolicyException;
use SimpleSAML\OpenID\Network\AddressPinner;
use SimpleSAML\OpenID\Network\DestinationGuardMiddleware;
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
     * A request which fails is reported on its own, by index, with the failure's code, message and type.
     * The failure is the handler's here; an earlier version of this test sent the request to example.org
     * for real and relied on what came back.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testLogsAnErrorForARequestWhichFails(): void
    {
        $mockHandler = new MockHandler([
            fn(RequestInterface $request): ConnectException => new ConnectException('Connection refused', $request),
        ]);

        $this->loggerServiceMock
            ->expects($this->once())
            ->method('error')
            ->with(
                'Backchannel Logout (index 0) - error, reason: 0 Connection refused, exception type: ' .
                ConnectException::class,
            );

        $this->mocked()->handle($this->sampleRelyingPartyAssociation, HandlerStack::create($mockHandler));
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
            ->with($this->matchesRegularExpression($this->refusalReportPattern()));

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
     * A deployment can configure a bare handler callable rather than a stack. There is nothing to push the
     * guard onto, so the handler is wrapped in it instead, and the wrapped one is what the requests go
     * through: the configured handler is kept, which is what this proves; that the wrapping guards is the
     * next test's.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testKeepsABareHandlerSuppliedThroughTheConfiguredClientOptions(): void
    {
        $reached = false;

        $configuredHandler = new MockHandler([
            function () use (&$reached): Response {
                $reached = true;
                return new Response(200);
            },
        ]);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getBackChannelLogoutHttpClientOptions')
            ->willReturn(['handler' => $configuredHandler]);

        $this->loggerServiceMock->expects($this->never())->method('warning');
        $this->loggerServiceMock->expects($this->never())->method('error');

        $this->mocked()->handle($this->sampleRelyingPartyAssociation);

        $this->assertTrue($reached, 'The configured handler was replaced rather than wrapped.');
    }


    /**
     * The wrapping is the guard: a destination the policy forbids is refused before the bare handler, as it
     * is before a stack.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testGuardsABareHandlerSuppliedThroughTheConfiguredClientOptions(): void
    {
        $this->destinationPolicy = new DestinationPolicy();

        $association = $this->getSampleRelyingPartyAssociation(
            backChannelLogoutUri: 'https://127.0.0.1/logout',
        );

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getBackChannelLogoutHttpClientOptions')->willReturn([
            'handler' => new MockHandler([
                fn(): Response => $this->fail('The request reached the handler, so the guard was not applied.'),
            ]),
        ]);

        $this->loggerServiceMock
            ->expects($this->once())
            ->method('error')
            ->with($this->matchesRegularExpression($this->refusalReportPattern()));

        $this->mocked()->handle([$association]);
    }


    /**
     * Guzzle refuses a handler which is not callable when the client is built, so this is reached only
     * through a client which answers otherwise for its handler. What is pinned is what the handler does
     * with one: it says so rather than throwing, and hands the client back as it was, unguarded.
     *
     * @throws \Exception
     */
    public function testWarnsWhenTheGuardCanBeNeitherPushedNorWrapped(): void
    {
        $client = $this->createMock(Client::class);
        $client->method('getConfig')->with('handler')->willReturn('not a handler');

        $this->loggerServiceMock->expects($this->once())->method('warning')->with(
            'The outbound destination policy could not be attached to the Back-Channel Logout HTTP client, ' .
            'because its handler is neither a handler stack nor callable. Logout requests are not ' .
            'restricted to permitted destinations.',
        );

        $sut = new class (
            $this->logoutTokenBuilderMock,
            $this->loggerServiceMock,
            $this->moduleConfigMock,
            $this->destinationPolicy,
        ) extends BackChannelLogoutHandler {
            /**
             * @param array<string,mixed> $clientConfig
             * @throws \Exception
             */
            public function exposedGuarded(Client $client, array $clientConfig, bool $hasSuppliedTransport): Client
            {
                return $this->guarded($client, $clientConfig, $hasSuppliedTransport);
            }
        };

        $this->assertSame($client, $sut->exposedGuarded($client, [], false));
    }


    /**
     * The transports the handler can establish nothing about: handed to handle(), configured as a stack or
     * as a bare handler, or built by Guzzle on one of the four options which take part in its choice of
     * handler.
     *
     * @return array<string, array{0: array<string,mixed>, 1: ?\GuzzleHttp\HandlerStack}>
     */
    public static function transportNotEstablishedHereProvider(): array
    {
        return [
            'a stack handed to handle()' => [[], HandlerStack::create(new MockHandler())],
            'a stack from the client options' => [['handler' => HandlerStack::create(new MockHandler())], null],
            'a bare handler from the client options' => [['handler' => new MockHandler()], null],
            'a handler-selection option, Guzzle building the stack' => [['max_host_connections' => 4], null],
        ];
    }


    /**
     * Nothing is established about a transport the handler did not choose, so the guard is told it cannot
     * pin: a pin claimed on a transport which ignores the cURL option would be a guarantee never made. The
     * same for a stack Guzzle builds on an option which takes part in its choice of handler, since that
     * choice cannot be reproduced here.
     *
     * @param array<string,mixed> $clientOptions
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    #[DataProvider('transportNotEstablishedHereProvider')]
    public function testClaimsNoPinForATransportItDidNotEstablish(
        array $clientOptions,
        ?HandlerStack $handlerStack,
    ): void {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getBackChannelLogoutHttpClientOptions')->willReturn($clientOptions);

        $this->assertFalse($this->handlerIsCurl($this->capturePinner($handlerStack)));
    }


    /**
     * For a stack Guzzle builds with nothing steering its choice, the guard is told which handler Guzzle
     * chose for this system: cURL wherever the extension is loaded and usable, which is what allows a pin.
     * Asked of Guzzle here as the handler asks it, since the answer is the system's rather than the test's.
     * On a system with neither cURL nor allow_url_fopen Guzzle answers with an exception instead, which the
     * handler reads as no pin; such a system cannot run this suite, so that reading stays unpinned.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testTellsTheGuardWhichHandlerGuzzleChoseForAStackItBuilt(): void
    {
        $this->assertSame(
            !Utils::chooseHandler() instanceof StreamHandler,
            $this->handlerIsCurl($this->capturePinner(null)),
        );
    }


    /**
     * The requests are prepared as the pool draws them, so a logout token which cannot be built surfaces
     * from the pool's promise rather than from any one request. It is reported as such, once the request
     * was announced, and the client whose token it was gets no request.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testLogsAPromiseErrorWhenALogoutTokenCannotBeBuilt(): void
    {
        $exception = OAuthServerException::serverError('The signing key is unreadable.');
        $this->logoutTokenBuilderMock->method('forRelyingPartyAssociation')->willThrowException($exception);

        $mockHandler = new MockHandler([
            fn(): Response => $this->fail('A request was sent although its logout token could not be built.'),
        ]);

        $this->loggerServiceMock->expects($this->once())->method('notice')->with(
            'Backhannel Logout (index 0) - preparing request to: ' .
            $this->sampleRelyingPartyAssociation[0]->getBackChannelLogoutUri(),
        );
        $this->loggerServiceMock->expects($this->once())->method('error')
            ->with('Back-channel Logout promise error: ' . $exception->getMessage());

        $this->mocked()->handle($this->sampleRelyingPartyAssociation, HandlerStack::create($mockHandler));
    }


    /**
     * The report of the first request refused by the policy, pinned in what the handler contributes, the
     * index, the code and the exception type, around a message which is the library's to word.
     */
    protected function refusalReportPattern(): string
    {
        $exceptionType = preg_quote(DestinationPolicyException::class, '/');

        return '/^Backchannel Logout \(index 0\) - error, reason: 0 .+, exception type: ' . $exceptionType . '$/';
    }


    /**
     * Run a logout with no associations, so nothing is sent, through a policy which records the pinner the
     * handler asks its middleware for.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function capturePinner(?HandlerStack $handlerStack): AddressPinner
    {
        $captured = null;
        $realPolicy = $this->destinationPolicy;

        $policyMock = $this->createMock(DestinationPolicy::class);
        $policyMock->expects($this->once())->method('middleware')->willReturnCallback(
            function (?AddressPinner $addressPinner) use (&$captured, $realPolicy): DestinationGuardMiddleware {
                $captured = $addressPinner;
                return $realPolicy->middleware($addressPinner);
            },
        );
        $this->destinationPolicy = $policyMock;

        $this->mocked()->handle([], $handlerStack);

        $this->assertInstanceOf(AddressPinner::class, $captured, 'The middleware was asked for with no pinner.');

        return $captured;
    }


    /**
     * What the pinner was told about the handler; the only thing it holds, and what its own answer on
     * whether a request can be pinned is derived from, together with facts about the system.
     */
    protected function handlerIsCurl(AddressPinner $addressPinner): bool
    {
        return (bool)(new ReflectionProperty(AddressPinner::class, 'handlerIsCurl'))->getValue($addressPinner);
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
