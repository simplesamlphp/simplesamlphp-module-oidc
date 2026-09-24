<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services\Introspection;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\RequestOptions;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\Introspection\UpstreamIntrospectionClient;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionUpstream;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Decorators\HttpClientDecorator;
use SimpleSAML\OpenID\Exceptions\DestinationPolicyException;
use SimpleSAML\OpenID\Factories\HttpClientDecoratorFactory;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Network\DestinationPolicy;

#[CoversClass(UpstreamIntrospectionClient::class)]
#[AllowMockObjectsWithoutExpectations]
class UpstreamIntrospectionClientTest extends TestCase
{
    protected const string TOKEN = 'header.payload.signature';


    protected MockObject $moduleConfigMock;

    protected MockObject $destinationPolicyFactoryMock;

    protected MockObject $httpClientDecoratorFactoryMock;

    protected DestinationPolicy $destinationPolicy;

    protected MockHandler $mockHandler;

    /** @var array<int, array{request: \Psr\Http\Message\RequestInterface, options: array}> */
    protected array $history = [];


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getProtocolHttpClientOptions')->willReturn([]);

        $this->destinationPolicy = new DestinationPolicy();
        $this->destinationPolicyFactoryMock = $this->createMock(DestinationPolicyFactory::class);
        $this->destinationPolicyFactoryMock->method('build')->willReturn($this->destinationPolicy);

        // The upstream, answering from a queue, and every request it was sent.
        $this->mockHandler = new MockHandler();
        $handlerStack = HandlerStack::create($this->mockHandler);
        $handlerStack->push(Middleware::history($this->history));

        $this->httpClientDecoratorFactoryMock = $this->createMock(HttpClientDecoratorFactory::class);
        $this->httpClientDecoratorFactoryMock->method('build')
            ->willReturn(new HttpClientDecorator(new Client(['handler' => $handlerStack])));
    }


    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?DestinationPolicyFactory $destinationPolicyFactory = null,
        ?HttpClientDecoratorFactory $httpClientDecoratorFactory = null,
    ): UpstreamIntrospectionClient {
        return new UpstreamIntrospectionClient(
            $moduleConfig ?? $this->moduleConfigMock,
            $destinationPolicyFactory ?? $this->destinationPolicyFactoryMock,
            $httpClientDecoratorFactory ?? $this->httpClientDecoratorFactoryMock,
            new Helpers(),
        );
    }


    protected function upstream(
        ClientAuthenticationMethodsEnum $method = ClientAuthenticationMethodsEnum::ClientSecretBasic,
        string $endpoint = 'https://hub.example.org/introspect',
    ): IntrospectionUpstream {
        return new IntrospectionUpstream(
            'https://hub.example.org/',
            $endpoint,
            'our client:id',
            'our/secret',
            $method,
            1.5,
            4.0,
        );
    }


    protected function sentRequest(int $index = 0): RequestInterface
    {
        $this->assertArrayHasKey($index, $this->history);

        return $this->history[$index]['request'];
    }


    /**
     * @return array<string, string>
     */
    protected function sentForm(int $index = 0): array
    {
        parse_str((string)$this->sentRequest($index)->getBody(), $form);

        /** @var array<string, string> $form */
        return $form;
    }


    /**
     * The request is this OP's own: the token, the caller's hint, and this OP's credentials in the Authorization
     * header, each form-urlencoded before they are joined (RFC 6749 section 2.3.1).
     */
    public function testAsksWithTheTokenTheHintAndItsOwnCredentialsInTheAuthorizationHeader(): void
    {
        $this->mockHandler->append(new Response(200, [], '{"active": true, "sub": "someone"}'));

        $answer = $this->sut()->introspect($this->upstream(), self::TOKEN, 'access_token');

        $this->assertSame(['active' => true, 'sub' => 'someone'], $answer);

        $request = $this->sentRequest();
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame('https://hub.example.org/introspect', (string)$request->getUri());
        $this->assertSame('application/json', $request->getHeaderLine('Accept'));
        $this->assertSame(
            'Basic ' . base64_encode('our+client%3Aid:our%2Fsecret'),
            $request->getHeaderLine('Authorization'),
        );
        $this->assertSame(['token' => self::TOKEN, 'token_type_hint' => 'access_token'], $this->sentForm());
    }


    public function testSendsItsCredentialsInTheBodyWhenConfiguredTo(): void
    {
        $this->mockHandler->append(new Response(200, [], '{"active": false}'));

        $this->sut()->introspect($this->upstream(ClientAuthenticationMethodsEnum::ClientSecretPost), self::TOKEN, null);

        $this->assertFalse($this->sentRequest()->hasHeader('Authorization'));
        $this->assertSame(
            ['token' => self::TOKEN, 'client_id' => 'our client:id', 'client_secret' => 'our/secret'],
            $this->sentForm(),
        );
    }


    /**
     * The client is built once per upstream, with the upstream's timeouts over the transport options of the
     * protocol HTTP client options, redirects off, the answer bounded, and the deployment's destination policy.
     * Nothing which would add to the request is taken over: credentials of any other kind would be sent along
     * with, or instead of, the upstream's.
     */
    public function testBuildsOneClientPerUpstreamOnTheDeploymentsPolicyAndTheUpstreamsTimeouts(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getProtocolHttpClientOptions')
            ->willReturn([
                'verify' => '/etc/ssl/hub-ca.pem',
                RequestOptions::PROXY => 'http://proxy.example.org:3128',
                RequestOptions::TIMEOUT => 60,
                RequestOptions::AUTH => ['global-user', 'global-secret'],
                RequestOptions::HEADERS => ['Authorization' => 'Bearer global-token'],
                RequestOptions::ALLOW_REDIRECTS => true,
                'curl' => [CURLOPT_USERPWD => 'global-user:global-secret'],
            ]);

        $this->httpClientDecoratorFactoryMock = $this->createMock(HttpClientDecoratorFactory::class);
        $this->httpClientDecoratorFactoryMock->expects($this->once())
            ->method('build')
            ->with(
                null,
                [
                    'verify' => '/etc/ssl/hub-ca.pem',
                    RequestOptions::PROXY => 'http://proxy.example.org:3128',
                    RequestOptions::CONNECT_TIMEOUT => 1.5,
                    RequestOptions::TIMEOUT => 4.0,
                    RequestOptions::ALLOW_REDIRECTS => false,
                ],
                UpstreamIntrospectionClient::MAX_RESPONSE_BYTES,
                $this->destinationPolicy,
            )
            ->willReturn(new HttpClientDecorator(new Client(['handler' => HandlerStack::create($this->mockHandler)])));

        $this->mockHandler->append(new Response(200, [], '{"active": false}'));
        $this->mockHandler->append(new Response(200, [], '{"active": false}'));

        $sut = $this->sut(moduleConfig: $moduleConfigMock);
        $sut->introspect($this->upstream(), self::TOKEN, null);
        $sut->introspect($this->upstream(), self::TOKEN, null);
    }


    public function testAnswersAnInactiveTokenWithNothingButThat(): void
    {
        $this->mockHandler->append(
            new Response(200, [], '{"active": false, "sub": "someone", "exp": "not even a number"}'),
        );

        $this->assertSame(['active' => false], $this->sut()->introspect($this->upstream(), self::TOKEN, null));
    }


    /**
     * A member keeps the shape the upstream gave it: an empty object is not an empty list, and an object with
     * numeric keys is not a list either.
     */
    public function testKeepsTheShapeOfTheMembersItPassesOn(): void
    {
        $body = '{"active":true,"address":{},"groups":[],"labels":{"0":"a","1":"b"},"nested":{"deeper":{"x":1}}}';
        $this->mockHandler->append(new Response(200, [], $body));

        $answer = $this->sut()->introspect($this->upstream(), self::TOKEN, null);

        $this->assertSame($body, json_encode($answer, JSON_THROW_ON_ERROR));
    }


    /**
     * The standard members are checked, and everything else the upstream says is passed on as it came.
     */
    public function testPassesAnActiveTokensAnswerOnAsItCame(): void
    {
        $body = [
            'active' => true,
            'scope' => 'openid profile',
            'client_id' => 'a-client-of-node-a',
            'token_type' => 'Bearer',
            'exp' => 1_900_000_000,
            'iat' => 1_899_999_000.5,
            'aud' => ['a', 'b'],
            'iss' => 'https://node-a.example.org',
            'jti' => 'jti-at-node-a',
            'eduperson_entitlement' => ['urn:example:entitlement'],
        ];
        $this->mockHandler->append(new Response(200, [], json_encode($body, JSON_THROW_ON_ERROR)));

        $this->assertSame($body, $this->sut()->introspect($this->upstream(), self::TOKEN, null));
    }


    public static function unusableAnswersProvider(): array
    {
        return [
            'not JSON' => ['<html>Service Unavailable</html>'],
            'empty' => [''],
            'a JSON list' => ['[true]'],
            'a JSON string' => ['"active"'],
            'no active member' => ['{"sub": "someone"}'],
            'an active member which is not a boolean' => ['{"active": "true"}'],
            'a scope which is not a string' => ['{"active": true, "scope": ["openid"]}'],
            'a subject which is not a string' => ['{"active": true, "sub": 42}'],
            'an issuer which is not a string' => ['{"active": true, "iss": null}'],
            'an expiry which is not a number' => ['{"active": true, "exp": "1900000000"}'],
            // Beyond what a PHP integer holds exactly, so it could not be read back as the time it names.
            'an expiry which is not a usable NumericDate' => ['{"active": true, "exp": 1e100}'],
            'an audience list with an object in it' => ['{"active": true, "aud": ["a", {"b": "c"}]}'],
            'an audience list with a number in it' => ['{"active": true, "aud": ["a", 1]}'],
            'an audience which is an object' => ['{"active": true, "aud": {"a": "b"}}'],
            'an audience which is an object with numeric keys' => ['{"active": true, "aud": {"0": "rs1"}}'],
            'a number too large to pass on' => ['{"active": true, "custom": 1e400}'],
            'nested past the depth limit' => [
                '{"active": true, "x": ' . str_repeat('[', 64) . str_repeat(']', 64) . '}',
            ],
        ];
    }


    /**
     * An answer which is not an introspection response is no answer at all, and certainly not a verdict.
     */
    #[DataProvider('unusableAnswersProvider')]
    public function testRefusesAnAnswerWhichIsNotAnIntrospectionResponse(string $body): void
    {
        $this->mockHandler->append(new Response(200, [], $body));

        try {
            $this->sut()->introspect($this->upstream(), self::TOKEN, null);
            $this->fail('An unusable answer was accepted.');
        } catch (UpstreamIntrospectionException $exception) {
            $this->assertFalse($exception->isOwnFault());
            $this->assertStringContainsString('unusable response', $exception->getMessage());
        }
    }


    public static function refusedCredentialsProvider(): array
    {
        return [[401], [403]];
    }


    /**
     * The upstream refusing this OP's credentials is this deployment's fault, which no retry will cure.
     */
    #[DataProvider('refusedCredentialsProvider')]
    public function testReportsRefusedCredentialsAsItsOwnFault(int $status): void
    {
        $this->mockHandler->append(new Response($status, [], '{"error": "invalid_client"}'));

        try {
            $this->sut()->introspect($this->upstream(), self::TOKEN, null);
            $this->fail('A refusal was accepted.');
        } catch (UpstreamIntrospectionException $exception) {
            $this->assertTrue($exception->isOwnFault());
            $this->assertStringContainsString(sprintf('(HTTP %d)', $status), $exception->getMessage());
        }
    }


    public static function unavailableUpstreamProvider(): array
    {
        return [
            'a server error' => [new Response(503)],
            'throttled' => [new Response(429, ['Retry-After' => '30'])],
            'a bad request' => [new Response(400, [], '{"error": "invalid_request"}')],
            // Not followed: a redirect is not an answer.
            'a redirect' => [new Response(302, ['Location' => 'https://elsewhere.example.org/introspect'])],
            'no connection' => [
                new ConnectException('Connection timed out', new Request('POST', 'https://hub.example.org/introspect')),
            ],
            'an answer past the size limit' => [
                new Response(200, [], '{"active": true, "x": "' .
                    str_repeat('a', UpstreamIntrospectionClient::MAX_RESPONSE_BYTES) . '"}'),
            ],
        ];
    }


    #[DataProvider('unavailableUpstreamProvider')]
    public function testReportsAnUpstreamWhichGaveNoAnswerAsUnavailable(Response|ConnectException $outcome): void
    {
        $this->mockHandler->append($outcome);

        try {
            $this->sut()->introspect($this->upstream(), self::TOKEN, null);
            $this->fail('No answer was taken for one.');
        } catch (UpstreamIntrospectionException $exception) {
            $this->assertFalse($exception->isOwnFault());
            $this->assertStringContainsString('No answer from the introspection endpoint', $exception->getMessage());
        }

        $this->assertCount(1, $this->history);
    }


    /**
     * The destination policy is the deployment's own, so its refusal is too. Built with the library's real factory:
     * a loopback endpoint is refused before anything is sent.
     */
    public function testReportsTheDestinationPolicyRefusingTheEndpointAsItsOwnFault(): void
    {
        $sut = $this->sut(httpClientDecoratorFactory: new HttpClientDecoratorFactory());

        try {
            $sut->introspect(
                $this->upstream(endpoint: 'https://127.0.0.1/introspect'),
                self::TOKEN,
                null,
            );
            $this->fail('A refused destination was reached.');
        } catch (UpstreamIntrospectionException $exception) {
            $this->assertTrue($exception->isOwnFault());
            $this->assertInstanceOf(DestinationPolicyException::class, $exception->getPrevious());
        }
    }


    public function testReportsAClientWhichCanNotBeBuiltAsItsOwnFault(): void
    {
        $this->destinationPolicyFactoryMock = $this->createMock(DestinationPolicyFactory::class);
        $this->destinationPolicyFactoryMock->method('build')
            ->willThrowException(new ConfigurationError('Unusable outbound allowed CIDR.'));

        try {
            $this->sut()->introspect($this->upstream(), self::TOKEN, null);
            $this->fail('A client was built from an unusable configuration.');
        } catch (UpstreamIntrospectionException $exception) {
            $this->assertTrue($exception->isOwnFault());
            $this->assertInstanceOf(ConfigurationError::class, $exception->getPrevious());
        }
    }
}
