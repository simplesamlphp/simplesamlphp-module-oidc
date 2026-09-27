<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\RequestObject;
use SimpleSAML\OpenID\Jar\RequestObject as JarRequestObject;
use SimpleSAML\OpenID\RequestObject\RequestObjectBag;
use Stringable;

#[CoversClass(RequestObjectRule::class)]
#[AllowMockObjectsWithoutExpectations]
class RequestObjectRuleTest extends TestCase
{
    protected MockObject $clientStub;

    protected Stub $resultBagStub;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $requestObjectMock;

    protected MockObject $jarRequestObjectMock;

    protected MockObject $requestObjectBagMock;

    protected Stub $requestStub;

    protected LoggerService&MockObject $loggerServiceMock;

    /** @var array<int,array{level:string,message:string,context:array}> */
    protected array $logRecords = [];

    protected MockObject $jwksResolverMock;

    protected Helpers $helpers;

    protected Stub $responseModeStub;

    protected Stub $moduleConfigStub;


    protected function setUp(): void
    {
        $this->clientStub = $this->createMock(ClientEntityInterface::class);
        $this->clientStub->method('getIdentifier')->willReturn('client123');
        $this->resultBagStub = $this->createStub(ResultBag::class);
        $this->resultBagStub->method('getOrFail')->willReturnMap([
            [ClientRule::class, new Result(ClientRule::class, $this->clientStub)],
            [ClientRedirectUriRule::class, new Result(ClientRedirectUriRule::class, 'https://example.com/redirect')],
        ]);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->requestObjectMock = $this->createMock(RequestObject::class);
        $this->requestObjectMock->method('getPayload')->willReturn(['payload']);
        $this->jarRequestObjectMock = $this->createMock(JarRequestObject::class);
        $this->jarRequestObjectMock->method('getPayload')->willReturn(['payload']);
        $this->requestObjectBagMock = $this->createMock(RequestObjectBag::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        foreach (['debug', 'info', 'notice', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []) use ($level): void {
                    $this->logRecords[] = [
                        'level' => $level,
                        'message' => (string)$message,
                        'context' => $context,
                    ];
                },
            );
        }
        $this->jwksResolverMock = $this->createMock(JwksResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?JwksResolver $jwksResolver = null,
        ?ModuleConfig $moduleConfig = null,
    ): RequestObjectRule {
        $requestParamsResolver ??= $this->requestParamsResolverMock;
        $helpers ??= $this->helpers;
        $jwksResolver ??= $this->jwksResolverMock;
        $moduleConfig ??= $this->moduleConfigStub;

        return new RequestObjectRule(
            $requestParamsResolver,
            $helpers,
            $jwksResolver,
            $moduleConfig,
        );
    }


    /**
     * The records of one level, so that a test pins the event it is about without being coupled to the
     * rule's entry trace.
     *
     * @return array<int,array{message:string,context:array}>
     */
    protected function logRecordsOfLevel(string $level): array
    {
        return array_values(array_map(
            static fn(array $record): array => ['message' => $record['message'], 'context' => $record['context']],
            array_filter($this->logRecords, static fn(array $record): bool => $record['level'] === $level),
        ));
    }


    protected function prepareOidcRequest(?RequestObject $requestObject = null): void
    {
        // A `request` param signals a Request Object is present (by value).
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        // OpenID Connect request is designated by the openid scope.
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')->willReturn('openid');
        $this->requestObjectBagMock->method('get')
            ->willReturnMap([
                [RequestObject::class, $requestObject ?? $this->requestObjectMock],
            ]);
        $this->requestParamsResolverMock->method('getRequestObjectBag')
            ->willReturn($this->requestObjectBagMock);
    }


    protected function prepareOAuth2Request(?JarRequestObject $jarRequestObject = null): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        // No openid scope, so this is a plain OAuth 2.0 request (JAR rules apply).
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')->willReturn('profile');
        $this->requestObjectBagMock->method('get')
            ->willReturnMap([
                [RequestObject::class, $this->requestObjectMock],
                [JarRequestObject::class, $jarRequestObject],
            ]);
        $this->requestParamsResolverMock->method('getRequestObjectBag')
            ->willReturn($this->requestObjectBagMock);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RequestObjectRule::class, $this->sut());
    }


    public function testRequestParamCanBeAbsent(): void
    {
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
        $this->assertNull($result);
    }


    /**
     * ClientRule resolves a client from a Request Object when a request registers automatically in OpenID
     * Federation, and adds that object's payload to the result bag under this rule's key
     * (`ClientRule::resolveFromFederation()`, line 387). The rule must not parse the same request a second
     * time then: the bag is filled as that flow leaves it, source param included, and nothing is asked of
     * the parser.
     */
    public function testSkipsARequestObjectWhichHasAlreadyBeenResolved(): void
    {
        // A `request` param is present, so there is a Request Object source for the rule to find.
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturnCallback(
            fn(string $paramKey): ?string => $paramKey === ParamsEnum::Request->value ? 'not-a-jwt' : null,
        );
        $this->requestParamsResolverMock->expects($this->never())->method('getRequestObjectBag');

        // Federation's automatic registration leaves the client in the bag as well, so a rule which did not
        // skip would get as far as parsing rather than failing on a missing dependency.
        $resultBag = new ResultBag();
        $resultBag->add(new Result(RequestObjectRule::class, ['iss' => 'client123', 'scope' => 'openid']));
        $resultBag->add(new Result(ClientRule::class, $this->clientStub));
        $resultBag->add(new Result(ClientRedirectUriRule::class, 'https://example.com/redirect'));

        $this->assertNull(
            $this->sut()->checkRule(
                $this->requestStub,
                $resultBag,
                $this->loggerServiceMock,
                [],
                $this->responseModeStub,
            ),
        );
        $this->assertContains(
            'Request object has already been resolved, skipping rule ' . RequestObjectRule::class,
            array_column($this->logRecordsOfLevel('debug'), 'message'),
        );
    }


    public function testThrowsWhenRequestObjectSourceIsPresentButBagCannotBeResolved(): void
    {
        // `request` param present (source present), but the resolver could not parse/fetch it (null bag).
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        $this->requestParamsResolverMock->method('getRequestObjectBag')->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    /**
     * @return array<string,array{0:?string}>
     */
    public static function refusedRequestStateProvider(): array
    {
        return [
            'the state the client sent comes back with the refusal' => ['state123'],
            'a request which sent no state is refused without one' => [null],
        ];
    }


    /**
     * A `request` param which no flavour can parse leaves the bag empty rather than absent:
     * `RequestObjectParser::fromToken()` swallows each factory's failure and returns the bag it has built,
     * so it is this rule which decides what an empty one means. An OpenID Connect authorization request is
     * judged by the OpenID Connect Core flavour, and without it there is nothing to judge.
     */
    #[DataProvider('refusedRequestStateProvider')]
    public function testRefusesAnOidcRequestWhoseRequestObjectIsNotAnOidcOne(?string $state): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturnCallback(
            fn(string $paramKey): ?string => $paramKey === ParamsEnum::Request->value ? 'not-a-jwt' : null,
        );
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')->willReturnCallback(
            fn(string $paramKey): ?string => $paramKey === ParamsEnum::Scope->value ? 'openid' : null,
        );
        // The real bag, empty, as the parser returns it when no factory could read the token.
        $this->requestParamsResolverMock->method('getRequestObjectBag')->willReturn(new RequestObjectBag());

        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $this->clientStub));
        $resultBag->add(new Result(ClientRedirectUriRule::class, 'https://example.com/redirect'));
        if ($state !== null) {
            $resultBag->add(new Result(StateRule::class, $state));
        }

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $resultBag,
                $this->loggerServiceMock,
                [],
                $this->responseModeStub,
            );
            $this->fail('A request object which is not an OpenID Connect one must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame('Request object is not a valid Request Object.', $exception->getHint());
            $this->assertSame('https://example.com/redirect', $exception->getRedirectUri());
            // The refusal is a redirect back to the client, so what it sent has to come back with it.
            if ($state === null) {
                $this->assertArrayNotHasKey('state', $exception->getPayload());
            } else {
                $this->assertSame($state, $exception->getPayload()['state']);
            }
        }

        $this->assertSame(
            [
                [
                    'message' => 'Authorization request rejected: request object is not a valid OpenID Connect ' .
                        'Request Object.',
                    'context' => ['client_id' => 'client123'],
                ],
            ],
            $this->logRecordsOfLevel('notice'),
        );
    }


    public function testUnprotectedRequestParamCanBeUsedForOidcRequest(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
        $this->assertInstanceOf(Result::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertNotEmpty($result->getValue());
    }


    public function testMissingClientJwksThrows(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->jwksResolverMock->expects($this->once())->method('forClient')
            ->with($this->clientStub)->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testThrowsForInvalidRequestObject(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->requestObjectMock->expects($this->once())->method('verifyWithKeySet')->with(['jwks'])
        ->willThrowException(OidcServerException::accessDenied());
        $this->jwksResolverMock->expects($this->once())->method('forClient')
            ->with($this->clientStub)
            ->willReturn(['jwks']);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testReturnsValidRequestObject(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->requestObjectMock->expects($this->once())->method('verifyWithKeySet')->with(['jwks']);

        $this->jwksResolverMock->expects($this->once())
            ->method('forClient')
            ->with($this->clientStub)
            ->willReturn(['jwks']);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertNotEmpty($result->getValue());
    }


    public function testThrowsWhenGlobalRequireSignedRequestObjectIsEnabled(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);

        $this->moduleConfigStub->method('getRequireSignedRequestObject')->willReturn(true);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testThrowsWhenClientRequireSignedRequestObjectIsEnabled(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);

        $this->moduleConfigStub->method('getRequireSignedRequestObject')->willReturn(false);
        $this->clientStub->method('getRequireSignedRequestObject')->willReturn(true);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testAcceptsOidcRequestWhenAudienceIncludesIssuer(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->requestObjectMock->method('getAudience')->willReturn(['https://op.example.org/']);
        $this->moduleConfigStub->method('getIssuer')->willReturn('https://op.example.org/');

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
    }


    public function testThrowsForOidcRequestWhenAudienceDoesNotIncludeIssuer(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->requestObjectMock->method('getAudience')->willReturn(['https://other-op.example.org/']);
        $this->moduleConfigStub->method('getIssuer')->willReturn('https://op.example.org/');

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testThrowsForOAuth2RequestWhenAudienceDoesNotIncludeIssuer(): void
    {
        $this->jarRequestObjectMock->method('getClientId')->willReturn('client123');
        $this->jarRequestObjectMock->method('verifyWithKeySet')->with(['jwks']);
        $this->jarRequestObjectMock->method('getAudience')->willReturn(['https://other-op.example.org/']);
        $this->prepareOAuth2Request($this->jarRequestObjectMock);

        $this->jwksResolverMock->method('forClient')->with($this->clientStub)->willReturn(['jwks']);
        $this->moduleConfigStub->method('getIssuer')->willReturn('https://op.example.org/');

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testAcceptsOidcRequestWhenIssuerMatchesClient(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->requestObjectMock->method('getIssuer')->willReturn('client123');

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
    }


    public function testThrowsForOidcRequestWhenIssuerDoesNotMatchClient(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->requestObjectMock->method('getIssuer')->willReturn('otherClient');

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testThrowsForOAuth2RequestWhenIssuerDoesNotMatchClient(): void
    {
        $this->jarRequestObjectMock->method('getClientId')->willReturn('client123');
        $this->jarRequestObjectMock->method('verifyWithKeySet')->with(['jwks']);
        $this->jarRequestObjectMock->method('getIssuer')->willReturn('otherClient');
        $this->prepareOAuth2Request($this->jarRequestObjectMock);

        $this->jwksResolverMock->method('forClient')->with($this->clientStub)->willReturn(['jwks']);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testThrowsForOAuth2RequestWithNonJarRequestObject(): void
    {
        // For example, an unsigned Request Object is not a valid JAR Request Object.
        $this->prepareOAuth2Request(null);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testThrowsForOAuth2RequestWithMismatchedClientIdClaim(): void
    {
        $this->jarRequestObjectMock->method('getClientId')->willReturn('otherClient');
        $this->prepareOAuth2Request($this->jarRequestObjectMock);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }


    public function testReturnsValidJarRequestObjectForOAuth2Request(): void
    {
        $this->jarRequestObjectMock->method('getClientId')->willReturn('client123');
        $this->jarRequestObjectMock->expects($this->once())->method('verifyWithKeySet')->with(['jwks']);
        $this->prepareOAuth2Request($this->jarRequestObjectMock);

        $this->jwksResolverMock->expects($this->once())
            ->method('forClient')
            ->with($this->clientStub)
            ->willReturn(['jwks']);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertNotEmpty($result->getValue());
    }


    protected static function unsignedRequestObject(array $header, array $payload): string
    {
        $segment = fn(array $data): string => rtrim(
            strtr(base64_encode(json_encode((object)$data, JSON_THROW_ON_ERROR)), '+/', '-_'),
            '=',
        );

        return $segment($header) . '.' . $segment($payload) . '.';
    }


    public static function unusableRequestObjectProvider(): array
    {
        return [
            // RFC 7519 section 4.1.1: 'iss' is a string.
            'an issuer which is a number' => [['alg' => 'none'], ['iss' => 42], 'issuer (iss)'],
            'an issuer which is true' => [['alg' => 'none'], ['iss' => true], 'issuer (iss)'],
            // RFC 7519 section 4.1.3: 'aud' is a string or an array of strings.
            'an audience which is a number' => [['alg' => 'none'], ['aud' => 42], 'audience (aud)'],
            // RFC 7515 section 4.1.1: 'alg' is a string, and REQUIRED.
            'an algorithm which is a number' => [['alg' => 42], ['iss' => 'client123'], 'algorithm (alg)'],
            'no algorithm' => [[], ['iss' => 'client123'], 'algorithm (alg)'],
            'an algorithm the library does not know' => [['alg' => 'XS256'], ['iss' => 'client123'], 'algorithm (alg)'],
        ];
    }


    /**
     * The library reads these members of a Request Object which parses only when they are asked for. A value it
     * can not use is the client's error, answered as an invalid request, and not a failure of the OP.
     */
    #[DataProvider('unusableRequestObjectProvider')]
    public function testRefusesARequestObjectWithAnUnusableMemberAsAnInvalidRequest(
        array $header,
        array $payload,
        string $member,
    ): void {
        $this->prepareOidcRequest(
            (new Core())->requestObjectFactory()->fromToken(self::unsignedRequestObject($header, $payload)),
        );

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $this->resultBagStub,
                $this->loggerServiceMock,
                [],
                $this->responseModeStub,
            );
            $this->fail('A Request Object whose ' . $member . ' is unusable must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertStringContainsString($member, (string)$exception->getHint());
        }
    }
}
