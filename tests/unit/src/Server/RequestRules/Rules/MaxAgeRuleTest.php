<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils as SspBridgeUtils;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\LoginHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Utils\HTTP as SspHttp;

#[CoversClass(MaxAgeRule::class)]
#[AllowMockObjectsWithoutExpectations]
class MaxAgeRuleTest extends TestCase
{
    protected MockObject $requestParamsResolverMock;

    protected MockObject $authSimpleFactoryMock;

    protected MockObject $authenticationServiceMock;

    protected MockObject $sspBridgeMock;

    protected MockObject $authSimpleMock;

    protected MockObject $clientMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $requestMock;

    protected MockObject $responseModeMock;

    protected ResultBag $resultBag;


    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->authSimpleFactoryMock = $this->createMock(AuthSimpleFactory::class);
        $this->authenticationServiceMock = $this->createMock(AuthenticationService::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->authSimpleMock = $this->createMock(Simple::class);
        $this->clientMock = $this->createMock(ClientEntityInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->responseModeMock = $this->createMock(ResponseModeInterface::class);

        $this->authSimpleFactoryMock->method('build')->willReturn($this->authSimpleMock);

        $this->resultBag = new ResultBag();
        $this->resultBag->add(new Result(ClientRule::class, $this->clientMock));
    }


    protected function sut(): MaxAgeRule
    {
        return new MaxAgeRule(
            $this->requestParamsResolverMock,
            new Helpers(),
            $this->authSimpleFactoryMock,
            $this->authenticationServiceMock,
            $this->sspBridgeMock,
        );
    }


    protected function checkRule(): ?Result
    {
        return $this->sut()->checkRule(
            $this->requestMock,
            $this->resultBag,
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
    }


    public function testReturnsNullWhenNoMaxAgeNoDefaultAndNoRequireAuthTime(): void
    {
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')->willReturn([]);
        $this->clientMock->method('getDefaultMaxAge')->willReturn(null);
        $this->clientMock->method('getRequireAuthTime')->willReturn(false);

        $this->assertNull($this->checkRule());
    }


    public function testRequireAuthTimeReturnsAuthInstantWithoutMaxAge(): void
    {
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')->willReturn([]);
        $this->clientMock->method('getDefaultMaxAge')->willReturn(null);
        $this->clientMock->method('getRequireAuthTime')->willReturn(true);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);
        $this->authSimpleMock->method('getAuthData')->willReturn(1000);
        // No re-authentication must happen when there is no effective max_age.
        $this->authenticationServiceMock->expects($this->never())->method('authenticateForClient');

        $result = $this->checkRule();

        $this->assertSame(1000, $result?->getValue());
    }


    public function testDefaultMaxAgeNotExpiredReturnsAuthInstant(): void
    {
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')->willReturn([]);
        $this->clientMock->method('getDefaultMaxAge')->willReturn(3600);
        $this->clientMock->method('getRequireAuthTime')->willReturn(false);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);
        $this->authSimpleMock->method('getAuthData')->willReturn(time() - 10);
        $this->authenticationServiceMock->expects($this->never())->method('authenticateForClient');

        $this->assertNotNull($this->checkRule());
    }


    public function testExpiredMaxAgeReAuthenticatesAndPropagatesLoginHint(): void
    {
        $this->resultBag->add(new Result(ClientRedirectUriRule::class, 'https://rp.example.org/cb'));
        $this->resultBag->add(new Result(StateRule::class, 'state123'));
        $this->resultBag->add(new Result(LoginHintRule::class, 'user@example.org'));
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->willReturn(['max_age' => 0, 'login_hint' => 'user@example.org']);
        $this->clientMock->method('getRequireAuthTime')->willReturn(false);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);
        // Authenticated well before the (zero) max_age window, so re-authentication is enforced.
        $this->authSimpleMock->method('getAuthData')->willReturn(time() - 3600);

        $httpMock = $this->createMock(SspHttp::class);
        $httpMock->method('getSelfURLNoQuery')->willReturn('https://op.example.org/authorize');
        $httpMock->method('addURLParameters')->willReturn('https://op.example.org/authorize?max_age=0');
        $utilsMock = $this->createMock(SspBridgeUtils::class);
        $utilsMock->method('http')->willReturn($httpMock);
        $this->sspBridgeMock->method('utils')->willReturn($utilsMock);

        $this->authenticationServiceMock->expects($this->once())
            ->method('authenticateForClient')
            ->with(
                $this->clientMock,
                $this->callback(fn(array $loginParams): bool =>
                    ($loginParams['core:username'] ?? null) === 'user@example.org'),
            );

        $this->checkRule();
    }


    /**
     * @return array<string,array{0:mixed}>
     */
    public static function unusableMaxAgeProvider(): array
    {
        return [
            'a word' => ['abc'],
            'a negative number of seconds' => ['-1'],
            'a fraction' => ['1.5'],
            'an empty value' => [''],
            // filter_var() reads no leading zeros, so a zero-padded number of seconds is refused as well.
            'a zero-padded number of seconds' => ['08'],
            'more seconds than an integer holds' => ['999999999999999999999999'],
            // `?max_age[]=10` arrives as an array, which filter_var() refuses rather than casting.
            'an array, as a repeated query param arrives' => [['10']],
            // Params from a Request Object are merged in as they are decoded
            // (`RequestParamsResolver::getAllBasedOnAllowedMethods()`), so a JSON null can arrive here.
            'null, as a Request Object claim can be' => [null],
        ];
    }


    /**
     * `max_age` is a number of seconds (OpenID Connect Core 1.0, section 3.1.2.1), and the rule refuses a
     * value which is not one rather than casting it. A cast would not fail, which is the point: `(int)`
     * gives 0 for `abc`, 1 for `1.5` and 1 for `['10']`, windows which force re-authentication for any
     * session older than a second -- a request the client did not make, answered as if it had.
     */
    #[DataProvider('unusableMaxAgeProvider')]
    public function testRefusesAMaxAgeWhichIsNotANonNegativeInteger(mixed $maxAge): void
    {
        $this->resultBag->add(new Result(ClientRedirectUriRule::class, 'https://rp.example.org/cb'));
        $this->resultBag->add(new Result(StateRule::class, 'state123'));
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->willReturn(['max_age' => $maxAge]);
        $this->clientMock->method('getIdentifier')->willReturn('client123');
        $this->loggerServiceMock->expects($this->once())
            ->method('notice')
            ->with(
                'Authorization request rejected: `max_age` is not a valid non-negative integer.',
                ['client_id' => 'client123'],
            );
        // The refusal comes before anything reads the session, so nothing is re-authenticated.
        $this->authSimpleMock->expects($this->never())->method('isAuthenticated');
        $this->authenticationServiceMock->expects($this->never())->method('authenticateForClient');

        try {
            $this->checkRule();
            $this->fail('A max_age of ' . var_export($maxAge, true) . ' must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame('max_age must be a valid integer', $exception->getHint());
            $this->assertSame('https://rp.example.org/cb', $exception->getRedirectUri());
            $payload = $exception->getPayload();
            $this->assertSame('invalid_request', $payload['error']);
            $this->assertStringEndsWith('(max_age must be a valid integer)', (string)$payload['error_description']);
            $this->assertSame('state123', $payload['state']);
        }
    }


    /**
     * @return array<string,array{0:mixed}>
     */
    public static function usableMaxAgeProvider(): array
    {
        return [
            'zero, which asks for re-authentication now' => ['0'],
            'a number of seconds' => ['3600'],
            // filter_var() trims surrounding whitespace, so this is 10 seconds and not a refusal.
            'a number of seconds with surrounding whitespace' => [' 10 '],
            // filter_var(true, FILTER_VALIDATE_INT) is 1, so a Request Object claim of `true` passes the
            // guard as a one-second window. Pinned as it stands; section 13 of the todo has it.
            'true, which filter_var() reads as 1' => [true],
        ];
    }


    /**
     * The other half of the guard: a `max_age` which `filter_var()` accepts must not be refused. Zero is a
     * legitimate value (re-authenticate now), so a guard which refused it would be as wrong as one which let
     * `abc` through. The session is unauthenticated here, so the rule returns before the clock is consulted
     * and the test says nothing about which window has passed -- `testExpiredMaxAge...` pins that half.
     */
    #[DataProvider('usableMaxAgeProvider')]
    public function testAcceptsAMaxAgeWhichIsANonNegativeInteger(mixed $maxAge): void
    {
        $this->resultBag->add(new Result(ClientRedirectUriRule::class, 'https://rp.example.org/cb'));
        $this->resultBag->add(new Result(StateRule::class, 'state123'));
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->willReturn(['max_age' => $maxAge]);
        $this->clientMock->method('getRequireAuthTime')->willReturn(false);
        // Reaching the session at all means the guard let the value through: a refusal throws before this.
        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(false);
        $this->loggerServiceMock->expects($this->never())->method('notice');
        $this->authenticationServiceMock->expects($this->never())->method('authenticateForClient');

        $this->assertNull($this->checkRule());
    }
}
