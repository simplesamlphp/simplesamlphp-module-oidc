<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * The rule that decides which client a request claims to be from.
 *
 * It is the first link in the chain -- every later rule resolves the client from what this returns -- so
 * the two places a client_id may arrive from, and the refusal when it arrives from neither, are what
 * matter here.
 */
#[CoversClass(ClientIdRule::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
class ClientIdRuleTest extends TestCase
{
    private RequestParamsResolver&MockObject $requestParamsResolverMock;
    private ServerRequestInterface&MockObject $requestMock;
    private LoggerService&MockObject $loggerServiceMock;
    private ResponseModeInterface&MockObject $responseModeMock;

    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->responseModeMock = $this->createMock(ResponseModeInterface::class);

        $this->requestMock->method('getServerParams')->willReturn([]);
    }

    public function testResolvesTheClientIdFromTheRequestParameters(): void
    {
        $this->resolverReturns('client-from-parameter');

        $this->assertSame('client-from-parameter', $this->check()?->getValue());
    }

    public function testFallsBackToTheHttpBasicAuthenticationUser(): void
    {
        // With client_secret_basic the client identifies itself in the Authorization header rather than in
        // a parameter, so the header is the only place the identity can be read from.
        $this->resolverReturns(null);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['PHP_AUTH_USER' => 'client-from-basic-auth']);

        $this->assertSame('client-from-basic-auth', $this->check($request)?->getValue());
    }

    public function testPrefersTheRequestParameterOverTheBasicAuthenticationUser(): void
    {
        $this->resolverReturns('client-from-parameter');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['PHP_AUTH_USER' => 'client-from-basic-auth']);

        $this->assertSame('client-from-parameter', $this->check($request)?->getValue());
    }

    public function testRejectsARequestThatNamesNoClientAtAll(): void
    {
        $this->resolverReturns(null);

        try {
            $this->check();
            $this->fail('A request without a client_id must be rejected.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
        }
    }

    private function resolverReturns(?string $clientId): void
    {
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturnCallback(
                static fn(string $parameter): ?string => $parameter === ParamsEnum::ClientId->value ?
                    $clientId :
                    null,
            );
    }

    private function check(?ServerRequestInterface $request = null): ?Result
    {
        $rule = new ClientIdRule($this->requestParamsResolverMock, new Helpers());

        return $rule->checkRule(
            $request ?? $this->requestMock,
            new ResultBag(),
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
    }
}
