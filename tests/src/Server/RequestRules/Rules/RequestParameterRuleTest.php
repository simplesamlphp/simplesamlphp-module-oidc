<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;
use SimpleSAML\OpenID\Core\RequestObject;

#[CoversClass(RequestParameterRule::class)]
class RequestParameterRuleTest extends TestCase
{
    protected Stub $clientStub;
    protected Stub $resultBagStub;
    protected MockObject $paramsResolverMock;
    protected MockObject $requestObjectMock;
    protected Stub $requestStub;
    protected Stub $loggerServiceStub;

    protected function setUp(): void
    {
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->resultBagStub = $this->createStub(ResultBag::class);
        $this->resultBagStub->method('getOrFail')->willReturnMap([
            [ClientIdRule::class, new Result(ClientIdRule::class, $this->clientStub)],
            [RedirectUriRule::class, new Result(RedirectUriRule::class, 'https://example.com/redirect')],
        ]);
        $this->paramsResolverMock = $this->createMock(ParamsResolver::class);
        $this->requestObjectMock = $this->createMock(RequestObject::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    protected function mock(): RequestParameterRule
    {
        return new RequestParameterRule($this->paramsResolverMock);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RequestParameterRule::class, $this->mock());
    }

    public function testRequestParamCanBeAbsent(): void
    {
        $result = $this->mock()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
        $this->assertNull($result);
    }

    public function testUnprotectedRequestParamCanBeUsed(): void
    {
        $this->paramsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->paramsResolverMock->expects($this->once())->method('parseRequestObjectToken')
        ->with('token')->willReturn($this->requestObjectMock);

        $result = $this->mock()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame($this->requestObjectMock, $result->getValue());
    }

    public function testMissingClientJwksThrows(): void
    {
        $this->paramsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->paramsResolverMock->expects($this->once())->method('parseRequestObjectToken')
            ->with('token')->willReturn($this->requestObjectMock);
        $this->clientStub->expects($this->once())->method('getJwks')->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->mock()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    public function testThrowsForInvalidRequestObject(): void
    {
        $this->paramsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->requestObjectMock->expects($this->once())->method('verifyWithKeySet')->with(['jwks'])
        ->willThrowException(OidcServerException::accessDenied());
        $this->paramsResolverMock->expects($this->once())->method('parseRequestObjectToken')
            ->with('token')->willReturn($this->requestObjectMock);
        $this->clientStub->expects($this->once())->method('getJwks')->willReturn(['jwks']);

        $this->expectException(OidcServerException::class);
        $this->mock()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    public function testReturnsValidRequestObject(): void
    {
        $this->paramsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->requestObjectMock->expects($this->once())->method('verifyWithKeySet')->with(['jwks']);
        $this->paramsResolverMock->expects($this->once())->method('parseRequestObjectToken')
            ->with('token')->willReturn($this->requestObjectMock);
        $this->clientStub->expects($this->once())->method('getJwks')->willReturn(['jwks']);

        $result = $this->mock()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame($this->requestObjectMock, $result->getValue());
    }
}
