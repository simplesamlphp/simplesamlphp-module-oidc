<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

#[CoversClass(MaxAgeRule::class)]
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
}
