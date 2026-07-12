<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils as SspBridgeUtils;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\LoginHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Utils\HTTP as SspHttp;

#[CoversClass(PromptRule::class)]
class PromptRuleTest extends TestCase
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
        $this->resultBag->add(new Result(ClientRedirectUriRule::class, 'https://rp.example.org/cb'));
        $this->resultBag->add(new Result(StateRule::class, 'state123'));
    }

    protected function sut(): PromptRule
    {
        return new PromptRule(
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

    public function testReturnsNullWhenNoPromptParam(): void
    {
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')->willReturn([]);
        $this->authenticationServiceMock->expects($this->never())->method('authenticateForClient');

        $this->assertNull($this->checkRule());
    }

    public function testPromptLoginReAuthenticatesAndPropagatesLoginHint(): void
    {
        $this->resultBag->add(new Result(LoginHintRule::class, 'user@example.org'));
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->willReturn(['prompt' => 'login', 'login_hint' => 'user@example.org']);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);

        $httpMock = $this->createMock(SspHttp::class);
        $httpMock->method('getSelfURLNoQuery')->willReturn('https://op.example.org/authorize');
        $httpMock->method('addURLParameters')
            ->willReturn('https://op.example.org/authorize?login_hint=user@example.org');
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

        $this->assertNull($this->checkRule());
    }
}
