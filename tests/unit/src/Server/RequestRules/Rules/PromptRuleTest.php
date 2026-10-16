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
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\LoginHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\AuthorizationErrorRedirect;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;
use SimpleSAML\OpenID\Core\IdTokenHint;
use SimpleSAML\Utils\HTTP as SspHttp;

#[CoversClass(PromptRule::class)]
#[AllowMockObjectsWithoutExpectations]
class PromptRuleTest extends TestCase
{
    private const string PUSHED_REQUEST_URI = 'urn:ietf:params:oauth:request_uri:pushed-request';


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
        $this->responseModeMock->method('getMode')->willReturn(ResponseModesEnum::FormPost);

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

        // A cancelled re-authentication is answered at the request's redirect, with its state, in its response mode.
        $this->authenticationServiceMock->expects($this->once())
            ->method('authenticateForClient')
            ->with(
                $this->clientMock,
                new AuthorizationErrorRedirect('https://rp.example.org/cb', 'state123', ResponseModesEnum::FormPost),
                $this->callback(fn(array $loginParams): bool =>
                    ($loginParams['core:username'] ?? null) === 'user@example.org'),
            );

        $this->assertNull($this->checkRule());
    }


    public static function requestUriProvider(): array
    {
        return [
            'a pushed request' => [self::PUSHED_REQUEST_URI, self::PUSHED_REQUEST_URI],
            'a Request Object by reference' => ['https://rp.example.org/request.jwt', null],
        ];
    }


    /**
     * A cancelled re-authentication of a pushed request consumes that request, so its redirect carries the
     * request_uri; a Request Object's request_uri is no pushed request.
     */
    #[DataProvider('requestUriProvider')]
    public function testPromptLoginReAuthenticationCarriesThePushedRequest(
        string $requestUri,
        ?string $expectedPushedRequestUri,
    ): void {
        $this->resultBag->add(new Result(LoginHintRule::class, null));
        $this->resultBag->add(new Result(RequestUriRule::class, $requestUri));
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')->willReturn(['prompt' => 'login']);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);

        $httpMock = $this->createMock(SspHttp::class);
        $httpMock->method('getSelfURLNoQuery')->willReturn('https://op.example.org/authorize');
        $httpMock->method('addURLParameters')->willReturn('https://op.example.org/authorize');
        $utilsMock = $this->createMock(SspBridgeUtils::class);
        $utilsMock->method('http')->willReturn($httpMock);
        $this->sspBridgeMock->method('utils')->willReturn($utilsMock);

        $this->authenticationServiceMock->expects($this->once())
            ->method('authenticateForClient')
            ->with(
                $this->clientMock,
                new AuthorizationErrorRedirect(
                    'https://rp.example.org/cb',
                    'state123',
                    ResponseModesEnum::FormPost,
                    $expectedPushedRequestUri,
                ),
                $this->anything(),
            );

        $this->assertNull($this->checkRule());
    }


    public function testPromptNoneThrowsLoginRequiredWhenNotAuthenticated(): void
    {
        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->willReturn(['prompt' => 'none']);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(false);

        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('End-User is not already authenticated.');
        $this->checkRule();
    }


    public function testPromptNoneWithMatchingIdTokenHintProceeds(): void
    {
        $idTokenHintMock = $this->createMock(IdTokenHint::class);
        $idTokenHintMock->method('getSubject')->willReturn('subject-123');
        $this->resultBag->add(new Result(IdTokenHintRule::class, $idTokenHintMock));

        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->willReturn(['prompt' => 'none']);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);
        $this->authSimpleMock->method('getAttributes')->willReturn(['uid' => ['subject-123']]);
        $this->authenticationServiceMock->method('subjectMatchesAttributes')->willReturn(true);

        $this->assertNull($this->checkRule());
    }


    public function testPromptNoneWithoutIdTokenHintProceeds(): void
    {
        $this->resultBag->add(new Result(IdTokenHintRule::class, null));

        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->willReturn(['prompt' => 'none']);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);
        $this->authenticationServiceMock->expects($this->never())->method('subjectMatchesAttributes');

        $this->assertNull($this->checkRule());
    }


    public function testPromptNoneWithMismatchedIdTokenHintThrowsLoginRequired(): void
    {
        $idTokenHintMock = $this->createMock(IdTokenHint::class);
        $idTokenHintMock->method('getSubject')->willReturn('subject-123');
        $this->resultBag->add(new Result(IdTokenHintRule::class, $idTokenHintMock));

        $this->requestParamsResolverMock->method('getAllBasedOnAllowedMethods')
            ->willReturn(['prompt' => 'none']);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);
        $this->authSimpleMock->method('getAttributes')->willReturn(['uid' => ['other-user']]);
        $this->authenticationServiceMock->method('subjectMatchesAttributes')->willReturn(false);

        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('End-User is not already authenticated.');
        $this->checkRule();
    }
}
