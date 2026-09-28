<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule
 */
#[AllowMockObjectsWithoutExpectations]
class RequiredOpenIdScopeRuleTest extends TestCase
{
    protected array $scopeEntities = [];

    protected Result $redirectUriResult;

    protected Result $stateResult;

    protected Result $scopeResult;

    protected Stub $requestStub;

    protected Stub $loggerServiceStub;

    protected Stub $requestParamsResolverStub;

    protected Helpers $helpers;

    protected Stub $responseModeStub;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->redirectUriResult = new Result(ClientRedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->scopeEntities = [
            'openid' => new ScopeEntity('openid'),
            'profile' => new ScopeEntity('profile'),
        ];
        $this->scopeResult = new Result(ScopeRule::class, $this->scopeEntities);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): RequiredOpenIdScopeRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new RequiredOpenIdScopeRule(
            $requestParamsResolver,
            $helpers,
        );
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, [], $this->responseModeStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleStateDependency(): void
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(LogicException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, [], $this->responseModeStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRulePassesWhenOpenIdScopeIsPresent()
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add($this->scopeResult);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ) ??
        new Result(RequiredOpenIdScopeRule::class, null);

        $this->assertTrue($result->getValue());
    }


    /**
     * @throws \Throwable
     */
    public function testCheckRuleThrowsWhenOpenIdScopeIsNotPresent()
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $invalidScopeEntities = [
            'profile' => new ScopeEntity('profile'),
        ];
        $resultBag->add(new Result(ScopeRule::class, $invalidScopeEntities));

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, [], $this->responseModeStub);
    }


    /**
     * An OpenID4VCI authorization code request need not carry openid. Whether a request is one is the
     * resolver's call, made from the methods the rule is allowed to read, and with the broad detection:
     * a wallet starting the flow on its own carries no issuer_state.
     *
     * @throws \Throwable
     */
    public function testCheckRulePassesWithoutOpenIdScopeForAVciRequest(): void
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add(new Result(ScopeRule::class, ['ResearchCredential' => new ScopeEntity('ResearchCredential')]));
        $requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolverMock->expects($this->once())->method('isVciAuthorizationCodeRequest')
            ->with($this->identicalTo($this->requestStub), [HttpMethodsEnum::POST])
            ->willReturn(true);
        $requestParamsResolverMock->expects($this->never())->method('isVciAuthorizationCodeRequestWithIssuerState');

        $result = $this->sut($requestParamsResolverMock)->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
            [HttpMethodsEnum::POST],
        );

        $this->assertTrue($result?->getValue());
    }
}
