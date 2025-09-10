<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule
 */
class CodeChallengeRuleTest extends TestCase
{
    protected CodeChallengeRule $rule;
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Result $redirectUriResult;
    protected Result $stateResult;

    protected string $codeChallenge = '123123123123123123123123123123123123123123123123123123123123';
    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;
    protected Stub $clientStub;
    protected Result $clientIdResult;
    protected Helpers $helpers;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->redirectUriResult = new Result(RedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->clientIdResult = new Result(ClientRule::class, $this->clientStub);
        $this->helpers = new Helpers();
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): CodeChallengeRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new CodeChallengeRule(
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
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
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
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     */
    public function testCheckRuleNoCodeReturnsNullForConfidentialClients(): void
    {
        $this->clientStub->method('isConfidential')->willReturn(true);
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn(null);
        $result = $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertNull($result->getValue());
    }

    /**
     * @throws \Throwable
     */
    public function testCheckRuleInvalidCodeChallengeThrows(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('too-short');
        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleForValidCodeChallenge(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($this->codeChallenge);

        $result = $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($this->codeChallenge, $result->getValue());
    }

    protected function prepareValidResultBag(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add($this->clientIdResult);
        return $resultBag;
    }
}
