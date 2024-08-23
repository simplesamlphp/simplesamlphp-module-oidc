<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule
 */
class RequiredNonceRuleTest extends TestCase
{
    protected ResultBag $resultBag;
    protected Result $redirectUriResult;
    protected Result $stateResult;

    protected Stub $requestStub;

    protected array $requestQueryParams = [
        'nonce' => 'nonce123',
        'state' => 'state123',
    ];

    protected Stub $loggerServiceStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->redirectUriResult = new Result(RedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
        $this->resultBag->add($this->redirectUriResult);
        $this->resultBag->add($this->stateResult);

        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $rule = new RequiredNonceRule();
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleStateDependency(): void
    {
        $rule = new \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule();
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRulePassesWhenNonceIsPresent()
    {
        $rule = new \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule();

        $this->requestStub->method('getMethod')->willReturn('GET');
        $this->requestStub->method('getQueryParams')->willReturn($this->requestQueryParams);

        $result = $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
        new Result(RequiredNonceRule::class, null);

        $this->assertEquals($this->requestQueryParams['nonce'], $result->getValue());
    }

    /**
     * @throws \Throwable
     */
    public function testCheckRuleThrowsWhenNonceIsNotPresent()
    {
        $rule = new \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule();

        $invalidParams = $this->requestQueryParams;
        unset($invalidParams['nonce']);

        $this->requestStub->method('getQueryParams')->willReturn($invalidParams);

        $this->expectException(OidcServerException::class);

        $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }
}
