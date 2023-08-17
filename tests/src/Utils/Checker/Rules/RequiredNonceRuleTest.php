<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use LogicException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredNonceRule
 */
class RequiredNonceRuleTest extends TestCase
{
    protected ResultBag $resultBag;
    protected Result $redirectUriResult;
    protected Result $stateResult;

    protected $requestStub;

    protected array $requestQueryParams = [
        'nonce' => 'nonce123',
        'state' => 'state123',
    ];

    protected $loggerServiceStub;

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
     * @throws Throwable
     * @throws OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $rule = new RequiredNonceRule();
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, []);
    }

    /**
     * @throws Throwable
     * @throws OidcServerException
     */
    public function testCheckRuleStateDependency(): void
    {
        $rule = new RequiredNonceRule();
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, []);
    }

    /**
     * @throws Throwable
     * @throws OidcServerException
     */
    public function testCheckRulePassesWhenNonceIsPresent()
    {
        $rule = new RequiredNonceRule();

        $this->requestStub->method('getQueryParams')->willReturn($this->requestQueryParams);

        $result = $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub, []) ??
            new Result(RequiredNonceRule::class, null);

        $this->assertEquals($this->requestQueryParams['nonce'], $result->getValue());
    }

    /**
     * @throws Throwable
     */
    public function testCheckRuleThrowsWhenNonceIsNotPresent()
    {
        $rule = new RequiredNonceRule();

        $invalidParams = $this->requestQueryParams;
        unset($invalidParams['nonce']);

        $this->requestStub->method('getQueryParams')->willReturn($invalidParams);

        $this->expectException(OidcServerException::class);

        $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub, []);
    }
}
