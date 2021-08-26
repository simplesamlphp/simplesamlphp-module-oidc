<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use LogicException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredNonceRule
 */
class RequiredNonceRuleTest extends TestCase
{
    protected $resultBag;
    protected $redirectUriResult;
    protected $stateResult;

    protected $requestStub;

    protected $requestQueryParams = [
        'nonce' => 'nonce123',
        'state' => 'state123',
    ];

    protected function setUp(): void
    {
        $this->redirectUriResult = new Result(RedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
        $this->resultBag->add($this->redirectUriResult);
        $this->resultBag->add($this->stateResult);
    }

    public function testCheckRuleRedirectUriDependency(): void
    {
        $rule = new RequiredNonceRule();
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, []);
    }

    public function testCheckRuleStateDependency(): void
    {
        $rule = new RequiredNonceRule();
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, []);
    }

    public function testCheckRulePassesWhenNonceIsPresent()
    {
        $rule = new RequiredNonceRule();

        $this->requestStub->method('getQueryParams')->willReturn($this->requestQueryParams);

        $result = $rule->checkRule($this->requestStub, $this->resultBag, []) ??
            new Result(RequiredNonceRule::class, null);

        $this->assertEquals($this->requestQueryParams['nonce'], $result->getValue());
    }

    public function testCheckRuleThrowsWhenNonceIsNotPresent()
    {
        $rule = new RequiredNonceRule();

        $invalidParams = $this->requestQueryParams;
        unset($invalidParams['nonce']);

        $this->requestStub->method('getQueryParams')->willReturn($invalidParams);

        $this->expectException(OidcServerException::class);

        $rule->checkRule($this->requestStub, $this->resultBag, []);
    }
}
