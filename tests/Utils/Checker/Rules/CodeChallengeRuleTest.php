<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeRule
 */
class CodeChallengeRuleTest extends TestCase
{
    protected $rule;
    protected $requestStub;
    protected $resultBagStub;
    protected $redirectUriResult;
    protected $stateResult;

    protected $codeChallenge = '123123123123123123123123123123123123123123123123123123123123';

    protected function setUp(): void
    {
        $this->rule = new CodeChallengeRule();
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->redirectUriResult = new Result(RedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
    }

    public function testCheckRuleRedirectUriDependency(): void
    {
        $resultBag = new ResultBag();
        $this->expectException(\LogicException::class);
        $this->rule->checkRule($this->requestStub, $resultBag, []);
    }

    public function testCheckRuleStateDependency(): void
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(\LogicException::class);
        $this->rule->checkRule($this->requestStub, $resultBag, []);
    }

    public function testCheckRuleNoCodeChallengeThrows(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestStub->method('getQueryParams')->willReturn([]);
        $this->expectException(OidcServerException::class);
        $this->rule->checkRule($this->requestStub, $resultBag, []);
    }

    public function testCheckRuleInvalidCodeChallengeThrows(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestStub->method('getQueryParams')->willReturn(['code_challenge' => 'too-short']);
        $this->expectException(OidcServerException::class);
        $this->rule->checkRule($this->requestStub, $resultBag, []);
    }

    public function testCheckRuleForValidCodeChallenge(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestStub->method('getQueryParams')->willReturn(['code_challenge' => $this->codeChallenge]);
        $result = $this->rule->checkRule($this->requestStub, $resultBag, []);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($this->codeChallenge, $result->getValue());
    }

    protected function prepareValidResultBag(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        return $resultBag;
    }
}
