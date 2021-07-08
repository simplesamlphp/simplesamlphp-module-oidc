<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use LogicException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\ResultBag;

/**
 * @covers \SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RequiredOpenIdScopeRule
 */
class RequiredOpenIdScopeRuleTest extends TestCase
{
    protected $resultBagStub;

    protected $scopeEntities = [];

    protected $redirectUriResult;
    protected $stateResult;
    protected $scopeResult;

    protected $requestStub;

    protected function setUp(): void
    {
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->redirectUriResult = new Result(RedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->scopeEntities = [
            'openid' => ScopeEntity::fromData('openid'),
            'profile' => ScopeEntity::fromData('profile'),
        ];
        $this->scopeResult = new Result(ScopeRule::class, $this->scopeEntities);
    }

    public function testCheckRuleRedirectUriDependency(): void
    {
        $rule = new RequiredOpenIdScopeRule();
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, []);
    }

    public function testCheckRuleStateDependency(): void
    {
        $rule = new RequiredOpenIdScopeRule();
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, []);
    }

    public function testCheckRulePassesWhenOpenIdScopeIsPresent()
    {
        $rule = new RequiredOpenIdScopeRule();
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add($this->scopeResult);

        $this->assertTrue(($rule->checkRule($this->requestStub, $resultBag, []))->getValue());
    }

    public function testCheckRuleThrowsWhenOpenIdScopeIsNotPresent()
    {
        $rule = new RequiredOpenIdScopeRule();
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $invalidScopeEntities = [
            'profile' => ScopeEntity::fromData('profile'),
        ];
        $resultBag->add(new Result(ScopeRule::class, $invalidScopeEntities));

        $this->expectException(OidcServerException::class);

        $rule->checkRule($this->requestStub, $resultBag, []);
    }
}
