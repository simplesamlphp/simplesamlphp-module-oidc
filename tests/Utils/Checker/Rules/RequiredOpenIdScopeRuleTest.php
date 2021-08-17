<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use LogicException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\ScopeEntity;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredOpenIdScopeRule
 */
class RequiredOpenIdScopeRuleTest extends TestCase
{
    protected $scopeEntities = [];

    protected $redirectUriResult;
    protected $stateResult;
    protected $scopeResult;

    protected $requestStub;

    protected function setUp(): void
    {
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

        $result = $rule->checkRule($this->requestStub, $resultBag, []) ??
            new Result(RequiredOpenIdScopeRule::class, null);

        $this->assertTrue($result->getValue());
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
