<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredOpenIdScopeRule
 */
class RequiredOpenIdScopeRuleTest extends TestCase
{
    protected array $scopeEntities = [];

    protected Result $redirectUriResult;
    protected Result $stateResult;
    protected Result $scopeResult;

    protected Stub $requestStub;

    protected Stub $loggerServiceStub;

    /**
     * @throws \Exception
     */
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
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $rule = new RequiredOpenIdScopeRule();
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
        $rule = new RequiredOpenIdScopeRule();
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRulePassesWhenOpenIdScopeIsPresent()
    {
        $rule = new RequiredOpenIdScopeRule();
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add($this->scopeResult);

        $result = $rule->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub) ??
        new Result(RequiredOpenIdScopeRule::class, null);

        $this->assertTrue($result->getValue());
    }

    /**
     * @throws \Throwable
     */
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

        $rule->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }
}
