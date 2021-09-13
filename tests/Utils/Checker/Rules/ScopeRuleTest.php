<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\ScopeEntity;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeRule
 */
class ScopeRuleTest extends TestCase
{
    protected $scopeRepositoryStub;
    protected $resultBagStub;
    protected $data = [
        'default_scope' => '',
        'scope_delimiter_string' => ' ',
    ];
    protected $scopes = 'openid profile';

    protected $scopeEntities = [];

    protected $redirectUriResult;
    protected $stateResult;

    protected $requestStub;

    protected function setUp(): void
    {
        $this->scopeRepositoryStub = $this->createStub(ScopeRepositoryInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->redirectUriResult = new Result(RedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->scopeEntities = [
            'openid' => ScopeEntity::fromData('openid'),
            'profile' => ScopeEntity::fromData('profile'),
        ];
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(ScopeRule::class, new ScopeRule($this->scopeRepositoryStub));
    }

    public function testCheckRuleRedirectUriDependency(): void
    {
        $rule = new ScopeRule($this->scopeRepositoryStub);
        $resultBag = new ResultBag();
        $this->expectException(\LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, $this->data);
    }

    public function testCheckRuleStateDependency(): void
    {
        $rule = new ScopeRule($this->scopeRepositoryStub);
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(\LogicException::class);
        $rule->checkRule($this->requestStub, $resultBag, $this->data);
    }

    public function testValidScopes(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestStub->method('getQueryParams')->willReturn(['scope' => 'openid profile']);
        $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturn(
                $this->onConsecutiveCalls(
                    $this->scopeEntities['openid'],
                    $this->scopeEntities['profile']
                )
            );

        $result = (new ScopeRule($this->scopeRepositoryStub))->checkRule($this->requestStub, $resultBag, $this->data);
        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertSame($this->scopeEntities['openid'], $result->getValue()[0]);
        $this->assertSame($this->scopeEntities['profile'], $result->getValue()[1]);
    }

    public function testInvalidScopeThrows(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestStub->method('getQueryParams')->willReturn(['scope' => 'openid']);
        $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturn(
                $this->onConsecutiveCalls(
                    'invalid-scope-entity'
                )
            );

        $this->expectException(OidcServerException::class);
        (new ScopeRule($this->scopeRepositoryStub))->checkRule($this->requestStub, $resultBag, $this->data);
    }

    protected function prepareValidResultBag(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        return $resultBag;
    }

    protected function prepareValidScopeRepositoryStub()
    {
        return $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturn(
                $this->onConsecutiveCalls(
                    $this->scopeEntities['openid'],
                    $this->scopeEntities['profile']
                )
            );
    }
}
