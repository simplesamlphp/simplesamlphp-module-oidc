<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LogicException;
use PHPUnit\Framework\MockObject\Builder\InvocationStubber;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule
 */
class ScopeRuleTest extends TestCase
{
    protected Stub $scopeRepositoryStub;
    protected Stub $resultBagStub;
    protected array $data = [
        'default_scope' => '',
        'scope_delimiter_string' => ' ',
    ];
    protected string $scopes = 'openid profile';

    protected array $scopeEntities = [];

    protected Result $redirectUriResult;
    protected Result $stateResult;

    protected Stub $requestStub;

    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;

    /**
     * @throws \Exception
     */
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
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
    }

    protected function mock(): ScopeRule
    {
        return new ScopeRule(
            $this->requestParamsResolverStub,
            $this->scopeRepositoryStub,
        );
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(ScopeRule::class, $this->mock());
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $this->mock()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, $this->data);
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
        $this->mock()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, $this->data);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidScopes(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('openid profile');
        $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturn(
                $this->onConsecutiveCalls(
                    $this->scopeEntities['openid'],
                    $this->scopeEntities['profile'],
                ),
            );

        $result = $this->mock()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, $this->data);
        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertSame($this->scopeEntities['openid'], $result->getValue()[0]);
        $this->assertSame($this->scopeEntities['profile'], $result->getValue()[1]);
    }

    /**
     * @throws \Throwable
     */
    public function testInvalidScopeThrows(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('openid');
        $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturn(
                $this->onConsecutiveCalls(
                    'invalid-scope-entity',
                ),
            );

        $this->expectException(OidcServerException::class);
        $this->mock()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, $this->data);
    }

    protected function prepareValidResultBag(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        return $resultBag;
    }

    protected function prepareValidScopeRepositoryStub(): InvocationStubber
    {
        return $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturn(
                $this->onConsecutiveCalls(
                    $this->scopeEntities['openid'],
                    $this->scopeEntities['profile'],
                ),
            );
    }
}
