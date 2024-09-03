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
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

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
    protected Stub $requestParamsResolverStub;

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
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
    }

    protected function mock(): RequiredNonceRule
    {
        return new RequiredNonceRule($this->requestParamsResolverStub);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $this->mock()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
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
        $this->mock()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRulePassesWhenNonceIsPresent()
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn($this->requestQueryParams['nonce']);

        $result = $this->mock()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
        new Result(RequiredNonceRule::class, null);

        $this->assertEquals($this->requestQueryParams['nonce'], $result->getValue());
    }

    /**
     * @throws \Throwable
     */
    public function testCheckRuleThrowsWhenNonceIsNotPresent()
    {
        $this->expectException(OidcServerException::class);

        $this->mock()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }
}
