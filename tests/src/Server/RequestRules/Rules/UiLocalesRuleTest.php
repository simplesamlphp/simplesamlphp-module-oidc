<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule
 */
class UiLocalesRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->requestStub->method('getMethod')->willReturn('GET');

        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
    }

    protected function mock(): UiLocalesRule
    {
        return new UiLocalesRule($this->requestParamsResolverStub);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleReturnsResultWhenParamSet()
    {
        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn('en');

        $result = $this->mock()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        new Result(\SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule::class);

        $this->assertEquals('en', $result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleReturnsNullWhenParamNotSet()
    {
        $this->requestStub->method('getQueryParams')->willReturn([]);

        $result = $this->mock()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        new Result(UiLocalesRule::class);

        $this->assertNull($result->getValue());
    }
}
