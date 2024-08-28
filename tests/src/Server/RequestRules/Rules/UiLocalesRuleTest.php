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
use SimpleSAML\Module\oidc\Utils\ParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule
 */
class UiLocalesRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $loggerServiceStub;
    protected Stub $paramsResolverStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->requestStub->method('getMethod')->willReturn('GET');

        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->paramsResolverStub = $this->createStub(ParamsResolver::class);
    }

    protected function mock(): UiLocalesRule
    {
        return new UiLocalesRule($this->paramsResolverStub);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleReturnsResultWhenParamSet()
    {
        $this->paramsResolverStub->method('getBasedOnAllowedMethods')->willReturn('en');

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
