<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\UiLocalesRule;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\UiLocalesRule
 */
class UiLocalesRuleTest extends TestCase
{
    protected $requestStub;
    protected $resultBagStub;

    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->requestStub->method('getMethod')->willReturn('GET');

        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
    }

    public function testCheckRuleReturnsResultWhenParamSet()
    {
        $this->requestStub->method('getQueryParams')->willReturn(['ui_locales' => 'en']);

        $result = (new UiLocalesRule())->checkRule($this->requestStub, $this->resultBagStub) ??
            new Result(UiLocalesRule::class);

        $this->assertEquals('en', $result->getValue());
    }

    public function testCheckRuleReturnsNullWhenParamNotSet()
    {
        $this->requestStub->method('getQueryParams')->willReturn([]);

        $result = (new UiLocalesRule())->checkRule($this->requestStub, $this->resultBagStub) ??
            new Result(UiLocalesRule::class);

        $this->assertNull($result->getValue());
    }
}
