<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
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
    protected $loggerServiceStub;

    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->requestStub->method('getMethod')->willReturn('GET');

        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @throws OidcServerException
     */
    public function testCheckRuleReturnsResultWhenParamSet()
    {
        $this->requestStub->method('getQueryParams')->willReturn(['ui_locales' => 'en']);

        $result = (new UiLocalesRule())
                ->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
                    new Result(UiLocalesRule::class);

        $this->assertEquals('en', $result->getValue());
    }

    /**
     * @throws OidcServerException
     */
    public function testCheckRuleReturnsNullWhenParamNotSet()
    {
        $this->requestStub->method('getQueryParams')->willReturn([]);

        $result = (new UiLocalesRule())
                ->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
                    new Result(UiLocalesRule::class);

        $this->assertNull($result->getValue());
    }
}
