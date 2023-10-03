<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\Stub;
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
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $loggerServiceStub;

    /**
     * @throws Exception
     */
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
