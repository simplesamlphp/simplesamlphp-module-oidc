<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\Stub;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AcrValuesRule;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\AcrValuesRule
 */
class AcrValuesRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $resultStub;
    protected Stub $loggerServiceStub;

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->resultStub = $this->createStub(ResultInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @throws OidcServerException
     */
    public function testNoAcrIsSetIfAcrValuesNotRequested(): void
    {
        $result = (new AcrValuesRule())->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub
        ) ?? new Result(AcrValuesRule::class, null);
        $this->assertNull($result->getValue());
    }

    /**
     * @throws OidcServerException
     */
    public function testPopulatesAcrValuesFromClaimsParameter(): void
    {
        $claims = ['id_token' => ['acr' => ['values' => ['1', '0'], 'essential' => true]]];
        $this->resultStub->method('getValue')->willReturn($claims);
        $this->resultBagStub->method('get')->willReturn($this->resultStub);

        $result = (new AcrValuesRule())->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub
        ) ?? new Result(AcrValuesRule::class, null);

        $this->assertSame(['1', '0'], $result->getValue()['values']);
        $this->assertTrue($result->getValue()['essential']);
    }

    /**
     * @throws OidcServerException
     */
    public function testPopulatesAcrValuesFromAcrValuesRequestParameter(): void
    {
        $this->requestStub->method('getQueryParams')->willReturn(['acr_values' => '1 0']);

        $result = (new AcrValuesRule())->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub
        ) ?? new Result(AcrValuesRule::class, null);

        $this->assertSame(['1', '0'], $result->getValue()['values']);
        $this->assertFalse($result->getValue()['essential']);
    }
}
