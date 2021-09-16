<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
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
    protected $rule;
    protected $requestStub;
    protected $resultBagStub;
    protected $resultStub;

    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->resultStub = $this->createStub(ResultInterface::class);
    }

    public function testNoAcrIsSetIfAcrValuesNotRequested(): void
    {
        $result = (new AcrValuesRule())->checkRule($this->requestStub, $this->resultBagStub) ??
            new Result(AcrValuesRule::class, null);
        $this->assertNull($result->getValue());
    }

    public function testPopulatesAcrValuesFromClaimsParameter(): void
    {
        $claims = ['id_token' => ['acr' => ['values' => ['1', '0'], 'essential' => true]]];
        $this->resultStub->method('getValue')->willReturn($claims);
        $this->resultBagStub->method('get')->willReturn($this->resultStub);

        $result = (new AcrValuesRule())->checkRule($this->requestStub, $this->resultBagStub) ??
            new Result(AcrValuesRule::class, null);

        $this->assertSame(['1', '0'], $result->getValue()['values']);
        $this->assertTrue($result->getValue()['essential']);
    }

    public function testPopulatesAcrValuesFromAcrValuesRequestParameter(): void
    {
        $this->requestStub->method('getQueryParams')->willReturn(['acr_values' => '1 0']);

        $result = (new AcrValuesRule())->checkRule($this->requestStub, $this->resultBagStub) ??
            new Result(AcrValuesRule::class, null);

        $this->assertSame(['1', '0'], $result->getValue()['values']);
        $this->assertFalse($result->getValue()['essential']);
    }
}
