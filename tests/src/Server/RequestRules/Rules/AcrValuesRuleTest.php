<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule
 */
class AcrValuesRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $resultStub;
    protected Stub $loggerServiceStub;
    protected Stub $paramsResolverStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->resultStub = $this->createStub(ResultInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->paramsResolverStub = $this->createStub(ParamsResolver::class);
    }

    protected function mock(): AcrValuesRule
    {
        return new AcrValuesRule($this->paramsResolverStub);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testNoAcrIsSetIfAcrValuesNotRequested(): void
    {
        $result = $this->mock()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        ) ?? new Result(AcrValuesRule::class, null);
        $this->assertNull($result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testPopulatesAcrValuesFromClaimsParameter(): void
    {
        $claims = ['id_token' => ['acr' => ['values' => ['1', '0'], 'essential' => true]]];
        $this->resultStub->method('getValue')->willReturn($claims);
        $this->resultBagStub->method('get')->willReturn($this->resultStub);

        $result = $this->mock()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        ) ?? new Result(AcrValuesRule::class, null);

        $this->assertSame(['1', '0'], $result->getValue()['values']);
        $this->assertTrue($result->getValue()['essential']);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testPopulatesAcrValuesFromAcrValuesRequestParameter(): void
    {
        $this->paramsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('1 0');

        $result = $this->mock()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        ) ?? new Result(AcrValuesRule::class, null);

        $this->assertSame(['1', '0'], $result->getValue()['values']);
        $this->assertFalse($result->getValue()['essential']);
    }
}
