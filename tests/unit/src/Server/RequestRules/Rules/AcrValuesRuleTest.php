<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule
 */
class AcrValuesRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $resultStub;
    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;
    protected Helpers $helpers;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->resultStub = $this->createStub(ResultInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): AcrValuesRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new AcrValuesRule(
            $requestParamsResolver,
            $helpers,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testNoAcrIsSetIfAcrValuesNotRequested(): void
    {
        $result = $this->sut()->checkRule(
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

        $result = $this->sut()->checkRule(
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
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('1 0');

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        ) ?? new Result(AcrValuesRule::class, null);

        $this->assertSame(['1', '0'], $result->getValue()['values']);
        $this->assertFalse($result->getValue()['essential']);
    }
}
