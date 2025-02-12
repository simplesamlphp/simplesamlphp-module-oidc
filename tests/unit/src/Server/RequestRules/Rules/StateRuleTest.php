<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule
 */
class StateRuleTest extends TestCase
{
    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;
    protected Helpers $helpers;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): StateRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new StateRule(
            $requestParamsResolver,
            $helpers,
        );
    }

    public function testGetKey(): void
    {
        $this->assertSame(StateRule::class, $this->sut()->getKey());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCheckRuleHasValue(): void
    {
        $value = '123';

        $request = $this->createStub(ServerRequestInterface::class);
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($value);

        $resultBag = new ResultBag();
        $data = [];
        $result = $this->sut()->checkRule($request, $resultBag, $this->loggerServiceStub, $data);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($value, $result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCheckRulePostMethod(): void
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn(null);

        $resultBag = new ResultBag();
        $result = $this->sut()->checkRule(
            $request,
            $resultBag,
            $this->loggerServiceStub,
        );

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame(null, $result->getValue());
    }
}
