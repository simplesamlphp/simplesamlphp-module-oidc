<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule
 */
class StateRuleTest extends TestCase
{
    protected Stub $loggerServiceStub;
    protected Stub $paramsResolverStub;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->paramsResolverStub = $this->createStub(ParamsResolver::class);
    }

    protected function mock(): StateRule
    {
        return new StateRule($this->paramsResolverStub);
    }

    public function testGetKey(): void
    {
        $this->assertSame(StateRule::class, $this->mock()->getKey());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCheckRuleHasValue(): void
    {
        $value = '123';

        $request = $this->createStub(ServerRequestInterface::class);
        $this->paramsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($value);

        $resultBag = new ResultBag();
        $data = [];
        $result = $this->mock()->checkRule($request, $resultBag, $this->loggerServiceStub, $data);

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
        $this->paramsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn(null);

        $resultBag = new ResultBag();
        $result = $this->mock()->checkRule(
            $request,
            $resultBag,
            $this->loggerServiceStub,
        );

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame(null, $result->getValue());
    }
}
