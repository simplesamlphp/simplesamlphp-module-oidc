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

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule
 */
class StateRuleTest extends TestCase
{
    protected Stub $loggerServiceStub;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    public function testGetKey(): void
    {
        $rule = new StateRule();
        $this->assertSame(StateRule::class, $rule->getKey());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCheckRuleGetMethod(): void
    {
        $key = 'state';
        $value = '123';

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getQueryParams')->willReturn([$key => $value]);

        $resultBag = new ResultBag();
        $data = [];
        $rule = new StateRule();
        $result = $rule->checkRule($request, $resultBag, $this->loggerServiceStub, $data);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($value, $result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCheckRulePostMethod(): void
    {
        $key = 'state';
        $value = '123';

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getParsedBody')->willReturn([$key => $value]);

        $resultBag = new ResultBag();
        $data = [];
        $rule = new StateRule();
        $result = $rule->checkRule($request, $resultBag, $this->loggerServiceStub, $data, false, ['GET', 'POST']);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($value, $result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCheckRuleReturnsNullWhenMethodNotAllowed(): void
    {
        $key = 'state';
        $value = '123';

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getParsedBody')->willReturn([$key => $value]);

        $resultBag = new ResultBag();
        $rule = new StateRule();
        $result = $rule->checkRule($request, $resultBag, $this->loggerServiceStub);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertNull($result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCheckRuleReturnsNullWhenMethodNotSupported(): void
    {
        $key = 'state';
        $value = '123';

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('OPTIONS');
        $request->method('getParsedBody')->willReturn([$key => $value]);

        $resultBag = new ResultBag();
        $rule = new StateRule();
        $result = $rule->checkRule($request, $resultBag, $this->loggerServiceStub, [], false, ['OPTIONS']);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertNull($result->getValue());
    }
}
