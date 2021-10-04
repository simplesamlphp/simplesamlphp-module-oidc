<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\AbstractRule
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule
 */
class StateRuleTest extends TestCase
{
    protected $loggerServiceStub;

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
     * @throws OidcServerException
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
     * @throws OidcServerException
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
     * @throws OidcServerException
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
        $result = $rule->checkRule($request, $resultBag, $this->loggerServiceStub, [], false, ['GET']);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertNull($result->getValue());
    }

    /**
     * @throws OidcServerException
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
