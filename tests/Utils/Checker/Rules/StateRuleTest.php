<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\ResultBag;

/**
 * @covers \SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\AbstractRule
 * @covers \SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\StateRule
 */
class StateRuleTest extends TestCase
{
    public function testGetKey(): void
    {
        $rule = new StateRule();
        $this->assertSame(StateRule::class, $rule->getKey());
    }

    public function testCheckRule(): void
    {
        $key = 'state';
        $value = '123';

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([$key => $value]);

        $resultBag = new ResultBag();
        $data = [];
        $rule = new StateRule();
        $result = $rule->checkRule($request, $resultBag, $data);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($value, $result->getValue());
    }
}
