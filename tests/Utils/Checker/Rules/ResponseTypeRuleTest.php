<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\ResultBag;

class ResponseTypeRuleTest extends TestCase
{
    protected $requestStub;

    protected $requestParams = [
        'client_id' => 'client123',
        'response_type' => '',
    ];

    protected $sampleResponseTypes = [
        'should_add' => [
            'id_token',
        ],
        'should_not_add' => [
            'code',
            'token',
            'id_token token',
            'code id_token',
            'code token',
            'code id_token token',
        ],
    ];

    /**
     * @var ResultBag
     */
    private $resultBag;

    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
    }

    /**
     * @dataProvider validResponseTypeProvider
     */
    public function testResponseTypeRuleTest($responseType)
    {
        $rule = new ResponseTypeRule();

        $this->requestParams['response_type'] = $responseType;
        $this->requestStub->method('getQueryParams')->willReturn($this->requestParams);
        $result = $rule->checkRule($this->requestStub, $this->resultBag) ??
            new Result(ResponseTypeRule::class, null);
        $this->assertSame($responseType, $result->getValue());
    }

    public function validResponseTypeProvider(): array
    {
        return [
            ['id_token'],
            ['code'],
        ];
    }

    public function testResponseTypeRuleThrowsWithNoResponseTypeParamTest()
    {
        $rule = new ResponseTypeRule();
        $params = $this->requestParams;
        unset($params['response_type']);
        $this->requestStub->method('getQueryParams')->willReturn($params);
        $this->expectException(OidcServerException::class);
        $rule->checkRule($this->requestStub, $this->resultBag);
    }
}
