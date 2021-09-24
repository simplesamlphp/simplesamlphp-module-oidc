<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ResponseTypeRule;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\ResponseTypeRule
 */
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

    protected $loggerServiceStub;

    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @dataProvider validResponseTypeProvider
     */
    public function testResponseTypeRuleTest($responseType)
    {
        $rule = new ResponseTypeRule();

        $this->requestParams['response_type'] = $responseType;
        $this->requestStub->method('getQueryParams')->willReturn($this->requestParams);
        $result = $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
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
        $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }
}
