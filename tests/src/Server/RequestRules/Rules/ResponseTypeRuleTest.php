<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule
 */
class ResponseTypeRuleTest extends TestCase
{
    protected Stub $requestStub;

    protected array $requestParams = [
        'client_id' => 'client123',
        'response_type' => '',
    ];

    protected array $sampleResponseTypes = [
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
     * @var \SimpleSAML\Module\oidc\Server\RequestRules\ResultBag
     */
    private ResultBag $resultBag;

    protected Stub $loggerServiceStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @dataProvider validResponseTypeProvider
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testResponseTypeRuleTest($responseType)
    {
        $rule = new ResponseTypeRule();

        $this->requestParams['response_type'] = $responseType;
        $this->requestStub->method('getMethod')->willReturn('GET');
        $this->requestStub->method('getQueryParams')->willReturn($this->requestParams);
        $result = $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
        new Result(ResponseTypeRule::class, null);
        $this->assertSame($responseType, $result->getValue());
    }

    public static function validResponseTypeProvider(): array
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
