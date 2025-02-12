<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule
 */
class ResponseTypeRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $requestParamsResolverStub;
    protected Helpers $helpers;

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
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): ResponseTypeRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new ResponseTypeRule(
            $requestParamsResolver,
            $helpers,
        );
    }

    /**
     * @dataProvider validResponseTypeProvider
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testResponseTypeRuleTest($responseType)
    {
        $this->requestParams['response_type'] = $responseType;
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);
        $result = $this->sut()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
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
        $params = $this->requestParams;
        unset($params['response_type']);
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);
        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }
}
