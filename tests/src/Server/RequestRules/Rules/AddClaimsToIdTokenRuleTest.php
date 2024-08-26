<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule
 */
class AddClaimsToIdTokenRuleTest extends TestCase
{
    protected Stub $requestStub;

    protected array $requestParams = [
        'client_id' => 'client123',
        'response_type' => '',
    ];

    protected array $sampleResponseTypes = [
        'should_add' => [
            'id_token',
            'code',
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

    private ResultBag $resultBag;

    private Stub $loggerServiceStub;

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
     * @throws \Throwable
     */
    public function testAddClaimsToIdTokenRuleTest($responseType)
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->resultBag->add(new Result(ResponseTypeRule::class, $responseType));

        $result = $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
        new Result(AddClaimsToIdTokenRule::class, null);
        $this->assertTrue($result->getValue());
    }

    public static function validResponseTypeProvider(): array
    {
        return [
            ['id_token'],
        ];
    }

    /**
     * @dataProvider invalidResponseTypeProvider
     * @throws \Throwable
     */
    public function testDoNotAddClaimsToIdTokenRuleTest($responseType)
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->resultBag->add(new Result(ResponseTypeRule::class, $responseType));

        $result = $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
        new Result(AddClaimsToIdTokenRule::class, null);

        $this->assertFalse($result->getValue());
    }

    public static function invalidResponseTypeProvider(): array
    {
        return [
            ['code'],
            ['token'],
            ['id_token token'],
            ['code id_token'],
            ['code token'],
            ['code id_token token'],
        ];
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAddClaimsToIdTokenRuleThrowsWithNoResponseTypeParamTest()
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }
}
